"""python-can bus over a VAS 6154: RawMode sends, monitor receives, CAN1 on OBD pins 6/14."""

from __future__ import annotations

import time
from typing import Any

import can

from . import wire
from .errors import OpenPduError
from .links import PRIMITIVE_TIMEOUT, MonitorLink, RawLink, close_quietly
from .session import Vci


class OpenPduBus(can.BusABC):
    """`channel` = VCI address, "host" or "host:port". Sends any id, 11- or 29-bit, one frame at a time."""

    def __init__(self, channel: str, bitrate: int = 500_000, *, receive_own_messages: bool = False,
                 **kwargs: Any) -> None:
        host, _, port = str(channel).partition(":")
        self.receive_own_messages = receive_own_messages
        self.vci = Vci.connect(host, int(port or wire.PORT))
        physical = {"Baudrate": bitrate}
        try:
            self.monitor = MonitorLink.open(self.vci, physical=physical)
            try:
                self.raw = RawLink.open(self.vci, physical=physical)
            except BaseException:
                close_quietly(self.monitor)
                raise
        except BaseException:
            self.vci.close()
            raise
        version = ".".join(map(str, self.vci.greet.version))
        self.channel_info = f"OpenPDU {host} (VCI firmware {version})"
        super().__init__(channel=channel, **kwargs)

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        """The VCI keeps one RawMode frame in flight, so a send always waits for the VCI's ack of its frame.
        `timeout` bounds that wait; None or <= 0 (python-can's "do not block") mean the default 5 s, since a frame
        already handed to the VCI may still go out and a retry would put it on the bus twice."""
        if msg.is_remote_frame or msg.is_fd or msg.is_error_frame:
            raise can.CanOperationError("OpenPDU sends classic CAN data frames only")
        try:
            self.raw.send(msg.arbitration_id, bytes(msg.data), extended=msg.is_extended_id,
                          timeout=timeout if timeout is not None and timeout > 0 else PRIMITIVE_TIMEOUT)
        except OpenPduError as exc:
            raise can.CanOperationError(str(exc), error_code=exc.code) from exc

    def _recv_internal(self, timeout: float | None) -> tuple[can.Message | None, bool]:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            left = None if deadline is None else max(0.0, deadline - time.monotonic())
            try:
                rec = self.monitor.recv(left)
            except OpenPduError as exc:
                raise can.CanOperationError(str(exc), error_code=exc.code) from exc
            if rec is None:
                return None, False
            if rec.echo and not self.receive_own_messages:
                continue
            # ponytail: host receive time; rec.timestamp_us is the VCI's own µs clock (wraps every 71 min)
            return can.Message(timestamp=time.time(), arbitration_id=rec.can_id, is_extended_id=rec.extended,
                               data=rec.data, dlc=len(rec.data), is_rx=not rec.echo, channel=self.channel_info), False

    def shutdown(self) -> None:
        """Free both links and end the session. A link that fails to close is only logged: the session ends
        either way, and the VCI frees the links of a closed session itself."""
        super().shutdown()
        close_quietly(self.raw)
        close_quietly(self.monitor)
        self.vci.close()
