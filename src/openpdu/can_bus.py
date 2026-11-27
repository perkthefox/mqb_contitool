"""python-can bus over a VAS 6154: RawMode sends, monitor receives, CAN1 on OBD pins 6/14."""

from __future__ import annotations

import ipaddress
import time
from typing import Any

import can

from . import wire
from .errors import OpenPduError
from .links import PRIMITIVE_TIMEOUT, MonitorLink, RawLink, close_quietly
from .session import Vci


def _parse_channel(channel: object) -> tuple[str, int]:
    """Parse "host", "host:port", "[ipv6]", "[ipv6]:port", or bare IPv6 into `(host, port)`."""
    if channel is None:
        raise ValueError("OpenPDU channel host must not be empty")
    raw = str(channel).strip()
    if not raw:
        raise ValueError("OpenPDU channel host must not be empty")
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise ValueError(f"invalid OpenPDU channel {channel!r}: missing ']'")
        host = raw[1:end].strip()
        rest = raw[end + 1:]
        if not host:
            raise ValueError(f"invalid OpenPDU channel {channel!r}: empty host")
        if rest == "":
            port_str = ""
        elif rest.startswith(":"):
            port_str = rest[1:]
            if not port_str:
                raise ValueError(f"invalid OpenPDU channel {channel!r}: empty port")
        else:
            raise ValueError(f"invalid OpenPDU channel {channel!r}: unexpected suffix {rest!r}")
    elif raw.count(":") == 1:
        host, _, port_str = raw.partition(":")
        host = host.strip()
        if not host:
            raise ValueError(f"invalid OpenPDU channel {channel!r}: empty host")
        if not port_str:
            raise ValueError(f"invalid OpenPDU channel {channel!r}: empty port")
    elif ":" in raw:
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            raise ValueError(f"invalid OpenPDU channel {channel!r}: wrap IPv6 addresses in brackets") from None
        host, port_str = raw, ""
    else:
        host, port_str = raw, ""
    if not port_str:
        return host, wire.PORT
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"invalid OpenPDU port {port_str!r} in {channel!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"OpenPDU port {port} out of range (1..65535)")
    return host, port


class OpenPduBus(can.BusABC):
    """`channel` = VCI address, "host", "host:port", or "[ipv6]:port". Sends any id, 11- or 29-bit, one frame at a
    time."""

    every_id_raw = True

    def __init__(self, channel: str, bitrate: int = 500_000, *, receive_own_messages: bool = False,
                 **kwargs: Any) -> None:
        host, port = _parse_channel(channel)
        self.receive_own_messages = receive_own_messages
        self.vci = Vci.connect(host, port)
        physical = {"Baudrate": bitrate}
        monitor: MonitorLink | None = None
        raw: RawLink | None = None
        try:
            monitor = MonitorLink.open(self.vci, physical=physical)
            self.monitor = monitor
            raw = RawLink.open(self.vci, physical=physical)
            self.raw = raw
            version = ".".join(map(str, self.vci.greet.version))
            self.channel_info = f"OpenPDU {host} (VCI firmware {version})"
            super().__init__(channel=channel, **kwargs)
        except BaseException:
            if raw is not None:
                close_quietly(raw)
            if monitor is not None:
                close_quietly(monitor)
            self.vci.close()
            raise

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
        if getattr(self, "_is_shutdown", False):
            return
        super().shutdown()
        close_quietly(self.raw)
        close_quietly(self.monitor)
        self.vci.close()
