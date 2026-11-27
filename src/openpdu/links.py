"""Logical links on a VCI and the primitives that run on them.

Lifetime of every link: CREATE (protocol, pins) -> CONNECT (all ComParams at once) -> STARTCOMM ... STOPCOMM ->
DISCONNECT -> DESTROY. A primitive is acknowledged with 0xC9 (executing), may produce results, and ends with code 0
(finished); an error code comes before that final 0. The VCI holds up to 30 primitives per link and answers 0x1E
when full, which the reference driver meets by resending after 80 ms. A primitive the host stops waiting for is
cancelled on the VCI (IOCTL 0x81): the VCI starts a link's next primitive only when the one before it has ended.
"""

from __future__ import annotations

import collections
import logging
import struct
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from . import comparams as cp
from . import wire
from .errors import ConnectionLost, OpenPduError, Refused, VciTimeout

if TYPE_CHECKING:
    from .session import Replies, Vci

log = logging.getLogger("openpdu")

PRIMITIVE_TIMEOUT = 5.0
CANCEL_TIMEOUT = 2.0  # the VCI answers an IOCTL at once; no answer ends the session, as for any sync request
CANCEL_DRAIN = 0.2  # s to wait for a cancelled primitive's terminal DONE before unsubscribing
QUEUE_FULL_RETRY = 0.08  # as the reference driver
RESPONSE_MARGIN = 2.0  # s the host waits for a UDS response past the VCI's own longest wait
# the VCI's RX_TIMEOUT: P2 / P2* expired, response-pending (RC78) completion expired, cyclic response timeout
UDS_TIMEOUT_CODES = {0x0133, 0x0134, 0x0135}

Block = Mapping[str, Any]  # ComParam overrides by field name, in wire units (see comparams)


class Link:
    """A started link. Subclasses build the CONNECT blocks and add their own primitives."""

    def __init__(self, vci: Vci, link_id: int) -> None:
        self.vci = vci
        self.id = link_id
        self._started = False
        self._closed = False

    @classmethod
    def _open(cls, vci: Vci, protocol: int, *, raw_mode: bool, app: bytes, transport: bytes, physical: bytes,
              urids: Sequence[bytes] = (), **init: Any) -> Any:
        reply = vci.request(wire.create(protocol, raw_mode=raw_mode), "link create")
        link = cls(vci, reply.link, **init)
        try:
            vci.request(wire.connect(link.id, app, transport, physical, urids), "link connect")
            link.start()
        except BaseException:
            close_quietly(link)
            raise
        return link

    def start(self) -> None:
        self._primitive(wire.STARTCOMM)
        self._started = True

    def stop(self) -> None:
        if self._started:
            self._started = False
            self._primitive(wire.STOPCOMM)

    def close(self) -> None:
        """Stop, disconnect and destroy, each tried even if the one before failed (the first failure is raised
        after). Idempotent; once the session has ended there is nothing to do: the VCI frees its links itself."""
        if self._closed:
            return
        self._closed = True
        first_error: OpenPduError | None = None
        for step in (self.stop,
                     lambda: self.vci.request(wire.disconnect(self.id), "link disconnect"),
                     lambda: self.vci.request(wire.destroy(self.id), "link destroy")):
            try:
                step()
            except OpenPduError as exc:
                if not self.vci.alive:
                    return
                first_error = first_error or exc
        if first_error is not None:
            raise first_error

    def __enter__(self) -> Link:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _primitive(self, cop_type: int, data: bytes = b"", *, timeout: float = PRIMITIVE_TIMEOUT,
                   hcop: int | None = None, replies: Replies | None = None, **cop: Any) -> list[wire.Result]:
        """Run one primitive to its end and return its results. With `hcop` + `replies` the caller owns the
        subscription (and keeps it afterwards); otherwise it lives just as long as the primitive."""
        results, _, _ = self._run_primitive(cop_type, data, timeout=timeout, keep_subscription=replies is not None,
                                            hcop=hcop, replies=replies, **cop)
        return results

    def _run_primitive(self, cop_type: int, data: bytes = b"", *, timeout: float = PRIMITIVE_TIMEOUT,
                       keep_subscription: bool = False, hcop: int | None = None, replies: Replies | None = None,
                       **cop: Any) -> tuple[list[wire.Result], int, Replies]:
        """Run one primitive to its end and return `(results, hcop, replies)`.

        When `keep_subscription` is True and the primitive finishes cleanly, the active `(self.id, hcop)`
        subscription is kept for the caller (used by `MonitorLink.start`); otherwise it is unsubscribed before
        returning or raising."""
        if hcop is None:
            hcop = self.vci.next_hcop()
        if replies is None:
            replies = self.vci.subscribe(self.id, hcop)
        payload = wire.cop(self.id, hcop, cop_type, data, **cop)
        results: list[wire.Result] = []
        failure: int | None = None
        finished = False
        what = f"primitive {cop_type} on link {self.id}"
        deadline = time.monotonic() + timeout
        try:
            self.vci.send(payload)
            while not finished and (msg := self.vci.next_reply(replies, deadline)) is not None:
                if isinstance(msg, wire.Result):
                    results.append(msg)
                elif not isinstance(msg, wire.Ack) or msg.code in wire.PROGRESS:
                    continue
                elif msg.code == wire.DONE:
                    finished = True
                elif msg.code == wire.QUEUE_FULL:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise VciTimeout(f"{what} did not finish within {timeout:g} s")
                    if remaining <= QUEUE_FULL_RETRY:
                        time.sleep(remaining)
                        raise VciTimeout(f"{what} did not finish within {timeout:g} s")
                    time.sleep(QUEUE_FULL_RETRY)
                    if time.monotonic() >= deadline:
                        raise VciTimeout(f"{what} did not finish within {timeout:g} s")
                    self.vci.unsubscribe(self.id, hcop)
                    hcop = self.vci.next_hcop()
                    replies = self.vci.subscribe(self.id, hcop)
                    payload = wire.cop(self.id, hcop, cop_type, data, **cop)
                    self.vci.send(payload)
                elif failure is None:
                    failure = msg.code
            if not finished:
                self._cancel(hcop)
                if self.vci.alive:
                    drain_deadline = time.monotonic() + CANCEL_DRAIN
                    while (msg := self.vci.next_reply(replies, drain_deadline)) is not None:
                        if isinstance(msg, wire.Ack) and msg.code == wire.DONE:
                            break
        finally:
            if not (keep_subscription and finished and failure is None):
                self.vci.unsubscribe(self.id, hcop)
        if failure in UDS_TIMEOUT_CODES:
            raise VciTimeout(f"{what}: no response from the ECU", failure)
        if failure is not None:
            raise Refused(f"{what} failed: code {failure:#06x}", failure)
        if not finished:
            raise VciTimeout(f"{what} did not finish within {timeout:g} s")
        return results, hcop, replies

    def _cancel(self, hcop: int) -> None:
        """Best effort: drop a primitive the host gave up on, so it neither runs late nor holds up the link.
        A session that has ended raises ConnectionLost; any other failure is only logged."""
        try:
            self.vci.ioctl(wire.IOCTL_CANCEL, hcop, link=self.id, timeout=CANCEL_TIMEOUT)
        except ConnectionLost:
            raise
        except OpenPduError as exc:
            log.debug("cancelling hCop %d on link %#x failed: %s", hcop, self.id, exc)


def close_quietly(link: Link) -> None:
    """Close `link` while another error is on its way out: a failure here is logged, so it does not replace that
    error."""
    try:
        link.close()
    except OpenPduError as exc:
        log.debug("closing link %#x failed: %s", link.id, exc)


class MonitorLink(Link):
    """Every frame on the bus, including the VCI's echoes of frames it sent. One per CAN controller."""

    def __init__(self, vci: Vci, link_id: int) -> None:
        super().__init__(vci, link_id)
        self._feed: Replies | None = None
        self._feed_hcop = 0
        self._pending: collections.deque[wire.CanRecord] = collections.deque()

    @classmethod
    def open(cls, vci: Vci, *, transport: Block = {}, physical: Block = {}) -> MonitorLink:
        return cls._open(
            vci, wire.PROTO_MONITOR, raw_mode=True, app=b"",
            transport=cp.pack(cp.MONITOR_TRANSPORT, transport, cp.MONITOR_DEFAULTS),
            physical=cp.pack(cp.PHYSICAL_CAN, physical, cp.PHYSICAL_DEFAULTS),
        )

    def start(self) -> None:
        """The reference driver's receive-anything primitive: STARTCOMM with one accept-any response."""
        early, hcop, feed = self._run_primitive(wire.STARTCOMM, keep_subscription=True, expected=[wire.Expected(1)])
        self._feed, self._feed_hcop, self._started = feed, hcop, True
        for result in early:
            self._pending.extend(wire.monitor_records(result.data))

    def stop(self) -> None:
        try:
            if self._started and self._feed is not None:
                self._cancel(self._feed_hcop)
            super().stop()
        finally:
            self._end_feed(ConnectionLost(f"monitor link {self.id} stopped"))

    def recv(self, timeout: float | None = None) -> wire.CanRecord | None:
        """The next frame, or None after `timeout` seconds (None: wait forever).

        Raises ConnectionLost once the link is stopped or the VCI ends the monitor, Refused (with the VCI's code)
        when the VCI reports that the monitor failed; either way the link receives no more."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._pending:
            feed = self._feed
            if feed is None:
                raise ConnectionLost(f"monitor link {self.id} is not running")
            msg = self.vci.next_reply(feed, deadline)
            if msg is None:
                return None
            if isinstance(msg, wire.Result):
                self._pending.extend(wire.monitor_records(msg.data))
            elif isinstance(msg, wire.Ack) and msg.code not in wire.PROGRESS:
                error = (ConnectionLost(f"the VCI ended monitor link {self.id}") if msg.code == wire.DONE
                         else Refused(f"monitor link {self.id} failed: code {msg.code:#06x}", msg.code))
                self._end_feed(error)
                raise error
        return self._pending.popleft()

    def _end_feed(self, error: OpenPduError) -> None:
        """Stop routing the feed; whoever still waits on it gets `error`."""
        feed, self._feed = self._feed, None
        if feed is not None:
            self.vci.unsubscribe(self.id, self._feed_hcop)
            feed.put(error)


class RawLink(Link):
    """RawMode sender: any CAN id, 11- or 29-bit. The VCI keeps one frame in flight, so `send` waits for it."""

    @classmethod
    def open(cls, vci: Vci, *, app: Block = {}, transport: Block = {}, physical: Block = {}) -> RawLink:
        return cls._open(
            vci, wire.PROTO_RAW_CAN, raw_mode=True,
            app=cp.pack(cp.RAW_APP, app, cp.RAW_APP_DEFAULTS),
            transport=cp.pack(cp.RAW_TRANSPORT, transport, cp.RAW_TRANSPORT_DEFAULTS),
            physical=cp.pack(cp.PHYSICAL_CAN, physical, cp.PHYSICAL_DEFAULTS),
            urids=[cp.pack(cp.RAW_URID, {}, cp.RAW_URID_DEFAULTS)],
        )

    def send(self, can_id: int, data: bytes, *, extended: bool | None = None,
             timeout: float = PRIMITIVE_TIMEOUT) -> None:
        """Put one frame on the bus. `extended` defaults to "the id does not fit in 11 bits"."""
        if not 0 <= can_id <= 0x1FFFFFFF:
            raise ValueError(f"CAN id {can_id:#x} out of range")
        if len(data) > 8:
            raise ValueError(f"a classic CAN frame carries at most 8 bytes, got {len(data)}")
        if extended is None:
            extended = can_id > 0x7FF
        elif not extended and can_id > 0x7FF:
            raise ValueError(f"CAN id {can_id:#x} needs 29 bits")
        self._primitive(wire.SENDRECV, struct.pack(">I", can_id) + bytes(data), num_send=1, extended=extended,
                        timeout=timeout)


class IsoTpLink(Link):
    """Hardware ISO 15765-2 with UDS timing (ISO 15765-3) inside the VCI: one primitive per request, while the
    VCI does the FlowControl, P2/P2*, `7F xx 78` waits and tester present (`3E 80` every 2 s by default)."""

    def __init__(self, vci: Vci, link_id: int, response_timeout: float) -> None:
        super().__init__(vci, link_id)
        self.response_timeout = response_timeout  # s, the default host-side wait of `request`

    @classmethod
    def open(cls, vci: Vci, tx_id: int, rx_id: int, *, app: Block = {}, transport: Block = {},
             physical: Block = {}, urid: Block = {}) -> IsoTpLink:
        """`urid` overrides fields of the link's URID entry other than the two ids. An id above 0x7FF needs the
        29-bit CanPhysReqFormat / CanRespUSDTFormat there; those values are not verified on a VCI."""
        entry = {**cp.ISOTP_URID_DEFAULTS, **urid, "CanPhysReqId": tx_id, "CanRespUSDTId": rx_id}
        for can_id, fmt in ((tx_id, "CanPhysReqFormat"), (rx_id, "CanRespUSDTFormat")):
            if can_id > 0x7FF and entry[fmt] == cp.NORMAL_11BIT:
                raise ValueError(f"CAN id {can_id:#x} needs 29 bits, but {fmt} is normal 11-bit addressing")
        effective_app = {**cp.UDS_DEFAULTS, **app}
        # The VCI reports a silent ECU itself (0x0133); the host waits past the VCI's own longest wait.
        response_timeout = ((effective_app["RC78CompletionTimeout"] + effective_app["P2Star"]) * cp.TIME_UNIT
                            + RESPONSE_MARGIN)
        return cls._open(
            vci, wire.PROTO_UDS, raw_mode=False,
            app=cp.pack(cp.UDS_APP, effective_app),
            transport=cp.pack(cp.ISOTP_TRANSPORT, transport, cp.ISOTP_DEFAULTS),
            physical=cp.pack(cp.PHYSICAL_CAN, physical, cp.PHYSICAL_DEFAULTS),
            urids=[cp.pack(cp.ISOTP_URID, entry)],
            response_timeout=response_timeout,
        )

    def request(self, req: bytes, *, expect: bytes | None = None, suppress_positive: bool = False,
                timeout: float | None = None) -> bytes:
        """Send one UDS request and return the response PDU, positive or `7F <SID> <NRC>`.

        A positive response must start with `expect` (default: SID + 0x40), so a late answer to an earlier request
        is not taken for this one. With `suppress_positive` (a request with the SPRMIB bit, e.g. `3E 80`) only a
        negative response comes back; none at all gives b"". `timeout` (s, host side) defaults to
        `response_timeout`."""
        if not req:
            raise ValueError("empty UDS request")
        expect = expect or bytes([(req[0] + 0x40) & 0xFF])
        expected = [
            wire.Expected(0, tuple((0xFF, b) for b in expect)),
            wire.Expected(1, ((0xFF, 0x7F), (0xFF, req[0])), negative=True),
        ]
        try:
            results = self._primitive(wire.SENDRECV, bytes(req), num_send=1, num_recv=1, expected=expected,
                                      suppress_positive=suppress_positive,
                                      timeout=self.response_timeout if timeout is None else timeout)
        except VciTimeout as exc:
            if suppress_positive and exc.code in UDS_TIMEOUT_CODES:
                return b""
            raise
        final = [r.data for r in results if r.data[:1] != b"\x7f" or r.data[2:3] != b"\x78"]
        if final:
            return final[-1]
        if suppress_positive:
            return b""
        raise VciTimeout(f"no UDS response to {req[:4].hex()}")
