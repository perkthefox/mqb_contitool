"""A stand-in VCI for the OpenPDU tests, and the reference driver's own messages to compare against.

The fake builds its replies with `struct` straight from the protocol notes, not with `openpdu.wire`, so a mistake in
the code under test cannot cancel out in the fake.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
import time
from collections.abc import Callable
from pathlib import Path

GREET = bytes.fromhex("0E1A011B1B01022C02E7071D02021E0211")  # firmware 27.2.0 of 2023-02-17
SYNC = 0xFFFFFFFF
MONITOR, RAW, ISOTP = 200, 0x11, 2
FIRST_LINK = {MONITOR: 0x17E, RAW: 0x142, ISOTP: 1}  # the reference session's link ids


def _golden() -> dict[str, bytes]:
    out = {}
    for line in (Path(__file__).parent / "data" / "vw_pdu_api_27_2.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            name, hexdata = line.split()
            out[name] = bytes.fromhex(hexdata)
    return out


VW = _golden()


def retarget(payload: bytes, *, hcop: int) -> bytes:
    """A reference primitive with this session's hCop (bytes 3..6), the only field that is session state."""
    return payload[:3] + struct.pack(">I", hcop) + payload[7:]


def wait_for(predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
    """Poll `predicate` until it holds or `timeout` passes; whether it held."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


def ack(link: int, hcop: int, code: int = 0) -> bytes:
    return struct.pack(">BHIIH", 4, link, hcop, SYNC, code)


def result(link: int, hcop: int, data: bytes, *, urid: int = 1, header: bytes = b"") -> bytes:
    return (struct.pack(">BHIIIIIBB4sBBI", 3, link, hcop, urid, 0, SYNC, 0, 0, len(header), header.ljust(4, b"\0"),
                        0, 0, len(data)) + data)


def record(can_id: int, data: bytes, *, extended: bool = False, echo: bool = False, time_us: int = 0) -> bytes:
    flags = (0 if echo else 0x10) | (0x20 if extended else 0)
    return struct.pack(">BIBIBB", 0, can_id, 0, time_us, len(data), flags) + data


class FakeVci:
    """Serves one client on 127.0.0.1. Records every payload it receives in `received`.

    Default answers: IOCTL -> zeros, link requests -> code 0, primitives -> C9 (+ results) + 0, a RawMode send ->
    its echo on the running monitor, an ISO-TP request -> SID + 0x40 and the rest of the request. A test replaces
    the answer to any message with `answer(payload) -> list of replies` (None keeps the default)."""

    def __init__(self) -> None:
        self.server = socket.create_server(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.greet = GREET
        self.received: list[bytes] = []
        self.answer: Callable[[bytes], list[bytes] | None] = lambda payload: None
        self.protocol: dict[int, int] = {}
        self.monitor_feed: dict[int, int] = {}  # monitor link -> hCop of its STARTCOMM
        self._next_link = dict(FIRST_LINK)
        self._client: socket.socket | None = None
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def push(self, *payloads: bytes) -> None:
        with self._lock:
            assert self._client is not None, "no client connected"
            for p in payloads:
                self._client.sendall(struct.pack(">I", len(p)) + p)

    def bus_frame(self, can_id: int, data: bytes, **kw: bool) -> None:
        """A frame on the bus, as every running monitor reports it."""
        for link, hcop in self.monitor_feed.items():
            self.push(result(link, hcop, record(can_id, data, **kw), urid=0xFFFFFFFE))

    def drop(self) -> None:
        with self._lock:
            if self._client is not None:
                with contextlib.suppress(OSError):  # the client hung up first
                    self._client.shutdown(socket.SHUT_RDWR)
                self._client.close()
                self._client = None

    def close(self) -> None:
        self.drop()
        self.server.close()

    def _serve(self) -> None:
        try:
            client, _ = self.server.accept()
        except OSError:
            return
        self._client = client
        self.push(self.greet)
        try:
            while True:
                (n,) = struct.unpack(">I", _recv(client, 4))
                payload = _recv(client, n)
                self.received.append(payload)
                replies = self.answer(payload)
                self.push(*(self._default(payload) if replies is None else replies))
        except (OSError, EOFError, AssertionError):
            return

    def _default(self, p: bytes) -> list[bytes]:
        kind, link = p[0], struct.unpack_from(">H", p, 1)[0]
        if kind == 0x06:
            return [b"\x07" + p[1:4] + bytes(8)]  # same link and IOCTL code, both values 0
        if kind == 0x10:
            proto = struct.unpack_from(">I", p, 10)[0]
            new = self._next_link[proto]
            self._next_link[proto] += 1
            self.protocol[new] = proto
            return [ack(new, SYNC)]
        if kind in (0x11, 0x12, 0x13):
            return [ack(link, SYNC)]
        if kind == 0x02:
            return self._primitive(link, p)
        return []

    def _primitive(self, link: int, p: bytes) -> list[bytes]:
        hcop, cop_type, n = struct.unpack_from(">I", p, 3)[0], p[20], struct.unpack_from(">I", p, 21)[0]
        data, proto = p[30:30 + n], self.protocol.get(link)
        if proto == MONITOR and cop_type == 1:
            self.monitor_feed[link] = hcop
        if proto == MONITOR and cop_type == 2:
            self.monitor_feed.pop(link, None)
        out = [ack(link, hcop, 0xC9)]
        if proto == ISOTP and cop_type == 4:
            out.append(result(link, hcop, bytes([data[0] + 0x40]) + data[1:], header=struct.pack(">I", 0x77A)))
        out.append(ack(link, hcop))
        if proto == RAW and cop_type == 4:
            can_id = struct.unpack_from(">I", data)[0]
            extended = bool(p[19] & 4)
            out += [result(m, h, record(can_id, data[4:], extended=extended, echo=True), urid=0xFFFFFFFE)
                    for m, h in self.monitor_feed.items()]
        return out


def _recv(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf
