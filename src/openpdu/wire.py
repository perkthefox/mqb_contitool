"""VAS 6154 PC <-> VCI messages over TCP 4500: framing, builders for what the PC sends, parsers for the replies.

Frame = u32 big-endian length + payload. payload[0] is the message type, payload[1..2] the VCI link id (0xFFFF for
the module itself). All integers are big-endian. No checksum, no sequence number, no encryption.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .errors import ProtocolError

PORT = 4500
MODULE = 0xFFFF  # link id of module-level messages
SYNC = 0xFFFFFFFF  # hCop of the reply to a link create/connect/disconnect/destroy
EVENT = 0xFFFFFFFE  # hCop of a link-level event that belongs to no primitive
NO_TIME = 0xFFFFFFFF

# message types
COP = 0x02
RESULT = 0x03
ACK = 0x04
PARAM = 0x05
IOCTL = 0x06
IOCTL_REPLY = 0x07
DATA = 0x08
INFO = 0x09
PING = 0x0A
PONG = 0x0B
GREET = 0x0E
GREET_REFUSED = 0x0F
CREATE = 0x10
DESTROY = 0x11
CONNECT = 0x12
DISCONNECT = 0x13

# CoP types
STARTCOMM = 1
STOPCOMM = 2
SENDRECV = 4
DELAY = 5

# ack codes
DONE = 0x0000
QUEUE_FULL = 0x001E
EXECUTING = 0x00C9
WAITING = 0x00CA
START_OF_MESSAGE = 0x00CB
TX_DONE = 0x00CC
PROGRESS = {EXECUTING, WAITING, START_OF_MESSAGE, TX_DONE, 0x00CD, 0x00CE}  # informational, not an outcome

# IOCTLs, on link MODULE unless noted
IOCTL_READ_VBATT = 0x05
IOCTL_CANCEL = 0x81  # on the primitive's link, in1 = its hCop
IOCTL_SYNC_TIME = 0x83  # in1 = Unix seconds, in2 = microseconds
IOCTL_CONFIGURE_FIRMWARE = 0x85  # in1 = remote logging on/off

# CREATE protocol ids (MDF ids, sent as they are)
PROTO_KWP_CAN = 1
PROTO_UDS = 2
PROTO_RAW_CAN = 0x11
PROTO_MONITOR = 200
BUS_CAN_HS = 0
PINS_CAN_HS = (6, 14)

# monitor record flags
REC_FROM_BUS = 0x10  # clear: the VCI's echo of a frame it sent
REC_EXTENDED = 0x20


def frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def create(protocol: int, *, raw_mode: bool, bus: int = BUS_CAN_HS, pins: tuple[int, int] = PINS_CAN_HS,
           obd: bool = False) -> bytes:
    flags = (1 if raw_mode else 0) | (2 if obd else 0)
    return struct.pack(">BHBBBII", CREATE, MODULE, pins[0], pins[1], flags, bus, protocol)


def connect(link: int, app: bytes, transport: bytes, physical: bytes, urids: Sequence[bytes] = ()) -> bytes:
    entry = len(urids[0]) if urids else 0
    if any(len(u) != entry for u in urids):
        raise ValueError("URID entries differ in size")
    return (struct.pack(">BH5I", CONNECT, link, len(app), len(transport), len(physical), entry, len(urids))
            + app + transport + physical + b"".join(urids))


def disconnect(link: int) -> bytes:
    return struct.pack(">BH", DISCONNECT, link)


def destroy(link: int) -> bytes:
    return struct.pack(">BH", DESTROY, link)


def ioctl(link: int, code: int, in1: int = 0, in2: int = 0) -> bytes:
    return struct.pack(">BHBII", IOCTL, link, code, in1 & 0xFFFFFFFF, in2 & 0xFFFFFFFF)


def pong(seq: int) -> bytes:
    return struct.pack(">BH", PONG, seq)


@dataclass(frozen=True)
class Expected:
    """One expected response of a primitive: matched by mask/pattern bytes, then by URID (none = any)."""
    acceptance_id: int
    mask_pattern: tuple[tuple[int, int], ...] = ((0x00, 0x00),)  # one byte, mask 0: anything
    urids: tuple[int, ...] = ()
    negative: bool = False

    def encode(self) -> bytes:
        return (struct.pack(">BIII", 1 if self.negative else 0, self.acceptance_id, len(self.mask_pattern),
                            len(self.urids))
                + bytes(b for pair in self.mask_pattern for b in pair)
                + b"".join(struct.pack(">I", u) for u in self.urids))


def cop(link: int, hcop: int, cop_type: int, data: bytes = b"", *, num_send: int = 0, num_recv: int = 0,
        time_100us: int = 0, extended: bool = False, suppress_positive: bool = False,
        expected: Iterable[Expected] = ()) -> bytes:
    """A communication primitive. RawMode data = 4-byte CAN id + payload; ISO-TP data = the UDS request."""
    exp = list(expected)
    flags = (2 if suppress_positive else 0) | (4 if extended else 0)
    return (struct.pack(">BHIIiiBBIIB", COP, link, hcop, time_100us, num_send, num_recv, flags, cop_type,
                        len(data), 0, len(exp))
            + data + b"".join(e.encode() for e in exp))


@dataclass(frozen=True)
class Ack:
    link: int
    hcop: int
    vci_time: int  # µs, NO_TIME when absent
    code: int


@dataclass(frozen=True)
class IoctlReply:
    link: int
    code: int
    value1: int
    value2: int


@dataclass(frozen=True)
class Result:
    link: int
    hcop: int
    urid: int
    acceptance_id: int
    tx_done_us: int
    start_us: int
    rx_flags: int
    header: bytes
    footer: bytes
    data: bytes


@dataclass(frozen=True)
class Info:
    text: str


@dataclass(frozen=True)
class Ping:
    seq: int


@dataclass(frozen=True)
class Greet:
    """The VCI's first message: TLV fields; 10..12 firmware version, 20..22 firmware date."""
    fields: dict[int, bytes]

    def number(self, tag: int) -> int:
        return int.from_bytes(self.fields.get(tag, b""), "little")

    @property
    def version(self) -> tuple[int, int, int]:
        return self.number(10), self.number(11), self.number(12)

    @property
    def date(self) -> tuple[int, int, int]:
        return self.number(20), self.number(21), self.number(22)


@dataclass(frozen=True)
class GreetRefused:
    reason: str


@dataclass(frozen=True)
class Unknown:
    payload: bytes


Message = Ack | IoctlReply | Result | Info | Ping | Greet | GreetRefused | Unknown


def _leb128(data: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(data):
            raise ProtocolError("truncated TLV")
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return value, pos


def parse_tlv(data: bytes) -> dict[int, bytes]:
    """hdr = tag&7 | (tag>>3 ? 8) | (len&7)<<4 | (len>>3 ? 0x80), then LEB128 tag>>3, LEB128 len>>3, value."""
    out: dict[int, bytes] = {}
    pos = 0
    while pos < len(data):
        hdr = data[pos]
        pos += 1
        tag, length = hdr & 7, (hdr >> 4) & 7
        if hdr & 0x08:
            hi, pos = _leb128(data, pos)
            tag |= hi << 3
        if hdr & 0x80:
            hi, pos = _leb128(data, pos)
            length |= hi << 3
        if pos + length > len(data):
            raise ProtocolError("truncated TLV value")
        out[tag] = data[pos:pos + length]
        pos += length
    return out


def parse(payload: bytes) -> Message:
    if not payload:
        raise ProtocolError("empty message")
    kind = payload[0]
    try:
        if kind == ACK:
            if len(payload) != 13:
                raise ProtocolError(f"ack of {len(payload)} bytes")
            return Ack(*struct.unpack(">HIIH", payload[1:]))
        if kind == IOCTL_REPLY:
            return IoctlReply(*struct.unpack_from(">HBII", payload, 1))
        if kind == RESULT:
            (link, hcop, urid, acc, tx_done, start, rx_flags, n_hdr, hdr, n_foot, foot,
             n_data) = struct.unpack_from(">HIIIIIBB4sBBI", payload, 1)
            data = payload[35:35 + n_data]
            if len(data) != n_data:
                raise ProtocolError("truncated result")
            return Result(link, hcop, urid, acc, tx_done, start, rx_flags, hdr[:n_hdr], bytes([foot])[:n_foot], data)
        if kind == INFO:
            return Info(payload[10:].split(b"\0", 1)[0].decode("latin-1"))
        if kind == PING:
            return Ping(struct.unpack_from(">H", payload, 1)[0])
        if kind == GREET:
            return Greet(parse_tlv(payload[1:]))
        if kind == GREET_REFUSED:
            return GreetRefused(payload[1:].decode("latin-1", "replace"))
    except struct.error as exc:
        raise ProtocolError(f"malformed message type {kind:#04x}: {exc}") from None
    return Unknown(payload)


@dataclass(frozen=True)
class CanRecord:
    """One frame from a monitor link."""
    controller: int
    can_id: int
    timestamp_us: int
    flags: int
    data: bytes

    @property
    def echo(self) -> bool:
        """The VCI's copy of a frame it sent itself, not one it received."""
        return not self.flags & REC_FROM_BUS

    @property
    def extended(self) -> bool:
        return bool(self.flags & REC_EXTENDED)


def monitor_records(data: bytes) -> list[CanRecord]:
    """Split a monitor result into frames: controller u8, id u32, 0, time u32 µs, len u8, flags u8, payload."""
    out = []
    pos = 0
    while pos + 12 <= len(data):
        controller, can_id, _, ts, length, flags = struct.unpack_from(">BIBIBB", data, pos)
        payload = data[pos + 12:pos + 12 + length]
        if len(payload) != length:
            raise ProtocolError("truncated monitor record")
        out.append(CanRecord(controller, can_id & 0x1FFFFFFF, ts, flags, payload))
        pos += 12 + length
    if pos != len(data):
        raise ProtocolError(f"{len(data) - pos} stray bytes after monitor records")
    return out
