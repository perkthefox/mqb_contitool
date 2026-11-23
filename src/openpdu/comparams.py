"""ComParam blocks of a link CONNECT: fixed binary layouts, big-endian, values in wire units.

A link's ComParams travel to the VCI all at once, inside CONNECT, as an application, a transport and a physical
block plus a list of unique-response-id (URID) entries. Each block has one fixed layout per protocol; the VCI parses
it by its own sizes, so a field out of place shifts everything after it.

Wire units: every time is in 100 µs steps (P2Max 500 = 50 ms), except CollectTimeout (ms × 10) and StMin (100 µs).
The defaults are exactly what the reference driver sends for a CAN HS link at 500 kbit/s.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping, Sequence
from typing import Any

Layout = tuple[tuple[str, str], ...]  # (field name, struct format without byte order)

PHYSICAL_CAN: Layout = (
    ("Reserved", "B"), ("Baudrate", "I"), ("BitSamplePoint", "H"), ("SyncJumpWidth", "H"), ("SamplesPerBit", "B"),
    ("ListenOnly", "B"), ("CanBaudrateRecordLen", "B"), ("CanBaudrateRecord", "12I"), ("CANFDBaudrate", "I"),
    ("CANFDBitSamplePoint", "H"), ("CANFDSyncJumpWidth", "H"),
)
RAW_APP: Layout = (
    ("CyclicRespTimeout", "I"), ("P2Max", "I"), ("P3Phys", "I"), ("P3Func", "I"), ("SwCanHighVoltage", "B"),
    ("RepeatReqCountApp", "I"), ("RawCanSequenceHandling", "B"), ("ChangeSpeedMessage", "12s"),
    ("ChangeSpeedMessageLen", "B"), ("ChangeSpeedRate", "I"), ("ChangeSpeedTxDelay", "I"), ("ChangeSpeedCtrl", "B"),
    ("ChangeSpeedResCtrl", "B"),
)
RAW_TRANSPORT: Layout = (
    ("Constant", "I"), ("CanFillerByte", "B"), ("CanFillerByteHandling", "B"), ("SendRemoteFrame", "B"),
    ("CANFDTxMaxDataLength", "B"),
)
MONITOR_TRANSPORT: Layout = (
    ("DataPacketSize", "I"), ("CollectTimeout", "I"), ("MonitoredChannels", "B"), ("SetCanFilterBits", "2I"),
    ("SetCanFilterIdsLen", "B"), ("SetCanFilterIds", "100I"),
)
ISOTP_TRANSPORT: Layout = (
    ("RequestAddrMode", "B"), ("BlockSize", "B"), ("BlockSizeOverride", "H"), ("As", "I"), ("Ar", "I"), ("Bs", "I"),
    ("Br", "I"), ("Cs", "I"), ("Cr", "I"), ("StMin", "H"), ("StMinOverride", "I"), ("CanFuncReqId", "I"),
    ("CanFillerByteHandling", "B"), ("CanFillerByte", "B"), ("CanFuncReqExtAddr", "B"), ("CanFuncReqFormat", "B"),
    ("CanDataSizeOffset", "B"), ("CanMaxNumWaitFrames", "H"), ("SendRemoteFrame", "B"),
    ("CanFirstConsecutiveFrameValue", "B"), ("CANFDTxMaxDataLength", "B"), ("EscapeSequenceHandling", "B"),
)
UDS_APP: Layout = (
    ("P2Max", "I"), ("P2Min", "I"), ("P2Star", "I"), ("P3Func", "I"), ("P3Phys", "I"), ("P3Min", "I"),
    ("RC21CompletionTimeout", "I"), ("RC21Handling", "B"), ("RC21RequestTime", "I"), ("RC23CompletionTimeout", "I"),
    ("RC23Handling", "B"), ("RC23RequestTime", "I"), ("RC78CompletionTimeout", "I"), ("RC78Handling", "B"),
    ("RCByteOffset", "I"), ("StartMsgIndEnable", "B"), ("TesterPresentTime", "I"), ("TesterPresentHandling", "B"),
    ("TesterPresentReqRsp", "B"), ("TesterPresentMessage", "12s"), ("TesterPresentMessageLen", "B"),
    ("TesterPresentAddrMode", "B"), ("TesterPresentSendType", "B"), ("TesterPresentExpPosResp", "12s"),
    ("TesterPresentExpPosRespLen", "B"), ("TesterPresentExpNegResp", "12s"), ("TesterPresentExpNegRespLen", "B"),
    ("CyclicRespTimeout", "I"), ("ModifyTiming", "B"), ("CanTransmissionTime", "I"), ("TransmitIndEnable", "B"),
    ("RepeatReqCountApp", "I"), ("SessionTimingOverride", "24s"), ("SessionTimingOverrideCount", "B"),
    ("ChangeSpeedMessage", "12s"), ("ChangeSpeedMessageLen", "B"), ("ChangeSpeedRate", "I"),
    ("ChangeSpeedTxDelay", "I"), ("ChangeSpeedCtrl", "B"), ("ChangeSpeedResCtrl", "B"), ("SuspendQueueOnError", "B"),
    ("TesterPresentGrouping", "B"),
)
RAW_URID: Layout = (
    ("UniqueRespIdentifier", "I"), ("CanPhysReqExtAddr", "B"), ("CanPhysReqFormat", "B"), ("CanPhysReqId", "I"),
    ("CanRespUUDTExtAddr", "B"), ("CanRespUUDTFormat", "B"), ("CanRespUUDTId", "I"),
)
ISOTP_URID: Layout = (
    ("UniqueRespIdentifier", "I"), ("CanPhysReqExtAddr", "B"), ("CanPhysReqFormat", "B"), ("CanPhysReqId", "I"),
    ("CanRespUSDTExtAddr", "B"), ("CanRespUSDTFormat", "B"), ("CanRespUSDTId", "I"), ("CanRespUUDTExtAddr", "B"),
    ("CanRespUUDTFormat", "B"), ("CanRespUUDTId", "I"),
)

NONE = 0xFFFFFFFF  # "not set" for a 32-bit value (an id, P3Min)
TIME_UNIT = 100e-6  # s per wire time step
NORMAL_11BIT = 5  # Can*Format: normal addressing, 11-bit ids

PHYSICAL_DEFAULTS: dict[str, Any] = {
    "Baudrate": 500_000, "BitSamplePoint": 80, "SyncJumpWidth": 15, "CanBaudrateRecordLen": 2,
    "CanBaudrateRecord": (500_000, 250_000), "CANFDBitSamplePoint": 80, "CANFDSyncJumpWidth": 15,
}
RAW_APP_DEFAULTS: dict[str, Any] = {"P2Max": 500}
RAW_TRANSPORT_DEFAULTS: dict[str, Any] = {"Constant": 10_000}
MONITOR_DEFAULTS: dict[str, Any] = {"DataPacketSize": 2300, "CollectTimeout": 100, "MonitoredChannels": 1}
ISOTP_DEFAULTS: dict[str, Any] = {
    "RequestAddrMode": 1, "BlockSizeOverride": 0xFFFF, "As": 10_000, "Ar": 10_000, "Bs": 10_000, "Cr": 10_000,
    "StMinOverride": NONE, "CanFuncReqId": 0x700, "CanFillerByteHandling": 1, "CanFillerByte": 0x55,
    "CanFuncReqFormat": NORMAL_11BIT, "CanMaxNumWaitFrames": 15, "CanFirstConsecutiveFrameValue": 1,
}
UDS_DEFAULTS: dict[str, Any] = {
    "P2Max": 2000, "P2Star": 51_500, "P3Func": 4000, "P3Phys": 4000, "P3Min": NONE, "RC21CompletionTimeout": 600_000,
    "RC21Handling": 1, "RC21RequestTime": 2000, "RC23RequestTime": 2000, "RC78CompletionTimeout": 1_000_000,
    "RC78Handling": 1, "RCByteOffset": NONE, "TesterPresentTime": 20_000, "TesterPresentHandling": 1,
    "TesterPresentMessage": b"\x3e\x80", "TesterPresentMessageLen": 2, "TesterPresentAddrMode": 1, "ModifyTiming": 1,
    "CanTransmissionTime": 1500,
}
# In RawMode the VCI sends each frame on the id it carries and keeps only the URID of this entry, so 0x7E0 here is
# just the reference driver's placeholder.
RAW_URID_DEFAULTS: dict[str, Any] = {
    "UniqueRespIdentifier": 0xFFFFFFFE, "CanPhysReqFormat": NORMAL_11BIT, "CanPhysReqId": 0x7E0,
    "CanRespUUDTId": NONE,
}
ISOTP_URID_DEFAULTS: dict[str, Any] = {
    "UniqueRespIdentifier": 1, "CanPhysReqFormat": NORMAL_11BIT, "CanRespUSDTFormat": NORMAL_11BIT,
    "CanRespUUDTId": NONE,
}


def _fields(layout: Layout) -> list[tuple[str, str, int]]:
    """(name, format, number of struct items): "12I" is twelve integers, "12s" one byte string."""
    out = []
    for name, fmt in layout:
        count = int(fmt[:-1]) if fmt[:-1] else 1
        out.append((name, fmt, 1 if fmt[-1] == "s" else count))
    return out


def size(layout: Layout) -> int:
    return struct.calcsize(">" + "".join(fmt for _, fmt in layout))


def pack(layout: Layout, values: Mapping[str, Any] = {}, defaults: Mapping[str, Any] = {}) -> bytes:
    """Serialize one block. A field missing from both `values` and `defaults` is 0 (or zero bytes)."""
    unknown = set(values) - {name for name, _ in layout}
    if unknown:
        raise KeyError(f"unknown ComParam field(s): {', '.join(sorted(unknown))}")
    items: list[Any] = []
    for name, fmt, count in _fields(layout):
        value = values.get(name, defaults.get(name))
        if fmt[-1] == "s":
            items.append(bytes(value or b""))
        elif count > 1:
            seq = list(value or ())
            if len(seq) > count:
                raise ValueError(f"{name}: at most {count} values, got {len(seq)}")
            items.extend(seq + [0] * (count - len(seq)))
        else:
            items.append(int(value or 0))
    return struct.pack(">" + "".join(fmt for _, fmt in layout), *items)


def unpack(layout: Layout, data: bytes) -> dict[str, Any]:
    """Inverse of `pack`: every field by name; multi-value fields come back as tuples."""
    raw = struct.unpack(">" + "".join(fmt for _, fmt in layout), data)
    out: dict[str, Any] = {}
    pos = 0
    for name, _, count in _fields(layout):
        out[name] = raw[pos] if count == 1 else tuple(raw[pos:pos + count])
        pos += count
    return out


def nonzero(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Only the fields that are not 0 / all-zero: the compact form the defaults are written in."""
    def zero(v: Any) -> bool:
        return not any(v) if isinstance(v, (bytes, tuple)) else v == 0
    return {k: v for k, v in fields.items() if not zero(v)}


def baudrate_record(*rates: int) -> dict[str, Any]:
    return {"CanBaudrateRecordLen": len(rates), "CanBaudrateRecord": tuple(rates)}


def urid_entries(layout: Layout, entries: Sequence[Mapping[str, Any]], defaults: Mapping[str, Any]) -> bytes:
    return b"".join(pack(layout, e, defaults) for e in entries)
