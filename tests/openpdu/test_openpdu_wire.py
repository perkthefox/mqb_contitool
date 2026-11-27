"""OpenPDU messages and ComParam blocks, checked against what the reference driver sends."""

from __future__ import annotations

import struct

import pytest
from fake_vci import VW, record

from openpdu import comparams as cp
from openpdu import wire
from openpdu.errors import ProtocolError

LAYOUT_SIZES = {
    "PHYSICAL_CAN": 68, "RAW_APP": 45, "RAW_TRANSPORT": 8, "MONITOR_TRANSPORT": 418, "ISOTP_TRANSPORT": 49,
    "UDS_APP": 163, "RAW_URID": 16, "ISOTP_URID": 22,
}


@pytest.mark.parametrize("name,expected", LAYOUT_SIZES.items())
def test_every_layout_has_the_size_the_vci_checks(name: str, expected: int) -> None:
    assert cp.size(getattr(cp, name)) == expected


def test_default_blocks_are_the_reference_drivers_connect_messages() -> None:
    phy = cp.pack(cp.PHYSICAL_CAN, {}, cp.PHYSICAL_DEFAULTS)
    monitor = cp.pack(cp.MONITOR_TRANSPORT, {}, cp.MONITOR_DEFAULTS)
    assert wire.connect(0x17E, b"", monitor, phy) == VW["connect_monitor"]
    assert wire.connect(
        0x142, cp.pack(cp.RAW_APP, {}, cp.RAW_APP_DEFAULTS), cp.pack(cp.RAW_TRANSPORT, {}, cp.RAW_TRANSPORT_DEFAULTS),
        phy, [cp.pack(cp.RAW_URID, {}, cp.RAW_URID_DEFAULTS)],
    ) == VW["connect_raw"]
    assert wire.connect(
        1, cp.pack(cp.UDS_APP, {}, cp.UDS_DEFAULTS), cp.pack(cp.ISOTP_TRANSPORT, {}, cp.ISOTP_DEFAULTS), phy,
        [cp.pack(cp.ISOTP_URID, {"CanPhysReqId": 0x710, "CanRespUSDTId": 0x77A}, cp.ISOTP_URID_DEFAULTS)],
    ) == VW["connect_isotp"]


def test_a_block_unpacks_to_what_it_was_packed_from() -> None:
    fields = cp.unpack(cp.UDS_APP, cp.pack(cp.UDS_APP, {"P2Max": 250}, cp.UDS_DEFAULTS))
    assert fields["P2Max"] == 250
    assert fields["TesterPresentMessage"][:2] == b"\x3e\x80"
    assert cp.nonzero(fields) == {**cp.UDS_DEFAULTS, "P2Max": 250,
                                  "TesterPresentMessage": b"\x3e\x80".ljust(12, b"\0")}


def test_a_block_refuses_fields_it_does_not_have_or_values_that_do_not_fit() -> None:
    with pytest.raises(KeyError, match="P2Maxx"):
        cp.pack(cp.UDS_APP, {"P2Maxx": 1})
    with pytest.raises(ValueError, match="at most 12"):
        cp.pack(cp.PHYSICAL_CAN, {"CanBaudrateRecord": range(13)})
    with pytest.raises(ValueError, match="at most 12 bytes"):
        cp.pack(cp.UDS_APP, {"TesterPresentMessage": b"\x01" * 13})
    with pytest.raises(ValueError, match="at most 24 bytes"):
        cp.pack(cp.UDS_APP, {"SessionTimingOverride": b"\x02" * 25})
    assert cp.unpack(cp.UDS_APP, cp.pack(cp.UDS_APP, {"TesterPresentMessage": b"\xaa" * 12}))[
        "TesterPresentMessage"
    ] == b"\xaa" * 12
    single = (("Flag", "s"),)
    assert cp.pack(single, {"Flag": b"x"}) == b"x"
    with pytest.raises(ValueError, match="at most 1 bytes"):
        cp.pack(single, {"Flag": b"xy"})


def test_link_requests_are_the_reference_drivers() -> None:
    assert wire.create(wire.PROTO_MONITOR, raw_mode=True) == VW["create_monitor"]
    assert wire.create(wire.PROTO_RAW_CAN, raw_mode=True) == VW["create_raw"]
    assert wire.create(wire.PROTO_UDS, raw_mode=False) == VW["create_isotp"]
    assert wire.disconnect(0x17E) == VW["disconnect_monitor"]
    assert wire.destroy(0x142) == VW["destroy_raw"]
    assert wire.ioctl(wire.MODULE, wire.IOCTL_CONFIGURE_FIRMWARE) == VW["ioctl_configure_firmware"]


def test_primitives_are_the_reference_drivers() -> None:
    assert wire.cop(0x17E, 0, wire.STARTCOMM, expected=[wire.Expected(1)]) == VW["start_monitor"]
    assert wire.cop(0x142, 1, wire.STARTCOMM) == VW["start_raw"]
    assert wire.cop(0x142, 2, wire.SENDRECV, bytes.fromhex("000007100210030000000000"),
                    num_send=1) == VW["send_raw_11bit"]
    assert wire.cop(0x142, 3, wire.SENDRECV, bytes.fromhex("1bfca2ed0001020304050607"), num_send=1,
                    extended=True) == VW["send_raw_29bit"]
    assert wire.cop(1, 8, wire.SENDRECV, bytes.fromhex("22f187"), num_send=1, num_recv=1, expected=[
        wire.Expected(0, ((0xFF, 0x62), (0xFF, 0xF1), (0xFF, 0x87))),
        wire.Expected(1, ((0xFF, 0x7F), (0xFF, 0x22)), negative=True),
    ]) == VW["request_22f187"]
    assert wire.cop(0x17E, 5, wire.STOPCOMM) == VW["stop_monitor"]


def test_the_greet_gives_firmware_version_and_date() -> None:
    greet = wire.parse(bytes.fromhex("0E1A011B1B01022C02E7071D02021E0211"))
    assert isinstance(greet, wire.Greet)
    assert greet.version == (27, 2, 0)  # patch 0 is simply not sent
    assert greet.date == (2023, 2, 17)


def test_tlv_tags_and_lengths_past_seven_use_leb128() -> None:
    name = b"VAS6154 USB module"  # 18 bytes, tag 61: both need the continuation byte
    hdr = (61 & 7) | 0x08 | ((len(name) & 7) << 4) | 0x80
    assert wire.parse_tlv(bytes([hdr, 61 >> 3, len(name) >> 3]) + name) == {61: name}
    with pytest.raises(ProtocolError):
        wire.parse_tlv(bytes([hdr, 61 >> 3, len(name) >> 3]) + name[:-1])


def test_replies_parse_into_their_fields() -> None:
    assert wire.parse(struct.pack(">BHIIH", 4, 0x142, 7, 0xFFFFFFFF, 0x1E)) == wire.Ack(0x142, 7, 0xFFFFFFFF, 0x1E)
    assert wire.parse(bytes.fromhex("07ffff850000000100000002")) == wire.IoctlReply(0xFFFF, 0x85, 1, 2)
    assert wire.parse(bytes.fromhex("0a1234")) == wire.Ping(0x1234)
    assert wire.parse(b"\x0fbusy") == wire.GreetRefused("busy")
    res = wire.parse(struct.pack(">BHIIIIIBB4sBBI", 3, 1, 8, 1, 0, 5, 6, 0, 4, b"\0\0\x07\x7a", 0, 0, 3)
                     + b"\x62\xf1\x87")
    assert isinstance(res, wire.Result)
    assert (res.link, res.hcop, res.header, res.data) == (1, 8, b"\0\0\x07\x7a", b"\x62\xf1\x87")


def test_an_ack_of_the_wrong_size_is_a_protocol_error() -> None:
    with pytest.raises(ProtocolError):
        wire.parse(struct.pack(">BHIIH", 4, 1, 2, 3, 0) + b"\0")


def test_parse_validates_lengths_and_result_bounds() -> None:
    # INFO requires at least 10 header bytes
    assert wire.parse(b"\x09" + bytes(9)) == wire.Info("")
    assert wire.parse(b"\x09" + bytes(9) + b"ok\0tail") == wire.Info("ok")
    for n in (1, 5, 9):
        with pytest.raises(ProtocolError):
            wire.parse(b"\x09" + bytes(n - 1))

    # IOCTL_REPLY must be exactly 12 bytes
    valid_ioctl = bytes.fromhex("07ffff850000000100000002")
    with pytest.raises(ProtocolError):
        wire.parse(valid_ioctl[:-1])
    with pytest.raises(ProtocolError):
        wire.parse(valid_ioctl + b"\x00")

    # PING must be exactly 3 bytes
    with pytest.raises(ProtocolError):
        wire.parse(b"\x0a\x12")
    with pytest.raises(ProtocolError):
        wire.parse(b"\x0a\x12\x34\x56")

    # RESULT header/footer bounds and exact data length
    def make_result(*, n_hdr: int = 0, n_foot: int = 0, foot: int = 0,
                    n_data: int = 2, data: bytes = b"\xaa\xbb") -> bytes:
        return struct.pack(">BHIIIIIBB4sBBI", 3, 1, 8, 1, 0, 5, 6, 0, n_hdr, b"\x01\x02\x03\x04",
                           n_foot, foot, n_data) + data

    parsed = wire.parse(make_result(n_hdr=4, n_foot=1, foot=0x5A))
    assert isinstance(parsed, wire.Result)
    assert parsed.header == b"\x01\x02\x03\x04"
    assert parsed.footer == b"\x5a"
    assert parsed.data == b"\xaa\xbb"

    with pytest.raises(ProtocolError):
        wire.parse(b"\x03" + bytes(33))  # < 35 bytes
    with pytest.raises(ProtocolError):
        wire.parse(make_result(n_hdr=5))  # n_hdr > 4
    with pytest.raises(ProtocolError):
        wire.parse(make_result(n_foot=2))  # n_foot > 1
    with pytest.raises(ProtocolError):
        wire.parse(make_result(n_data=3, data=b"\xaa\xbb"))  # truncated data
    with pytest.raises(ProtocolError):
        wire.parse(make_result(n_data=1, data=b"\xaa\xbb"))  # trailing bytes


def test_a_monitor_result_splits_into_frames_with_their_flags() -> None:
    data = record(0x710, b"\x02\x10\x03", echo=True, time_us=5) + record(0x1BFCA2ED, bytes(8), extended=True)
    first, second = wire.monitor_records(data)
    assert (first.can_id, first.data, first.echo, first.extended, first.timestamp_us) == (0x710, b"\x02\x10\x03",
                                                                                          True, False, 5)
    assert (second.can_id, second.echo, second.extended) == (0x1BFCA2ED, False, True)
    with pytest.raises(ProtocolError):
        wire.monitor_records(data[:-1])
