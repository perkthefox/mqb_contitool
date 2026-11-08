"""Tests for J533 CAN ISO-TP framing, 0x6F0 RAM-loader protocol, SA2, and repository hygiene."""

from __future__ import annotations

from functools import reduce
from pathlib import Path
import re
import can

from contitool.can import (
    BEACON_ASCII,
    DFLASH_READER_STUB,
    J533CanLink,
    LOADER_PASSWORD,
    LOADER_SYNC,
    build_dflash_reader_payload,
    build_loader_packet,
    build_reader_payload,
    build_service_loader_uds_steps,
    build_uflash_one_shot_payload,
    enter_ram_loader,
    fbl_sa2,
    read_memory_bytes,
    verify_payload_self_tests,
)


def test_payload_digests_and_sa2_vectors() -> None:
    verify_payload_self_tests()
    assert fbl_sa2(0x12345678) == 0x7CA16271

    pkt = build_loader_packet(b"\xfe\xff")
    assert len(pkt) == 0x120 + 3
    assert len(DFLASH_READER_STUB) == 652
    assert len(build_dflash_reader_payload(0xFF200000, 4096, calls=16, feed=True)) == 668
    assert pkt[0x110:0x118] == LOADER_PASSWORD
    assert pkt[0x118:0x11A] == b"\xfe\xff"
    assert reduce(lambda a, b: a ^ b, pkt[:-1], 0) == pkt[-1]

    rdr = build_reader_payload(0xFF200000, 4096)
    assert len(rdr) == 28


def test_uflash_one_shot_builder(synth_uflash: bytes) -> None:
    payload, pages = build_uflash_one_shot_payload(synth_uflash)
    assert 1 <= pages <= 122
    assert len(payload) == 436 + pages * 256


class _MockGatewayBus:
    """Deterministic in-memory J533 ECU responder simulating UDS 0x710/0x77A + RAM-Loader 0x6F0/0x6F1."""

    def __init__(self) -> None:
        self.rx_queue: list[can.Message] = []
        self.tx_frames: list[tuple[int, bytes]] = []
        self._in_loader = False
        self._loader_expected = 0
        self._loader_buf = bytearray()
        self._uds_multi_expected = 0
        self._uds_multi_buf = bytearray()

    def recv(self, timeout: float = 0.0):
        if not self.rx_queue:
            return None
        return self.rx_queue.pop(0)

    def _reply(self, arb_id: int, data: bytes) -> None:
        self.rx_queue.append(can.Message(arbitration_id=arb_id, data=data, is_extended_id=False))

    def send(self, message: can.Message, timeout: float = 1.0) -> None:
        arb = message.arbitration_id
        raw = bytes(message.data)
        self.tx_frames.append((arb, raw))

        if arb == 0x710:
            pci = raw[0] >> 4
            if pci == 0:
                req = raw[1 : 1 + (raw[0] & 0x0F)]
                self._handle_uds(req)
            elif pci == 1:
                self._uds_multi_expected = ((raw[0] & 0x0F) << 8) | raw[1]
                self._uds_multi_buf = bytearray(raw[2:])
                self._reply(0x77A, b"\x30\x00\x00\xaa\xaa\xaa\xaa\xaa")
            elif pci == 2:
                self._uds_multi_buf.extend(raw[1:])
                if len(self._uds_multi_buf) >= self._uds_multi_expected:
                    req = bytes(self._uds_multi_buf[: self._uds_multi_expected])
                    self._handle_uds(req)
        elif arb == 0x6F0:
            if raw == LOADER_SYNC:
                self._loader_buf.clear()
                self._loader_expected = 0
                self._reply(0x6F1, LOADER_SYNC)
                return
            if not self._loader_buf:
                sz = raw[0] | ((raw[1] & 0x7F) << 8)
                self._loader_expected = sz + 3
            self._loader_buf.extend(raw)
            if len(self._loader_buf) >= self._loader_expected:
                pkt = bytes(self._loader_buf[: self._loader_expected])
                code = pkt[0x118:-1]
                if BEACON_ASCII in code:
                    self._reply(0x6F1, BEACON_ASCII[:8])
                    self._reply(0x6F1, BEACON_ASCII[8:] + b"\x00" * 5)
                    self._reply(0x6F1, b"\x00\x00")
                elif code.startswith(b"\x26\x06"):
                    ln = int.from_bytes(code[8:12], "little")
                    blob = bytes((i & 0xFF) for i in range(ln))
                    for off in range(0, ln, 8):
                        chunk = blob[off : off + 8].ljust(8, b"\x00")
                        self._reply(0x6F1, chunk)
                    self._reply(0x6F1, b"\x00\x00")

    def _handle_uds(self, req: bytes) -> None:
        stage1, stage2, trigger = build_service_loader_uds_steps()
        if req == b"\x10\x03":
            self._reply(0x77A, b"\x06\x50\x03\x00\x32\x01\xf4\xaa")
        elif req == b"\x27\x03":
            self._reply(0x77A, b"\x06\x67\x03\x11\x22\x33\x44\xaa")
        elif req.startswith(b"\x27\x04"):
            self._reply(0x77A, b"\x02\x67\x04\xaa\xaa\xaa\xaa\xaa")
        elif req == bytes.fromhex("31010203"):
            self._reply(0x77A, b"\x05\x71\x01\x02\x03\x00\xaa\xaa")
        elif req == b"\x10\x02":
            # Emit ResponsePending (7F 10 78) first to verify pending handling!
            self._reply(0x77A, b"\x03\x7f\x10\x78\xaa\xaa\xaa\xaa")
            self._reply(0x77A, b"\x06\x50\x02\x00\x32\x01\xf4\xaa")
        elif req == b"\x27\x11":
            self._reply(0x77A, b"\x06\x67\x11\xde\xad\xbe\xef\xaa")
        elif req.startswith(b"\x2e\x04\x10"):
            self._reply(0x77A, b"\x03\x6e\x04\x10\xaa\xaa\xaa\xaa")
        elif req == stage1:
            resp = b"\x62" + (b"\x00" * 334) + bytes.fromhex("041005")
            assert len(resp) == 338
            self._reply(0x77A, bytes([0x10 | (len(resp) >> 8), len(resp) & 0xFF]) + resp[:6])
            seq = 1
            for off in range(6, len(resp), 7):
                self._reply(0x77A, bytes([0x20 | seq]) + resp[off : off + 7].ljust(7, b"\xaa"))
                seq = (seq + 1) & 0x0F
        elif req == stage2:
            pass  # Suppressed negative response
        elif req == trigger:
            self._in_loader = True


def test_can_link_service_loader_entry_and_native_reader() -> None:
    bus = _MockGatewayBus()
    with J533CanLink("mock", bus=bus) as link:
        info = enter_ram_loader(link)
        assert info["loader_ready"] is True
        assert info["beacon"] == BEACON_ASCII.decode("ascii")
        sample = read_memory_bytes(link, 0x01000000, 32)
        assert sample == bytes(range(32))
