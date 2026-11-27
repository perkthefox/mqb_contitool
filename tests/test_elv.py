"""Comprehensive tests for VAG MQB 2B ELV / J764 (Marquardt 3Q0 905 861) across core, CAN, CLI, and GUI."""

from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import struct
from typing import Any

import can
import pytest

from contitool.can.ecus import can_scan_bus
from contitool.can.elv import (
    can_elv_adapt,
    can_elv_adapt_from_cluster,
    can_elv_check_bootloader,
    can_elv_clear_dtc,
    can_elv_read_dflash,
    can_elv_reset_idac,
    can_elv_status,
    can_elv_virginize,
)
from contitool.can.workflows import can_identify
from contitool.cli.main import main as cli_main
from contitool.core.constants import T4_ELV_BENCH_PINS
from contitool.core.dtc import describe_elv
from contitool.core.dtc_elv import ELV_DTC_ORDER, ELV_DTCS
from contitool.core.elv import (
    ELV_02E1_CONST10,
    ELV_02F9_CONST12,
    ELV_DEV_MEM_RX_ID,
    ELV_DEV_MEM_TX_ID,
    ELV_DFLASH_BASE_ADDR,
    ELV_DFLASH_COMPACT_SIZE,
    ELV_DFLASH_POOL_SIZE,
    ELV_DFLASH_RAW64K_SIZE,
    ELV_EEELIB_ACTIVE_MARKER,
    ELV_GATEWAY_71_CAN_ID,
    ELV_KL_STATUS_CAN_ID,
    ELV_KL_STATUS_KENNUNG,
    ELV_UDS_RX_ID,
    ELV_UDS_TX_ID,
    ELV_WFS5_CASC,
    ELV_WFS5_SUFFIX_01A_TYPE2,
    ELV_WFS5_SUFFIX_01A_TYPE3,
    ELV_WFS5_SUFFIX_01B_CASC,
    ELV_WFS5_SUFFIX_01B_REPLY,
    ELV_WFS5_SUFFIX_01B_REPLY,
    ELV_WFS_ELV_CAN_ID,
    ELV_WFS_KOMBI_CAN_ID,
    elv_adapt_dflash,
    elv_aes128_ecb_decrypt,
    elv_aes128_ecb_encrypt,
    elv_bootloader_seed_to_key,
    elv_build_02e1_payload,
    elv_build_02e2_adapt_payload,
    elv_build_02e2_virgin_payload,
    elv_build_3c0_frame,
    elv_build_dev_mem_read_frame,
    elv_build_eeh_payload,
    elv_build_wfs5_01b_casc_request,
    elv_build_wfs5_01b_response,
    elv_compact32k_to_raw64k,
    elv_compute_02f9_mac,
    elv_crc16_ccitt,
    elv_crc32,
    elv_crc8_autosar,
    elv_decrypt_eeh_payload,
    elv_derive_eeprom_key,
    elv_extract_cluster_material,
    elv_is_dflash_bytes,
    elv_parse_dflash,
    elv_verify_02f9,
    elv_verify_wfs5_01a_reply,
    elv_virginize_dflash,
    elv_wfs5_mac,
)

# ────────────────────────────── Synthetic 47-record EEELib Fixture Builder ──────────────────────────────

# Exact 47-entry directory (vaddr, vlen, flags) matching 3Q0 905 861 SW 0032
_SYNTH_DIR_SPEC: tuple[tuple[int, int, int], ...] = (
    (0x0001, 0x68, 0x09), (0x0069, 0x68, 0x09), (0x00D1, 0x68, 0x09),  # ID 0..2: Block 0 Identity
    (0x0139, 0x48, 0x01),                                               # ID 3: Block 1 Bootloader flags
    (0x0181, 0x18, 0x0B), (0x0199, 0x18, 0x0B), (0x01B1, 0x18, 0x0B),  # ID 4..6: Block 2 Counters
    (0x01C9, 0x38, 0x01),                                               # ID 7: Block 3
    (0x0201, 0x18, 0x0B), (0x0219, 0x18, 0x0B), (0x0231, 0x18, 0x0B),  # ID 8..10: Block 4 IDp/IDac
    (0x0249, 0x18, 0x03),                                               # ID 11: Block 5 PRNG
    (0x0261, 0x18, 0x01),                                               # ID 12: Block 6 02FF
    (0x0279, 0x38, 0x09), (0x02B1, 0x38, 0x09), (0x02E9, 0x38, 0x09),  # ID 13..15: Block 7 Serial
    (0x0321, 0x48, 0x09), (0x0369, 0x48, 0x09), (0x03B1, 0x48, 0x09),  # ID 16..18: Block 8 Coding
    *tuple((0x03F9 + i * 0x28, 0x28, 0x01) for i in range(20)),         # ID 19..38: Blocks 9..28 DTCs
    (0x0719, 0x28, 0x01),                                               # ID 39: Block 29
    (0x0741, 0x18, 0x01),                                               # ID 40: Block 30
    (0x0759, 0x18, 0x01),                                               # ID 41: Block 31 Bolt/Cycles
    (0x0771, 0x18, 0x01),                                               # ID 42: Block 32 DEM
    (0x0789, 0x48, 0x01),                                               # ID 43: Block 33 Profiler
    (0x07D1, 0x38, 0x0B), (0x0809, 0x38, 0x0B), (0x0841, 0x38, 0x0B),  # ID 44..46: Block 34 WFS5
)
assert len(_SYNTH_DIR_SPEC) == 47


def make_synth_elv_dflash(
    *,
    active_pool: int = 1,
    format_64k: bool = False,
    vin: str = "WVWZZZAUZJW000001",
    k5_hex: str = "102132435465768798A9BACBDCEDFE0F",
    power_class: int = 0x6F,
    cfg: int = 0x80,
    brand: int = 0x01,
    mode: int = 0x02,
    idp_hex: str = "A956",
    idac_hex: str = "6BAB",
    idac_state: int = 0xAA,
    bolt_state: int = 0xC3,
    cycles: int = 6365,
    fazit: str = "TST-ELV01.01.0000000001",
) -> bytes:
    """Build a valid 47-record EEELib Marquardt 3Q0 905 861 Data Flash image (32 KiB or 64 KiB)."""
    compact = bytearray(b"\xff" * ELV_DFLASH_COMPACT_SIZE)
    markers = [0xFFFFFFFF] * (ELV_DFLASH_COMPACT_SIZE // 4)

    # Inactive pool counter (erased) + active pool marker/counter
    other_pool = 1 - active_pool
    struct.pack_into("<HH", compact, other_pool * ELV_DFLASH_POOL_SIZE + 0x3FFC, 0x002D, 0xFFD2)
    base = active_pool * ELV_DFLASH_POOL_SIZE
    struct.pack_into("<I", compact, base + 0x3FF8, ELV_EEELIB_ACTIVE_MARKER)
    struct.pack_into("<HH", compact, base + 0x3FFC, 0x002C, 0xFFD3)

    # Write 47 directory entries
    for idx, (va, vl, _fl) in enumerate(_SYNTH_DIR_SPEC):
        struct.pack_into("<HH", compact, base + idx * 4, va, vl)

    # Prepare decrypted payloads per block
    b0 = bytearray(b"\xff" * (0x68 - 8))
    b0[0:11] = b"3Q0905861  "
    b0[25:36] = b"3Q0905861  "
    b0[36:39] = b"H05"
    b0[39:55] = b"EV_ELVMarquMQBB\x00"
    b0[55:61] = b"001007"
    b0[66:89] = fazit.encode("ascii")[:23].ljust(23, b" ")

    b1 = bytearray(b"\xff" * (0x48 - 8))
    b1[1] = 0x00
    b1[2] = 0xD1
    b1[10:14] = b"0032"

    b2 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF]) + b"\xff" * 8

    b4 = bytearray(16)
    b4[1:3] = bytes.fromhex(idp_hex)
    b4[3:5] = bytes.fromhex(idac_hex)
    b4[5] = idac_state
    b4[6:10] = bytes.fromhex("EF796D76")

    b7 = bytearray(b"\xff" * (0x38 - 8))
    b7[16:30] = b"17000379886018"

    b8 = bytearray(b"\xff" * (0x48 - 8))
    b8[0:8] = bytes.fromhex("0800000000000000")
    b8[8:11] = bytes.fromhex("170605")
    b8[11:17] = bytes.fromhex("000210E614BF")
    b8[17:28] = b"-" * 11

    b31 = bytearray(b"\xff" * (0x18 - 8))
    b31[0] = 0x06
    b31[1] = bolt_state
    b31[2] = 0xF9
    b31[3] = (~bolt_state) & 0xFF
    struct.pack_into(">H", b31, 4, cycles)

    b34 = vin.encode("ascii")[:17].ljust(17, b"-") + bytes.fromhex(k5_hex) + bytes([power_class, cfg, brand, mode]) + bytes(11)

    dtc_slot0 = bytearray(b"\xff" * (0x28 - 8))
    dtc_slot0[0] = 9  # 0x100100
    dtc_slot0[1] = 0x00
    dtc_slot0[2] = 0x89

    data_by_vaddr: dict[int, bytes] = {
        0x0001: bytes(b0), 0x0069: bytes(b0), 0x00D1: bytes(b0),
        0x0139: bytes(b1),
        0x0181: b2, 0x0199: b2, 0x01B1: b2,
        0x0201: bytes(b4), 0x0219: bytes(b4), 0x0231: bytes(b4),
        0x0279: bytes(b7), 0x02B1: bytes(b7), 0x02E9: bytes(b7),
        0x0321: bytes(b8), 0x0369: bytes(b8), 0x03B1: bytes(b8),
        0x03F9: bytes(dtc_slot0),
        0x0759: bytes(b31),
        0x07D1: b34, 0x0809: b34, 0x0841: b34,
    }

    # Lay out records downward from end-16 (just like EEELib)
    cursor = base + ELV_DFLASH_POOL_SIZE - 16
    for va, vl, fl in _SYNTH_DIR_SPEC:
        dec = data_by_vaddr.get(va, b"\xff" * (vl - 8))
        payload = elv_build_eeh_payload(va, dec, fl)
        rec_size = vl + 8
        cursor -= rec_size
        struct.pack_into("<HH", compact, cursor, va, vl)
        compact[cursor + 4 : cursor + 4 + vl] = payload
        struct.pack_into("<HH", compact, cursor + 4 + vl, va, vl)
        markers[cursor // 4] = 0x00000000

    if format_64k:
        return elv_compact32k_to_raw64k(compact, markers)
    return bytes(compact)


# ────────────────────────────── Synthetic CAN ECU Simulator (FakeElvBus) ──────────────────────────────


class FakeElvBus:
    """Firmware-faithful in-memory simulator of Marquardt 3Q0 905 861 SW 0032 on CAN."""

    def __init__(self, dflash_32k: bytes) -> None:
        self.dflash = bytearray(dflash_32k)
        self.parsed = elv_parse_dflash(bytes(self.dflash))
        self.rx_queue: deque[can.Message] = deque()
        self.sent_frames: list[can.Message] = []
        self.session: int = 0x01
        self.in_bootloader: bool = False
        self.engine_stopped_seen: bool = False
        self.kl15_on: bool = False
        self.wfs5_authorized: bool = False
        self.wfs5_type1_authed: bool = False
        self._pending_p_chal: bytes | None = None
        self._awaiting_31_01_02_03: bool = False
        self.c_diag: bytes = bytes.fromhex("11223344")
        self.bl_seed: int = 0x12345678
        self.bl_unlocked: bool = False
        self.dtcs: list[tuple[int, int]] = [(0x100100, 0x09), (0xC14000, 0x08)]
        # ISO-TP reassembly state
        self._rx_buf = bytearray()
        self._rx_expected = 0
        self._rx_sn = 1

    def shutdown(self) -> None:
        pass

    def _enqueue(self, arb_id: int, data: bytes) -> None:
        self.rx_queue.append(
            can.Message(arbitration_id=arb_id, data=data, is_extended_id=bool(arb_id > 0x7FF))
        )

    def _send_isotp(self, payload: bytes) -> None:
        n = len(payload)
        if n <= 7:
            self._enqueue(ELV_UDS_RX_ID, (bytes([n]) + payload).ljust(8, b"\x55"))
            return
        ff = bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + payload[:6]
        self._enqueue(ELV_UDS_RX_ID, ff)
        pos = 6
        sn = 1
        while pos < n:
            chunk = payload[pos : pos + 7]
            self._enqueue(ELV_UDS_RX_ID, (bytes([0x20 | sn]) + chunk).ljust(8, b"\x55"))
            pos += 7
            sn = (sn + 1) & 0x0F

    def _current_02ed(self) -> bytes:
        b34 = self.parsed["block34"]
        return bytes([b34["mode"], b34["brand"], 0x03, b34["power_class"], 0, 0, 0, 0, 0, 0])

    def _current_02ee(self) -> bytes:
        b34 = self.parsed["block34"]
        b04 = self.parsed["block04"]
        b1 = (b34["config"] & 0x80) | (0x40 if b04["idac_state"] == 0xAA else 0x00)
        return bytes([0x00, b1, 0, 0, 0, 0, 0, 0, 0, 0])

    def _b4ed_allowed(self) -> bool:
        """Exact `DAT_ram_ffffb4ed` rule from `FUN_ram_000274de`."""
        if self.parsed["block34"]["mode"] != 2:
            return True
        return self.kl15_on and self.wfs5_type1_authed

    def _handle_uds(self, req: bytes) -> None:
        if not req:
            return
        sid = req[0]
        if sid == 0x10 and len(req) >= 2:
            sub = req[1]
            if self.in_bootloader:
                if sub == 0x03:
                    self._send_isotp(b"\x7f\x10\x7e")
                    return
                if sub == 0x01:
                    self.in_bootloader = False
                    self.session = 0x01
                    self._send_isotp(b"\x50\x01\x00\x32\x01\xf4")
                    return
                self._send_isotp(bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4]))
                return
            if sub == 0x02:
                if not self._b4ed_allowed():
                    self._send_isotp(b"\x7f\x10\x22")
                    return
                self._send_isotp(b"\x7f\x10\x78")
                self.in_bootloader = True
                self.session = 0x02
            else:
                self.session = sub
            self._send_isotp(bytes([0x50, sub, 0x00, 0x32, 0x01, 0xF4]))
            return
        if sid == 0x11 and len(req) >= 2:
            if self.in_bootloader and req[1] != 0x01:
                # Bootloader `FUN_ram_00008502` ONLY accepts HardReset (0x01); 0x02 returns NRC 0x12.
                self._send_isotp(b"\x7f\x11\x12")
                return
            self.in_bootloader = False
            self.session = 0x01
            self.kl15_on = False
            self.wfs5_type1_authed = False
            self._send_isotp(bytes([0x51, req[1]]))
            return
        if sid == 0x3E:
            self._send_isotp(bytes([0x7E, req[1] if len(req) > 1 else 0x00]))
            return
        if sid == 0x27 and len(req) >= 2:
            if not self.in_bootloader:
                self._send_isotp(bytes([0x7F, 0x27, 0x11]))
                return
            sub = req[1]
            if sub == 0x11:
                self._send_isotp(b"\x67\x11" + struct.pack(">I", self.bl_seed))
            elif sub == 0x12 and len(req) >= 6:
                got = struct.unpack_from(">I", req, 2)[0]
                if got == elv_bootloader_seed_to_key(self.bl_seed):
                    self.bl_unlocked = True
                    self._send_isotp(b"\x67\x12")
                else:
                    self._send_isotp(b"\x7f\x27\x35")
            return
        if sid == 0x31 and req[:4] == b"\x31\x01\x02\x03":
            if self._b4ed_allowed():
                self._send_isotp(b"\x71\x01\x02\x03")
                return
            if self.parsed["block34"]["mode"] == 2 and self.kl15_on:
                # Matches `FUN_ram_0002052e` -> `FUN_ram_000205b4` -> `FUN_ram_00026dc0`:
                # returns 7F 31 78 ResponsePending and issues 0x01A Type 1 challenge P.
                self._pending_p_chal = bytes.fromhex("A1B2C3D4")
                self._awaiting_31_01_02_03 = True
                self._send_isotp(b"\x7f\x31\x78")
                self._enqueue(ELV_WFS_ELV_CAN_ID, b"\x01" + self._pending_p_chal + b"\x00\x00\x00")
                return
            self._send_isotp(b"\x71\x01\x02\x03\x02")
            return
        if sid == 0x14 and len(req) >= 4:
            self.dtcs.clear()
            self._send_isotp(b"\x54")
            return
        if sid == 0x19 and len(req) >= 3 and req[1] == 0x02:
            body = bytearray(b"\x59\x02\xff")
            for code, st in self.dtcs:
                body.extend([(code >> 16) & 0xFF, (code >> 8) & 0xFF, code & 0xFF, st])
            self._send_isotp(bytes(body))
            return
        if sid == 0x22 and len(req) >= 3:
            did = (req[1] << 8) | req[2]
            ident = self.parsed["identity"]
            b34 = self.parsed["block34"]
            b31 = self.parsed["block31"]
            did_map: dict[int, bytes] = {
                0xF187: ident["part_number"].encode("ascii").ljust(11, b" "),
                0xF189: (ident["sw_version"] or "0032").encode("ascii"),
                0xF191: ident["hw_part_number"].encode("ascii").ljust(11, b" "),
                0xF1A3: ident["hw_version"].encode("ascii"),
                0xF17C: ident["fazit"].encode("ascii").ljust(23, b" "),
                0xF18C: ident["serial"].encode("ascii"),
                0xF197: b"ELV-MQBB",
                0xF19E: ident["asam_odx"].encode("ascii"),
                0xF1A2: ident["asam_version"].encode("ascii"),
                0xF190: b34["vin"].encode("ascii").ljust(17, b"-"),
                0x0600: bytes.fromhex(ident["coding_hex"]),
                0xF1DF: bytes([0x44 if self.in_bootloader else 0x40]),
                0x1105: bytes([b34["mode"]]),
                0x02ED: self._current_02ed(),
                0x02EE: self._current_02ee(),
                0x02EF: bytes(6),
                0x02E0: self.c_diag,
                0x2C8B: struct.pack(">H", b31["lock_cycles"]),
                0x1109: struct.pack(">HH", 24, 28),
            }
            if did == 0x02F9:
                reply_02f9 = elv_compute_02f9_mac(
                    b34["slot_a_hex"],
                    fazit=ident["fazit"],
                    vin=b34["vin"],
                    did_02ed=self._current_02ed(),
                    did_02ee=self._current_02ee(),
                    c_diag=self.c_diag,
                )
                self._send_isotp(b"\x62\x02\xf9" + reply_02f9)
                return
            if did in did_map:
                self._send_isotp(bytes([0x62, req[1], req[2]]) + did_map[did])
            else:
                self._send_isotp(bytes([0x7F, 0x22, 0x31]))
            return
        if sid == 0x2E and len(req) >= 3:
            did = (req[1] << 8) | req[2]
            payload = req[3:]
            b34 = self.parsed["block34"]
            cur_k5 = bytes.fromhex(b34["slot_a_hex"])
            if did == 0x02E1 and len(payload) == 4:
                cmd, arg = payload[2], payload[3]
                if (cmd, arg) != (0x04, 0x80) or b34["mode"] != 2:
                    self._send_isotp(b"\x7f\x2e\x22")
                    return
                expected = elv_build_02e1_payload(cur_k5, self.c_diag, cmd=cmd, arg=arg)
                if payload != expected:
                    self._send_isotp(b"\x7f\x2e\x31")
                    return
                # Reset IDac state 0xAA -> 0x00 in internal DFLASH
                self.dflash = bytearray(
                    elv_adapt_dflash(
                        bytes(self.dflash),
                        vin=b34["vin"],
                        k5=cur_k5,
                        power_class=b34["power_class"],
                        idac=None,
                        config_byte=b34["config"],
                        brand_byte=b34["brand"],
                    )
                )
                self.parsed = elv_parse_dflash(bytes(self.dflash))
                self._send_isotp(b"\x6e\x02\xe1")
                return
            if did == 0x02E2 and len(payload) == 52:
                if not self.engine_stopped_seen:
                    self._send_isotp(b"\x7f\x2e\x22")
                    return
                pt = elv_aes128_ecb_decrypt(cur_k5, payload[:48])
                crc_got = struct.unpack_from(">I", payload, 48)[0]
                if elv_crc32(pt) != crc_got:
                    self._send_isotp(b"\x7f\x2e\x31")
                    return
                # Check FUN_ram_00027ad0 Virgin Reset branch
                if pt[:17] == b"\xff" * 17 and pt[33:37] == bytes([0x00, 0xFF, 0xFF, 0x03]):
                    vk5 = pt[17:33]
                    self.dflash = bytearray(elv_virginize_dflash(bytes(self.dflash), virgin_k5=vk5))
                else:
                    new_vin = pt[:17].decode("ascii")
                    new_k5 = pt[17:33]
                    new_pc, new_cfg, new_brand = pt[33], pt[34], pt[35]
                    self.dflash = bytearray(
                        elv_adapt_dflash(
                            bytes(self.dflash),
                            vin=new_vin,
                            k5=new_k5,
                            power_class=new_pc,
                            idac=None,
                            config_byte=new_cfg,
                            brand_byte=new_brand,
                        )
                    )
                self.parsed = elv_parse_dflash(bytes(self.dflash))
                self._send_isotp(b"\x6e\x02\xe2")
                return
            self._send_isotp(b"\x7f\x2e\x31")

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        self.sent_frames.append(msg)
        aid = msg.arbitration_id
        data = bytes(msg.data)

        if aid == ELV_GATEWAY_71_CAN_ID and len(data) >= 6 and (data[0] & 0x01) == 1:
            self.engine_stopped_seen = True
            return

        if aid == ELV_KL_STATUS_CAN_ID and len(data) >= 4:
            if data[0] == elv_crc8_autosar(data[1:4] + bytes([ELV_KL_STATUS_KENNUNG])):
                new_kl15 = bool(data[2] & 0x02)
                if self.kl15_on and not new_kl15:
                    # Matches `FUN_ram_0002818c` -> `FUN_ram_0002776e(0)`: turning KL15 off clears `bfdc & 0x10`!
                    self.wfs5_type1_authed = False
                self.kl15_on = new_kl15
            return

        if aid == ELV_WFS_KOMBI_CAN_ID and len(data) == 8:
            b34 = self.parsed["block34"]
            b04 = self.parsed["block04"]
            r_chal = data[4:8]
            if self._pending_p_chal is not None:
                p_chal = self._pending_p_chal
                mac_in = elv_wfs5_mac(b34["slot_a_hex"], b34["power_class"], p_chal, r_chal, ELV_WFS5_SUFFIX_01B_REPLY)
                if data[0] == mac_in[0] and data[1] == mac_in[1]:
                    cand_idac = bytes([data[2] ^ mac_in[2], data[3] ^ mac_in[3]])
                    if cand_idac.hex().upper() == b04["idac_hex"]:
                        self.wfs5_type1_authed = True
                        self.wfs5_authorized = True
                        self._pending_p_chal = None
                        if self._awaiting_31_01_02_03:
                            self._awaiting_31_01_02_03 = False
                            self._send_isotp(b"\x71\x01\x02\x03")
                        return
                # Wrong 0x01B key/IDac -> 31 01 02 03 finishes with failure byte 0x02
                self._pending_p_chal = None
                if self._awaiting_31_01_02_03:
                    self._awaiting_31_01_02_03 = False
                    self._send_isotp(b"\x71\x01\x02\x03\x02")
                return
            mac_in = elv_wfs5_mac(b34["slot_a_hex"], b34["power_class"], ELV_WFS5_CASC, r_chal, ELV_WFS5_SUFFIX_01B_CASC)
            if data[0] == mac_in[0] and data[1] == mac_in[1]:
                cand_idac = bytes([data[2] ^ mac_in[2], data[3] ^ mac_in[3]])
                if cand_idac.hex().upper() == b04["idac_hex"]:
                    # Autonomous 'casc' sets bfdc bit 0 only — NOT bit 0x10 (so it does NOT unlock `10 02`).
                    self.wfs5_authorized = True
                    mac_out = elv_wfs5_mac(
                        b34["slot_a_hex"], b34["power_class"], r_chal, ELV_WFS5_CASC, ELV_WFS5_SUFFIX_01A_TYPE3
                    )
                    idp = bytes.fromhex(b04["idp_hex"])
                    rep = bytes([
                        0x03,
                        mac_out[0],
                        mac_out[1],
                        mac_out[2] ^ idp[0],
                        mac_out[3] ^ idp[1],
                        0x00,
                        0x00,
                        0x07,
                    ])
                    self._enqueue(ELV_WFS_ELV_CAN_ID, rep)
            return

        if aid == ELV_DEV_MEM_TX_ID and len(data) == 8 and data[5:8] == b"42B":
            addr = struct.unpack_from("<I", data, 0)[0]
            length = data[4]
            if 1 <= length <= 8 and ELV_DFLASH_BASE_ADDR <= addr < ELV_DFLASH_BASE_ADDR + ELV_DFLASH_COMPACT_SIZE:
                off = addr - ELV_DFLASH_BASE_ADDR
                chunk = bytes(self.dflash[off : off + length]).ljust(8, b"\x00")
                self._enqueue(ELV_DEV_MEM_RX_ID, chunk)
            return

        if aid == ELV_UDS_TX_ID and data:
            pci = data[0] >> 4
            if pci == 0:
                ln = data[0] & 0x0F
                self._handle_uds(data[1 : 1 + ln])
            elif pci == 1:
                self._rx_expected = ((data[0] & 0x0F) << 8) | data[1]
                self._rx_buf = bytearray(data[2:8])
                self._rx_sn = 1
                self._enqueue(ELV_UDS_RX_ID, b"\x30\x00\x00\x55\x55\x55\x55\x55")
            elif pci == 2 and self._rx_expected > 0:
                if (data[0] & 0x0F) == self._rx_sn:
                    self._rx_buf.extend(data[1:8])
                    self._rx_sn = (self._rx_sn + 1) & 0x0F
                    if len(self._rx_buf) >= self._rx_expected:
                        full = bytes(self._rx_buf[: self._rx_expected])
                        self._rx_expected = 0
                        self._rx_buf.clear()
                        self._handle_uds(full)

    def recv(self, timeout: float | None = None) -> can.Message | None:
        if self.rx_queue:
            return self.rx_queue.popleft()
        return None


# ────────────────────────────── 1. Core Crypto & Protocol Tests ──────────────────────────────


def test_elv_aes_crc_and_key_derivation_vectors() -> None:
    # FIPS-197 Appendix B standard AES-128 test vector
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    assert elv_aes128_ecb_encrypt(key, pt) == ct
    assert elv_aes128_ecb_decrypt(key, ct) == pt

    # IEEE 802.3 CRC-32 & CRC-16/CCITT-FALSE
    assert elv_crc32(b"123456789") == 0xCBF43926
    assert elv_crc16_ccitt(b"123456789") == 0x29B1

    # AUTOSAR E2E Profile 2 CRC-8 (poly 0x2F) & 0x3C0 Klemmen_Status_01
    frame = elv_build_3c0_frame(bz=5, kl_s=True, kl_15=True, kl_50=False)
    assert len(frame) == 4
    assert frame[1] == 5 and frame[2] == 0x03 and frame[3] == 0x00
    assert frame[0] == elv_crc8_autosar(frame[1:4] + bytes([ELV_KL_STATUS_KENNUNG]))

    # Exact Marquardt EEH LFSR derived keys verified against 47/47 CRCs on real 3Q0 905 861 dumps
    assert elv_derive_eeprom_key(0x0181).hex() == "17170264444001044018000000000000"
    assert elv_derive_eeprom_key(0x0201).hex() == "17178000000000000000000000000000"
    assert elv_derive_eeprom_key(0x07D1).hex() == "1717104401628f8a180061e06fac6014"
    assert elv_derive_eeprom_key(0x0809).hex() == "17170207220281180000000000000000"
    assert elv_derive_eeprom_key(0x0841).hex() == "1717000210051e9000c8019088402820"

    # Bootloader SecurityAccess 27 11/12 deterministic check (exact verified constants)
    assert elv_bootloader_seed_to_key(0x00000000) == 0xCC12F1D7
    assert elv_bootloader_seed_to_key(0x12345678) == 0xD82DBEFF

    # Developer read frame format
    req = elv_build_dev_mem_read_frame(0xFCFF8000, 8)
    assert req == bytes.fromhex("0080fffc08343242")


def test_elv_02f9_02e1_02e2_and_wfs5_mac_roundtrips() -> None:
    k5 = bytes.fromhex("102132435465768798A9BACBDCEDFE0F")
    fazit = "TST-ELV01.01.0000000001"
    vin = "WVWZZZAUZJW000001"
    did_02ed = bytes.fromhex("0201036f000000000000")
    did_02ee = bytes.fromhex("00c00000000000000000")
    c_diag = bytes.fromhex("a1b2c3d4")

    # 22 02F9 round-trip
    resp_02f9 = elv_compute_02f9_mac(k5, fazit=fazit, vin=vin, did_02ed=did_02ed, did_02ee=did_02ee, c_diag=c_diag)
    assert len(resp_02f9) == 5 and resp_02f9[0] == 0x82
    ver = elv_verify_02f9(k5, resp_02f9, fazit=fazit, vin=vin, did_02ed=did_02ed, did_02ee=did_02ee, c_diag=c_diag)
    assert ver["match"] is True
    bad = elv_verify_02f9(b"\x00" * 16, resp_02f9, fazit=fazit, vin=vin, did_02ed=did_02ed, did_02ee=did_02ee, c_diag=c_diag)
    assert bad["match"] is False

    # 2E 02E1 exact FUN_ram_00027dd6 verification
    p_02e1 = elv_build_02e1_payload(k5, c_diag, cmd=0x04, arg=0x80)
    assert len(p_02e1) == 4 and p_02e1[2:] == b"\x04\x80"
    ct_e1 = elv_aes128_ecb_encrypt(k5, bytes([0x04, 0x80]) + c_diag + ELV_02E1_CONST10)
    assert struct.unpack(">H", p_02e1[:2])[0] == elv_crc16_ccitt(ct_e1)
    with pytest.raises(ValueError):
        elv_build_02e1_payload(k5, b"\x00\x00\x00\x00", cmd=0x04, arg=0x80)
    with pytest.raises(ValueError):
        elv_build_02e1_payload(k5, c_diag, cmd=0x05, arg=0x00)

    # 2E 02E2 adapt & virgin payloads match FUN_ram_00027bc2 / FUN_ram_00027ad0
    new_k5 = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    p_adapt = elv_build_02e2_adapt_payload(k5, new_vin="WVWZZZAUZJW000002", new_k5=new_k5, new_power_class=0x76)
    assert len(p_adapt) == 52
    pt_adapt = elv_aes128_ecb_decrypt(k5, p_adapt[:48])
    assert struct.unpack(">I", p_adapt[48:52])[0] == elv_crc32(pt_adapt)
    assert pt_adapt[:17] == b"WVWZZZAUZJW000002"
    assert pt_adapt[17:33] == new_k5
    assert pt_adapt[33:37] == bytes([0x76, 0x80, 0x01, 0x02])

    p_vir = elv_build_02e2_virgin_payload(k5, virgin_k5=new_k5)
    assert len(p_vir) == 52
    pt_vir = elv_aes128_ecb_decrypt(k5, p_vir[:48])
    assert struct.unpack(">I", p_vir[48:52])[0] == elv_crc32(pt_vir)
    assert pt_vir[:17] == b"\xff" * 17
    assert pt_vir[17:33] == new_k5
    assert pt_vir[33:37] == bytes([0x00, 0xFF, 0xFF, 0x03])

    # WFS5 CAN 0x01A <-> 0x01B Little-Endian MAC round-trip
    p_chal = bytes.fromhex("01020304")
    r_chal = bytes.fromhex("05060708")
    idac = bytes.fromhex("6BAB")
    idp = bytes.fromhex("A956")
    f_01b = elv_build_wfs5_01b_response(k5, 0x6F, p_chal, r_chal, idac)
    assert len(f_01b) == 8 and f_01b[4:8] == r_chal
    mac_rep = elv_wfs5_mac(k5, 0x6F, r_chal, p_chal, ELV_WFS5_SUFFIX_01A_TYPE2)
    f_01a = bytes([0x02, mac_rep[0], mac_rep[1], mac_rep[2] ^ idp[0], mac_rep[3] ^ idp[1], 0, 0, 0x07])
    res_01a = elv_verify_wfs5_01a_reply(k5, 0x6F, f_01a, r_challenge=r_chal, p_challenge=p_chal, expected_idp=idp)
    assert res_01a["ok"] is True and res_01a["recovered_idp_hex"] == "A956"


def test_elv_dtc_table_complete() -> None:
    assert len(ELV_DTCS) == 71
    assert len(ELV_DTC_ORDER) == 71
    assert ELV_DTC_ORDER[0] == 0x000006
    assert ELV_DTC_ORDER[9] == 0x100100
    assert ELV_DTC_ORDER[-1] == 0xD0170F
    disp, desc = describe_elv(0x100100)
    assert disp == "B11F713" and len(desc) > 5


# ────────────────────────────── 2. 32K & 64K DFLASH Offline Parsing / Patching ──────────────────────────────


@pytest.mark.parametrize("active_pool,format_64k", [(0, True), (1, False), (0, False), (1, True)])
def test_elv_dflash_parse_virginize_and_adapt_roundtrip(active_pool: int, format_64k: bool) -> None:
    raw = make_synth_elv_dflash(active_pool=active_pool, format_64k=format_64k)
    assert len(raw) == (ELV_DFLASH_RAW64K_SIZE if format_64k else ELV_DFLASH_COMPACT_SIZE)
    assert elv_is_dflash_bytes(raw) is True

    info = elv_parse_dflash(raw)
    assert info["active_pool"] == active_pool
    assert info["all_crc_ok"] is True and info["crc_valid_count"] == 47
    assert info["triple_copy_ok"] is True
    assert info["block34"]["vin"] == "WVWZZZAUZJW000001"
    assert info["block34"]["slot_a_hex"] == "102132435465768798A9BACBDCEDFE0F"
    assert info["block04"]["idp_hex"] == "A956"
    assert info["block04"]["idac_hex"] == "6BAB"
    assert info["block31"]["lock_cycles"] == 6365
    assert len(info["stored_dtcs"]) == 1 and info["stored_dtcs"][0]["code"] == 0x100100

    # Virginize preserves size, format, IDp, and 47/47 CRCs
    vir_raw = elv_virginize_dflash(raw)
    assert len(vir_raw) == len(raw)
    vir_info = elv_parse_dflash(vir_raw)
    assert vir_info["all_crc_ok"] is True and vir_info["triple_copy_ok"] is True
    assert vir_info["block34"]["mode"] == 1
    assert vir_info["block34"]["vin"] == "-" * 17
    assert vir_info["block34"]["power_class"] == 0x00
    assert vir_info["block04"]["idp_hex"] == "A956"
    assert vir_info["block04"]["idac_state"] == 0x00

    # Adapt (auto-learn IDac)
    ad_auto = elv_adapt_dflash(
        raw,
        vin="WVWZZZAUZJW000002",
        k5="AABBCCDDEEFF00112233445566778899",
        power_class=0x76,
    )
    assert len(ad_auto) == len(raw)
    ai = elv_parse_dflash(ad_auto)
    assert ai["all_crc_ok"] is True and ai["triple_copy_ok"] is True
    assert ai["block34"]["mode"] == 2
    assert ai["block34"]["vin"] == "WVWZZZAUZJW000002"
    assert ai["block34"]["slot_a_hex"] == "AABBCCDDEEFF00112233445566778899"
    assert ai["block34"]["power_class"] == 0x76
    assert ai["block04"]["idac_state"] == 0x00 and ai["block04"]["idac_hex"] == "0000"

    # Adapt (explicit locked IDac)
    ad_lock = elv_adapt_dflash(
        raw,
        vin="WVWZZZAUZJW000002",
        k5="AABBCCDDEEFF00112233445566778899",
        power_class=0x76,
        idac="B2B8",
    )
    li = elv_parse_dflash(ad_lock)
    assert li["all_crc_ok"] is True and li["block04"]["idac_hex"] == "B2B8" and li["block04"]["idac_state"] == 0xAA


# ────────────────────────────── 3. Live CAN Workflows via FakeElvBus ──────────────────────────────


def test_elv_can_end_to_end_workflows(tmp_path: Path) -> None:
    dflash = make_synth_elv_dflash(active_pool=1, format_64k=False)
    bus = FakeElvBus(dflash)

    # 1. Bus scan & identify
    scan = can_scan_bus("fake", target_kind="elv", bus=bus)
    assert scan.topology == "direct" and len(scan.ecus) == 1
    assert scan.ecus[0].kind == "elv" and scan.ecus[0].diag_addr == "2B"
    ident = can_identify("fake", target="elv", bus=bus)
    assert ident["ecu_kind"] == "elv" and ident["responding"] is True

    # 2. Status + DTC read/clear
    st = can_elv_status("fake", bus=bus)
    assert st["passport"]["part_number"] == "3Q0905861"
    assert st["status"]["mode"] == 0x02
    assert len(st["dtcs"]) == 2
    clr = can_elv_clear_dtc("fake", bus=bus)
    assert clr["cleared"] is True and clr["remaining_count"] == 0

    # 3. Full 32 KB Data Flash read + 47/47 CRC + live 22 02F9 verification + backup save
    out_dir = tmp_path / "elv_read"
    rd = can_elv_read_dflash("fake", out_dir=out_dir, bus=bus)
    assert rd["dflash_bytes"] == dflash
    assert rd["dflash_parsed"]["all_crc_ok"] is True
    assert rd["verify_02f9"]["verified"] is True and rd["verify_02f9"]["match"] is True
    assert (out_dir / "elv_dflash_32k.bin").is_file()
    assert (out_dir / "elv_report.json").is_file()

    # 4. Reset IDac via 2E 02E1 (auto-reads current_k5 from DFLASH)
    rid = can_elv_reset_idac("fake", backup_dir=tmp_path / "b_idac", bus=bus)
    assert rid["ok"] is True
    assert rid["post_status"]["idac_locked"] is False

    # 5. Adapt to new vehicle via 2E 02E2 (sends 0x3DC precondition, writes new VIN/K_5/PC, verifies new 02F9)
    new_k5 = "00112233445566778899AABBCCDDEEFF"
    ad = can_elv_adapt(
        "fake",
        new_vin="WVWZZZAUZJW000002",
        new_k5=new_k5,
        new_power_class=0x76,
        backup_dir=tmp_path / "b_adapt",
        bus=bus,
    )
    assert ad["ok"] is True
    assert ad["post_passport"]["vin"] == "WVWZZZAUZJW000002"
    assert ad["post_status"]["mode"] == 0x02
    assert ad["post_status"]["power_class"] == 0x76
    assert ad["verify_02f9"]["match"] is True

    # 6. Virginize via 2E 02E2 (Mode 2 -> Mode 1)
    vir = can_elv_virginize("fake", backup_dir=tmp_path / "b_vir", bus=bus)
    assert vir["ok"] is True
    assert vir["post_status"]["mode"] == 0x01
    assert vir["post_passport"]["vin"] == "-" * 17
    assert vir["verify_02f9"]["match"] is True

    # 7a. Bootloader preconditions-only without credentials -> returns failure code 0x02
    bus2 = FakeElvBus(dflash)
    pre_only = can_elv_check_bootloader("fake", enter_programming=False, bus=bus2)
    assert pre_only["preconditions_ok"] is False
    assert pre_only["preconditions_raw_hex"] == "02"
    assert len(pre_only["preconditions_reasons"]) == 1

    # 7b. Bootloader entry (Mode 2, explicit credentials): 0x3C0 KL15=1 + 31 01 02 03 -> 0x01A Type1/0x01B -> 10 02 -> 27 11/12 -> 11 01
    bl = can_elv_check_bootloader(
        "fake",
        current_k5="102132435465768798A9BACBDCEDFE0F",
        power_class=0x6F,
        idac="6BAB",
        enter_programming=True,
        bus=bus2,
    )
    assert bl["preconditions_ok"] is True
    assert bl["wfs5_handshake_ok"] is True
    assert bl["programming_session_ok"] is True
    assert bl["security_access_ok"] is True
    assert bl["returned_to_app"] is True
    assert bus2.bl_unlocked is True and bus2.in_bootloader is False

    # 7c. Bootloader entry (Mode 2, NO credentials passed): auto-reads DFLASH, runs WFS5 Type 1, unlocks & resets via 11 01
    bus3 = FakeElvBus(dflash)
    bl_auto = can_elv_check_bootloader("fake", enter_programming=True, bus=bus3)
    assert bl_auto["preconditions_ok"] is True
    assert bl_auto["wfs5_handshake_ok"] is True
    assert bl_auto["programming_session_ok"] is True
    assert bl_auto["security_access_ok"] is True
    assert bl_auto["returned_to_app"] is True
    assert bus3.bl_unlocked is True and bus3.in_bootloader is False

    # 7d. Bootloader entry (Mode 2, wrong K_5): fails cleanly at 31 01 02 03 precondition check
    bus4 = FakeElvBus(dflash)
    with pytest.raises(RuntimeError, match="0x02"):
        can_elv_check_bootloader(
            "fake",
            current_k5="00" * 16,
            power_class=0x6F,
            idac="6BAB",
            enter_programming=True,
            bus=bus4,
        )
    assert bus4.in_bootloader is False

    # 7e. Bootloader entry (Mode 1 Virgin): DAT_ram_ffffb4ed == 1 without WFS5
    bus_vir = FakeElvBus(elv_virginize_dflash(dflash))
    bl_vir = can_elv_check_bootloader("fake", enter_programming=True, bus=bus_vir)
    assert bl_vir["preconditions_ok"] is True
    assert bl_vir["programming_session_ok"] is True
    assert bl_vir["security_access_ok"] is True
    assert bl_vir["returned_to_app"] is True
    assert bus_vir.bl_unlocked is True and bus_vir.in_bootloader is False


# ────────────────────────────── 4. CLI Tests ──────────────────────────────


def test_elv_cli_offline_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    in_bin = tmp_path / "elv_in.bin"
    in_bin.write_bytes(make_synth_elv_dflash(active_pool=1, format_64k=False))

    # inspect
    rc = cli_main(["elv", "inspect", "--dflash", str(in_bin)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["all_crc_ok"] is True and out["block34"]["vin"] == "WVWZZZAUZJW000001"

    # virginize-dflash
    vir_bin = tmp_path / "elv_vir.bin"
    rc = cli_main(["elv", "virginize-dflash", "--dflash", str(in_bin), "-o", str(vir_bin)])
    assert rc == 0
    v_out = json.loads(capsys.readouterr().out)
    assert v_out["block34"]["mode"] == 1 and vir_bin.stat().st_size == ELV_DFLASH_COMPACT_SIZE

    # adapt-dflash
    ad_bin = tmp_path / "elv_ad.bin"
    rc = cli_main([
        "elv", "adapt-dflash",
        "--dflash", str(in_bin),
        "-o", str(ad_bin),
        "--vin", "WVWZZZAUZJW000002",
        "--k5", "11223344556677889900AABBCCDDEEFF",
        "--power-class", "76",
    ])
    assert rc == 0
    a_out = json.loads(capsys.readouterr().out)
    assert a_out["block34"]["vin"] == "WVWZZZAUZJW000002" and a_out["block34"]["power_class"] == 0x76

    # Mutating online command requires --yes
    rc = cli_main(["elv", "virginize", "--port", "fake"])
    assert rc == 1


# ────────────────────────────── 5. Headless GUI Smoke Tests ──────────────────────────────


def test_elv_gui_smoke(tmp_path: Path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QSettings

    from contitool.gui.app import create_window
    from contitool.gui.dialogs.guide import GuideDialog
    from contitool.gui.widgets.pinout_card import ElvPinoutCard
    from contitool.i18n import set_lang

    pin_map = {pin: sig for pin, sig, _, _ in T4_ELV_BENCH_PINS}
    assert set(pin_map.keys()) == {1, 2, 3, 4}
    assert pin_map[1] == "CAN-H" and pin_map[2] == "CAN-L"

    QSettings().clear()
    set_lang("ru")
    app, win = create_window()
    win.show()

    # Load ELV dump folder via MainWindow.open_folder
    folder = tmp_path / "3Q0905861_elv"
    folder.mkdir()
    (folder / "elv_dflash_32k.bin").write_bytes(make_synth_elv_dflash(active_pool=1, format_64k=False))
    win.open_folder(str(folder))
    app.processEvents()

    assert win.elv_screen.is_open
    assert win.stack.currentWidget() is win.elv_screen
    assert win.elv_screen.current_idp_hex == "A956"
    assert win.elv_screen.current_k5_hex == "102132435465768798A9BACBDCEDFE0F"

    # Visit all 4 sidebar tabs & switch RU <-> EN
    for tab_key in ("immo", "adapt", "status", "dtc"):
        item = win.elv_screen._nav_items[tab_key]
        win.elv_screen.nav.setCurrentItem(item)
        app.processEvents()
    set_lang("en")
    app.processEvents()
    set_lang("ru")
    app.processEvents()

    # Verify terminal target & T4 pinout card in GuideDialog
    win.terminal.set_target_ecu("elv")
    assert win.terminal.ed_tx.text() == "731" and win.terminal.ed_rx.text() == "79B"

    card = ElvPinoutCard()
    assert not card.grab().isNull()
    dlg = GuideDialog(win)
    assert dlg.pinout_stack.currentIndex() == 2  # T4 ELV tab auto-selected
    dlg.close()

    win.close_ecu()
    app.processEvents()
    assert not win.elv_screen.is_open
    assert win.stack.currentWidget() is win.start_screen
    win.close()


def test_elv_adapt_from_fpke_cluster(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from test_fpke import build_synthetic_fpke_dflash
    from contitool.core.fpke import apply_fpke_dflash_edits, fpke_s0_s1_from_slots

    target_slot_a = bytes.fromhex("A1B2C3D4E5F60718293A4B5C6D7E8F90")
    target_slot_b = bytes.fromhex("0F1E2D3C4B5A69788796A5B4C3D2E1F0")
    s0, s1 = fpke_s0_s1_from_slots(target_slot_a, target_slot_b)
    fpke_df = apply_fpke_dflash_edits(
        build_synthetic_fpke_dflash(),
        slot_s0_hex=s0.hex(),
        slot_s1_hex=s1.hex(),
        crc_a_hex=struct.pack("<I", elv_crc32(target_slot_a)).hex(),
        crc_b_hex=struct.pack("<I", elv_crc32(target_slot_b)).hex(),
    )
    mat = elv_extract_cluster_material(fpke_df)
    assert len(mat["vin"]) == 17
    assert mat["slot_a_hex"] == target_slot_a.hex().upper()
    assert mat["slot_a_crc_ok"] is True
    assert mat["power_class"] is not None

    # Live CAN adaptation directly from FPK_E dump
    elv_df = make_synth_elv_dflash(active_pool=1, format_64k=False)
    bus = FakeElvBus(elv_df)
    res = can_elv_adapt_from_cluster("fake", fpke_df, backup_dir=tmp_path / "b_cl", bus=bus)
    assert res["ok"] is True
    assert res["post_passport"]["vin"] == mat["vin"]
    assert res["post_status"]["power_class"] == mat["power_class"]
    assert res["verify_02f9"]["match"] is True

    # Offline CLI adaptation directly from --cluster-dflash
    elv_in = tmp_path / "elv_in.bin"
    cl_in = tmp_path / "fpke_df.bin"
    elv_out = tmp_path / "elv_from_cl.bin"
    elv_in.write_bytes(elv_df)
    cl_in.write_bytes(fpke_df)
    rc = cli_main([
        "elv", "adapt-dflash",
        "--dflash", str(elv_in),
        "--cluster-dflash", str(cl_in),
        "--lock-cluster-idac",
        "-o", str(elv_out),
    ])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["all_crc_ok"] is True
    assert out["block34"]["vin"] == mat["vin"]
    assert out["block34"]["slot_a_hex"] == mat["slot_a_hex"]
    if mat["cluster_mac_id"]:
        assert out["block04"]["idac_hex"] == mat["cluster_mac_id"]
        assert out["block04"]["idac_state"] == 0xAA


# ────────────────────────────── 6. Code-Review & Design Regressions (C1–C6, H1–H11, M1–M6) ──────────────────────────────


def test_elv_c5_triple_copy_majority_voting_and_h11_validation() -> None:
    """C5: corrupted copy 0 of Block 4 / Block 34 must recover from intact copies 1 & 2, never re-sealing bad IDp."""
    raw = bytearray(make_synth_elv_dflash(active_pool=1, format_64k=False))
    # Corrupt copy 0 of Block 4 (vaddr 0x0201) and Block 34 (vaddr 0x07D1) in active pool 1
    info_orig = elv_parse_dflash(bytes(raw))
    for vaddr in (0x0201, 0x07D1):
        rec = next(r for r in info_orig["records"] if r["vaddr"] == vaddr)
        off = int(rec["compact_offset_hex"], 16)
        raw[off + 12] ^= 0xFF

    # Parser recovers intact IDp & K_5 from copies 1 & 2 via majority vote
    parsed = elv_parse_dflash(bytes(raw))
    assert parsed["block04"]["idp_hex"] == "A956"
    assert parsed["block34"]["slot_a_hex"] == "102132435465768798A9BACBDCEDFE0F"
    assert parsed["triple_copy_ok"] is False

    # Virginize & adapt must preserve intact factory IDp ("A956") from valid copies
    vir = elv_virginize_dflash(bytes(raw))
    v_info = elv_parse_dflash(vir)
    assert v_info["all_crc_ok"] is True
    assert v_info["block04"]["idp_hex"] == "A956"

    ad = elv_adapt_dflash(bytes(raw), vin="WVWZZZAUZJW000009", k5="22" * 16, power_class=0x6F)
    a_info = elv_parse_dflash(ad)
    assert a_info["all_crc_ok"] is True
    assert a_info["block04"]["idp_hex"] == "A956"
    assert a_info["block34"]["config"] == 0x80

    # H11: out-of-range u8 values and control chars in VIN must raise ValueError
    with pytest.raises(ValueError):
        elv_adapt_dflash(bytes(raw), vin="WVWZZZAUZJW000009", k5="22" * 16, power_class=0x1FF)
    with pytest.raises(ValueError):
        elv_adapt_dflash(bytes(raw), vin="WVWZZZ\x00UZJW000009", k5="22" * 16, power_class=0x6F)


def test_elv_c2_c3_c4_h1_h3_h8_can_safety_and_dpdu(tmp_path: Path) -> None:
    """C2 (02F9 fail-closed & cancel), C3 (PRIME_PAIRS), C4 (29-bit ext flag), H1 (gateway guard), H8 (11 01 finally)."""
    from contitool.can.dpdu import PRIME_PAIRS, SLAVE_UDS_PAIRS
    from contitool.can.elv import ElvCanLink
    from contitool.progress import OperationCancelledError

    # C3: (0x731, 0x79B) registered in D-PDU SLAVE_UDS_PAIRS & PRIME_PAIRS
    assert (0x731, 0x79B) in SLAVE_UDS_PAIRS
    assert PRIME_PAIRS[0x731] == (0x731, 0x79B)

    # C4: 29-bit UDS ID sets is_extended_id=True on send_frame
    sent_msgs: list[can.Message] = []

    class RecordingBus:
        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            sent_msgs.append(msg)

        def recv(self, timeout: float = 0.0) -> can.Message | None:
            return None

        def shutdown(self) -> None:
            pass

    with ElvCanLink("fake", bus=RecordingBus()) as lnk:
        lnk.send_frame(0x17FC0231, b"\x02\x10\x03")
        lnk.send_frame(0x731, b"\x02\x10\x03")
    assert sent_msgs[0].is_extended_id is True
    assert sent_msgs[1].is_extended_id is False

    # C2: unverified / mismatched 22 02F9 aborts write before 2E 02E2
    dflash = make_synth_elv_dflash(active_pool=1, format_64k=False)

    class Bad02F9Bus(FakeElvBus):
        def _handle_uds(self, req: bytes) -> None:
            if req == b"\x22\x02\xf9":
                self._enqueue(ELV_UDS_RX_ID, b"\x03\x7f\x22\x31\x55\x55\x55\x55")
                return
            super()._handle_uds(req)

    bus_bad = Bad02F9Bus(dflash)
    with pytest.raises(RuntimeError):
        can_elv_adapt(
            "fake",
            new_vin="WVWZZZAUZJW000009",
            new_k5="33" * 16,
            new_power_class=0x76,
            current_k5="102132435465768798A9BACBDCEDFE0F",
            bus=bus_bad,
        )

    # C2: user cancellation during pre-write backup must NEVER be swallowed
    class CancelReporter:
        def check_cancelled(self) -> None:
            raise OperationCancelledError("cancelled")

        def step(self, *a, **k) -> None:
            pass

        def info(self, *a, **k) -> None:
            pass

        def warning(self, *a, **k) -> None:
            pass

        def progress(self, *a, **k) -> None:
            pass

        def can_log(self, *a, **k) -> None:
            pass

    with pytest.raises(OperationCancelledError):
        can_elv_virginize(
            "fake",
            current_k5="102132435465768798A9BACBDCEDFE0F",
            backup_dir=tmp_path / "cancel_b",
            bus=FakeElvBus(dflash),
            reporter=CancelReporter(),  # type: ignore[arg-type]
        )

    # H1: via_gateway=True without gateway_bridge and without current_k5 raises clear bridge/known-K5 error
    with pytest.raises(RuntimeError, match="3Q0 907 530|K_5|RAM-мост|RAM bridge"):
        can_elv_virginize("fake", via_gateway=True, gateway_bridge=False, bus=FakeElvBus(dflash))

    # H8: bootloader check sends 11 01 HardReset in finally even if 27 12 fails after 10 02
    class Fail2712Bus(FakeElvBus):
        def _handle_uds(self, req: bytes) -> None:
            if req[:2] == b"\x27\x12":
                self._enqueue(ELV_UDS_RX_ID, b"\x03\x7f\x27\x35\x55\x55\x55\x55")
                return
            super()._handle_uds(req)

    from contitool.can.transport import UdsNegativeResponse

    bus_bl = Fail2712Bus(dflash)
    with pytest.raises(UdsNegativeResponse):
        can_elv_check_bootloader(
            "fake",
            current_k5="102132435465768798A9BACBDCEDFE0F",
            power_class=0x6F,
            idac="6BAB",
            enter_programming=True,
            bus=bus_bl,
        )
    # Must have executed 11 01 HardReset in finally: so ELV is NOT left trapped in bootloader!
    assert bus_bl.in_bootloader is False


def test_elv_c1_c6_h10_h11_gui_restore_report_and_cli_guards(tmp_path: Path) -> None:
    """C1 (RestoreDialog rejects 64K ELV), C6 (close_elv resets), H10 (UDS-only report open), H11 (--cfg 80 hex), StartScreen 3x2."""
    from PySide6.QtCore import QSettings

    from contitool.gui.app import create_window
    from contitool.gui.dialogs.restore import RestoreDialog
    from contitool.i18n import set_lang

    # H11: CLI --cfg 80 parses as hex 0x80 (not decimal 80 = 0x50), and check-bootloader --enter-programming requires --yes
    in_bin = tmp_path / "elv_in.bin"
    out_bin = tmp_path / "elv_out.bin"
    in_bin.write_bytes(make_synth_elv_dflash(active_pool=1, format_64k=False))
    rc_ad = cli_main([
        "elv", "adapt-dflash",
        "--dflash", str(in_bin),
        "-o", str(out_bin),
        "--vin", "WVWZZZAUZJW000005",
        "--k5", "44" * 16,
        "--power-class", "6F",
        "--cfg", "80",
        "--brand", "01",
    ])
    assert rc_ad == 0
    assert elv_parse_dflash(out_bin.read_bytes())["block34"]["config"] == 0x80

    rc_bl = cli_main(["elv", "check-bootloader", "--port", "fake", "--enter-programming"])
    assert rc_bl != 0

    QSettings().clear()
    set_lang("en")
    app, win = create_window()
    try:
        # C1: RestoreDialog must reject 64 KiB ELV programmer DFLASH dump
        elv64 = tmp_path / "Dflash.bin"
        elv64.write_bytes(make_synth_elv_dflash(active_pool=1, format_64k=True))
        dlg = RestoreDialog(win, str(tmp_path))
        try:
            rejected = dlg.add_files([elv64])
            assert rejected == ["Dflash.bin"]
            assert "dflash" not in dlg.files
        finally:
            dlg.close()

        # StartScreen 3x2 grid: 6 cards arranged in 2 rows x 3 cols without clipping
        assert len(win.start_screen._target_cards) == 6
        assert win.start_screen._target_cards["elv"].lbl_name.text() == "Steering Lock ELV"

        # H10: UDS-only elv_report.json folder opens cleanly in ElvScreen
        rep_dir = tmp_path / "3Q0905861_uds_only"
        rep_dir.mkdir()
        (rep_dir / "elv_report.json").write_text(
            json.dumps({
                "ecu_kind": "elv",
                "passport": {"part_number": "3Q0905861", "sw_version": "0032", "vin": "WVWZZZAUZJW000007"},
                "status": {"mode": 2, "power_class": 0x6F, "power_class_hex": "0x6F"},
                "dtcs": [],
            }),
            encoding="utf-8",
        )
        win.open_folder(str(rep_dir))
        app.processEvents()
        assert win.elv_screen.is_open is True
        assert win.stack.currentWidget() is win.elv_screen
        assert win.elv_screen.part_number == "3Q0905861"

        # C6: close_elv resets drafts, routing, and manual cluster state completely
        win.elv_screen._draft_cur_k5 = "AA" * 16
        win.elv_screen._draft_vin = "WVWZZZAUZJW999999"
        win.elv_screen._via_gateway = True
        win.elv_screen._cluster_source_manual = True
        win.elv_screen.close_elv()
        assert win.elv_screen._draft_cur_k5 == ""
        assert win.elv_screen._draft_vin == ""
        assert win.elv_screen._via_gateway is False
        assert win.elv_screen._cluster_source_manual is False
    finally:
        win.close()


def test_elv_unverified_pn_sw_allows_read_with_warning_and_banner(tmp_path: Path) -> None:
    from PySide6.QtWidgets import QApplication, QLabel

    from contitool.core.elv import elv_detect_profile
    from contitool.gui.main_window import MainWindow
    from contitool.i18n import set_lang
    from contitool.progress import OperationReporter

    set_lang("ru")
    # Verified Marquardt 3Q0 905 861 SW 0032 -> no warning
    assert elv_detect_profile({"part_number": "3Q0905861", "sw_version": "0032"})["warning"] is None

    # Unverified ELV (different PN or SW) -> warning with PN + SW, read NOT blocked
    prof = elv_detect_profile({"part_number": "5Q0905861A", "sw_version": "0040"})
    assert prof["verified"] is False
    assert prof["warning"] and "5Q0905861A" in prof["warning"] and "0040" in prof["warning"]
    assert "официально не поддерживается" in prof["warning"]

    bus = FakeElvBus(make_synth_elv_dflash(active_pool=1, format_64k=False))
    bus.parsed["identity"]["part_number"] = "5Q0905861A"
    bus.parsed["identity"]["sw_version"] = "0040"
    warns: list[str] = []

    class RecRep(OperationReporter):
        def warning(self, message: str) -> None:
            warns.append(message)

    st = can_elv_status("fake", bus=bus, reporter=RecRep())
    assert st["officially_supported"] is False
    assert st["support_warning"] and "5Q0905861A" in st["support_warning"] and "0040" in st["support_warning"]

    df_res = can_elv_read_dflash("fake", out_dir=tmp_path, bus=bus, reporter=RecRep())
    assert df_res["officially_supported"] is False
    assert len(df_res["dflash_bytes"]) == 0x8000
    assert any("5Q0905861A" in w and "0040" in w for w in warns)

    # ElvScreen displays warning banner for unverified ELV
    app = QApplication.instance() or QApplication([])
    win = MainWindow()
    try:
        win.elv_screen.open_from_read_result(df_res)
        app.processEvents()
        page_w = win.elv_screen.page_area.widget()
        texts = [lbl.text() for lbl in page_w.findChildren(QLabel)]
        assert any("5Q0905861A" in t and "0040" in t and "официально не поддерживается" in t for t in texts)
    finally:
        win.close()


