"""Unit, simulated CAN bus, CLI, and headless Qt 6 GUI tests for 09 BCM (J519, Continental MPC5607B)."""

from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any
import zlib

import can
import pytest

from contitool.can.bcm import (
    BcmCanLink,
    can_bcm_adapt_ffb,
    can_bcm_adapt_ffb_from_cluster,
    can_bcm_read_gfa,
    can_bcm_read_keys,
    can_bcm_status,
    can_bcm_write_keys,
)
from contitool.core.bcm import (
    BCM_CP_KEY_TYPE_GFA,
    BCM_CP_KEY_TYPE_IKA,
    BCM_FFB_C16,
    BCM_PROFILES,
    BCM_UDS_RX_ID,
    BCM_UDS_TX_ID,
    BCM_WFS_RX_ID,
    BCM_WFS_TX_ID,
    BCM_XCP_DD_RX_ID,
    BCM_XCP_DD_TX_ID,
    BCM_XCP_RX_ID,
    BCM_XCP_TX_ID,
    _AES_SBOX,
    bcm_aes128_ecb_decrypt,
    bcm_aes128_ecb_encrypt,
    bcm_aes128_final_round,
    bcm_build_cp_key_container,
    bcm_build_ffb_key_plaintext,
    bcm_build_job3_injection_stages,
    bcm_build_wfs_80_01,
    bcm_build_wfs_80_02,
    bcm_compute_sa_key,
    bcm_decode_status_dids,
    bcm_derive_k_ffb,
    bcm_detect_profile,
    bcm_encrypt_ffb_key_record,
    bcm_extract_cluster_ffb_material,
    bcm_gfa_raw_to_working,
    bcm_gfa_working_to_raw,
    bcm_parse_ffb_key_plaintext,
    bcm_recover_ika_from_job3,
    bcm_unpack_cp_key_container,
)
from contitool.i18n import set_lang


def _invert_final_round_for_sim(final_block_16b: bytes, last_round_key_16b: bytes) -> bytes:
    """Inverse of `bcm_aes128_final_round` so `FakeBcmBus` can synthesize the exact MPC5607B `job3_state+1` buffer."""
    k = [int.from_bytes(last_round_key_16b[i : i + 2], "big") for i in range(0, 16, 2)]
    inv_s = [0] * 16
    for i in range(8):
        inv_s[2 * i] = final_block_16b[2 * i] ^ (k[i] & 0xFF)
        inv_s[2 * i + 1] = final_block_16b[2 * i + 1] ^ ((k[i] >> 8) & 0xFF)
    sb = [_AES_SBOX[b & 0xFF] for b in inv_s]
    # Map back to w[0..7] lo/hi positions used by bcm_aes128_final_round
    w_lo = [0] * 8
    w_hi = [0] * 8
    lo_map = (0, 5, 2, 7, 4, 1, 6, 3)
    hi_map = (6, 3, 0, 5, 2, 7, 4, 1)
    for idx in range(8):
        w_lo[lo_map[idx]] = sb[2 * idx]
        w_hi[hi_map[idx]] = sb[2 * idx + 1]
    out = bytearray(16)
    for i in range(8):
        val = ((w_hi[i] & 0xFF) << 8) | (w_lo[i] & 0xFF)
        out[2 * i : 2 * i + 2] = val.to_bytes(2, "big")
    return bytes(out)


class FakeBcmBus:
    """In-memory simulator for 09 BCM (EA/0511 or DD/0273): UDS `0x70E/0x778`, XCP, and WFS Ch 3 (`0x17F8140E/0x17FA0E14`)."""

    def __init__(
        self,
        *,
        profile_id: str = "ea_0511",
        ika: bytes = bytes.fromhex("112233445566778899aabbccddeeff01"),
        gfa: bytes = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
        freq_code: int = 0x02,
    ) -> None:
        self.profile = BCM_PROFILES[profile_id]
        self.ika = bytes(ika)
        self.gfa = bytes(gfa)
        self.freq_code = freq_code
        self.session = 0x01
        self.sa_unlocked = False
        self.cp_mismatch = 0
        self.ika_virgin = False
        self.k_ffb = bytes(16)
        self.ffb_serials: dict[int, bytes] = {i: b"\x00" * 4 for i in range(1, 8)}
        self.ffb_counters: dict[int, bytes] = {i: b"\x00" * 4 for i in range(1, 8)}
        self.ffb_sync_states: dict[int, int] = {i: 0 for i in range(1, 8)}
        self.ffb_learned_mask = 0
        self.ffb_synced_mask = 0
        self.allow_dev_session = True
        self.dtcs: list[tuple[int, int]] = [
            (0xEA6400, 0x09),  # U110100: Component protection active
            (0x001A0A, 0x09),  # B121715: Left low beam headlamp bulb open/short to B+
            (0x081215, 0x08),  # U112100: Databus missing message (ESP_21)
        ]
        self.last_round_key = bytes.fromhex("303132333435363738393a3b3c3d3e3f")
        self.rx_queue: deque[can.Message] = deque()
        self.ram: dict[int, int] = {}

        # Populate initial WFS buffer, descriptor & FFB NvM RAM mirror in simulated RAM
        buf_addr = int(self.profile["wfs_rx_buf"])
        self._write_ram(int(self.profile["wfs_rx_desc"]), buf_addr.to_bytes(4, "big"))
        self._write_ram(int(self.profile["ika_working_addr"]), self.ika)
        self._write_ram(int(self.profile["gfa_working_addr"]), self.gfa)
        self._sync_ffb_ram_mirror()

        self._uds_mf_buf = bytearray()
        self._uds_mf_expected = 0
        self._wfs_mf_buf = bytearray()
        self._wfs_mf_expected = 0

    def _sync_ffb_ram_mirror(self) -> None:
        if "ffb_nvm_key_addr" in self.profile:
            self._write_ram(int(self.profile["ffb_nvm_key_addr"]), self.k_ffb)
        ser_base = int(self.profile["ffb_serials_addr"])
        cnt_base = int(self.profile["ffb_counters_addr"])
        sync_base = int(self.profile["ffb_syncs_addr"])
        for slot in range(1, 8):
            self._write_ram(ser_base + (slot - 1) * 4, self.ffb_serials[slot])
            self._write_ram(cnt_base + (slot - 1) * 4, self.ffb_counters[slot])
            self._write_ram(sync_base + (slot - 1), bytes([self.ffb_sync_states[slot] & 0xFF]))

    def _write_ram(self, address: int, data: bytes) -> None:
        for idx, b in enumerate(data):
            self.ram[(address + idx) & 0xFFFFFFFF] = b

    def _read_ram(self, address: int, size: int) -> bytes:
        return bytes(self.ram.get((address + idx) & 0xFFFFFFFF, 0) for idx in range(size))

    def _enqueue_frame(self, arb_id: int, data: bytes) -> None:
        raw = bytes(data)
        if len(raw) < 8:
            raw += b"\xaa" * (8 - len(raw))
        self.rx_queue.append(
            can.Message(arbitration_id=arb_id, data=raw[:8], is_extended_id=bool(arb_id > 0x7FF))
        )

    def _enqueue_isotp(self, rx_id: int, payload: bytes) -> None:
        if len(payload) <= 7:
            self._enqueue_frame(rx_id, bytes([len(payload)]) + payload)
            return
        length = len(payload)
        self._enqueue_frame(rx_id, bytes([0x10 | ((length >> 8) & 0x0F), length & 0xFF]) + payload[:6])
        seq = 1
        for off in range(6, length, 7):
            chunk = payload[off : off + 7]
            self._enqueue_frame(rx_id, bytes([0x20 | (seq & 0x0F)]) + chunk)
            seq = (seq + 1) & 0x0F

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        arb = msg.arbitration_id
        raw = bytes(msg.data)
        xcp_tx = int(self.profile["xcp_tx_id"])
        xcp_rx = int(self.profile["xcp_rx_id"])

        if arb == xcp_tx:
            cmd = raw[0]
            if cmd == 0xFF:  # XCP CONNECT
                self._enqueue_frame(xcp_rx, b"\xff\x00\x08\x08\x00\x00\x01\x01")
            elif cmd == 0xF4:  # XCP SHORT_UPLOAD
                length = min(7, raw[1])
                addr = int.from_bytes(raw[4:8], "big")
                nvm02_addr = int(self.profile.get("ffb_nvm_key_addr", 0))
                if getattr(self, "block_nvm_02_direct", True) and nvm02_addr and (
                    nvm02_addr <= addr < nvm02_addr + 16 or nvm02_addr < addr + length <= nvm02_addr + 16
                ):
                    self._enqueue_frame(xcp_rx, b"\xfe\x25\x00\x00\x00\x00\x00\x00")
                    return
                chunk = self._read_ram(addr, length)
                self._enqueue_frame(xcp_rx, b"\xff" + chunk.ljust(7, b"\x00"))
            return

        if arb == BCM_UDS_TX_ID:
            kind = raw[0] >> 4
            if kind == 0:
                sf_len = raw[0] & 0x0F
                self._handle_uds(raw[1 : 1 + sf_len])
            elif kind == 1:
                self._uds_mf_expected = ((raw[0] & 0x0F) << 8) | raw[1]
                self._uds_mf_buf = bytearray(raw[2:8])
                self._enqueue_frame(BCM_UDS_RX_ID, b"\x30\x00\x01")
            elif kind == 2 and self._uds_mf_expected > 0:
                take = min(7, self._uds_mf_expected - len(self._uds_mf_buf))
                self._uds_mf_buf.extend(raw[1 : 1 + take])
                if len(self._uds_mf_buf) >= self._uds_mf_expected:
                    pdu = bytes(self._uds_mf_buf[: self._uds_mf_expected])
                    self._uds_mf_expected = 0
                    self._handle_uds(pdu)
            return

        if arb == BCM_WFS_TX_ID:
            kind = raw[0] >> 4
            buf_addr = int(self.profile["wfs_rx_buf"])
            if kind == 0:
                sf_len = raw[0] & 0x0F
                pdu = raw[1 : 1 + sf_len]
                self._write_ram(buf_addr, pdu)
                self._handle_wfs(pdu)
            elif kind == 1:
                self._wfs_mf_expected = ((raw[0] & 0x0F) << 8) | raw[1]
                self._wfs_mf_buf = bytearray(raw[2:8])
                self._write_ram(int(self.profile["wfs_rx_desc"]), buf_addr.to_bytes(4, "big"))
                self._enqueue_frame(BCM_WFS_RX_ID, b"\x30\x00\x01")
            elif kind == 2 and self._wfs_mf_expected > 0:
                take = min(7, self._wfs_mf_expected - len(self._wfs_mf_buf))
                self._wfs_mf_buf.extend(raw[1 : 1 + take])
                if len(self._wfs_mf_buf) >= self._wfs_mf_expected:
                    pdu = bytes(self._wfs_mf_buf[: self._wfs_mf_expected])
                    self._wfs_mf_expected = 0
                    self._write_ram(buf_addr, pdu)
                    self._handle_wfs(pdu)
            return

    def _handle_uds(self, pdu: bytes) -> None:
        if not pdu:
            return
        sid = pdu[0]
        if sid == 0x10 and len(pdu) >= 2:
            if pdu[1] == 0x4F and not self.allow_dev_session:
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x10\x22")
                return
            self.session = pdu[1]
            self._enqueue_isotp(BCM_UDS_RX_ID, bytes([0x50, self.session, 0x00, 0x32, 0x01, 0xF4]))
            return
        if sid == 0x11 and len(pdu) >= 2:
            # Real BCM HardReset reloads working IKA/GFA from NvM into SRAM and resets Job 3 state
            self.session = 0x01
            self.sa_unlocked = False
            self._write_ram(int(self.profile["ika_working_addr"]), self.ika)
            self._write_ram(int(self.profile["gfa_working_addr"]), self.gfa)
            self._write_ram(int(self.profile["job3_state_addr"]), b"\x01" + bytes(16))
            self._enqueue_isotp(BCM_UDS_RX_ID, bytes([0x51, pdu[1]]))
            return
        if sid == 0x27 and len(pdu) >= 2:
            sub = pdu[1]
            if sub == 0x03:
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x67\x03\x12\x34\x56\x78")
            elif sub == 0x04 and len(pdu) >= 6:
                if pdu[2:6] == bcm_compute_sa_key(b"\x12\x34\x56\x78"):
                    self.sa_unlocked = True
                    self._enqueue_isotp(BCM_UDS_RX_ID, b"\x67\x04")
                else:
                    self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x27\x35")
            return
        if sid == 0x22 and len(pdu) >= 3:
            did = int.from_bytes(pdu[1:3], "big")
            pn_map = {
                "ea_0511": b"5Q0937084EA ",
                "dd_0273": b"5Q0937084DD ",
                "bq_0212": b"5Q0937084BQ ",
                "bl_0175": b"5Q0937084BL ",
            }
            sw_map = {
                "ea_0511": b"0511",
                "dd_0273": b"0273",
                "bq_0212": b"0212",
                "bl_0175": b"0175",
            }
            pn = pn_map.get(self.profile["id"], b"5Q0937084EA ")
            sw = sw_map.get(self.profile["id"], b"0511")
            dids: dict[int, bytes] = {
                0xF187: pn,
                0xF189: sw,
                0xF191: pn,
                0xF1A3: b"H34",
                0xF17C: b"TST-00001.01.2012340511",
                0xF197: b"BCM MQBAB H",
                0xF19E: b"EV_BCMMQB",
                0xF190: b"WVWZZZAUZJW000001",
                0x0600: bytes(30),
                0x03DE: self.cp_mismatch.to_bytes(2, "big"),
                0x0440: bytes([0, 0, 0, 0, 0, 0, 1 if self.ika_virgin else 0]),
                0x043F: b"\x03",
                0x02E0: b"\xaa\xbb\xcc\xdd",
                0x02F9: b"\x81\x7d\xf6\x21\x04",
                0x0A65: bytes([0x71 | ((self.freq_code & 0x03) << 1), 0xD4, 0x02, 0x00, 0x00, 0x00, 0x00]),
                0x1983: bytes([0xFF, ((bin(self.ffb_learned_mask >> 1).count("1") & 0x0F) << 4) | 0x03, 0xFF, 0xDF]),
                0x24A6: b"\x01\x02\x03\x04\x05\x06",
            }
            if did in dids:
                self._enqueue_isotp(BCM_UDS_RX_ID, bytes([0x62, pdu[1], pdu[2]]) + dids[did])
            else:
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x22\x31")
            return
        if sid == 0x19 and len(pdu) >= 3 and pdu[1] == 0x02:
            body = bytearray(b"\x59\x02\xff")
            for code, st_byte in self.dtcs:
                body.extend(code.to_bytes(3, "big"))
                body.append(st_byte & 0xFF)
            self._enqueue_isotp(BCM_UDS_RX_ID, bytes(body))
            return
        if sid == 0x14 and len(pdu) == 4:
            self.dtcs.clear()
            self._enqueue_isotp(BCM_UDS_RX_ID, b"\x54")
            return
        if sid == 0x23 and len(pdu) >= 5 and pdu[1] == 0x12:
            if self.session != 0x4F:
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x23\x7f")
                return
            nvm_id = pdu[2]
            payload: bytes | None = None
            if nvm_id == 0x02:
                if getattr(self, "block_nvm_02_direct", True):
                    self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x23\x11")
                    return
                payload = self.k_ffb
            elif nvm_id == 0x03:
                payload = bytes([self.ffb_learned_mask & 0xFF])
            elif 0x05 <= nvm_id <= 0x0B:
                slot = (nvm_id - 0x05) + 1
                payload = self.ffb_counters[slot]
            elif 0x0C <= nvm_id <= 0x12:
                slot = (nvm_id - 0x0C) + 1
                payload = bytes([self.ffb_sync_states[slot] & 0xFF])
            elif 0x13 <= nvm_id <= 0x19:
                slot = (nvm_id - 0x13) + 1
                payload = self.ffb_serials[slot]
            if payload is not None:
                # Real MPC5607B BCM firmware (`0x0005D4B6` / `0x00059B6C`) responds:
                # 63 12 <nvm_id> <len_hi> <len_lo> <payload>
                hdr = bytes([0x63, 0x12, nvm_id]) + len(payload).to_bytes(2, "big")
                self._enqueue_isotp(BCM_UDS_RX_ID, hdr + payload)
            else:
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x23\x11")
            return
        if sid == 0x2E and len(pdu) == 37:
            did = int.from_bytes(pdu[1:3], "big")
            container = pdu[3:37]
            unpacked = bcm_unpack_cp_key_container(self.ika, container)
            if not unpacked["valid_complement"]:
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x2e\x31")
                return
            new_key = bytes.fromhex(unpacked["new_key_hex"])
            if did == 0x00BE and unpacked["key_type"] == BCM_CP_KEY_TYPE_IKA:
                self.ika = new_key
                self.ika_virgin = False
                self.gfa = b"\xff" * 16  # firmware rule: writing 00BE resets GFA to FF*16
                self._write_ram(int(self.profile["ika_working_addr"]), self.ika)
                self._write_ram(int(self.profile["gfa_working_addr"]), self.gfa)
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x6e\x00\xbe")
                return
            if did == 0x00BD and unpacked["key_type"] == BCM_CP_KEY_TYPE_GFA:
                if self.ika_virgin:
                    self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x2e\x22")
                    return
                self.gfa = new_key
                self.cp_mismatch = 0
                self._write_ram(int(self.profile["gfa_working_addr"]), self.gfa)
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x6e\x00\xbd")
                return
            self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x2e\x31")

    def _handle_wfs(self, pdu: bytes) -> None:
        if len(pdu) < 2 or pdu[0] != 0x80:
            return
        sub = pdu[1]
        if sub == 0x01 and len(pdu) == 18:
            # 1. Task 0x15 (`FUN_000ba180`) runs `queue[0]` (Job 3, priority 0x01) FIRST — BEFORE Job 5 (priority 0x0A)
            #    and BEFORE `FUN_000b8502` overwrites `NvM 0x02` (`ffb_nvm_key_addr`) or clears learned FFB slots!
            self._write_ram(int(self.profile["gfa_aes_buf"]), bcm_gfa_working_to_raw(self.gfa))
            self._write_ram(int(self.profile["last_round_key_addr"]), self.last_round_key)
            q0 = self._read_ram(int(self.profile["queue_base_addr"]), 8)
            j3_state_addr = int(self.profile["job3_state_addr"])
            j3_status = self._read_ram(j3_state_addr, 1)[0]
            if q0[:4] == b"\x03\x01\x01\x0a" and j3_status == 3:
                src_addr = int.from_bytes(q0[4:8], "big")
                src_plain = self._read_ram(src_addr, 16)
                final_block = bcm_aes128_ecb_decrypt(self.gfa, src_plain)
                # Real MPC5607B Crypto Job 3 writes the decrypted block in-place to src_addr!
                self._write_ram(src_addr, final_block)
                round9_state = _invert_final_round_for_sim(final_block, self.last_round_key)
                self._write_ram(j3_state_addr, b"\x01" + round9_state)

            # 2. Next, Job 5 finishes and `FUN_000b8502` overwrites `K_ffb` (`NvM 0x02`) and zeroes all FFB slots.
            self.k_ffb = bcm_aes128_ecb_decrypt(self.gfa, pdu[2:18])
            for s in range(1, 8):
                self.ffb_serials[s] = b"\x00" * 4
                self.ffb_counters[s] = b"\x00" * 4
                self.ffb_sync_states[s] = 0
            self.ffb_learned_mask = 0
            self.ffb_synced_mask = 0
            self._sync_ffb_ram_mirror()

            self._enqueue_isotp(BCM_WFS_RX_ID, b"\x7f\x80\x01\x78")
            self._enqueue_isotp(BCM_WFS_RX_ID, b"\xc0\x01")
            return

        if sub == 0x02 and len(pdu) >= 3:
            if pdu[2] == 0x00 and len(pdu) == 3:
                for s in range(1, 8):
                    self.ffb_serials[s] = b"\x00" * 4
                    self.ffb_counters[s] = b"\x00" * 4
                    self.ffb_sync_states[s] = 0
                self.ffb_learned_mask = 0
                self.ffb_synced_mask = 0
                self._sync_ffb_ram_mirror()
                self._enqueue_isotp(BCM_WFS_RX_ID, b"\x7f\x80\x02\x78")
                self._enqueue_isotp(BCM_WFS_RX_ID, b"\xc0\x02")
                return

            body = pdu[2:]
            if len(body) % 17 != 0:
                self._enqueue_isotp(BCM_WFS_RX_ID, b"\x7f\x80\x02\x13")
                return
            n_keys = len(body) // 17
            for idx in range(n_keys):
                entry = body[idx * 17 : (idx + 1) * 17]
                hdr = entry[0]
                slot = hdr & 0x0F
                cipher = entry[1:17]
                plain = bcm_aes128_ecb_decrypt(self.k_ffb, cipher)
                parsed = bcm_parse_ffb_key_plaintext(plain)
                # Real firmware 0x000C795E requires slot == idx + 1 sequentially (1..N)
                if slot != (idx + 1):
                    self._enqueue_isotp(BCM_WFS_RX_ID, b"\x7f\x80\x02\x31")
                    return
                if not parsed["crc_ok"]:
                    self._enqueue_isotp(BCM_WFS_RX_ID, b"\x7f\x80\x02\x35")
                    return
                if parsed["freq_code"] != self.freq_code:
                    self._enqueue_isotp(BCM_WFS_RX_ID, b"\x7f\x80\x02\x22")
                    return
                self.ffb_serials[slot] = bytes.fromhex(parsed["serial_be_hex"])
                self.ffb_counters[slot] = bytes.fromhex(parsed["counter_be_hex"])
                self.ffb_sync_states[slot] = 0
                self.ffb_learned_mask |= 1 << slot
                self.ffb_synced_mask |= 1 << slot
            self._sync_ffb_ram_mirror()
            self._enqueue_isotp(BCM_WFS_RX_ID, b"\x7f\x80\x02\x78")
            self._enqueue_isotp(BCM_WFS_RX_ID, b"\xc0\x02")

    def recv(self, timeout: float | None = None) -> can.Message | None:
        if self.rx_queue:
            return self.rx_queue.popleft()
        return None

    def shutdown(self) -> None:
        pass


def test_bcm_crypto_primitives_and_cp_containers() -> None:
    ika = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    gfa = bytes.fromhex("101112131415161718191a1b1c1d1e1f")

    # 1. Halfword raw <-> working GFA round-trip
    raw_gfa = bcm_gfa_working_to_raw(gfa)
    assert raw_gfa == bytes.fromhex("111013121514171619181b1a1d1c1f1e")
    assert bcm_gfa_raw_to_working(raw_gfa) == gfa

    # 2. Final-round reconstruction round-trip
    rk = bytes.fromhex("102030405060708090a0b0c0d0e0f001")
    final_blk = bcm_aes128_ecb_decrypt(gfa, ika)
    sim_state = _invert_final_round_for_sim(final_blk, rk)
    assert bcm_aes128_final_round(sim_state, rk) == final_blk
    rec = bcm_recover_ika_from_job3(sim_state, rk, gfa)
    assert rec["ika_hex"] == ika.hex()

    # 3. 2E 00BE (IKA) & 2E 00BD (GFA) 34-byte containers
    c_ika = bcm_build_cp_key_container(ika, ika, BCM_CP_KEY_TYPE_IKA)
    assert len(c_ika) == 34
    u_ika = bcm_unpack_cp_key_container(ika, c_ika)
    assert u_ika["valid_complement"] is True
    assert u_ika["new_key_hex"] == ika.hex()
    assert u_ika["key_type"] == BCM_CP_KEY_TYPE_IKA

    c_gfa = bcm_build_cp_key_container(ika, gfa, BCM_CP_KEY_TYPE_GFA)
    u_gfa = bcm_unpack_cp_key_container(ika, c_gfa)
    assert u_gfa["valid_complement"] is True
    assert u_gfa["new_key_hex"] == gfa.hex()
    assert u_gfa["key_type"] == BCM_CP_KEY_TYPE_GFA

    # 4. Application SecurityAccess 27 03 / 27 04
    assert bcm_compute_sa_key(0x00010000) == (0x00017A73).to_bytes(4, "big")


def test_bcm_wfs_ch3_ffb_key_synthesis_and_cluster_extraction() -> None:
    from test_fpke import build_synthetic_fpke_dflash

    dflash = build_synthetic_fpke_dflash()
    mat = bcm_extract_cluster_ffb_material(dflash, freq_code=0x02)
    assert len(mat["kc_hex"]) == 32
    assert len(mat["gfa_hex"]) == 32
    assert len(mat["k_ffb_hex"]) == 32
    assert mat["learned_keys"] >= 1
    assert len(mat["active_transponders"]) == mat["learned_keys"]

    k_ffb = bytes.fromhex(mat["k_ffb_hex"])
    for tp in mat["active_transponders"]:
        cipher = bytes.fromhex(tp["cipher_hex"])
        plain = bcm_aes128_ecb_decrypt(k_ffb, cipher)
        parsed = bcm_parse_ffb_key_plaintext(plain)
        assert parsed["crc_ok"] is True
        assert parsed["freq_code"] == 0x02
        assert parsed["display_id"] == tp["display_id"]


@pytest.mark.parametrize("profile_id", ["ea_0511", "dd_0273", "bq_0212", "bl_0175"])
def test_can_bcm_status_read_keys_write_keys_and_adapt_ffb(profile_id: str, tmp_path: Path, monkeypatch) -> None:
    from test_fpke import build_synthetic_fpke_dflash

    set_lang("ru")
    init_ika = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    init_gfa = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    bus = FakeBcmBus(profile_id=profile_id, ika=init_ika, gfa=init_gfa, freq_code=0x02)

    # 1. Pure UDS status poll
    st = can_bcm_status("fake", interface="slcan", bus=bus)
    assert st["profile"]["id"] == profile_id
    assert st["status"]["freq_code"] == 0x02
    assert st["status"]["cp_mismatch_counter"] == 0
    assert st["status"]["ika_virgin"] is False

    # 2. Keyless GFA read (WFS Job 5 + XCP SHORT_UPLOAD)
    gfa_res = can_bcm_read_gfa("fake", interface="slcan", bus=bus)
    assert gfa_res["gfa_working_hex"] == init_gfa.hex()
    assert gfa_res["flash_writes"] is False

    # 3. Keyless IKA + GFA read via two-stage WFS queue injection (also test via_gateway=True bridge)
    bridge_calls: list[str] = []

    class DummyBridge:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.bus = bus

        def __enter__(self) -> DummyBridge:
            bridge_calls.append("enter")
            return self

        def __exit__(self, *a: Any) -> None:
            bridge_calls.append("exit")

    monkeypatch.setattr("contitool.can.bridge.j533_can_bridge", lambda *a, **kw: DummyBridge(*a, **kw))

    keys_res = can_bcm_read_keys(
        "fake",
        interface="slcan",
        via_gateway=True,
        gateway_bridge=True,
        gateway_channel=0,
        output_dir=tmp_path / "bcm_out",
        bus=bus,
    )
    assert bridge_calls == ["enter", "exit"]
    assert keys_res["ika_hex"] == init_ika.hex()
    assert keys_res["gfa_working_hex"] == init_gfa.hex()
    assert (tmp_path / "bcm_out" / "bcm_keys.json").is_file()

    # 4. Write new IKA (2E 00BE) + new GFA (2E 00BD) over pure UDS (no bridge needed even when via_gateway=True!)
    bridge_calls.clear()
    new_ika = bytes.fromhex("0123456789abcdef0123456789abcdef")
    new_gfa = bytes.fromhex("fedcba9876543210fedcba9876543210")
    wr_res = can_bcm_write_keys(
        "fake",
        current_ika=init_ika.hex(),
        new_ika=new_ika.hex(),
        new_gfa=new_gfa.hex(),
        via_gateway=True,
        gateway_bridge=True,
        bus=bus,
    )
    assert bridge_calls == []  # pure UDS does not disrupt gateway with RAM bridge
    assert wr_res["ika_written"] is True
    assert wr_res["gfa_written"] is True
    assert bus.ika == new_ika
    assert bus.gfa == new_gfa

    # 5. Adapt FFB remote keys from instrument cluster DataFlash dump via stock WFS Ch 3 (80 01 + 80 02)
    fpke_df = build_synthetic_fpke_dflash()
    ffb_res = can_bcm_adapt_ffb_from_cluster(
        "fake",
        fpke_dflash=fpke_df,
        sync_bcm_gfa_to_cluster=True,
        current_bcm_ika=new_ika.hex(),
        via_gateway=True,
        gateway_bridge=True,
        bus=bus,
    )
    assert ffb_res["resp_80_01_hex"] == "c001"
    assert ffb_res["resp_80_02_hex"] == "c002"
    assert ffb_res["keys_adapted"] >= 1
    populated_slots = [s for s in ffb_res["status_after"]["ffb_slots"] if s["populated"]]
    assert len(populated_slots) == ffb_res["keys_adapted"]

    # 6. Clear all FFB remote key slots via 80 02 00
    clr_res = can_bcm_adapt_ffb(
        "fake",
        gfa=bus.gfa.hex(),
        k_ffb=ffb_res["k_ffb_hex"],
        clear_all=True,
        bus=bus,
    )
    assert clr_res["resp_80_02_hex"] == "c002"
    assert all(not s["populated"] for s in clr_res["status_after"]["ffb_slots"])


def test_gui_bcm_workspace_and_three_ecu_switching(
    synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    from contitool.can.ecus import can_scan_bus
    from contitool.gui.app import create_window
    from test_fpke import build_synthetic_extra_area, build_synthetic_fpke_dflash
    from test_gateway_bridge_and_bus_scan import FakeMultiEcuBus

    set_lang("ru")
    app, win = create_window()
    win.show()

    bus = FakeMultiEcuBus(has_j533=True, has_fpke=True, has_bcm=True)
    scan = can_scan_bus("fake", interface="slcan", bus=bus)
    win.bus_screen.set_scan_result(scan)

    # Load J533 + FPK_E dumps and open 09 BCM workspace simultaneously
    j533_dir = tmp_path / "j533"
    j533_dir.mkdir()
    (j533_dir / "Cflash.bin").write_bytes(synth_cflash)
    (j533_dir / "Dflash.bin").write_bytes(synth_dflash)
    (j533_dir / "Uflash.bin").write_bytes(synth_uflash)
    win.open_folder(str(j533_dir))

    fpke_dir = tmp_path / "fpke"
    fpke_dir.mkdir()
    (fpke_dir / "Dflash.bin").write_bytes(build_synthetic_fpke_dflash())
    (fpke_dir / "ExtraArea.bin").write_bytes(build_synthetic_extra_area())
    win.open_folder(str(fpke_dir))

    bcm_ecu = scan.find("bcm")
    assert bcm_ecu is not None
    win._on_bus_open_bcm_workspace(bcm_ecu)
    app.processEvents()

    assert win.bcm_screen.is_open is True
    assert win.stack.currentWidget() is win.bcm_screen
    assert win.ecu_switch_track.isVisible() is True
    assert win.btn_sw_j533.isVisible() is True
    assert win.btn_sw_fpke.isVisible() is True
    assert win.btn_sw_bcm.isVisible() is True

    # Navigate across all 4 pages of BcmScreen ("cp_keys", "ffb", "status", "dtc")
    for page_key in ("cp_keys", "status", "dtc", "ffb"):
        win.bcm_screen.select(page_key)
        app.processEvents()

    # On the FFB page, cluster K_c and GFA (/1) from the open 17 FPK_E workspace are automatically pre-populated!
    assert len(win.bcm_screen.ed_ffb_kc.text().strip()) == 32
    assert len(win.bcm_screen.ed_ffb_kffb.text().strip()) == 32

    # Switch between 19 J533, 17 FPK_E, and 09 BCM via header buttons
    win.btn_sw_j533.click()
    app.processEvents()
    assert win.stack.currentWidget() is win.ecu_screen

    win.btn_sw_bcm.click()
    app.processEvents()
    assert win.stack.currentWidget() is win.bcm_screen
    win.set_mode("terminal")
    app.processEvents()
    assert win.terminal.ed_tx.text() == "70E"
    assert win.terminal.ed_rx.text() == "778"

    win.close()


def test_cli_bcm_subcommand(monkeypatch, capsys, tmp_path: Path) -> None:
    import importlib

    cli_main = importlib.import_module("contitool.cli.main")
    ap = cli_main.build_arg_parser()

    ns = ap.parse_args(
        [
            "bcm",
            "read-keys",
            "--port",
            "COM4",
            "--via-gateway",
            "--profile",
            "ea_0511",
            "-o",
            str(tmp_path / "keys.json"),
        ]
    )
    assert ns.bcm_action == "read-keys"
    assert ns.via_gateway is True
    assert ns.profile == "ea_0511"

    bus = FakeBcmBus(profile_id="ea_0511")

    class DummyBridge:
        def __init__(self, *a: Any, **kw: Any) -> None:
            self.bus = bus

        def __enter__(self) -> DummyBridge:
            return self

        def __exit__(self, *a: Any) -> None:
            pass

    monkeypatch.setattr("contitool.can.bridge.j533_can_bridge", lambda *a, **kw: DummyBridge(*a, **kw))
    rc = cli_main.cmd_bcm(ns)
    assert rc == 0
    out = capsys.readouterr().out
    assert bus.ika.hex() in out
    assert bus.gfa.hex() in out
    assert (tmp_path / "keys.json").is_file()


def test_bcm_odis_dtc_decoding_and_real_hw_status_dids() -> None:
    from contitool.can.ecus import can_uds_read_dtc
    from contitool.core import dtc

    # 1. ODIS RU/EN BCM DTC decoding
    set_lang("ru")
    disp_cp, desc_cp = dtc.describe_bcm(0xEA6400)
    assert disp_cp == "U110100"
    assert "Защита компонентов активна" in desc_cp

    disp_b, desc_b = dtc.describe_bcm(0x001A0A)
    assert disp_b == "B121715"
    assert "ближнего света" in desc_b.lower()

    disp_esp, desc_esp = dtc.describe_bcm(0x081215)
    assert disp_esp == "U112100"
    assert "ESP_21" in desc_esp

    set_lang("en")
    disp_cp_en, desc_cp_en = dtc.describe_bcm(0xEA6400)
    assert disp_cp_en == "U110100"
    assert "Component protection active" in desc_cp_en

    # 2. Live UDS 19 02 decode via can_uds_read_dtc(..., ecu_kind="bcm")
    set_lang("ru")
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    res = can_uds_read_dtc("fake", BCM_UDS_TX_ID, BCM_UDS_RX_ID, ecu_kind="bcm", bus=bus)
    assert len(res["dtcs"]) == 3
    assert res["dtcs"][0]["display"] == "U110100"
    assert res["dtcs"][0]["code"] == "0xEA6400"
    assert res["dtcs"][0]["status"] == "0x09"
    assert "Защита компонентов" in res["dtcs"][0]["description"]
    assert res["dtcs"][2]["display"] == "U112100"
    assert "ESP_21" in res["dtcs"][2]["description"]

    # 3. Exact real 5Q0937084EA DID 0x0A65 (77 D4 02 00 00 00 00 -> 434.42 MHz) & DID 0x1983 (FF 03 FF DF -> 0 keys)
    decoded = bcm_decode_status_dids(
        {
            0x0A65: bytes.fromhex("77d40200000000"),
            0x1983: bytes.fromhex("ff03ffdf"),
            0x03DE: bytes.fromhex("0015"),
            0x0440: bytes.fromhex("02010204001200"),
        }
    )
    assert decoded["freq_code"] == 0x03
    assert decoded["freq_label"] == "434.42 MHz"
    assert decoded["ffb_learned_count"] == 0
    assert decoded["ffb_active_slot"] == 0xFF
    assert decoded["ffb_buttons"] == 0x03
    assert decoded["cp_mismatch_counter"] == 0x15
    assert decoded["cp_active_fault"] is False
    assert decoded["ika_virgin"] is False


def test_gui_bcm_dtc_and_learned_ffb_rendering() -> None:
    from PySide6.QtWidgets import QLabel

    from contitool.can.ecus import can_uds_read_dtc
    from contitool.gui.app import create_window

    set_lang("ru")
    app, win = create_window()
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    bus.ffb_serials[1] = bytes.fromhex("532B3512")
    bus.ffb_counters[1] = (1428).to_bytes(4, "big")
    bus.ffb_learned_mask = 1 << 1
    bus.ffb_synced_mask = 1 << 1

    st = can_bcm_status("fake", interface="slcan", bus=bus)
    dtc_res = can_uds_read_dtc("fake", BCM_UDS_TX_ID, BCM_UDS_RX_ID, ecu_kind="bcm", bus=bus)

    win.bcm_screen.open_from_discovered(None)
    win.bcm_screen._on_status_read(st)
    win.bcm_screen._on_dtc_read(dtc_res)

    # Check DTC page renders real ODIS display code, raw UDS hex, status, and Russian description
    win.bcm_screen.select("dtc")
    app.processEvents()
    dtc_texts = " ".join(lbl.text() for lbl in win.bcm_screen.page_area.findChildren(QLabel))
    assert "U110100" in dtc_texts
    assert "0xEA6400" in dtc_texts
    assert "0x09" in dtc_texts
    assert "Защита компонентов активна" in dtc_texts
    assert "B121715" in dtc_texts
    assert "ESP_21" in dtc_texts
    assert "Код неисправности UDS" not in dtc_texts

    # Check FFB page automatically pre-populates learned BCM keys & Rolling Counter without extra button clicks
    win.bcm_screen.select("ffb")
    app.processEvents()
    ffb_texts = " ".join(lbl.text() for lbl in win.bcm_screen.page_area.findChildren(QLabel))
    assert "434.42 MHz" in ffb_texts
    assert "Rolling Counter" in ffb_texts
    assert win.bcm_screen._draft_ffb_rows[0]["serial"] == "532B3512"
    assert win.bcm_screen._draft_ffb_rows[0]["counter"] == 1428
    assert win.bcm_screen._draft_ffb_rows[0]["source"] == "bcm"

    # Verify repeated IKA reads return identical deterministic IKA, while default `can_bcm_read_all` does NOT read keys
    from contitool.can.bcm import can_bcm_read_all

    bus.k_ffb = bytes.fromhex("5566778899aabbccddeeff0011223344")
    bus._sync_ffb_ram_mirror()
    r1 = can_bcm_read_keys("fake", interface="slcan", bus=bus)
    r2 = can_bcm_read_keys("fake", interface="slcan", bus=bus)
    r_default = can_bcm_read_all("fake", interface="slcan", bus=bus)
    r3 = can_bcm_read_all("fake", interface="slcan", bus=bus, include_keys=True)
    assert r1["ika_hex"] == bus.ika.hex()
    assert r2["ika_hex"] == bus.ika.hex()
    assert r_default["ika_hex"] == ""
    assert r_default["gfa_working_hex"] == ""
    assert len(r_default["dtcs"]) == 3
    assert r3["ika_hex"] == bus.ika.hex()
    assert len(r3["dtcs"]) == 3
    # Pre-existing K_ffb and learned slot #1 must survive all keyless reads!
    assert bus.k_ffb == bytes.fromhex("5566778899aabbccddeeff0011223344")
    assert bus.ffb_serials[1] == bytes.fromhex("532B3512")
    assert bus.ffb_counters[1] == (1428).to_bytes(4, "big")

    win.close()


@pytest.mark.parametrize("profile_id", ["ea_0511", "dd_0273", "bq_0212", "bl_0175"])
def test_bcm_keyless_reads_preserve_existing_k_ffb_and_learned_ffb_keys(profile_id: str) -> None:
    from contitool.can.bcm import can_bcm_read_all

    orig_ika = bytes.fromhex("1234567890abcdef1234567890abcdef")
    orig_gfa = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    orig_k_ffb = bytes.fromhex("cafebabefeedface0123456789abcdef")
    bus = FakeBcmBus(profile_id=profile_id, ika=orig_ika, gfa=orig_gfa, freq_code=0x03)
    bus.k_ffb = orig_k_ffb
    bus.ffb_serials[1] = bytes.fromhex("532B3512")
    bus.ffb_counters[1] = (1428).to_bytes(4, "big")
    bus.ffb_serials[2] = bytes.fromhex("A1B2C3D4")
    bus.ffb_counters[2] = (98765).to_bytes(4, "big")
    bus.ffb_learned_mask = (1 << 1) | (1 << 2)
    bus.ffb_synced_mask = (1 << 1) | (1 << 2)
    bus._sync_ffb_ram_mirror()

    # 1. Keyless GFA read must NOT wipe K_ffb or either learned FFB slot
    res_gfa = can_bcm_read_gfa("fake", interface="slcan", bus=bus)
    assert res_gfa["gfa_working_hex"] == orig_gfa.hex()
    assert bus.k_ffb == orig_k_ffb
    assert bus.ffb_serials[1] == bytes.fromhex("532B3512")
    assert bus.ffb_counters[1] == (1428).to_bytes(4, "big")
    assert bus.ffb_serials[2] == bytes.fromhex("A1B2C3D4")
    assert bus.ffb_counters[2] == (98765).to_bytes(4, "big")
    assert res_gfa["status"]["ffb_learned_count"] == 2

    # 2. Keyless IKA + GFA read must return deterministic keys AND preserve both FFB slots + counters
    res_keys = can_bcm_read_keys("fake", interface="slcan", bus=bus)
    assert res_keys["ika_hex"] == orig_ika.hex()
    assert res_keys["gfa_working_hex"] == orig_gfa.hex()
    assert bus.k_ffb == orig_k_ffb
    assert bus.ffb_serials[1] == bytes.fromhex("532B3512")
    assert bus.ffb_counters[1] == (1428).to_bytes(4, "big")
    assert bus.ffb_serials[2] == bytes.fromhex("A1B2C3D4")
    assert bus.ffb_counters[2] == (98765).to_bytes(4, "big")

    # 3. Default `can_bcm_read_all()` does NOT touch IKA/GFA, while `include_keys=True` reads & preserves everything
    res_passive = can_bcm_read_all("fake", interface="slcan", bus=bus)
    assert res_passive["ika_hex"] == ""
    assert res_passive["gfa_working_hex"] == ""
    pop_passive = [s for s in res_passive["status"]["ffb_slots"] if s["populated"]]
    assert [(s["display_id"], s["rolling_counter"]) for s in pop_passive] == [("532B3512", 1428), ("A1B2C3D4", 98765)]

    res_all = can_bcm_read_all("fake", interface="slcan", bus=bus, include_keys=True)
    assert res_all["ika_hex"] == orig_ika.hex()
    assert res_all["gfa_working_hex"] == orig_gfa.hex()
    pop = [s for s in res_all["status"]["ffb_slots"] if s["populated"]]
    assert [(s["display_id"], s["rolling_counter"]) for s in pop] == [("532B3512", 1428), ("A1B2C3D4", 98765)]
    assert bus.k_ffb == orig_k_ffb

    # 4. If 10 4F Dev Session is rejected (NRC 0x22), passive `can_bcm_read_all()` still populates FFB slots via XCP RAM mirror
    bus.allow_dev_session = False
    res_xcp_fb = can_bcm_read_all("fake", interface="slcan", bus=bus)
    assert res_xcp_fb["ika_hex"] == ""
    pop_fb = [s for s in res_xcp_fb["status"]["ffb_slots"] if s["populated"]]
    assert [(s["display_id"], s["rolling_counter"]) for s in pop_fb] == [("532B3512", 1428), ("A1B2C3D4", 98765)]


def test_bcm_ffb_zero_counter_and_serial_nvm_mapping() -> None:
    """Verify NvM 0x13..0x19 = Serial IDs and NvM 0x05..0x0B = Rolling Counters (including counter == 0)."""
    from contitool.can.bcm import can_bcm_read_all

    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    kc = bytes.fromhex("459E1F01A61C337B9216A35319A12AD9")
    res = can_bcm_adapt_ffb(
        "fake",
        gfa=bus.gfa,
        kc=kc,
        keys=[
            {"slot_number": 1, "serial_id": "532B3512", "rolling_counter": 0},
            {"slot_number": 2, "serial_id": "A1B2C3D4", "rolling_counter": 0},
        ],
        freq_code=0x02,  # deliberately mismatched -> must auto-sync with live DID 0x0A65 (0x03)
        interface="slcan",
        bus=bus,
    )
    assert res["keys_adapted"] == 2
    assert res["freq_code"] == 0x03
    pop_after = [s for s in res["status_after"]["ffb_slots"] if s["populated"]]
    assert [(s["display_id"], s["rolling_counter"]) for s in pop_after] == [("532B3512", 0), ("A1B2C3D4", 0)]
    # Verify RAM mirror placement on EA/0511: 0x40005D34 = Serials, 0x40005D50 = Counters
    assert bus._read_ram(0x40005D34, 8) == bytes.fromhex("532B3512A1B2C3D4")
    assert bus._read_ram(0x40005D50, 8) == bytes(8)

    # Re-connect / restart (`can_bcm_read_all`) must keep both zero-counter keys intact!
    res_restart = can_bcm_read_all("fake", interface="slcan", bus=bus)
    pop_restart = [s for s in res_restart["status"]["ffb_slots"] if s["populated"]]
    assert [(s["display_id"], s["rolling_counter"]) for s in pop_restart] == [("532B3512", 0), ("A1B2C3D4", 0)]
    assert bus._read_ram(0x40005D34, 8) == bytes.fromhex("532B3512A1B2C3D4")
    assert bus._read_ram(0x40005D50, 8) == bytes(8)


def test_gui_direct_bcm_flow_skips_topology_and_confirms_before_ika_gfa_read(monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QLabel

    from contitool.can.bcm import can_bcm_read_all as real_read_all, can_bcm_read_keys as real_read_keys
    from contitool.can.ecus import can_scan_bus as real_scan
    from contitool.gui import main_window
    from contitool.gui.app import create_window
    from contitool.gui.screens import bcm as bcm_screen_mod

    set_lang("ru")
    app, win = create_window()
    win.show()

    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    bus.ffb_serials[1] = bytes.fromhex("532B3512")
    bus.ffb_counters[1] = (10).to_bytes(4, "big")
    bus.ffb_learned_mask = 1 << 1
    bus.ffb_synced_mask = 1 << 1
    bus._sync_ffb_ram_mirror()

    monkeypatch.setattr(main_window, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(bcm_screen_mod, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(
        main_window,
        "can_scan_bus",
        lambda port, *, interface="slcan", target_kind=None, reporter=None: real_scan(
            port, interface=interface, target_kind=target_kind, bus=bus, reporter=reporter
        ),
    )
    monkeypatch.setattr(
        main_window,
        "can_bcm_read_all",
        lambda port, **kw: real_read_all(port, bus=bus, **{k: v for k, v in kw.items() if k != "bus"}),
    )
    monkeypatch.setattr(
        bcm_screen_mod,
        "can_bcm_read_keys",
        lambda port, **kw: real_read_keys(port, bus=bus, **{k: v for k, v in kw.items() if k != "bus"}),
    )

    # 1. Selecting a specific block ("bcm") hides bus topology & scan button, showing primary "Считать 09 BCM"
    win.start_screen.set_target_kind("bcm")
    app.processEvents()
    assert win.start_screen.diagram.isVisible() is False
    assert win.start_screen.btn_scan.isVisible() is False
    assert win.start_screen.btn_read.isVisible() is True
    assert "09 BCM" in win.start_screen.btn_read.text()

    # 2. Clicking "Считать 09 BCM" shows EcuFoundDialog first, then reads UDS data (without IKA/GFA) and opens page 1
    seen_found_dialogs: list[str] = []

    def _accept_found_dlg(dlg) -> bool:
        seen_found_dialogs.append(" ".join(lbl.text() for lbl in dlg.findChildren(QLabel)))
        return True

    monkeypatch.setattr(main_window, "run_dialog", _accept_found_dlg)

    loop = QEventLoop()
    win.bcm_screen.changed.connect(loop.quit)
    QTimer.singleShot(4000, loop.quit)
    win.start_screen.btn_read.click()
    loop.exec()
    for _ in range(10):
        app.processEvents()

    assert len(seen_found_dialogs) == 1
    assert "5Q0937084EA" in seen_found_dialogs[0]
    assert win.stack.currentWidget() is win.bcm_screen
    assert win.bcm_screen._key == "cp_keys"
    assert win.tab_bus.isVisible() is False
    # By default IKA and GFA are NOT read on initial connect!
    assert win.bcm_screen._ika_hex == ""
    assert win.bcm_screen._gfa_hex == ""
    assert win.bcm_screen._draft_ffb_rows[0]["serial"] == "532B3512"

    # 3. Clicking "Считать IKA + GFA" shows BcmReadKeysDialog with CP & FFB info; cancelling does NOT read keys
    seen_key_dialogs: list[str] = []
    monkeypatch.setattr(
        bcm_screen_mod,
        "run_dialog",
        lambda dlg: (seen_key_dialogs.append(" ".join(lbl.text() for lbl in dlg.findChildren(QLabel))) or False),
    )
    win.bcm_screen.action_read_keys()
    assert len(seen_key_dialogs) == 1
    assert "SAFE CP" in seen_key_dialogs[0]
    assert "хендшейк" in seen_key_dialogs[0]
    assert "Радиоключи FFB" in seen_key_dialogs[0]
    assert win.bcm_screen._ika_hex == ""

    # Accepting BcmReadKeysDialog reads IKA + GFA and preserves learned FFB keys
    monkeypatch.setattr(bcm_screen_mod, "run_dialog", lambda _dlg: True)
    loop2 = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop2.quit())
    QTimer.singleShot(4000, loop2.quit)
    win.bcm_screen.action_read_keys()
    loop2.exec()
    for _ in range(10):
        app.processEvents()

    assert win.bcm_screen._ika_hex == bus.ika.hex()
    assert win.bcm_screen._gfa_hex == bus.gfa.hex()
    assert bus.ffb_serials[1] == bytes.fromhex("532B3512")

    win.close()


def test_bcm_adapt_ffb_from_live_cluster_verifies_cluster_presence_on_can() -> None:
    set_lang("ru")
    bcm_only_bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    with pytest.raises(RuntimeError, match="Панель приборов 17 FPK_E"):
        can_bcm_adapt_ffb_from_cluster(
            "fake",
            fpke_dflash=None,
            interface="slcan",
            bus=bcm_only_bus,
        )


def test_bcm_unknown_sw_refuses_xcp_reads_and_protects_ffb(monkeypatch) -> None:
    set_lang("en")

    class UnknownSwBcmBus(FakeBcmBus):
        def _handle_uds(self, payload: bytes) -> None:
            if payload[:3] == b"\x22\xf1\x87":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x87" + b"5Q0937084CP ")
                return
            if payload[:3] == b"\x22\xf1\x91":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x91" + b"5Q0937084CP ")
                return
            if payload[:3] == b"\x22\xf1\x89":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x89" + b"0253")
                return
            super()._handle_uds(payload)

    bus = UnknownSwBcmBus(profile_id="ea_0511", freq_code=0x03)
    bus.ffb_serials[1] = bytes.fromhex("532B3512")

    with pytest.raises(RuntimeError, match="Unsupported 09 BCM firmware"):
        can_bcm_read_keys("fake", interface="slcan", bus=bus)
    with pytest.raises(RuntimeError, match="Unsupported 09 BCM firmware"):
        can_bcm_read_gfa("fake", interface="slcan", bus=bus)

    # Also verify via_gateway=True + gateway_bridge=True fails fast over normal UDS BEFORE launching j533_can_bridge!
    bridge_calls: list[str] = []

    def _forbid_bridge(*_a: Any, **_kw: Any) -> Any:
        bridge_calls.append("called")
        raise AssertionError("j533_can_bridge must not be entered for unsupported BCM SW")

    monkeypatch.setattr("contitool.can.bridge.j533_can_bridge", _forbid_bridge)
    with pytest.raises(RuntimeError, match="Unsupported 09 BCM firmware"):
        can_bcm_read_keys("fake", interface="slcan", via_gateway=True, gateway_bridge=True, bus=bus)
    with pytest.raises(RuntimeError, match="Unsupported 09 BCM firmware"):
        can_bcm_read_gfa("fake", interface="slcan", via_gateway=True, gateway_bridge=True, bus=bus)
    assert bridge_calls == []

    # Verified SW 0173, 0175 (5Q0937084BL / CJ), and 0212 (5Q0937084BQ) match bl_0175 and bq_0212
    assert bcm_detect_profile({"part_number": "5Q0937084BL", "sw_version": "0173"})["id"] == "bl_0175"
    assert bcm_detect_profile({"part_number": "5Q0937084BL", "sw_version": "0175"})["id"] == "bl_0175"
    assert bcm_detect_profile({"part_number": "5Q0937084CJ", "sw_version": "0175"})["id"] == "bl_0175"
    assert bcm_detect_profile({"part_number": "5Q0937084BQ", "sw_version": "0212"})["id"] == "bq_0212"

    # Learned FFB key must NEVER have been wiped by 80 01
    assert bus.ffb_serials[1] == bytes.fromhex("532B3512")


def test_bcm_pass2_failure_restores_ffb_and_persists_backup(monkeypatch, tmp_path) -> None:
    from contitool.can import bcm as bcm_can_mod

    set_lang("en")
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    bus.nvm_read_blocked = True  # force 2-pass Job 3 read (Pass 1 reads K_ffb, Pass 2 reads IKA)
    bus.k_ffb = bytes.fromhex("5566778899aabbccddeeff0011223344")
    bus.ffb_serials[1] = bytes.fromhex("532B3512")
    bus._sync_ffb_ram_mirror()
    orig_kffb = bytes(bus.k_ffb)

    real_job3 = bcm_can_mod._read_bcm_job3_target_in_session
    calls = {"n": 0}

    def _fail_second_pass(link, profile, *, target_addr, trigger_80_01_pdu=None):
        calls["n"] += 1
        if calls["n"] == 2:
            # Simulate failure right after Pass 1's HardReset zeroed gfa_aes_buf
            bus.gfa_aes_buf = bytes(16)
            raise TimeoutError("simulated pass-2 timeout")
        return real_job3(link, profile, target_addr=target_addr, trigger_80_01_pdu=trigger_80_01_pdu)

    monkeypatch.setattr(bcm_can_mod, "_read_bcm_job3_target_in_session", _fail_second_pass)
    with pytest.raises(TimeoutError, match="simulated pass-2 timeout"):
        can_bcm_read_keys("fake", interface="slcan", bus=bus, output_dir=tmp_path)

    # Backup JSON must exist on disk AND FFB key + K_ffb must be restored using Pass 1's GFA!
    assert (tmp_path / "bcm_ffb_backup.json").is_file()
    assert bus.k_ffb == orig_kffb
    assert bus.ffb_serials[1] == bytes.fromhex("532B3512")


def test_bcm_adapt_ffb_from_cluster_refuses_before_writing_gfa_without_bridge() -> None:
    from test_fpke import build_synthetic_fpke_dflash

    set_lang("en")
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    orig_gfa = bytes(bus.gfa)
    df = build_synthetic_fpke_dflash()

    with pytest.raises(RuntimeError, match="Aborted before modifying GFA"):
        can_bcm_adapt_ffb_from_cluster(
            "fake",
            fpke_dflash=df,
            sync_bcm_gfa_to_cluster=True,
            current_bcm_ika=bus.ika,
            interface="slcan",
            via_gateway=True,
            gateway_bridge=False,
            bus=bus,
        )
    assert bus.gfa == orig_gfa


def test_bcm_write_keys_partial_failure_surfaces_new_ika() -> None:
    set_lang("en")

    class Fail00BdBus(FakeBcmBus):
        def _handle_uds(self, payload: bytes) -> None:
            if payload[:3] == b"\x2e\x00\xbd":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x7f\x2e\x22")
                return
            super()._handle_uds(payload)

    bus = Fail00BdBus(profile_id="ea_0511", freq_code=0x03)
    new_ika = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
    new_gfa = bytes.fromhex("102030405060708090a0b0c0d0e0f001")
    with pytest.raises(RuntimeError, match=new_ika.hex().upper()):
        can_bcm_write_keys(
            "fake",
            current_ika=bus.ika,
            new_ika=new_ika,
            new_gfa=new_gfa,
            interface="slcan",
            bus=bus,
        )


def test_bcm_h15_non_sequential_key_number_normalized(monkeypatch) -> None:
    """H15: gaps in EEL 0x6A / key_ids must be renumbered sequentially 1..N so 80 02 never triggers NRC 0x31."""
    from contitool.core import bcm as bcm_core_mod

    kc = bytes.fromhex("459E1F01A61C337B9216A35319A12AD9")
    gfa = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    k_ffb = bcm_derive_k_ffb(kc)
    c1 = bcm_encrypt_ffb_key_record(k_ffb, 0x11223344, rolling_counter=10, freq_code=0x03)
    c3 = bcm_encrypt_ffb_key_record(k_ffb, 0x55667788, rolling_counter=25, freq_code=0x03)
    c5 = bcm_encrypt_ffb_key_record(k_ffb, 0x99AABBCC, rolling_counter=40, freq_code=0x03)

    fake_analysis = {
        "metadata": {"part_number": "83A920700E", "vin": "WAUZZZ00000000001", "immo_mode": 6},
        "items": [
            {"key_id": "kc", "hex": kc.hex()},
            {"key_id": "cp1_bank_0", "hex": gfa.hex()},
            {"key_id": "ika_cp3", "hex": "11" * 16},
        ],
        "transponder_records": {
            "learned_keys": 3,
            "allowed_keys": 7,
            "entries": [
                {"slot": 4, "key_number": 5, "usable": True, "hex": c5.hex()},
                {"slot": 1, "key_number": 2, "usable": False, "hex": "ff" * 16},
                {"slot": 0, "key_number": 1, "usable": True, "hex": c1.hex()},
                {"slot": 2, "key_number": 3, "usable": True, "hex": c3.hex()},
            ],
            "key_ids": [
                {"present": False, "within_learned_count": False, "hex": "00000000"},
                {"present": True, "within_learned_count": True, "hex": (0x11223344).to_bytes(4, "little").hex()},
                {"present": False, "within_learned_count": False, "hex": "00000000"},
                {"present": True, "within_learned_count": True, "hex": (0x55667788).to_bytes(4, "little").hex()},
            ],
        },
    }
    monkeypatch.setattr(bcm_core_mod, "analyze_fpke_dflash", lambda *_a, **_kw: fake_analysis)

    mat = bcm_extract_cluster_ffb_material(b"\x00" * 64, freq_code=0x03)
    assert mat["raw_6a_matches_freq"] is True
    assert [s for s, _c in mat["recommended_entries"]] == [1, 2, 3]
    assert [c for _s, c in mat["recommended_entries"]] == [c1.hex(), c3.hex(), c5.hex()]
    assert [t["slot_number"] for t in mat["active_transponders"]] == [1, 2]

    # Direct can_bcm_adapt_ffb with non-sequential entries (and an empty entry) must renumber 1..3 and succeed on BCM
    bus = FakeBcmBus(profile_id="ea_0511", gfa=gfa, freq_code=0x03)
    res = can_bcm_adapt_ffb(
        "fake",
        gfa=gfa,
        k_ffb=k_ffb,
        entries=[(1, c1), (2, b""), (3, c3), (5, c5)],
        freq_code=0x03,
        interface="slcan",
        bus=bus,
    )
    assert res["resp_80_02_hex"] == "c002"
    assert res["keys_adapted"] == 3
    pop = [s for s in res["status_after"]["ffb_slots"] if s["populated"]]
    assert [s["display_id"] for s in pop] == ["11223344", "55667788", "99AABBCC"]


def test_bcm_m6b_nvm_03_single_byte_slot_mask_decoded() -> None:
    """M6b: NvM 0x03 is 1 byte (slot_mask_learned in byte 0), not >= 4 bytes."""
    decoded = bcm_decode_status_dids(
        {},
        nvm_slots={
            1: (bytes.fromhex("532B3512"), (12).to_bytes(4, "big"), b"\x00"),
            2: (bytes.fromhex("00000000"), bytes(4), b"\x00"),
            3: (bytes.fromhex("A1B2C3D4"), (99).to_bytes(4, "big"), b"\x00"),
        },
        nvm_meta={"nvm_03": bytes([(1 << 1) | (1 << 3)])},
    )
    assert decoded["slot_mask_learned"] == 0x0A
    by_slot = {s["slot"]: s for s in decoded["ffb_slots"]}
    assert by_slot[1]["mask_learned"] is True
    assert by_slot[2]["mask_learned"] is False
    assert by_slot[3]["mask_learned"] is True

    # Also verify live status poll against FakeBcmBus (which serves 1-byte NvM 0x03)
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    bus.ffb_serials[1] = bytes.fromhex("532B3512")
    bus.ffb_learned_mask = (1 << 1) | (1 << 2)
    st = can_bcm_status("fake", interface="slcan", bus=bus)
    assert st["status"]["slot_mask_learned"] == 0x06


def test_bcm_m5c_isotp_cf_seq_xcp_short_resp_and_wfs_78_cap() -> None:
    """M5c: reject out-of-sequence/short CFs, short XCP responses, and unbounded WFS 0x78 loops."""
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    with BcmCanLink("fake", bus=bus) as link:
        # 1. Out-of-sequence CF (SN=2 instead of expected SN=1)
        bus.rx_queue.clear()
        bus._enqueue_frame(BCM_UDS_RX_ID, b"\x10\x10" + b"\x62\xf1\x87\x35\x51\x30")
        bus._enqueue_frame(BCM_UDS_RX_ID, b"\x22" + b"937084E")
        with pytest.raises(RuntimeError, match="sequence"):
            link.receive_isotp_channel(BCM_UDS_TX_ID, BCM_UDS_RX_ID, timeout=0.5)

        # 2. Truncated CF (shorter than required remaining bytes)
        bus.rx_queue.clear()
        bus.rx_queue.append(
            can.Message(arbitration_id=BCM_UDS_RX_ID, data=b"\x10\x0b\x62\xf1\x87\x35\x51\x30", is_extended_id=False)
        )
        bus.rx_queue.append(
            can.Message(arbitration_id=BCM_UDS_RX_ID, data=b"\x21\x39\x33", is_extended_id=False)
        )
        with pytest.raises(RuntimeError, match="Truncated"):
            link.receive_isotp_channel(BCM_UDS_TX_ID, BCM_UDS_RX_ID, timeout=0.5)

        # 3. Malformed SingleFrame (sf_len exceeds actual frame bytes)
        bus.rx_queue.clear()
        bus.rx_queue.append(
            can.Message(arbitration_id=BCM_UDS_RX_ID, data=b"\x07\x62\xf1", is_extended_id=False)
        )
        with pytest.raises(RuntimeError, match="Malformed"):
            link.receive_isotp_channel(BCM_UDS_TX_ID, BCM_UDS_RX_ID, timeout=0.5)

        # 4. Short XCP SHORT_UPLOAD response (< 1 + chunk_len)
        class ShortXcpBus(FakeBcmBus):
            def send(self, msg: can.Message, timeout: float | None = None) -> None:
                if msg.arbitration_id == int(self.profile["xcp_tx_id"]) and msg.data[0] == 0xF4:
                    self.rx_queue.append(
                        can.Message(arbitration_id=int(self.profile["xcp_rx_id"]), data=b"\xff\xaa\xbb", is_extended_id=True)
                    )
                    return
                super().send(msg, timeout=timeout)

        short_bus = ShortXcpBus(profile_id="ea_0511")
        with BcmCanLink("fake", bus=short_bus) as short_link:
            with pytest.raises(RuntimeError, match="Short XCP SHORT_UPLOAD"):
                short_link.xcp_read_memory(0x40000000, 4, timeout=0.5)

        # 5. Stuck WFS 7F 80 01 78 ResponsePending loop bounded by max_pending_retries
        class StuckWfsBus(FakeBcmBus):
            def _handle_wfs(self, pdu: bytes) -> None:
                for _ in range(10):
                    self._enqueue_isotp(BCM_WFS_RX_ID, b"\x7f\x80\x01\x78")

        stuck_bus = StuckWfsBus(profile_id="ea_0511")
        with BcmCanLink("fake", bus=stuck_bus) as stuck_link:
            with pytest.raises(TimeoutError, match="0x78"):
                stuck_link.request_wfs(b"\x80\x01" + bytes(16), timeout=0.5, max_pending_retries=3)


def test_bcm_passport_f197_f19e_distinct_and_empty_bytes_key_handling() -> None:
    """LOW: keep 0xF197 (system_name) and 0xF19E (asam_odx) distinct, and treat empty b'' key inputs as None."""
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    st = can_bcm_status("fake", interface="slcan", bus=bus)
    assert st["passport"]["system_name"] == "BCM MQBAB H"
    assert st["passport"]["asam_odx"] == "EV_BCMMQB"

    new_gfa = bytes.fromhex("102030405060708090a0b0c0d0e0f001")
    wr = can_bcm_write_keys(
        "fake",
        current_ika=bus.ika,
        new_ika=b"",
        new_gfa=new_gfa,
        interface="slcan",
        bus=bus,
    )
    assert wr["ika_written"] is False
    assert wr["gfa_written"] is True
    assert bus.gfa == new_gfa

    with pytest.raises(ValueError, match="At least one of new_ika or new_gfa"):
        can_bcm_write_keys("fake", current_ika=bus.ika, new_ika=b"", new_gfa=b"", interface="slcan", bus=bus)


def test_bcm_h4_dpdu_uds_session_and_29bit_warning() -> None:
    """H4: route UDS through DPduBus.uds_session(0x70E, 0x778) on uds_only/nonraw and warn on dpdu 29-bit ops."""
    import contextlib
    from contitool.progress import OperationReporter

    set_lang("en")
    inner = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)

    class FakeDpduBcmBus:
        def __init__(self, *, uds_only: bool = False, nonraw: dict[int, int] | None = None) -> None:
            self.uds_only = uds_only
            self.nonraw = dict(nonraw or {})
            self.spent = False
            self.session_calls: list[tuple[int, int]] = []
            self.uds_requests: list[bytes] = []
            self.raw_sends: list[int] = []

        @contextlib.contextmanager
        def uds_session(self, tx_id: int = 0x710, rx_id: int = 0x77A):
            self.session_calls.append((tx_id, rx_id))
            yield True

        def end_uds_session(self) -> None:
            pass

        def request_uds(self, req: bytes, *, timeout: float = 2.0, allow_pending: bool = True) -> bytes:
            self.uds_requests.append(bytes(req))
            inner.rx_queue.clear()
            inner._handle_uds(bytes(req))
            # Reassemble ISO-TP response enqueued by FakeBcmBus
            first = inner.rx_queue.popleft()
            raw0 = bytes(first.data)
            kind = raw0[0] >> 4
            if kind == 0:
                return raw0[1 : 1 + (raw0[0] & 0x0F)]
            total = ((raw0[0] & 0x0F) << 8) | raw0[1]
            out = bytearray(raw0[2:])
            while len(out) < total:
                out.extend(bytes(inner.rx_queue.popleft().data)[1:])
            return bytes(out[:total])

        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            self.raw_sends.append(msg.arbitration_id)
            raise AssertionError("Raw send should not be used when uds_session is active")

        def recv(self, timeout: float | None = None) -> can.Message | None:
            return None

        def shutdown(self) -> None:
            pass

    dpdu_bus = FakeDpduBcmBus(uds_only=True)
    st = can_bcm_status("fake", interface="dpdu", bus=dpdu_bus)
    assert dpdu_bus.session_calls == [(BCM_UDS_TX_ID, BCM_UDS_RX_ID)]
    assert len(dpdu_bus.uds_requests) > 0
    assert dpdu_bus.raw_sends == []
    assert st["passport"]["part_number"] == "5Q0937084EA"

    # Direct BcmCanLink on nonraw D-PDU bus also routes via uds_session(0x70E, 0x778)
    nonraw_bus = FakeDpduBcmBus(nonraw={0x710: 1})
    with BcmCanLink("fake", interface="dpdu", bus=nonraw_bus) as link:
        resp = link.request_uds(b"\x10\x03", 0x50)
        assert resp[0] == 0x50
    assert nonraw_bus.session_calls == [(BCM_UDS_TX_ID, BCM_UDS_RX_ID)]

    # 29-bit XCP / WFS Ch 3 operation on interface="dpdu" emits bilingual warning
    warnings: list[str] = []

    class RecReporter(OperationReporter):
        def warning(self, message: str) -> None:
            warnings.append(message)

    can_bcm_read_gfa("fake", interface="dpdu", bus=inner, reporter=RecReporter())
    assert any("29-bit" in w and "RawMode" in w and "native CAN" in w for w in warnings)


def test_bcm_unverified_sw_allows_uds_read_with_pn_sw_warning_and_fixes_prefix_fallback() -> None:
    from contitool.can.bcm import can_bcm_read_all
    from contitool.core.bcm import bcm_support_info
    from contitool.progress import OperationReporter

    set_lang("ru")
    # Same known EA part number, but DIFFERENT unverified SW 0512 -> must NOT match ea_0511!
    prof_0512 = bcm_detect_profile({"part_number": "5Q0937084EA", "sw_version": "0512"})
    assert prof_0512["matched"] is False
    sup_0512 = bcm_support_info({"part_number": "5Q0937084EA", "sw_version": "0512"})
    assert sup_0512["verified"] is False
    assert sup_0512["warning"] is not None
    assert "5Q0937084EA" in sup_0512["warning"]
    assert "0512" in sup_0512["warning"]
    assert "официально не поддерживается" in sup_0512["warning"]

    # Verified 0511 has no warning
    assert bcm_support_info({"part_number": "5Q0937084EA", "sw_version": "0511"})["warning"] is None
    # Missing SW still allows known part prefix fallback
    assert bcm_detect_profile({"part_number": "5Q0937084EA", "sw_version": ""})["matched"] is True

    class UnverifiedEaBus(FakeBcmBus):
        def _handle_uds(self, payload: bytes) -> None:
            if payload[:3] == b"\x22\xf1\x87":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x87" + b"5Q0937084EA ")
                return
            if payload[:3] == b"\x22\xf1\x89":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x89" + b"0512")
                return
            super()._handle_uds(payload)

    bus = UnverifiedEaBus(profile_id="ea_0511", freq_code=0x03)
    bus.ffb_serials[1] = bytes.fromhex("532B3512")
    warns: list[str] = []

    class RecRep(OperationReporter):
        def warning(self, message: str) -> None:
            warns.append(message)

    # UDS read works without blocking and emits (PN + SW) warning; include_keys=True still protects FFB keys!
    res = can_bcm_read_all("fake", interface="slcan", bus=bus, include_keys=True, reporter=RecRep())
    assert res["officially_supported"] is False
    assert res["support_warning"] and "5Q0937084EA" in res["support_warning"] and "0512" in res["support_warning"]
    assert any("5Q0937084EA" in w and "0512" in w for w in warns)
    assert bus.ffb_serials[1] == bytes.fromhex("532B3512")


def test_bcm_review_xcp_connect_no_mutation_and_profile_gating() -> None:
    """A.1: xcp_connect() must never mutate profile['matched'] or clobber profile IDs; XCP slot/key mirror gated on matched."""
    from contitool.can.bcm import _read_bcm_status_in_session, _read_ffb_slots_via_xcp

    dd_bus = FakeBcmBus(profile_id="dd_0273", freq_code=0x03)
    dd_bus.allow_dev_session = False
    dd_bus.ffb_serials[1] = bytes.fromhex("532B3512")
    dd_bus._sync_ffb_ram_mirror()

    unmatched_prof = bcm_detect_profile({"part_number": "5Q0937084CP", "sw_version": "0253"})
    assert unmatched_prof["matched"] is False
    orig_id = unmatched_prof["id"]
    orig_xcp_tx = unmatched_prof["xcp_tx_id"]

    with BcmCanLink("fake", bus=dd_bus) as link:
        resp = link.xcp_connect(profile=unmatched_prof, timeout=0.5)
        assert resp[0] == 0xFF
        # Link switched to DD XCP IDs, but caller's profile dict must remain untouched!
        assert link.xcp_tx_id == BCM_XCP_DD_TX_ID
        assert unmatched_prof["matched"] is False
        assert unmatched_prof["id"] == orig_id
        assert unmatched_prof["xcp_tx_id"] == orig_xcp_tx

        # Unmatched profile must NOT read FFB slots via XCP mirror
        assert _read_ffb_slots_via_xcp(link, unmatched_prof) == {}
        st = _read_bcm_status_in_session(link, include_nvm_slots=True, profile=unmatched_prof)
        assert st["ffb_slots"] == []

        # Also verify bq_0212 profile is never clobbered into ea_0511 on xcp_connect
        bq_prof = bcm_detect_profile({"part_number": "5Q0937084BQ", "sw_version": "0212"})
        link.xcp_connect(profile=bq_prof, timeout=0.5)
        assert bq_prof["id"] == "bq_0212"


def test_bcm_review_adapt_ffb_early_validation_precheck_and_unverified_gate(monkeypatch) -> None:
    """A.2: validate inputs before _managed_bcm_session(), precheck before bridge when gfa=None, gate unverified SW."""
    from contitool.can import bcm as bcm_can_mod

    set_lang("en")
    session_opened = False

    def _forbid_session(*_a: Any, **_kw: Any) -> Any:
        nonlocal session_opened
        session_opened = True
        raise AssertionError("_managed_bcm_session must not be entered on invalid inputs")

    monkeypatch.setattr(bcm_can_mod, "_managed_bcm_session", _forbid_session)
    with pytest.raises(ValueError, match="gfa"):
        can_bcm_adapt_ffb("fake", gfa="not-hex", kc="11" * 16, clear_all=True)
    with pytest.raises(ValueError, match="kc|k_ffb"):
        can_bcm_adapt_ffb("fake", gfa="11" * 16, clear_all=True)
    with pytest.raises(ValueError, match="entries, keys, or clear_all"):
        can_bcm_adapt_ffb("fake", gfa="11" * 16, kc="22" * 16)
    assert session_opened is False

    monkeypatch.undo()

    class UnknownSwBcmBus(FakeBcmBus):
        def _handle_uds(self, payload: bytes) -> None:
            if payload[:3] == b"\x22\xf1\x87":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x87" + b"5Q0937084CP ")
                return
            if payload[:3] == b"\x22\xf1\x89":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x89" + b"0253")
                return
            super()._handle_uds(payload)

    bus = UnknownSwBcmBus(profile_id="ea_0511", freq_code=0x03)
    monkeypatch.setattr(
        "contitool.can.bridge.j533_can_bridge",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("bridge must not launch for unverified SW")),
    )
    # Gateway + bridge with gfa=None must precheck and refuse before bridge
    with pytest.raises(RuntimeError, match="Unsupported 09 BCM firmware"):
        can_bcm_adapt_ffb(
            "fake",
            gfa=None,
            kc="33" * 16,
            clear_all=True,
            via_gateway=True,
            gateway_bridge=True,
            bus=bus,
        )
    # Direct with gfa=None must refuse before _read_bcm_gfa_in_session
    monkeypatch.setattr(
        bcm_can_mod,
        "_read_bcm_gfa_in_session",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("_read_bcm_gfa_in_session must not be called")),
    )
    with pytest.raises(RuntimeError, match="Unsupported 09 BCM firmware"):
        can_bcm_adapt_ffb("fake", gfa=None, kc="33" * 16, clear_all=True, bus=bus)


def test_bcm_review_restore_rejects_invalid_kffb_and_read_all_bridge_precheck(monkeypatch) -> None:
    """A.3: reject FF*16 and AES_DEC(GFA, 00*16) even with populated slots; can_bcm_read_all downgrades can_xcp before bridge."""
    from contitool.can import bcm as bcm_can_mod
    from contitool.can.bcm import _restore_bcm_ffb_after_read, can_bcm_read_all
    from contitool.progress import OperationReporter

    set_lang("en")
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    gfa = bus.gfa
    zero_dec = bcm_aes128_ecb_decrypt(gfa, bytes(16))
    pop_slots = [{"slot": 1, "populated": True, "display_id": "532B3512", "rolling_counter": 5}]

    for bad_kffb in (b"\xff" * 16, zero_dec):
        warns: list[str] = []

        class RecRep(OperationReporter):
            def warning(self, message: str) -> None:
                warns.append(message)

        with BcmCanLink("fake", bus=bus) as link:
            ok = _restore_bcm_ffb_after_read(
                link,
                gfa,
                {"k_ffb": bad_kffb, "freq_code": 0x03, "populated_slots": pop_slots},
                reporter=RecRep(),
            )
        assert ok is False
        assert warns and any("invalid" in w.lower() for w in warns)

    # can_bcm_read_all(include_keys=True, via_gateway=True, gateway_bridge=True) on unverified SW:
    # must precheck, downgrade can_xcp=False without launching bridge, and complete Steps 1-3!
    class UnverifiedBus(FakeBcmBus):
        def _handle_uds(self, payload: bytes) -> None:
            if payload[:3] == b"\x22\xf1\x87":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x87" + b"5Q0937084EA ")
                return
            if payload[:3] == b"\x22\xf1\x89":
                self._enqueue_isotp(BCM_UDS_RX_ID, b"\x62\xf1\x89" + b"0512")
                return
            super()._handle_uds(payload)

    unv_bus = UnverifiedBus(profile_id="ea_0511", freq_code=0x03)
    monkeypatch.setattr(
        "contitool.can.bridge.j533_can_bridge",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("bridge must not launch for unverified SW")),
    )
    res = can_bcm_read_all(
        "fake",
        interface="slcan",
        via_gateway=True,
        gateway_bridge=True,
        include_keys=True,
        bus=unv_bus,
    )
    assert res["gateway_bridged"] is False
    assert res["officially_supported"] is False
    assert res["ika_hex"] == "" and res["gfa_working_hex"] == ""
    assert res["passport"]["sw_version"] == "0512"
    assert res["keys_warning"]

    # Step 4 exception on verified BCM must NOT blindly fall back to _read_bcm_gfa_in_session
    ver_bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    monkeypatch.setattr(
        bcm_can_mod,
        "_read_bcm_keys_in_session",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("simulated job3 error")),
    )
    monkeypatch.setattr(
        bcm_can_mod,
        "_read_bcm_gfa_in_session",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("blind GFA fallback must be removed")),
    )
    res_err = can_bcm_read_all("fake", interface="slcan", include_keys=True, bus=ver_bus)
    assert "simulated job3 error" in res_err["keys_warning"]
    assert res_err["gfa_working_hex"] == ""


def test_bcm_review_pass1_zero_slots_fail_closed_and_pass2_hardreset(monkeypatch) -> None:
    """A.4: preserve K_ffb even with 0 learned slots; fail closed when learned_count>0 & no slots; HardReset on Pass-2 fail."""
    from contitool.can import bcm as bcm_can_mod

    set_lang("en")
    # 1. Zero learned slots, real K_ffb in NvM 0x02 (blocked on direct UDS/XCP) -> Pass 1 must preserve it!
    orig_kffb = bytes.fromhex("deadbeefcafebabe1122334455667788")
    bus0 = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    bus0.k_ffb = orig_kffb
    bus0._sync_ffb_ram_mirror()

    res_gfa = can_bcm_read_gfa("fake", interface="slcan", bus=bus0)
    assert res_gfa["k_ffb_hex"] == orig_kffb.hex()
    assert bus0.k_ffb == orig_kffb

    res_keys = can_bcm_read_keys("fake", interface="slcan", bus=bus0)
    assert res_keys["k_ffb_hex"] == orig_kffb.hex()
    assert bus0.k_ffb == orig_kffb

    # 2. Fail closed when DID 0x1983 reports ffb_learned_count > 0 but slots could not be backed up!
    bus_fail = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    bus_fail.k_ffb = orig_kffb
    bus_fail.ffb_serials[1] = bytes.fromhex("532B3512")
    bus_fail.ffb_learned_mask = 1 << 1
    bus_fail.allow_dev_session = False
    bus_fail._sync_ffb_ram_mirror()
    monkeypatch.setattr(bcm_can_mod, "_read_ffb_slots_via_xcp", lambda *_a, **_k: {})

    with pytest.raises(RuntimeError, match="could not be backed up"):
        can_bcm_read_keys("fake", interface="slcan", bus=bus_fail)
    with pytest.raises(RuntimeError, match="could not be backed up"):
        can_bcm_read_gfa("fake", interface="slcan", bus=bus_fail)
    assert bus_fail.k_ffb == orig_kffb
    assert bus_fail.ffb_serials[1] == bytes.fromhex("532B3512")

    # 3. Pass-2 failure must capture gfa_restore BEFORE _hard_reset_and_wait_bcm and call HardReset BEFORE restore!
    monkeypatch.undo()
    bus_p2 = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    bus_p2.k_ffb = orig_kffb
    bus_p2.ffb_serials[1] = bytes.fromhex("532B3512")
    bus_p2.ffb_learned_mask = 1 << 1
    bus_p2._sync_ffb_ram_mirror()

    events: list[str] = []
    real_job3 = bcm_can_mod._read_bcm_job3_target_in_session
    real_reset = bcm_can_mod._hard_reset_and_wait_bcm
    real_restore = bcm_can_mod._restore_bcm_ffb_after_read
    call_n = {"n": 0}

    def _job3_fail_p2(link, profile, *, target_addr, trigger_80_01_pdu=None):
        call_n["n"] += 1
        if call_n["n"] == 2:
            raise TimeoutError("p2 fail")
        return real_job3(link, profile, target_addr=target_addr, trigger_80_01_pdu=trigger_80_01_pdu)

    def _track_reset(*a, **kw):
        events.append("hard_reset")
        return real_reset(*a, **kw)

    def _track_restore(*a, **kw):
        events.append("restore_ffb")
        return real_restore(*a, **kw)

    monkeypatch.setattr(bcm_can_mod, "_read_bcm_job3_target_in_session", _job3_fail_p2)
    monkeypatch.setattr(bcm_can_mod, "_hard_reset_and_wait_bcm", _track_reset)
    monkeypatch.setattr(bcm_can_mod, "_restore_bcm_ffb_after_read", _track_restore)
    with pytest.raises(TimeoutError, match="p2 fail"):
        can_bcm_read_keys("fake", interface="slcan", bus=bus_p2)
    # Pass 1 reset, then Pass-2 exception reset, then restore_ffb
    assert events == ["hard_reset", "hard_reset", "restore_ffb"]
    assert bus_p2.k_ffb == orig_kffb


def test_bcm_review_precheck_empty_passport_uds_only_failfast_and_key_masking(monkeypatch) -> None:
    """A.5: precheck rejects empty passport & restores 10 01; adapt_ffb_from_cluster checks bridge first; uds_only failfast; masked logs."""
    import contextlib
    from contitool.can.bcm import _precheck_bcm_profile_before_bridge
    from contitool.progress import OperationReporter

    set_lang("en")

    # 1. Silent bus -> _precheck_bcm_profile_before_bridge raises instead of returning {}
    class SilentBus:
        rx_queue: deque[can.Message] = deque()

        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            pass

        def recv(self, timeout: float | None = None) -> can.Message | None:
            return None

        def shutdown(self) -> None:
            pass

    monkeypatch.setattr("contitool.can.bcm._read_bcm_passport_in_session", lambda _lnk: {})
    with pytest.raises(RuntimeError, match="did not answer UDS passport"):
        _precheck_bcm_profile_before_bridge("fake", bus=SilentBus())
    monkeypatch.undo()

    # 2. _precheck_bcm_profile_before_bridge returns BCM to 10 01 before closing
    bus = FakeBcmBus(profile_id="ea_0511", freq_code=0x03)
    pre = _precheck_bcm_profile_before_bridge("fake", bus=bus)
    assert pre["sw_version"] == "0511"
    assert bus.session == 0x01

    # 3. can_bcm_adapt_ffb_from_cluster(fpke_dflash=None, via_gateway=True, gateway_bridge=False) fails BEFORE probing FPK_E
    with pytest.raises(RuntimeError, match="Aborted before modifying GFA"):
        can_bcm_adapt_ffb_from_cluster(
            "fake",
            fpke_dflash=None,
            via_gateway=True,
            gateway_bridge=False,
            bus=bus,
        )

    # 4. uds_only=True with uds_session yielding False raises TimeoutError immediately
    class RefusingDpduBus:
        uds_only = True
        nonraw: dict[int, int] = {}
        uds_refusal = "cannot open link"

        @contextlib.contextmanager
        def uds_session(self, tx_id: int = 0x710, rx_id: int = 0x77A):
            yield False

        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            raise AssertionError("Must not fall back to raw send on uds_only bus")

        def recv(self, timeout: float | None = None) -> can.Message | None:
            return None

        def shutdown(self) -> None:
            pass

    with pytest.raises(TimeoutError, match="cannot open link"):
        can_bcm_status("fake", interface="dpdu", bus=RefusingDpduBus())
    with BcmCanLink("fake", interface="dpdu", bus=RefusingDpduBus()) as lnk:
        with pytest.raises(TimeoutError, match="cannot open link"):
            lnk.request_uds(b"\x10\x03", 0x50)

    # 5. Plaintext IKA/GFA/K_ffb must be masked in reporter.info() and reporter.can_log()
    log_lines: list[str] = []

    class CapRep(OperationReporter):
        def info(self, message: str) -> None:
            log_lines.append(message)

        def can_log(self, message: str) -> None:
            log_lines.append(message)

        def warning(self, message: str) -> None:
            log_lines.append(message)

    bus_m = FakeBcmBus(
        profile_id="ea_0511",
        ika=bytes.fromhex("112233445566778899aabbccddeeff01"),
        gfa=bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
        freq_code=0x03,
    )
    bus_m.k_ffb = bytes.fromhex("cafebabefeedface0123456789abcdef")
    bus_m._sync_ffb_ram_mirror()
    can_bcm_read_keys("fake", bus=bus_m, reporter=CapRep())
    can_bcm_write_keys(
        "fake",
        current_ika=bus_m.ika,
        new_ika="0123456789abcdef0123456789abcdef",
        new_gfa="fedcba9876543210fedcba9876543210",
        bus=bus_m,
        reporter=CapRep(),
    )
    joined = "\n".join(log_lines).upper()
    for secret in (
        "112233445566778899AABBCCDDEEFF01",
        "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF",
        "CAFEBABEFEEDFACE0123456789ABCDEF",
        "0123456789ABCDEF0123456789ABCDEF",
        "FEDCBA9876543210FEDCBA9876543210",
    ):
        assert secret not in joined
    assert "1122...FF01" in joined
    assert "A0A1...AEAF" in joined
    assert "CAFE...CDEF" in joined


def test_bcm_review_core_detect_aliases_short_serial_and_kombi_dispatch() -> None:
    """A.6: list ident, exact part_prefixes match, hw_part_number non-match, aliases, short serial, Kombi dispatch."""
    from contitool.core.bcm import bcm_get_profile
    from contitool.core.kombi import EEL_KOMBI_0310_IDS, build_kombi_eel_dflash
    from test_kombi import _build_synthetic_kombi_records

    # 1. list[dict[str, str]] accepted by bcm_detect_profile
    p_list = bcm_detect_profile([{"did": "F187", "value": "5Q0 937 084 EA"}, {"did": "F189", "value": "0511"}])
    assert p_list["matched"] is True and p_list["id"] == "ea_0511"

    # 2. Exact matching avoids 10-char prefix collision (5Q0937085B vs 5Q0937085BA, 5Q0937085C vs 5Q0937085CA)
    assert bcm_detect_profile({"part_number": "5Q0937085B", "sw_version": ""})["id"] == "dd_0273"
    assert bcm_detect_profile({"part_number": "5Q0937085B", "sw_version": ""})["matched"] is True
    assert bcm_detect_profile({"part_number": "5Q0937085BA", "sw_version": ""})["matched"] is False
    assert bcm_detect_profile({"part_number": "5Q0937085C", "sw_version": ""})["id"] == "ea_0511"
    assert bcm_detect_profile({"part_number": "5Q0937085C", "sw_version": ""})["matched"] is True
    assert bcm_detect_profile({"part_number": "5Q0937085CA", "sw_version": ""})["matched"] is False

    # 3. hw_part_number-only without part_number / sw_version does NOT match
    assert bcm_detect_profile({"hw_part_number": "5Q0937084EA"})["matched"] is False
    assert bcm_detect_profile([{"did": "F191", "value": "5Q0937084EA"}])["matched"] is False

    # 4. Missing aliases in bcm_get_profile
    assert bcm_get_profile("5q0937085c")["id"] == "ea_0511"
    assert bcm_get_profile("5q0937085b")["id"] == "dd_0273"
    assert bcm_get_profile("cg")["id"] == "dd_0273"
    assert bcm_get_profile("bc")["id"] == "bq_0212"
    assert bcm_get_profile("an")["id"] == "bl_0175"
    assert bcm_get_profile("al")["id"] == "bl_0175"

    # 5. Short serial (< 4 bytes) must not mark FFB slot populated
    dec = bcm_decode_status_dids({}, nvm_slots={1: (b"\x01\x02", b"\x00\x00\x00\x01", b"\x00")})
    assert dec["ffb_slots"][0]["populated"] is False

    # 6. bcm_extract_cluster_ffb_material dispatches V850E2 Kombi dumps (logical EEL & 64K) to analyze_kombi_dflash
    recs = _build_synthetic_kombi_records()
    logical_kombi = b"".join(recs[i] for i in sorted(EEL_KOMBI_0310_IDS))
    for kombi_blob in (logical_kombi, build_kombi_eel_dflash(recs)):
        mat = bcm_extract_cluster_ffb_material(kombi_blob, freq_code=0x03)
        assert mat["kc_hex"] == "ea046275eea646ef01e6d703f77899db"
        assert mat["gfa_hex"] == "e54e0aab8198ebcd8e781cceb0a3b33c"
        assert mat["vin"] == "XW8ZZZ5NZJG235992"
        assert mat["learned_keys"] == 2
        assert len(mat["active_transponders"]) == 2




