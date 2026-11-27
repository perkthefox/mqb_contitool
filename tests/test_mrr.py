"""Unit, simulated CAN/XCP bus, CLI, and headless Qt 6 GUI tests for 13 ACC Radar (Bosch MRR1Plus 3Q0 & MRRevo14F 5Q0/3QF)."""

from __future__ import annotations

from collections import deque
import hashlib
import json
import os
from pathlib import Path
import struct
from typing import Any

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import can  # noqa: E402
import pytest  # noqa: E402

from contitool.can.ecus import can_scan_bus, can_uds_read_dtc  # noqa: E402
from contitool.can.mrr import (  # noqa: E402
    MrrCanLink,
    can_mrr_activate_swap,
    can_mrr_deactivate_cp,
    can_mrr_flash_frf,
    can_mrr_read_keys,
    can_mrr_read_memory,
    can_mrr_reset_cp_counter,
    can_mrr_restore_cp_stock,
    can_mrr_restore_swap_stock,
    can_mrr_status,
    can_mrr_swap_status,
    can_mrr_write_keys,
)
from contitool.core.bcm import bcm_aes128_ecb_encrypt  # noqa: E402
from contitool.core.dtc import describe_mrr  # noqa: E402
from contitool.core.mrr import (  # noqa: E402
    MRR_BOOT_SIZE,
    MRR_CP_KEY_TYPE_GFA,
    MRR_CP_KEY_TYPE_IKA,
    MRR_DFLASH_ADDR,
    MRR_DFLASH_SIZE,
    MRR_DRIVER_ADDRESS,
    MRR_DRIVER_CONTROL,
    MRR_FAST_CAN_ID,
    MRR_FAST_READ_RAM_DRIVER,
    MRR_FAST_WRITE_RAM_DRIVER,
    MRR_FBLV_ALFID,
    MRR_FBLV_RSA_MODULUS,
    MRR_FBLV_SA2_BYTECODE,
    MRR_FLASH_DRIVER_SIZE,
    MRR_FLASH_SECTOR_DRIVER_ADDR,
    MRR_FLASH_SECTOR_WRITE_DRIVER,
    MRR_GEN1_SWAP_PACKAGES,
    MRR_GEN2_3C00_COND_STOCK,
    MRR_GEN2_3C00_LEN_STOCK,
    MRR_GEN2_RSA_DEV_PREFIX,
    MRR_GEN2_RSA_SERIES_PREFIX,
    MRR_GEN2_SWAP_STUB_REL,
    MRR_GEN2_SWAP_STUB_STOCK,
    MRR_KS_META_MAGIC,
    MRR_LOGIN_XCP_GATE,
    MRR_PROFILES,
    MRR_SHADOW_SECRET_MAGIC_A,
    MRR_SWAP_RSA_KEY_DID,
    MRR_SWAP_STATUS_DID,
    MRR_SWAP_VCRN_DID,
    MRR_UDS_RX_ID,
    MRR_UDS_TX_ID,
    MRR_XCP_RX_ID,
    MRR_XCP_TX_ID,
    MrrFrfBlock,
    MrrFrfImage,
    _MRR_GEN1_SWAP_REL_SITES,
    _MRR_GEN2_SWAP_FIXED_REL_SITES,
    mrr_apply_cp_disable_patch,
    mrr_apply_swap_patch,
    mrr_build_cp_key_container,
    mrr_build_gen1_3c00_stub,
    mrr_build_gen2_3c00_len_stub,
    mrr_build_gen2_3c00_read_stub,
    mrr_build_gen2_swap_group_stub,
    mrr_build_tlb1_0b_descriptor,
    mrr_compute_ecu_boot_sum,
    mrr_decode_gen1_3c00_stub,
    mrr_decode_gen2_3c00_len_stub,
    mrr_decode_gen2_3c00_read_stub,
    mrr_decode_gen2_swap_group_stub,
    mrr_decode_status_dids,
    mrr_decode_swap_status_byte,
    mrr_describe_gen2_swap_groups,
    mrr_detect_profile,
    mrr_dev_compute_key,
    mrr_extract_cp_affected_sectors,
    mrr_extract_swap_affected_sectors,
    mrr_fblv_compute_key,
    mrr_fblv_signature_valid,
    mrr_frf_compatibility,
    mrr_frf_decrypt,
    mrr_fsid_label,
    mrr_get_eraserouti_driver,
    mrr_get_swap_patch_stats,
    mrr_inspect_cflash_cp_state,
    mrr_inspect_cflash_swap_state,
    mrr_lzss_a0_decompress,
    mrr_parse_dflash_fee,
    mrr_parse_swap_uds_response,
    mrr_read_frf,
    mrr_sum32_be,
    mrr_unpack_cp_key_container,
    mrr_xcp_compute_key,
)
from contitool.i18n import set_lang  # noqa: E402


def _build_synthetic_mrr_cflash(profile_code: str, *, full_image: bool = True) -> bytes:
    """Create a synthetic CodeFlash or Application image populated with stock bytes at all CP and SWaP patch sites."""
    prof = MRR_PROFILES[profile_code]
    size = int(prof["cflash_size"] if full_image else prof["app_size"])
    base_off = 0 if full_image else MRR_BOOT_SIZE
    buf = bytearray(b"\xff" * size)
    if full_image:
        for off in range(0x8000, 0xA000, 4):
            buf[off : off + 4] = ((off * 0x01010101) & 0xFFFFFFFF).to_bytes(4, "big")
    for _name, addr, stock_hex, _patch_hex in prof["patches"]:
        rel = addr - base_off
        raw = bytes.fromhex(stock_hex)
        buf[rel : rel + len(raw)] = raw
    swap_cfg = prof.get("swap_config") or {}
    uds_3c00 = swap_cfg.get("uds_3c00") or {}
    if int(swap_cfg.get("generation") or 0) == 1:
        main_pa = int(swap_cfg["swap_main_pa"])
        rel_sites = swap_cfg.get("rel_sites") or _MRR_GEN1_SWAP_REL_SITES
        for rel_off, stock_hex, _pat_hex, _desc in rel_sites:
            rel = (main_pa + rel_off) - base_off
            raw = bytes.fromhex(stock_hex)
            buf[rel : rel + len(raw)] = raw
        if uds_3c00:
            for pa_k, st_k in (
                ("prepare_pa", "prepare_stock"),
                ("len_pa", "len_stock"),
                ("data_pa", "data_stock"),
            ):
                rel = int(uds_3c00[pa_k]) - base_off
                raw = bytes.fromhex(str(uds_3c00[st_k]))
                buf[rel : rel + len(raw)] = raw
    elif int(swap_cfg.get("generation") or 0) == 2:
        coord_pa = int(swap_cfg["coord_base_pa"])
        for rel_off, stock_hex, _pat_hex, _desc in _MRR_GEN2_SWAP_FIXED_REL_SITES:
            rel = (coord_pa + rel_off) - base_off
            raw = bytes.fromhex(stock_hex)
            buf[rel : rel + len(raw)] = raw
        bl_rel = (coord_pa + 0x498) - base_off
        bl_raw = bytes.fromhex(str(swap_cfg["e_bl_aff066"]))
        buf[bl_rel : bl_rel + len(bl_raw)] = bl_raw
        stub_rel = (coord_pa + MRR_GEN2_SWAP_STUB_REL) - base_off
        buf[stub_rel : stub_rel + len(MRR_GEN2_SWAP_STUB_STOCK)] = MRR_GEN2_SWAP_STUB_STOCK
        if uds_3c00:
            c_rel = int(uds_3c00["cond_pa"]) - base_off
            buf[c_rel : c_rel + len(MRR_GEN2_3C00_COND_STOCK)] = MRR_GEN2_3C00_COND_STOCK
            l_rel = int(uds_3c00["len_pa"]) - base_off
            buf[l_rel : l_rel + len(MRR_GEN2_3C00_LEN_STOCK)] = MRR_GEN2_3C00_LEN_STOCK
            d_rel = int(uds_3c00["data_pa"]) - base_off
            d_raw = bytes.fromhex(str(uds_3c00["data_stock"]))
            buf[d_rel : d_rel + len(d_raw)] = d_raw
    return bytes(buf)


def _build_synthetic_mrr_dflash(
    *,
    ika: bytes = bytes.fromhex("2f4b861d3a9c50e7b14d28f603a5c91e"),
    gfa: bytes = bytes.fromhex("d4a17e09c35b821f6e409a2cd73b5804"),
    prng_seed: bytes = bytes.fromhex("0102030405060708090a0b0c0d0e0f10"),
    ecu_boot_sum: bytes = bytes.fromhex("8f911c6c7d1bfe78823a1ddebaaa0e82"),
    cp_counter: int = 0x0000,
    gfa_learned: bool = True,
    ks_options: int = 0x8000,
    include_fee_ika: bool = True,
    shadow_ika: bytes | None = None,
) -> bytes:
    """Build a synthetic 64 KiB DFLASH0 image with AUTOSAR Fee Cluster 0 directory growing downward from +0x7FF8."""
    dflash = bytearray(b"\xff" * MRR_DFLASH_SIZE)

    ks_meta_plain = bytearray(16)
    ks_meta_plain[0 : len(MRR_KS_META_MAGIC)] = MRR_KS_META_MAGIC
    ks_meta_plain[0x0B] = 0x01 if gfa_learned else 0x00
    ks_meta_plain[0x0C:0x0E] = (ks_options & 0xFFFF).to_bytes(2, "big")
    ks_meta_plain[0x0E:0x10] = (cp_counter & 0xFFFF).to_bytes(2, "big")

    blocks: list[tuple[int, bytes]] = []
    if include_fee_ika:
        blocks.append((0x2A, bytes([0x01]) + bcm_aes128_ecb_encrypt(ecu_boot_sum, ika)))
    blocks.append((0x2B, bytes([0x01]) + bcm_aes128_ecb_encrypt(ecu_boot_sum, prng_seed)))
    blocks.append((0x2C, bytes([0x01]) + bcm_aes128_ecb_encrypt(ecu_boot_sum, bytes(ks_meta_plain))))
    blocks.append((0x2D, bytes([0x01]) + bcm_aes128_ecb_encrypt(ecu_boot_sum, gfa)))
    blocks.append((0x40, bytes([0x01]) + ecu_boot_sum + b"\x00\x00\x01\x00\x01"))

    data_off = 0x0040
    dir_off = 0x7FF8
    for blk_id, payload in blocks:
        dflash[data_off : data_off + len(payload)] = payload
        # 8-byte Fee directory entry: >HBBI (data_offset, block_and_copy, crc8, status=0)
        dflash[dir_off : dir_off + 8] = struct.pack(">HBBI", data_off, blk_id & 0x7F, 0x00, 0x00000000)
        data_off += (len(payload) + 7) & ~7
        dir_off -= 8

    if shadow_ika is not None:
        w_sum = sum(int.from_bytes(shadow_ika[i : i + 4], "big") for i in range(0, 16, 4)) & 0xFFFFFFFF
        rec = (
            MRR_SHADOW_SECRET_MAGIC_A.to_bytes(4, "big")
            + shadow_ika
            + w_sum.to_bytes(4, "big")
            + MRR_SHADOW_SECRET_MAGIC_A.to_bytes(4, "big")
        )
        dflash[0xC000 : 0xC000 + 28] = rec

    return bytes(dflash)


class FakeMrrBus:
    """In-memory simulator for 13 ACC Radar (UDS `0x757 -> 0x7C1`, XCP `0x1BFEBA00 -> 0x1BFEBA01`, Fast CAN `0x77E`)."""

    def __init__(
        self,
        *,
        sw_profile: str = "0192",
        ika: bytes = bytes.fromhex("2f4b861d3a9c50e7b14d28f603a5c91e"),
        gfa: bytes = bytes.fromhex("d4a17e09c35b821f6e409a2cd73b5804"),
        ecu_boot_sum: bytes = bytes.fromhex("8f911c6c7d1bfe78823a1ddebaaa0e82"),
        cp_counter: int = 0x001F,
        xcp_gate_open: bool = False,
        swap_3c00_entries: list[tuple[int, int]] | None = None,
        fes_vcrn: bytes = b"\x04\x4d\xf5\xe4\xae",
        rsa_key_prefix: bytes | None = None,
        in_fblv: bool = False,
        fblv_flash_sw_after: str | None = None,
        fblv_reject_rsa: bool = False,
    ) -> None:
        self.profile = MRR_PROFILES.get(sw_profile) or mrr_detect_profile(
            {"part_number": "3Q0907572B", "sw_version": sw_profile},
            sw_version=sw_profile,
        )
        self.sw_profile = sw_profile
        self.ika = bytearray(ika)
        self.gfa = bytearray(gfa)
        self.ecu_boot_sum = bytes(ecu_boot_sum)
        self.cp_counter = cp_counter
        self.gfa_learned = True
        self.ika_virgin = False
        self.xcp_gate_byte = 0x08 if xcp_gate_open else 0x00
        if swap_3c00_entries is not None:
            self.swap_3c00_entries = list(swap_3c00_entries)
        elif self.profile.get("mcu") == "MPC5674K":
            self.swap_3c00_entries = [(0x10003700, 0x4F)]
        else:
            self.swap_3c00_entries = [
                (0x10009007, 0x4F),
                (0x10009103, 0x4F),
                (0x10009204, 0x4F),
            ]
        self.fes_vcrn = bytes(fes_vcrn)
        if rsa_key_prefix is not None:
            self.rsa_key_prefix = bytes(rsa_key_prefix)
        elif sw_profile == "X720":
            self.rsa_key_prefix = MRR_GEN2_RSA_DEV_PREFIX
        else:
            self.rsa_key_prefix = MRR_GEN2_RSA_SERIES_PREFIX

        self.session = 0x01
        self.sa_unlocked = False
        self.xcp_connected = False
        self.xcp_unlocked = False
        self.xcp_mta = 0
        self.xcp_seed = 0x12345678
        self.dtcs: list[tuple[int, int]] = [
            (0xEA6100, 0x09),  # U110100: Component protection active
            (0xEA6400, 0x08),  # U110100: Component protection no basic setting
        ]
        self.reset_count = 0
        self.sector_writes: list[tuple[int, int]] = []
        self.in_fblv = bool(in_fblv)
        self.fblv_seed = 0x00047430
        self.fblv_unlocked = False
        self.fblv_fingerprint: bytes | None = None
        self.fblv_driver_ok = False
        self.fblv_erased = False
        self.fblv_app_ok = False
        self.fblv_deps_ok = False
        self.fblv_active_block: dict[str, Any] | None = None
        self.fblv_last_block: dict[str, Any] | None = None
        self.fblv_log: list[str] = []
        self.fblv_flash_sw_after = fblv_flash_sw_after
        self.fblv_reject_rsa = bool(fblv_reject_rsa)
        if self.in_fblv:
            self.session = 0x02

        synth_prof = sw_profile if sw_profile in MRR_PROFILES else "0192"
        self.cflash = bytearray(_build_synthetic_mrr_cflash(synth_prof, full_image=True))
        self.dflash = bytearray(
            _build_synthetic_mrr_dflash(
                ika=bytes(self.ika),
                gfa=bytes(self.gfa),
                ecu_boot_sum=self.ecu_boot_sum,
                cp_counter=self.cp_counter,
                gfa_learned=self.gfa_learned,
            )
        )
        self.sram: dict[int, int] = {}
        self._init_sram()

        self.rx_queue: deque[can.Message] = deque()
        self._uds_mf_buf = bytearray()
        self._uds_mf_expected = 0
        self._stream_state: dict[str, Any] | None = None

    def _init_sram(self) -> None:
        synch_slot = int(self.profile.get("xcp_synch_slot") or 0)
        synch_def = int(self.profile.get("xcp_synch_default") or 0)
        if synch_slot and synch_def:
            self._write_mem(synch_slot, synch_def.to_bytes(4, "big"))
        canary_addr = int(self.profile.get("user_stack_canary_addr") or 0)
        if canary_addr:
            self._write_mem(canary_addr, bytes.fromhex("deadbeefcafebabe"))
        self._sync_sram_mirrors()

    @property
    def cp_active(self) -> bool:
        return bool(self.cp_counter > 0x001E or not self.gfa_learned or self.ika_virgin)

    def _sync_sram_mirrors(self) -> None:
        if not self.profile.get("sram_ika_addr"):
            return
        self._write_mem(int(self.profile["sram_ika_addr"]), bytes(self.ika))
        self._write_mem(int(self.profile["sram_ika_inv_addr"]), bytes((~b) & 0xFF for b in self.ika))
        self._write_mem(int(self.profile["sram_gfa_addr"]), bytes(self.gfa))
        ks_meta = bytearray(16)
        ks_meta[0 : len(MRR_KS_META_MAGIC)] = MRR_KS_META_MAGIC
        ks_meta[0x0B] = 0x01 if self.gfa_learned else 0x00
        ks_meta[0x0C:0x0E] = b"\x80\x00"
        ks_meta[0x0E:0x10] = (self.cp_counter & 0xFFFF).to_bytes(2, "big")
        self._write_mem(int(self.profile["sram_ks_meta_addr"]), bytes(ks_meta))
        if int(self.profile.get("sram_ecu_boot_sum_addr") or 0):
            self._write_mem(int(self.profile["sram_ecu_boot_sum_addr"]), self.ecu_boot_sum)
        if int(self.profile.get("sram_cp_counter_addr") or 0):
            self._write_mem(int(self.profile["sram_cp_counter_addr"]), (self.cp_counter & 0xFFFF).to_bytes(2, "big"))
        if int(self.profile.get("sram_cp_active_addr") or 0):
            self._write_mem(int(self.profile["sram_cp_active_addr"]), bytes([0x01 if self.cp_active else 0x00]))

    def _rebuild_dflash(self) -> None:
        self.dflash[:] = _build_synthetic_mrr_dflash(
            ika=bytes(self.ika),
            gfa=bytes(self.gfa),
            ecu_boot_sum=self.ecu_boot_sum,
            cp_counter=self.cp_counter,
            gfa_learned=self.gfa_learned,
        )
        self._sync_sram_mirrors()

    def _read_mem(self, address: int, size: int) -> bytes:
        cflash_size = len(self.cflash)
        if 0 <= address and address + size <= cflash_size:
            return bytes(self.cflash[address : address + size])
        if MRR_DFLASH_ADDR <= address and address + size <= MRR_DFLASH_ADDR + MRR_DFLASH_SIZE:
            off = address - MRR_DFLASH_ADDR
            return bytes(self.dflash[off : off + size])
        return bytes(self.sram.get((address + i) & 0xFFFFFFFF, 0) for i in range(size))

    def _write_mem(self, address: int, data: bytes) -> None:
        cflash_size = len(self.cflash)
        if 0 <= address and address + len(data) <= cflash_size:
            self.cflash[address : address + len(data)] = data
            return
        if MRR_DFLASH_ADDR <= address and address + len(data) <= MRR_DFLASH_ADDR + MRR_DFLASH_SIZE:
            off = address - MRR_DFLASH_ADDR
            self.dflash[off : off + len(data)] = data
            return
        for idx, b in enumerate(data):
            self.sram[(address + idx) & 0xFFFFFFFF] = b

        # Check if KS_State_AuthSuccess trigger word was written as 0x00000001
        trig_addr = int(self.profile.get("sram_auth_success_trigger_addr") or 0)
        if trig_addr and address <= trig_addr + 3 < address + len(data):
            val = int.from_bytes(self._read_mem(trig_addr, 4), "big")
            if val == 1:
                self.cp_counter = 0
                for i in range(4):
                    self.sram[trig_addr + i] = 0
                self._rebuild_dflash()

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
        off = 6
        sn = 1
        while off < length:
            chunk = payload[off : off + 7]
            self._enqueue_frame(rx_id, bytes([0x20 | (sn & 0x0F)]) + chunk)
            off += 7
            sn = (sn + 1) & 0x0F

    def recv(self, timeout: float | None = None) -> can.Message | None:
        if self.rx_queue:
            return self.rx_queue.popleft()
        return None

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        arb = msg.arbitration_id
        data = bytes(msg.data)
        if arb == MRR_UDS_TX_ID:
            self._on_uds_frame(data)
        elif arb == MRR_XCP_TX_ID:
            self._on_xcp_frame(data)

    def _on_uds_frame(self, frame: bytes) -> None:
        pci = frame[0] >> 4
        if pci == 0x0:
            ln = frame[0] & 0x0F
            self._handle_uds(frame[1 : 1 + ln])
        elif pci == 0x1:
            self._uds_mf_expected = ((frame[0] & 0x0F) << 8) | frame[1]
            self._uds_mf_buf = bytearray(frame[2:8])
            self._enqueue_frame(MRR_UDS_RX_ID, b"\x30\x00\x00\xaa\xaa\xaa\xaa\xaa")
        elif pci == 0x2:
            self._uds_mf_buf.extend(frame[1:8])
            if len(self._uds_mf_buf) >= self._uds_mf_expected:
                pdu = bytes(self._uds_mf_buf[: self._uds_mf_expected])
                self._uds_mf_expected = 0
                self._handle_uds(pdu)

    def _handle_uds(self, pdu: bytes) -> None:
        sid = pdu[0]
        if sid == 0x10 and len(pdu) >= 2:
            sub = pdu[1]
            if self.in_fblv and sub == 0x03:
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x10\x7e")
                return
            if sub == 0x02:
                self.fblv_log.append("10_02")
                self.in_fblv = True
                self.session = 0x02
                self.fblv_unlocked = False
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x10\x78")
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x50\x02\x00\x32\x01\xf4")
                return
            self.session = sub
            self._enqueue_isotp(MRR_UDS_RX_ID, bytes([0x50, self.session, 0x00, 0x32, 0x01, 0xF4]))
            return
        if sid == 0x3E:
            if len(pdu) >= 2 and (pdu[1] & 0x80) == 0:
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7e\x00")
            return
        if sid == 0x11 and len(pdu) >= 2:
            self.reset_count += 1
            if self.in_fblv:
                self.fblv_log.append(f"11_{pdu[1]:02X}")
                if self.fblv_deps_ok or not self.fblv_erased:
                    self.in_fblv = False
                    self.session = 0x01
                    if self.fblv_deps_ok and self.fblv_flash_sw_after:
                        self.sw_profile = self.fblv_flash_sw_after
                        if self.sw_profile in MRR_PROFILES:
                            self.profile = MRR_PROFILES[self.sw_profile]
            self._enqueue_isotp(MRR_UDS_RX_ID, bytes([0x51, pdu[1]]))
            return
        if sid == 0x14:
            self.dtcs.clear()
            self._enqueue_isotp(MRR_UDS_RX_ID, b"\x54")
            return
        if sid == 0x19 and len(pdu) >= 2 and pdu[1] == 0x02:
            out = bytearray([0x59, 0x02, 0x8F])
            for code, st in self.dtcs:
                out.extend(code.to_bytes(3, "big"))
                out.append(st & 0xFF)
            self._enqueue_isotp(MRR_UDS_RX_ID, bytes(out))
            return
        if sid == 0x27 and len(pdu) >= 2:
            sub = pdu[1]
            if sub == 0x11 and self.in_fblv:
                self.fblv_log.append("27_11")
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x67\x11" + self.fblv_seed.to_bytes(4, "big"))
                return
            if sub == 0x12 and self.in_fblv and len(pdu) == 6:
                self.fblv_log.append("27_12")
                key = int.from_bytes(pdu[2:6], "big")
                if key == mrr_fblv_compute_key(self.fblv_seed):
                    self.fblv_unlocked = True
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x67\x12")
                else:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x27\x35")
                return
            if sub == 0x03:
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x67\x03\x11\x22\x33\x44")
                return
            if sub == 0x04 and len(pdu) >= 6:
                key = int.from_bytes(pdu[2:6], "big")
                expected = (0x11223344 + MRR_LOGIN_XCP_GATE) & 0xFFFFFFFF
                if key == expected:
                    self.sa_unlocked = True
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x67\x04")
                else:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x27\x35")
                return
        if sid == 0x34 and self.in_fblv and len(pdu) == 8:
            if not self.fblv_unlocked or self.fblv_fingerprint is None:
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x34\x33")
                return
            fmt, alfid, bid = pdu[1], pdu[2], pdu[3]
            usize = int.from_bytes(pdu[4:8], "big")
            if alfid != 0x41 or fmt not in (0x00, 0xA0) or bid not in (0x99, 0x10):
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x34\x31")
                return
            if bid == 0x10 and not self.fblv_erased:
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x34\x24")
                return
            self.fblv_active_block = {
                "bid": bid,
                "fmt": fmt,
                "usize": usize,
                "seq": 1,
                "stream": bytearray(),
            }
            self.fblv_log.append(f"34_{bid:02X}_{fmt:02X}")
            self._enqueue_isotp(MRR_UDS_RX_ID, b"\x74\x20\x0f\xf2")
            return
        if sid == 0x36 and self.in_fblv and len(pdu) >= 2:
            blk = self.fblv_active_block
            if blk is None:
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x36\x24")
                return
            seq = pdu[1]
            if seq != (blk["seq"] & 0xFF):
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x36\x73")
                return
            blk["stream"].extend(pdu[2:])
            blk["seq"] = (blk["seq"] + 1) & 0xFF
            self._enqueue_isotp(MRR_UDS_RX_ID, bytes([0x76, seq]))
            return
        if sid == 0x37 and self.in_fblv:
            blk = self.fblv_active_block
            if blk is None:
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x37\x24")
                return
            self.fblv_last_block = blk
            self.fblv_active_block = None
            self.fblv_log.append(f"37_{blk['bid']:02X}")
            self._enqueue_isotp(MRR_UDS_RX_ID, b"\x77")
            return
        if sid == 0x31 and self.in_fblv and len(pdu) >= 4 and pdu[1] == 0x01:
            rid = (pdu[2] << 8) | pdu[3]
            if rid == 0x0202:
                blk = self.fblv_last_block
                if blk is None:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x31\x24")
                    return
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x31\x78")
                self.fblv_log.append(f"31_0202_{blk['bid']:02X}")
                if self.fblv_reject_rsa and blk["bid"] == 0x10:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x71\x01\x02\x02\x01")
                    return
                if blk["bid"] == 0x99:
                    self.fblv_driver_ok = len(pdu) == 4 + 128
                    self._enqueue_isotp(MRR_UDS_RX_ID, bytes([0x71, 0x01, 0x02, 0x02, 0x00 if self.fblv_driver_ok else 0x01]))
                    return
                if blk["bid"] == 0x10:
                    if len(pdu) != 4 + 128 + 4:
                        self._enqueue_isotp(MRR_UDS_RX_ID, b"\x71\x01\x02\x02\x01")
                        return
                    stream_b = bytes(blk["stream"])
                    plain_b = mrr_lzss_a0_decompress(stream_b, expected_size=blk["usize"]) if blk["fmt"] == 0xA0 else stream_b
                    expected_crc = int.from_bytes(pdu[132:136], "big")
                    import zlib as _zlib

                    crc_ok = len(plain_b) == blk["usize"] and (_zlib.crc32(plain_b) & 0xFFFFFFFF) == expected_crc
                    if crc_ok:
                        if MRR_BOOT_SIZE + len(plain_b) <= len(self.cflash):
                            self.cflash[MRR_BOOT_SIZE : MRR_BOOT_SIZE + len(plain_b)] = plain_b
                        self.fblv_app_ok = True
                        self._enqueue_isotp(MRR_UDS_RX_ID, b"\x71\x01\x02\x02\x00")
                    else:
                        self._enqueue_isotp(MRR_UDS_RX_ID, b"\x71\x01\x02\x02\x01")
                    return
            if rid == 0xFF00 and pdu[4:] == b"\x01\x10":
                if not self.fblv_driver_ok:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x31\x24")
                    return
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x31\x78")
                self.fblv_erased = True
                self.fblv_log.append("31_FF00_10")
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x71\x01\xff\x00\x00")
                return
            if rid == 0xFF01:
                self.fblv_deps_ok = bool(self.fblv_app_ok)
                self.fblv_log.append("31_FF01")
                self._enqueue_isotp(MRR_UDS_RX_ID, bytes([0x71, 0x01, 0xFF, 0x01, 0x00 if self.fblv_deps_ok else 0x01]))
                return
        if sid == 0x22 and len(pdu) >= 3:
            did = (pdu[1] << 8) | pdu[2]
            if self.in_fblv:
                if did == 0xF186:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x62\xf1\x86\x02")
                else:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x22\x31")
                return
            pn_map = {
                "0130": (b"3Q0907572A ", b"3Q0907572A ", b"0130", b"H03", b"MRR1Plus"),
                "0192": (b"3Q0907572B ", b"3Q0907572B ", b"0192", b"H04", b"MRR1Plus"),
                "0194": (b"3Q0907572C ", b"3Q0907572B ", b"0194", b"H04", b"MRR1Plus"),
                "0195": (b"3Q0907572B ", b"3Q0907572B ", b"0195", b"H04", b"MRR1Plus"),
                "0196": (b"3Q0907572C ", b"3Q0907572B ", b"0196", b"H04", b"MRR1Plus"),
                "0682": (b"3QF907561D ", b"3QF907561A ", b"0682", b"H10", b"MRRevo14F"),
                "X720": (b"5Q0907572M ", b"5Q0907572G ", b"X720", b"H11", b"MRRevo14F"),
                "0771": (b"5Q0907572R ", b"5Q0907572G ", b"0771", b"H12", b"MRRevo14F"),
                "0780": (b"5Q0907572S ", b"5Q0907572G ", b"0780", b"H12", b"MRRevo14F"),
            }
            pn, hwpn, swv, hwv, sys_name = pn_map.get(self.sw_profile, pn_map["0192"])
            is_gen2 = self.profile.get("mcu") == "MPC5675K"
            coding_0600 = (
                bytes.fromhex("320067c258ffc728949c810573400000000000000000000000")
                if is_gen2
                else bytes.fromhex("320067c258ffc728949c8105")
            )
            raw_3c00: bytes | None = None
            swap_cfg = self.profile.get("swap_config") or {}
            uds_3c00 = swap_cfg.get("uds_3c00") or {}
            if uds_3c00:
                if int(swap_cfg.get("generation") or 0) == 1:
                    d_pa = int(uds_3c00["data_pa"])
                    p_idx = mrr_decode_gen1_3c00_stub(bytes(self.cflash[d_pa : d_pa + 52]))
                    if p_idx is not None:
                        buf_3c = bytearray()
                        for idx_i, fsid_i in enumerate((0x10003100, 0x10003200, 0x10003300, 0x10003400, 0x10003600, 0x10003700, 0x10003800)):
                            buf_3c.extend(fsid_i.to_bytes(4, "big"))
                            buf_3c.append(0xFF if idx_i == p_idx else 0xB0)
                        raw_3c00 = bytes(buf_3c)
                elif int(swap_cfg.get("generation") or 0) == 2:
                    d_pa = int(uds_3c00["data_pa"])
                    grps = mrr_decode_gen2_3c00_read_stub(bytes(self.cflash[d_pa : d_pa + 56]))
                    if grps is not None:
                        buf_3c = bytearray()
                        for g_i, g_val in enumerate(grps):
                            if g_val > 0:
                                buf_3c.extend(bytes([0x10, 0x00, 0x90 + g_i, g_val, 0x4F]))
                        raw_3c00 = bytes(buf_3c)
            if raw_3c00 is None:
                if self.swap_3c00_entries:
                    raw_3c00 = b"".join(
                        int(fsid).to_bytes(4, "big") + bytes([int(st) & 0xFF])
                        for fsid, st in self.swap_3c00_entries
                    )
                else:
                    raw_3c00 = b"\x00\x00\x00\x00\x00"
            raw_3c05 = self.rsa_key_prefix + b"\x11" * (128 - len(self.rsa_key_prefix)) + b"\x00" * 31 + b"\x03"
            did_table: dict[int, bytes] = {
                0xF187: pn,
                0xF191: hwpn,
                0xF189: swv,
                0xF1A3: hwv,
                0xF197: sys_name,
                0xF17C: b"TST-00024.08.1514121275",
                0xF19E: b"EV_ACCBOSCHVW416",
                0x0600: coding_0600,
                0x03DE: (self.cp_counter & 0xFFFF).to_bytes(2, "big"),
                0x043F: b"\x80\x00",
                0x02F9: b"\x04\x4d\xf5\xe4\xae",
                0x0902: bytes([self.xcp_gate_byte]),
                MRR_SWAP_STATUS_DID: raw_3c00,
                MRR_SWAP_VCRN_DID: self.fes_vcrn,
                MRR_SWAP_RSA_KEY_DID: raw_3c05,
            }
            if did == 0x0440:
                flags = (0x01 if self.ika_virgin else 0x00) | (0x00 if self.gfa_learned else 0x02)
                self._enqueue_isotp(MRR_UDS_RX_ID, bytes([0x62, 0x04, 0x40, 0x05, 0x01, 0x03, 0x01, 0x07, 0x00, flags]))
                return
            if did in did_table:
                self._enqueue_isotp(MRR_UDS_RX_ID, bytes([0x62, pdu[1], pdu[2]]) + did_table[did])
                return
            self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x22\x31")
            return
        if sid == 0x2E and len(pdu) >= 3:
            did = (pdu[1] << 8) | pdu[2]
            val = pdu[3:]
            if did == 0xF15A and self.in_fblv and len(val) == 9:
                if not self.fblv_unlocked:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x2e\x33")
                    return
                self.fblv_fingerprint = val
                self.fblv_log.append("2E_F15A")
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x6e\xf1\x5a")
                return
            if did == 0xF198:
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x6e\xf1\x98")
                return
            if did == 0x0902 and len(val) == 1:
                if not self.sa_unlocked:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x2e\x33")
                    return
                self.xcp_gate_byte = val[0]
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x6e\x09\x02")
                return
            if did in (0x00BE, 0x00BD):
                if self.cp_counter >= 0x23:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x2e\x22")
                    return
                expected_type = MRR_CP_KEY_TYPE_IKA if did == 0x00BE else MRR_CP_KEY_TYPE_GFA
                try:
                    info = mrr_unpack_cp_key_container(bytes(self.ika), val)
                except ValueError:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x2e\x31")
                    return
                if info["key_type"] != expected_type or not info["valid_complement"] or not info["trailer_zero"]:
                    self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x2e\x31")
                    return
                new_key = bytes.fromhex(info["new_key_hex"])
                if did == 0x00BE:
                    self.ika[:] = new_key
                else:
                    self.gfa[:] = new_key
                    self.gfa_learned = True
                self.cp_counter = 0
                self._rebuild_dflash()
                self._enqueue_isotp(MRR_UDS_RX_ID, bytes([0x6E, pdu[1], pdu[2]]))
                return
            self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x2e\x31")

    def _on_xcp_frame(self, data: bytes) -> None:
        if not (self.xcp_gate_byte & 0x08):
            return

        # If a Fast RAM or Flash stream is active, consume 8-byte data frames on 0x1BFEBA00
        if self._stream_state is not None:
            st = self._stream_state
            st["buf"].extend(data[:8])
            st["batch_frames"] += 1
            if len(st["buf"]) >= st["total"] or st["batch_frames"] == 8:
                st["batch_frames"] = 0
                st["offset"] = min(st["total"], len(st["buf"]))
                if st["offset"] >= st["total"]:
                    payload = bytes(st["buf"][: st["total"]])
                    self._write_mem(st["addr"], payload)
                    if st["kind"] == "ram":
                        next_dst = (st["addr"] + st["total"]) & 0xFFFFFFFF
                        self._write_mem(MRR_DRIVER_CONTROL, next_dst.to_bytes(4, "big"))
                        self._write_mem(MRR_DRIVER_CONTROL + 0x60, (4).to_bytes(4, "big") + (0x55).to_bytes(4, "big"))
                    elif st["kind"] == "flash":
                        self.sector_writes.append((st["addr"], st["total"]))
                        self._write_mem(MRR_DRIVER_CONTROL + 0x30, b"\x00" * 8)
                        self._write_mem(MRR_DRIVER_CONTROL + 0x60, (12).to_bytes(4, "big") + (0x55).to_bytes(4, "big"))
                    self._stream_state = None
                    self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x00\x00\x00\x00\x00\x00\x00")
                else:
                    rem_val = (
                        (st["total"] - st["offset"])
                        if st["count_in_bytes"]
                        else ((st["total"] - st["offset"]) // 8)
                    )
                    ready = (st["addr"] + st["offset"]).to_bytes(4, "big") + rem_val.to_bytes(4, "big")
                    self._enqueue_frame(MRR_FAST_CAN_ID, ready)
            return

        cmd = data[0]
        if cmd == 0xFE:  # DISCONNECT
            self.xcp_connected = False
            self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x00\x00\x00\x00\x00\x00\x00")
            return
        if cmd == 0xFF:  # CONNECT
            self.xcp_connected = True
            self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x04\x80\x08\x08\x00\x01\x01")
            return
        if cmd == 0xFD:  # GET_STATUS
            prot = 0x00 if self.xcp_unlocked else 0x04
            self._enqueue_frame(MRR_XCP_RX_ID, bytes([0xFF, 0x00, prot, 0x00, 0x00, 0x00, 0x00, 0x00]))
            return
        if cmd == 0xF8:  # GET_SEED
            self._enqueue_frame(MRR_XCP_RX_ID, bytes([0xFF, 0x04]) + self.xcp_seed.to_bytes(4, "big") + b"\x00\x00")
            return
        if cmd == 0xF7:  # UNLOCK
            expected = mrr_xcp_compute_key(self.xcp_seed).to_bytes(4, "little")
            if data[2:6] == expected:
                self.xcp_unlocked = True
                self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x00\x00\x00\x00\x00\x00\x00")
            else:
                self._enqueue_frame(MRR_XCP_RX_ID, b"\xfe\x25\x00\x00\x00\x00\x00\x00")
            return
        if cmd == 0xF6:  # SET_MTA
            self.xcp_mta = int.from_bytes(data[4:8], "big")
            self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x00\x00\x00\x00\x00\x00\x00")
            return
        if cmd == 0xF5:  # UPLOAD
            n = data[1]
            chunk = self._read_mem(self.xcp_mta, n)
            self.xcp_mta = (self.xcp_mta + n) & 0xFFFFFFFF
            self._enqueue_frame(MRR_XCP_RX_ID, bytes([0xFF]) + chunk.ljust(7, b"\x00"))
            return
        if cmd == 0xF4:  # SHORT_UPLOAD
            n = data[1]
            addr = int.from_bytes(data[4:8], "big")
            chunk = self._read_mem(addr, n)
            self.xcp_mta = (addr + n) & 0xFFFFFFFF
            self._enqueue_frame(MRR_XCP_RX_ID, bytes([0xFF]) + chunk.ljust(7, b"\x00"))
            return
        if cmd == 0xF3:  # BUILD_CHECKSUM
            blk = int.from_bytes(data[4:8], "big")
            if blk > 0x0400:
                self._enqueue_frame(MRR_XCP_RX_ID, b"\xfe\x22\x00\x00\x00\x00\x04\x00")
                return
            raw = self._read_mem(self.xcp_mta, blk)
            csum = mrr_sum32_be(raw)
            self.xcp_mta = (self.xcp_mta + blk) & 0xFFFFFFFF
            self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x09\x00\x00" + csum.to_bytes(4, "big"))
            return
        if cmd == 0xF0:  # DOWNLOAD
            n = data[1]
            self._write_mem(self.xcp_mta, data[2 : 2 + n])
            self.xcp_mta = (self.xcp_mta + n) & 0xFFFFFFFF
            self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x00\x00\x00\x00\x00\x00\x00")
            return
        if cmd == 0xFC:  # SYNCH (dispatches via xcp_synch_slot)
            self._emulate_synch_dispatch()
            return

    def _emulate_synch_dispatch(self) -> None:
        synch_slot = int(self.profile.get("xcp_synch_slot") or 0)
        target_fn = int.from_bytes(self._read_mem(synch_slot, 4), "big") if synch_slot else 0
        mmu_wrapper = int(self.profile.get("mmu_dispatch_wrapper") or 0)

        if target_fn == mmu_wrapper:
            self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x00\x00\x00\x00\x00\x00\x00")
            return

        if target_fn == MRR_DRIVER_ADDRESS:
            drv_head = self._read_mem(MRR_DRIVER_ADDRESS, 64)
            if drv_head == MRR_FAST_READ_RAM_DRIVER[:64]:
                ctrl = self._read_mem(MRR_DRIVER_CONTROL, 8)
                src_addr = int.from_bytes(ctrl[0:4], "big")
                n_frames = int.from_bytes(ctrl[4:8], "big")
                payload = self._read_mem(src_addr, n_frames * 8)
                for off in range(0, len(payload), 8):
                    self._enqueue_frame(MRR_FAST_CAN_ID, payload[off : off + 8])
                next_addr = (src_addr + n_frames * 8) & 0xFFFFFFFF
                self._write_mem(MRR_DRIVER_CONTROL, next_addr.to_bytes(4, "big"))
                self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x00\x00\x00\x00\x00\x00\x00")
                return

            if drv_head == MRR_FAST_WRITE_RAM_DRIVER[:64]:
                ctrl = self._read_mem(MRR_DRIVER_CONTROL, 8)
                dst_addr = int.from_bytes(ctrl[0:4], "big")
                n_frames = int.from_bytes(ctrl[4:8], "big")
                total_bytes = n_frames * 8
                self._stream_state = {
                    "kind": "ram",
                    "addr": dst_addr,
                    "total": total_bytes,
                    "offset": 0,
                    "batch_frames": 0,
                    "count_in_bytes": False,
                    "buf": bytearray(),
                }
                ready = dst_addr.to_bytes(4, "big") + n_frames.to_bytes(4, "big")
                self._enqueue_frame(MRR_FAST_CAN_ID, ready)
                return

        if target_fn == MRR_FLASH_SECTOR_DRIVER_ADDR:
            ctrl = self._read_mem(MRR_DRIVER_CONTROL + 0x28, 8)
            sector_addr = int.from_bytes(ctrl[0:4], "big")
            sector_len = int.from_bytes(ctrl[4:8], "big")
            self._stream_state = {
                "kind": "flash",
                "addr": sector_addr,
                "total": sector_len,
                "offset": 0,
                "batch_frames": 0,
                "count_in_bytes": True,
                "buf": bytearray(),
            }
            ready = sector_addr.to_bytes(4, "big") + sector_len.to_bytes(4, "big")
            self._enqueue_frame(MRR_FAST_CAN_ID, ready)
            return

        self._enqueue_frame(MRR_XCP_RX_ID, b"\xfe\x00\x00\x00\x00\x00\x00\x00")


# ────────────────────────────── 1. Core Crypto & Binary Patching Tests ──────────────────────────────


def test_mrr_seed_key_algorithms_and_ecu_boot_sum() -> None:
    key = mrr_xcp_compute_key(0x3A7F91C2)
    assert isinstance(key, int) and 0 <= key <= 0xFFFFFFFF
    assert mrr_xcp_compute_key(1) != 1

    assert mrr_fblv_compute_key(0x12345678) != 0x12345678
    assert mrr_dev_compute_key(0x00001000, MRR_LOGIN_XCP_GATE) == 0x00001000 + 24085

    cflash = _build_synthetic_mrr_cflash("0192", full_image=True)
    bsum = mrr_compute_ecu_boot_sum(cflash[:MRR_BOOT_SIZE])
    assert len(bsum) == 16
    assert bsum == mrr_compute_ecu_boot_sum(cflash)


def test_mrr_cp_key_container_pack_and_unpack_roundtrip() -> None:
    cur_ika = bytes.fromhex("2f4b861d3a9c50e7b14d28f603a5c91e")
    new_gfa = bytes.fromhex("d4a17e09c35b821f6e409a2cd73b5804")
    new_ika = bytes.fromhex("112233445566778899aabbccddeeff00")

    gfa_cont = mrr_build_cp_key_container(cur_ika, new_gfa, key_type=MRR_CP_KEY_TYPE_GFA)
    assert len(gfa_cont) == 34
    assert gfa_cont[32:34] == b"\x02\x00"
    unpacked_gfa = mrr_unpack_cp_key_container(cur_ika, gfa_cont)
    assert unpacked_gfa["key_type"] == MRR_CP_KEY_TYPE_GFA
    assert unpacked_gfa["valid_complement"] is True
    assert unpacked_gfa["new_key_hex"] == new_gfa.hex()

    ika_cont = mrr_build_cp_key_container(cur_ika, new_ika, key_type=MRR_CP_KEY_TYPE_IKA)
    assert len(ika_cont) == 34
    assert ika_cont[32:34] == b"\x01\x00"
    unpacked_ika = mrr_unpack_cp_key_container(cur_ika, ika_cont)
    assert unpacked_ika["key_type"] == MRR_CP_KEY_TYPE_IKA
    assert unpacked_ika["valid_complement"] is True
    assert unpacked_ika["new_key_hex"] == new_ika.hex()

    bad_cont = bytearray(gfa_cont)
    bad_cont[31] ^= 0x01
    unpacked_bad = mrr_unpack_cp_key_container(cur_ika, bytes(bad_cont))
    assert unpacked_bad["valid_complement"] is False


def test_mrr_parse_dflash_fee_and_shadow_secret_fallback() -> None:
    ika = bytes.fromhex("2f4b861d3a9c50e7b14d28f603a5c91e")
    gfa = bytes.fromhex("d4a17e09c35b821f6e409a2cd73b5804")
    bsum = bytes.fromhex("8f911c6c7d1bfe78823a1ddebaaa0e82")

    dflash = _build_synthetic_mrr_dflash(ika=ika, gfa=gfa, ecu_boot_sum=bsum, cp_counter=0x001E, gfa_learned=True)
    parsed = mrr_parse_dflash_fee(dflash)
    assert parsed["ika_hex"] == ika.hex()
    assert parsed["gfa_hex"] == gfa.hex()
    assert parsed["ecu_boot_sum_hex"] == bsum.hex()
    assert parsed["encryption_scheme"] == "aes128-ecb-ecu-boot-sum"
    assert parsed["cp_counter"] == 0x001E
    assert parsed["gfa_learned"] is True

    # Virgin radar where Fee 0x2A is absent -> falls back to ShadowFlashSecret_t at +0xC000
    shadow_ika = bytes.fromhex("fedcba98765432100123456789abcdef")
    dflash_virgin = bytearray(b"\xff" * MRR_DFLASH_SIZE)
    w_sum = sum(int.from_bytes(shadow_ika[i : i + 4], "big") for i in range(0, 16, 4)) & 0xFFFFFFFF
    dflash_virgin[0xC000 : 0xC000 + 28] = (
        MRR_SHADOW_SECRET_MAGIC_A.to_bytes(4, "big")
        + shadow_ika
        + w_sum.to_bytes(4, "big")
        + MRR_SHADOW_SECRET_MAGIC_A.to_bytes(4, "big")
    )
    parsed_v = mrr_parse_dflash_fee(bytes(dflash_virgin))
    assert parsed_v["ika_hex"] == shadow_ika.hex()
    assert parsed_v["encryption_scheme"] == "shadow-flash-virgin"


@pytest.mark.parametrize("profile_code", ["0130", "0192", "0194", "0196", "0682", "X720", "0771", "0780"])
def test_mrr_cp_disable_patch_roundtrip_across_all_profiles(profile_code: str) -> None:
    for full_img in (True, False):
        stock_blob = _build_synthetic_mrr_cflash(profile_code, full_image=full_img)
        st0 = mrr_inspect_cflash_cp_state(stock_blob, profile=profile_code)
        assert st0["cp_patch_state"] == "stock"
        assert st0["sw"] == profile_code

        patched_blob, man_off = mrr_apply_cp_disable_patch(stock_blob, restore_stock=False, profile=profile_code)
        assert man_off["mode"] == "cp_disable"
        assert man_off["patch_count"] == 7
        assert man_off["changed_bytes"] > 0
        st1 = mrr_inspect_cflash_cp_state(patched_blob, profile=profile_code)
        assert st1["cp_patch_state"] == "cp_disabled"

        sectors = mrr_extract_cp_affected_sectors(patched_blob, profile=profile_code)
        assert len(sectors) == 2

        restored_blob, man_stock = mrr_apply_cp_disable_patch(patched_blob, restore_stock=True, profile=profile_code)
        assert man_stock["mode"] == "restore_stock"
        assert man_stock["patch_count"] == 7
        assert restored_blob == stock_blob


@pytest.mark.parametrize("profile_code", ["0130", "0192", "0194", "0196", "0682", "X720", "0771", "0780"])
def test_mrr_swap_patch_roundtrip_across_all_profiles(profile_code: str) -> None:
    prof = MRR_PROFILES[profile_code]
    gen = int(prof["swap_config"]["generation"])
    exp_pts, exp_bytes = mrr_get_swap_patch_stats(prof)
    assert exp_pts == (9 if gen == 1 else 22)
    assert exp_bytes == (80 if gen == 1 else 194)
    for full_img in (True, False):
        stock_blob = _build_synthetic_mrr_cflash(profile_code, full_image=full_img)
        st0 = mrr_inspect_cflash_swap_state(stock_blob, profile=profile_code)
        assert st0["swap_patch_state"] == "stock"
        assert st0["sw"] == profile_code
        assert st0["generation"] == gen
        assert st0["total_points"] == exp_pts

        if gen == 1:
            for pkg_idx in (0, 1, 2, 4, 5, 6):
                patched_blob, man_sw = mrr_apply_swap_patch(
                    stock_blob,
                    restore_stock=False,
                    profile=profile_code,
                    package_index=pkg_idx,
                )
                assert man_sw["mode"] == "swap_activate"
                assert man_sw["patch_count"] == 9
                assert man_sw["package_index"] == pkg_idx
                assert man_sw["active_fsids"] == [MRR_GEN1_SWAP_PACKAGES[pkg_idx]["fsid_hex"]]
                st1 = mrr_inspect_cflash_swap_state(patched_blob)
                assert st1["swap_patch_state"] == "swap_activated"
                assert st1["package_index"] == pkg_idx
                assert st1["feature_level"] == MRR_GEN1_SWAP_PACKAGES[pkg_idx]["level"]

                sectors = mrr_extract_swap_affected_sectors(patched_blob, profile=profile_code)
                assert [s[0] for s in sectors] == [a for a, _ in prof["swap_affected_sectors"]]

                restored_blob, man_rst = mrr_apply_swap_patch(
                    patched_blob, restore_stock=True, profile=profile_code
                )
                assert man_rst["mode"] == "restore_swap_stock"
                assert restored_blob == stock_blob
        else:
            for g_combo in ((3, 3, 4, 7), (2, 2, 2, 1), (0, 0, 0, 0)):
                patched_blob, man_sw = mrr_apply_swap_patch(
                    stock_blob,
                    restore_stock=False,
                    profile=profile_code,
                    groups=g_combo,
                )
                assert man_sw["mode"] == "swap_activate"
                assert man_sw["patch_count"] == 22
                assert tuple(man_sw["groups"]) == g_combo
                st1 = mrr_inspect_cflash_swap_state(patched_blob)
                assert st1["swap_patch_state"] == "swap_activated"
                assert tuple(st1["groups"]) == g_combo
                assert st1["coding_byte12_13_hex"] == mrr_describe_gen2_swap_groups(g_combo)["coding_byte12_13_hex"]

                sectors = mrr_extract_swap_affected_sectors(patched_blob, profile=profile_code)
                assert [s[0] for s in sectors] == [a for a, _ in prof["swap_affected_sectors"]]

                restored_blob, man_rst = mrr_apply_swap_patch(
                    patched_blob, restore_stock=True, profile=profile_code
                )
                assert man_rst["mode"] == "restore_swap_stock"
                assert restored_blob == stock_blob


def test_mrr_embedded_drivers_and_dtc_descriptions() -> None:
    assert len(MRR_FAST_READ_RAM_DRIVER) == 224
    assert len(MRR_FAST_WRITE_RAM_DRIVER) == 1264
    assert len(MRR_FLASH_SECTOR_WRITE_DRIVER) == 2188

    er_0192 = mrr_get_eraserouti_driver("0192")
    er_0780 = mrr_get_eraserouti_driver("0780")
    assert len(er_0192) == MRR_FLASH_DRIVER_SIZE
    assert len(er_0780) == MRR_FLASH_DRIVER_SIZE
    assert hashlib.sha256(er_0192).hexdigest() == MRR_PROFILES["0192"]["eraserouti_sha256"]
    assert hashlib.sha256(er_0780).hexdigest() == MRR_PROFILES["0780"]["eraserouti_sha256"]

    set_lang("ru")
    desc_ru = describe_mrr(0xEA6100)
    assert desc_ru is not None and desc_ru[0] == "U110100" and "Защита компонентов" in desc_ru[1]
    set_lang("en")
    desc_en = describe_mrr(0xEA6100)
    assert desc_en is not None and desc_en[0] == "U110100" and "Component protection" in desc_en[1]
    desc_align = describe_mrr(0x00010B)
    assert desc_align is not None and desc_align[0] == "C110300" and "misadjusted" in desc_align[1].lower()
    assert describe_mrr(0xD10000)[0] == "U110000"
    assert describe_mrr(0xD20000)[0] == "U111400"
    assert describe_mrr(0x000438)[0] == "U112100"
    assert describe_mrr(0x000713)[0] == "U101300"


# ────────────────────────────── 2. Simulated CAN & XCP Workflow Tests ──────────────────────────────


def test_can_mrr_status_and_read_keys_auto_opens_xcp_gate(tmp_path: Path) -> None:
    bus = FakeMrrBus(sw_profile="0192", cp_counter=0x001F, xcp_gate_open=False)

    st = can_mrr_status("fake", bus=bus)
    assert st["passport"]["part_number"] == "3Q0907572B"
    assert st["passport"]["sw_version"] == "0192"
    assert st["status"]["cp_counter"] == 0x001F
    assert st["status"]["cp_active"] is True
    assert st["status"]["xcp_gate_enabled"] is False

    s_dir = tmp_path / "mrr_keys_session"
    res = can_mrr_read_keys("fake", session_dir=s_dir, bus=bus)
    assert bus.xcp_gate_byte == 0x08
    assert bus.xcp_unlocked is True
    assert res["ika_hex"] == bus.ika.hex()
    assert res["gfa_hex"] == bus.gfa.hex()
    assert res["ecu_boot_sum_hex"] == bus.ecu_boot_sum.hex()
    assert (s_dir / "Dflash.bin").read_bytes() == bytes(bus.dflash)
    assert (s_dir / "mrr_keys.json").is_file()


def test_can_mrr_write_keys_auto_unlocks_lockout_and_binds_gfa() -> None:
    bus = FakeMrrBus(sw_profile="0780", cp_counter=0x0023, xcp_gate_open=False)
    new_gfa = bytes.fromhex("102030405060708090a0b0c0d0e0f001")
    new_ika = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")

    res = can_mrr_write_keys(
        "fake",
        current_ika=None,
        new_ika=new_ika.hex(),
        new_gfa=new_gfa.hex(),
        reset_after=True,
        bus=bus,
    )
    assert res["active_ika_hex"] == new_ika.hex()
    assert res["active_gfa_hex"] == new_gfa.hex()
    assert bytes(bus.ika) == new_ika
    assert bytes(bus.gfa) == new_gfa
    assert bus.cp_counter == 0
    assert bus.cp_active is False
    assert bus.dtcs == []
    assert bus.reset_count >= 1


def test_can_mrr_reset_cp_counter_clears_counter_and_dtcs() -> None:
    bus = FakeMrrBus(sw_profile="0192", cp_counter=0x001F, xcp_gate_open=True)
    assert len(bus.dtcs) == 2

    res = can_mrr_reset_cp_counter("fake", reset_after=False, bus=bus)
    assert res["sram_counter_after"] == 0
    assert res["status_after"]["cp_counter"] == 0
    assert bus.cp_counter == 0
    assert bus.cp_active is False
    assert bus.dtcs == []


def test_can_mrr_read_memory_fast_burst_and_standard_fallback(tmp_path: Path) -> None:
    bus_fast = FakeMrrBus(sw_profile="0192", xcp_gate_open=True)
    out_fast = tmp_path / "fast_dflash"
    res_fast = can_mrr_read_memory("fake", region="dflash", fast=True, session_dir=out_fast, bus=bus_fast)
    assert res_fast["mode"] == "xcp-fast-can-burst"
    assert (out_fast / "Dflash.bin").read_bytes() == bytes(bus_fast.dflash)

    # Standard XCP SHORT_UPLOAD
    lnk = MrrCanLink("fake", bus=bus_fast, sw_profile="0192")
    lnk.xcp_connect_and_unlock()
    small = lnk.xcp_read_memory(MRR_DFLASH_ADDR, 64)
    assert small == bytes(bus_fast.dflash[:64])


def test_can_mrr_deactivate_cp_and_restore_stock_live(tmp_path: Path) -> None:
    bus = FakeMrrBus(sw_profile="0192", cp_counter=0x001F, xcp_gate_open=False)
    assert mrr_inspect_cflash_cp_state(bytes(bus.cflash), profile="0192")["cp_patch_state"] == "stock"

    # 1. Deactivate CP live over CAN/XCP
    s_off = tmp_path / "cp_off_session"
    res_off = can_mrr_deactivate_cp("fake", session_dir=s_off, bus=bus)
    assert res_off["mode"] == "apply_cp_disable"
    assert len(bus.sector_writes) == 2
    assert mrr_inspect_cflash_cp_state(bytes(bus.cflash), profile="0192")["cp_patch_state"] == "cp_disabled"
    assert bus.cp_counter == 0
    assert bus.cp_active is False
    assert bus.dtcs == []

    # Re-running when already cp_disabled skips unchanged sectors
    res_noop = can_mrr_deactivate_cp("fake", session_dir=tmp_path / "cp_off_noop", bus=bus)
    assert all(s["skipped_unchanged"] is True for s in res_noop["flash_result"]["sectors"])

    # 2. Restore stock CP live over CAN/XCP
    s_rest = tmp_path / "cp_restore_session"
    res_rest = can_mrr_restore_cp_stock("fake", session_dir=s_rest, bus=bus)
    assert res_rest["mode"] == "restore_cp_stock"
    assert mrr_inspect_cflash_cp_state(bytes(bus.cflash), profile="0192")["cp_patch_state"] == "stock"


def test_can_mrr_activate_swap_and_restore_stock_live_gen1_and_gen2(tmp_path: Path) -> None:
    # Gen 1 (0194): activate SWaP package 6 (0x10003800 Level 6) and restore stock
    bus_g1 = FakeMrrBus(sw_profile="0194", cp_counter=0x0000, xcp_gate_open=True)
    res_g1_on = can_mrr_activate_swap(
        "fake",
        package_index=6,
        session_dir=tmp_path / "swap_g1_on",
        bus=bus_g1,
    )
    assert res_g1_on["mode"] == "apply_swap_activate"
    assert res_g1_on["generation"] == 1
    assert res_g1_on["cflash_swap"]["swap_patch_state"] == "swap_activated"
    assert res_g1_on["cflash_swap"]["package_index"] == 6
    assert res_g1_on["cflash_swap"]["active_fsids"] == ["10003800"]
    assert res_g1_on["cflash_swap"]["total_points"] == 9
    assert res_g1_on["swap_uds"]["active_fsids"] == ["10003800"]
    st_g1 = mrr_inspect_cflash_swap_state(bytes(bus_g1.cflash), profile="0194")
    assert st_g1["swap_patch_state"] == "swap_activated"
    assert st_g1["package_index"] == 6

    res_g1_rst = can_mrr_restore_swap_stock("fake", session_dir=tmp_path / "swap_g1_rst", bus=bus_g1)
    assert res_g1_rst["mode"] == "restore_swap_stock"
    assert mrr_inspect_cflash_swap_state(bytes(bus_g1.cflash), profile="0194")["swap_patch_state"] == "stock"

    # Gen 1 (0130 & 0196): verify live multi-sector (0130) & single-sector (0196) SWaP+3C00 activation
    for sw_g1 in ("0130", "0196"):
        bus_extra = FakeMrrBus(sw_profile=sw_g1, cp_counter=0x0000, xcp_gate_open=True)
        res_ex = can_mrr_activate_swap("fake", package_index=5, session_dir=tmp_path / f"swap_{sw_g1}", bus=bus_extra)
        assert res_ex["cflash_swap"]["swap_patch_state"] == "swap_activated"
        assert res_ex["cflash_swap"]["total_points"] == 9
        assert res_ex["swap_uds"]["active_fsids"] == ["10003700"]
        res_ex_rst = can_mrr_restore_swap_stock("fake", session_dir=tmp_path / f"swap_{sw_g1}_rst", bus=bus_extra)
        assert res_ex_rst["mode"] == "restore_swap_stock"
        assert mrr_inspect_cflash_swap_state(bytes(bus_extra.cflash), profile=sw_g1)["swap_patch_state"] == "stock"

    # Gen 2 (0780): deactivate CP AND activate SWaP 4-group set (3, 3, 4, 7) and restore stock
    bus_g2 = FakeMrrBus(sw_profile="0780", cp_counter=0x001F, xcp_gate_open=False)
    res_g2_cp = can_mrr_deactivate_cp("fake", session_dir=tmp_path / "cp_g2_off", bus=bus_g2)
    assert res_g2_cp["cp_patch_state"] == "cp_disabled"
    assert mrr_inspect_cflash_cp_state(bytes(bus_g2.cflash), profile="0780")["cp_patch_state"] == "cp_disabled"

    res_g2_sw = can_mrr_activate_swap(
        "fake",
        groups=(3, 3, 4, 7),
        session_dir=tmp_path / "swap_g2_on",
        bus=bus_g2,
    )
    assert res_g2_sw["mode"] == "apply_swap_activate"
    assert res_g2_sw["generation"] == 2
    assert res_g2_sw["cflash_swap"]["swap_patch_state"] == "swap_activated"
    assert res_g2_sw["cflash_swap"]["total_points"] == 22
    assert res_g2_sw["cflash_swap"]["groups"] == [3, 3, 4, 7]
    assert res_g2_sw["cflash_swap"]["active_fsids"] == ["10009003", "10009103", "10009204", "10009307"]
    assert res_g2_sw["swap_uds"]["active_fsids"] == ["10009003", "10009103", "10009204", "10009307"]
    st_g2 = mrr_inspect_cflash_swap_state(bytes(bus_g2.cflash), profile="0780")
    assert st_g2["swap_patch_state"] == "swap_activated"
    assert st_g2["groups"] == [3, 3, 4, 7]

    res_g2_rst = can_mrr_restore_swap_stock("fake", session_dir=tmp_path / "swap_g2_rst", bus=bus_g2)
    assert res_g2_rst["mode"] == "restore_swap_stock"
    assert mrr_inspect_cflash_swap_state(bytes(bus_g2.cflash), profile="0780")["swap_patch_state"] == "stock"


def test_can_scan_bus_discovers_mrr_and_reads_mrr_dtcs(monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.can import FoundAdapter, can_identify
    from contitool.gui import connection
    from contitool.gui.app import create_window

    bus = FakeMrrBus(sw_profile="0192", cp_counter=0x001F)

    # 1. can_identify in auto and mrr mode detects 13 ACC Radar (0x757 -> 0x7C1)
    ident_auto = can_identify("fake", interface="slcan", bus=bus)
    assert ident_auto["responding"] is True
    assert ident_auto["ecu_kind"] == "mrr"
    assert ident_auto["diag_addr"] == "13"
    assert ident_auto["uds_tx_id"] == "0x757"
    assert ident_auto["uds_rx_id"] == "0x7C1"
    assert not ident_auto.get("unsupported")
    vals = {it["did"]: it["value"] for it in ident_auto["ident"]}
    assert vals["F187"] == "3Q0907572B"

    ident_mrr = can_identify("fake", interface="slcan", target="mrr", bus=bus)
    assert ident_mrr["ecu_kind"] == "mrr"

    # 2. ConnectionDialog "Проверить связь" passes with green "ok" tone and "[13 ACC]" tag
    set_lang("ru")
    app, win = create_window()
    monkeypatch.setattr(
        connection,
        "discover_adapters",
        lambda: [FoundAdapter("slcan", "/dev/cu.usbmodem1101", "CANable2", "SLCAN")],
    )
    monkeypatch.setattr(
        connection,
        "can_identify",
        lambda port, *, interface="slcan", reporter=None: can_identify(
            port, interface=interface, bus=bus, reporter=reporter
        ),
    )
    dlg = connection.ConnectionDialog(win.conn, win)
    while dlg._scan is not None:
        dlg._scan.wait(3000)
        app.processEvents()
    loop = QEventLoop()
    dlg._check_link()
    dlg._check.finished.connect(loop.quit)
    QTimer.singleShot(3000, loop.quit)
    loop.exec()
    for _ in range(10):
        app.processEvents()
    assert dlg.lbl_check.property("tone") == "ok"
    assert "13 ACC" in dlg.lbl_check.text()
    assert "3Q0907572B" in dlg.lbl_check.text()
    dlg.close()
    win.close()

    # 3. can_scan_bus and can_uds_read_dtc
    scan = can_scan_bus("fake", target_kind="mrr", bus=bus)
    assert scan.topology == "direct"
    assert [e.kind for e in scan.ecus] == ["mrr"]
    ecu = scan.ecus[0]
    assert ecu.diag_addr == "13"
    assert ecu.part_number == "3Q0907572B"
    assert ecu.memory_access_available is True

    dtcs = can_uds_read_dtc("fake", MRR_UDS_TX_ID, MRR_UDS_RX_ID, ecu_kind="mrr", bus=bus)
    assert len(dtcs["dtcs"]) == 2
    assert any(d["code"] == "0xEA6100" and d["display"] == "U110100" for d in dtcs["dtcs"])


# ────────────────────────────── 3. CLI & Headless Qt 6 GUI Tests ──────────────────────────────


def test_cli_mrr_subcommands(tmp_path: Path, capsys) -> None:
    import importlib

    cli_main = importlib.import_module("contitool.cli.main")

    dflash_path = tmp_path / "Dflash.bin"
    dflash_path.write_bytes(_build_synthetic_mrr_dflash())

    cflash_path = tmp_path / "CodeFlash_0192.bin"
    cflash_path.write_bytes(_build_synthetic_mrr_cflash("0192", full_image=True))
    patched_path = tmp_path / "CodeFlash_0192_cp_off.bin"

    ap = cli_main.build_arg_parser()

    # 1. contitool mrr inspect --dflash <Dflash.bin>
    ns_ins = ap.parse_args(["mrr", "inspect", "--dflash", str(dflash_path)])
    assert cli_main.cmd_mrr(ns_ins) == 0
    out_ins = json.loads(capsys.readouterr().out)
    assert out_ins["dflash_fee"]["ika_hex"] == "2f4b861d3a9c50e7b14d28f603a5c91e"
    assert out_ins["dflash_fee"]["gfa_hex"] == "d4a17e09c35b821f6e409a2cd73b5804"

    # 2. contitool mrr patch-cp --cflash <CodeFlash> --output <patched>
    ns_pat = ap.parse_args(["mrr", "patch-cp", "--cflash", str(cflash_path), "--output", str(patched_path)])
    assert cli_main.cmd_mrr(ns_pat) == 0
    out_pat = json.loads(capsys.readouterr().out)
    assert out_pat["mode"] == "cp_disable"
    assert out_pat["patch_count"] == 7
    assert mrr_inspect_cflash_cp_state(patched_path.read_bytes())["cp_patch_state"] == "cp_disabled"

    # 3. contitool mrr patch-swap (Gen 1 package 6 and Gen 2 groups 2,2,2,1) + mrr inspect
    swap_g1_path = tmp_path / "CodeFlash_0192_swap_on.bin"
    ns_sw1 = ap.parse_args(
        ["mrr", "patch-swap", "--cflash", str(cflash_path), "--swap-package", "6", "--output", str(swap_g1_path)]
    )
    assert cli_main.cmd_mrr(ns_sw1) == 0
    out_sw1 = json.loads(capsys.readouterr().out)
    assert out_sw1["mode"] == "swap_activate"
    assert out_sw1["package_index"] == 6
    assert out_sw1["active_fsids"] == ["10003800"]

    cflash_0780_path = tmp_path / "CodeFlash_0780.bin"
    cflash_0780_path.write_bytes(_build_synthetic_mrr_cflash("0780", full_image=True))
    swap_g2_path = tmp_path / "CodeFlash_0780_swap_on.bin"
    ns_sw2 = ap.parse_args(
        ["mrr", "patch-swap", "--cflash", str(cflash_0780_path), "--swap-groups", "2,2,2,1", "--output", str(swap_g2_path)]
    )
    assert cli_main.cmd_mrr(ns_sw2) == 0
    out_sw2 = json.loads(capsys.readouterr().out)
    assert out_sw2["mode"] == "swap_activate"
    assert out_sw2["groups"] == [2, 2, 2, 1]
    assert out_sw2["active_fsids"] == ["10009002", "10009102", "10009202", "10009301"]

    ns_ins_cf = ap.parse_args(["mrr", "inspect", "--cflash", str(swap_g2_path)])
    assert cli_main.cmd_mrr(ns_ins_cf) == 0
    out_ins_cf = json.loads(capsys.readouterr().out)
    assert out_ins_cf["cflash_swap"]["swap_patch_state"] == "swap_activated"
    assert out_ins_cf["cflash_swap"]["groups"] == [2, 2, 2, 1]


def test_gui_mrr_screen_tabs_and_window_integration(tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.can import can_identify
    from contitool.gui import main_window
    from contitool.gui.app import create_window

    set_lang("ru")
    app, win = create_window()
    win.conn.out_dir = tmp_path
    win.show()

    # StartScreen target selection supports "mrr"
    win.start_screen.set_target_kind("mrr")
    app.processEvents()
    assert win.start_screen._target_kind == "mrr"
    assert win.start_screen.btn_read.isVisible() is True

    # Test _read_mrr_over_can end-to-end via MainWindow
    fake_bus = FakeMrrBus(sw_profile="0192", cp_counter=0x0000, xcp_gate_open=True)
    real_read_keys = main_window.can_mrr_read_keys
    real_read_dtc = main_window.can_uds_read_dtc
    monkeypatch.setattr(
        main_window,
        "can_mrr_read_keys",
        lambda port, **kw: real_read_keys(port, bus=fake_bus, **kw),
    )
    monkeypatch.setattr(
        main_window,
        "can_uds_read_dtc",
        lambda port, tx, rx, **kw: real_read_dtc(port, tx, rx, bus=fake_bus, **kw),
    )
    ident = can_identify("fake", target="mrr", bus=fake_bus)
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    win._read_mrr_over_can(ident)
    QTimer.singleShot(5000, loop.quit)
    loop.exec()
    for _ in range(10):
        app.processEvents()
    assert win.runner.last_failure is None
    assert win.stack.currentWidget() is win.mrr_screen
    assert win.mrr_screen.is_open is True
    assert win.mrr_screen._cflash_cp.get("cp_patch_state") == "stock"
    assert win.mrr_screen._ika_hex == fake_bus.ika.hex()
    assert win.mrr_screen._gfa_hex == fake_bus.gfa.hex()

    # Open MrrScreen with initial passport, status, and keys
    win.mrr_screen.open_from_status_result(
        {
            "passport": {
                "part_number": "3Q0907572B",
                "sw_version": "0192",
                "hw_part_number": "3Q0907572B",
                "hw_version": "H04",
                "fazit": "TST-00024.08.1514121275",
                "asam_odx": "EV_ACCBOSCHVW416",
            },
            "status": mrr_decode_status_dids(
                {
                    "03DE": "0000",
                    "0440": "05010301070000",
                    "0902": "08",
                }
            ),
        }
    )
    win.mrr_screen._on_keys_read(
        {
            "ika_hex": "2f4b861d3a9c50e7b14d28f603a5c91e",
            "gfa_hex": "d4a17e09c35b821f6e409a2cd73b5804",
            "ecu_boot_sum_hex": "8f911c6c7d1bfe78823a1ddebaaa0e82",
        }
    )
    win.switch_ecu_view("mrr")
    app.processEvents()
    assert win.stack.currentWidget() is win.mrr_screen
    assert win._is_mrr_active() is True

    # Navigate across all 4 MrrScreen pages ("cp_keys", "memory", "status", "dtc")
    for idx in range(win.mrr_screen.nav.count()):
        item = win.mrr_screen.nav.item(idx)
        if item.flags() & item.flags().ItemIsSelectable:
            win.mrr_screen.nav.setCurrentRow(idx)
            app.processEvents()

    # Terminal auto-selects 757 / 7C1 when MrrScreen is active
    win.set_mode("terminal")
    app.processEvents()
    assert win.terminal.ed_tx.text() == "757"
    assert win.terminal.ed_rx.text() == "7C1"
    win.set_mode("work")
    app.processEvents()

    # Language switch RU <-> EN
    win._lang_buttons["en"].click()
    app.processEvents()
    win._lang_buttons["ru"].click()
    app.processEvents()

    win.mrr_screen.close_mrr()
    app.processEvents()
    assert win.mrr_screen.is_open is False
    win.close()


# ────────────────────────────── 4. Security, Protocol & UX Regression Tests ──────────────────────────────


def test_mrr_unknown_sw_and_dump_return_unverified_readonly_profile() -> None:
    prof_sw = mrr_detect_profile({"part_number": "3Q0907572B", "sw_version": "0195"})
    assert prof_sw["verified"] is False
    assert prof_sw["flash_write_supported"] is False
    assert prof_sw["fast_driver_supported"] is False
    assert prof_sw["sram_auth_success_trigger_addr"] is None
    assert prof_sw["patches"] == ()

    blank_img = b"\xff" * 0x180000
    prof_bin = mrr_detect_profile(image_bytes=blank_img)
    assert prof_bin["verified"] is False
    assert prof_bin["flash_write_supported"] is False
    st = mrr_inspect_cflash_cp_state(blank_img)
    assert st["cp_patch_state"] == "unsupported_sw"
    with pytest.raises(ValueError):
        mrr_apply_cp_disable_patch(blank_img)


def test_mrr_fee_dual_cluster_swap_copy_order_and_virgin_shadow() -> None:
    ika_old = bytes.fromhex("11111111111111111111111111111111")
    gfa_old = bytes.fromhex("22222222222222222222222222222222")
    ika_new = bytes.fromhex("33333333333333333333333333333333")
    gfa_new = bytes.fromhex("44444444444444444444444444444444")
    bsum = bytes.fromhex("8f911c6c7d1bfe78823a1ddebaaa0e82")

    # Active cluster 0 has higher erase cycle (0x000385) with fewer entries than obsolete cluster 1 (0x000384)
    c0 = bytearray(_build_synthetic_mrr_dflash(ika=ika_new, gfa=gfa_new, ecu_boot_sum=bsum, cp_counter=0))
    c1 = bytearray(_build_synthetic_mrr_dflash(ika=ika_old, gfa=gfa_old, ecu_boot_sum=bsum, cp_counter=0x001F))
    # Write real 24-byte Fee headers: cycle 0x000385 on cluster 0 (unfinalized), cycle 0x000384 on cluster 1 (finalized)
    c0[0:24] = bytes.fromhex("6a00038500000000ffffffffffffffffa5a5a5a500000000")
    # Put cluster 1 into 0x8000..0xFFFF and add extra dummy entries so cluster 1 has MORE directory entries
    c0[0x8000:0x10000] = c1[0x0000:0x8000]
    c0[0x8000 : 0x8000 + 24] = bytes.fromhex("77000384000000007700038400000000a5a5a5a500000000")
    for extra_i in range(10):
        off = 0xFF00 - extra_i * 8
        c0[off : off + 8] = struct.pack(">HBBI", 0x0200 + extra_i * 8, 0x30 + extra_i, 0x00, 0x00000000)

    parsed = mrr_parse_dflash_fee(bytes(c0))
    assert parsed["active_cluster_offset"] == "0x0000"
    assert parsed["ika_hex"] == ika_new.hex()
    assert parsed["gfa_hex"] == gfa_new.hex()
    assert parsed["cp_counter"] == 0

    # Virgin DFLASH: Fee has 0x2B/0x2C/0x2D/0x40 but NO 0x2A; shadow secret at +0xC000 must still supply IKA
    shadow_ika = bytes.fromhex("abcdef0123456789fedcba9876543210")
    df_virgin = _build_synthetic_mrr_dflash(
        ika=ika_old,
        gfa=gfa_new,
        ecu_boot_sum=bsum,
        include_fee_ika=False,
        shadow_ika=shadow_ika,
    )
    parsed_v = mrr_parse_dflash_fee(df_virgin)
    assert parsed_v["ika_hex"] == shadow_ika.hex()
    assert parsed_v["gfa_hex"] == gfa_new.hex()


def test_mrr_empty_status_dids_xcp_gate_bit_preservation_and_bridge_guard() -> None:
    # C4: empty DID dict reports cp_active=None (not False)
    dec = mrr_decode_status_dids({})
    assert dec["cp_active"] is None

    # H6: enable_xcp_gate_uds preserves pre-existing bits in DID 0x0902
    bus = FakeMrrBus(sw_profile="0192", xcp_gate_open=False)
    bus.xcp_gate_byte = 0x51  # pre-existing non-XCP flags
    lnk = MrrCanLink("fake", bus=bus, sw_profile="0192")
    gate_res = lnk.enable_xcp_gate_uds()
    assert gate_res["xcp_gate_enabled"] is True
    assert gate_res["did_0902_hex"] == "59"
    assert bus.xcp_gate_byte == 0x59  # 0x51 | 0x08

    # C1: refuse live flash write on unverified SW profile (e.g. 0195)
    bus_195 = FakeMrrBus(sw_profile="0195", xcp_gate_open=True)
    with pytest.raises(RuntimeError, match="0195"):
        can_mrr_deactivate_cp("fake", bus=bus_195)
    with pytest.raises(RuntimeError, match="0195"):
        can_mrr_activate_swap("fake", bus=bus_195)

    # H1: via_gateway=True with gateway_bridge=False rejects XCP operations explicitly
    with pytest.raises(RuntimeError, match="RAM-мост|RAM-Bridge"):
        can_mrr_read_keys("fake", via_gateway=True, gateway_bridge=False)


def test_cli_mrr_safety_guards_and_validation(tmp_path: Path) -> None:
    import importlib

    cli_main = importlib.import_module("contitool.cli.main")
    ap = cli_main.build_arg_parser()

    # C5: cp-off, cp-restore, swap-on, and swap-restore require --yes
    for act in ("cp-off", "cp-restore", "swap-on", "swap-restore"):
        ns_act = ap.parse_args(["mrr", act, "--port", "fake"])
        with pytest.raises(ValueError, match="--yes"):
            cli_main.cmd_mrr(ns_act)

    # M7: --address requires --length and vice versa
    ns_addr = ap.parse_args(["mrr", "read-mem", "--port", "fake", "--address", "0x800000"])
    with pytest.raises(ValueError, match="--address|--length"):
        cli_main.cmd_mrr(ns_addr)

    # M7: -o cannot be used with --region all
    ns_all_o = ap.parse_args(["mrr", "read-mem", "--port", "fake", "--region", "all", "-o", str(tmp_path / "x.bin")])
    with pytest.raises(ValueError, match="--region all"):
        cli_main.cmd_mrr(ns_all_o)


def test_gui_mrr_clear_dtc_offline_isolation_and_close_fallback(tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QTimer

    from contitool.gui.app import create_window
    from contitool.gui.screens import mrr as mrr_mod

    set_lang("ru")
    app, win = create_window()
    win.conn.out_dir = tmp_path
    win.conn.port = "fake"
    win.conn.interface = "slcan"
    win.conn.wiring_confirmed = True

    bus = FakeMrrBus(sw_profile="0192", cp_counter=0x001F, xcp_gate_open=True)
    real_clr = mrr_mod.can_uds_clear_dtc
    real_rd = mrr_mod.can_uds_read_dtc
    monkeypatch.setattr(mrr_mod, "can_uds_clear_dtc", lambda port, tx, rx, **kw: real_clr(port, tx, rx, bus=bus, **kw))
    monkeypatch.setattr(mrr_mod, "can_uds_read_dtc", lambda port, tx, rx, **kw: real_rd(port, tx, rx, bus=bus, **kw))

    # Open MRR with live stock status and 2 DTCs
    win.mrr_screen.open_from_status_result(
        {
            "passport": {"part_number": "3Q0907572B", "sw_version": "0192"},
            "status": mrr_decode_status_dids({"03DE": "001F", "0440": "05010301070000", "0902": "08"}),
            "cflash_cp": {"cp_patch_state": "stock", "patched_points": 0, "total_points": 7},
            "dtcs": [{"code": "0xEA6100", "display": "U110100", "active": True, "description": "CP"}],
        }
    )
    assert len(win.mrr_screen._dtcs or []) == 1

    # H2: action_clear_dtc clears and re-reads inside ONE background task without runner.is_busy error
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    win.mrr_screen.action_clear_dtc()
    QTimer.singleShot(5000, loop.quit)
    loop.exec()
    for _ in range(10):
        app.processEvents()
    assert win.runner.last_failure is None
    assert win.mrr_screen._dtcs == []

    # H3: Memory page no longer has the removed offline dump/patch card
    win.mrr_screen.select("memory")
    app.processEvents()
    mem_labels = [lbl.text() for lbl in win.mrr_screen.page_area.widget().findChildren(type(win.mrr_screen.lbl_pn))]
    assert not any("Офлайн-разбор" in t for t in mem_labels)

    # H7: closing resets _profile_override
    win.mrr_screen._on_profile_changed("0780")
    assert win.mrr_screen._profile_override == "0780"
    win.mrr_screen.close_mrr()
    assert win.mrr_screen._profile_override == ""

    # M4: opening offline MRR dump via MainWindow._load_paths loads state directly into MrrScreen
    patched_blob, _ = mrr_apply_cp_disable_patch(_build_synthetic_mrr_cflash("0192"), profile="0192")
    off_dir = tmp_path / "3Q0907572B_TST-00024.08.1514121275" / "dumps" / "2026-11-25_08-30-00_mrr_all"
    off_dir.mkdir(parents=True)
    off_file = off_dir / "Cflash.bin"
    off_file.write_bytes(patched_blob)
    win._load_paths([off_file])
    app.processEvents()
    assert win.mrr_screen.is_open is True
    assert win.stack.currentWidget() is win.mrr_screen
    assert win.mrr_screen._cflash_cp.get("cp_patch_state") == "cp_disabled"
    assert win.mrr_screen._offline_mode is True

    # M4: closing BCM falls back to open MRR screen
    win.bcm_screen._is_open = True
    win._active_screen = "bcm"
    win.close_ecu()
    assert win._active_screen == "mrr"
    assert win.stack.currentWidget() is win.mrr_screen

    win.close()


def test_mrr_swap_status_uds_gen1_gen2_cli_and_gateway_readonly(monkeypatch, capsys) -> None:
    import importlib

    cli_main = importlib.import_module("contitool.cli.main")

    # 1. Core status byte & UDS payload parser (active, empty, rejected with VCRN + signature)
    assert mrr_decode_swap_status_byte(0x4F)["state"] == "active"
    assert mrr_decode_swap_status_byte(0xFF)["state"] == "active"
    assert mrr_decode_swap_status_byte(0xB0)["state"] == "not_activated"
    rej = mrr_decode_swap_status_byte(0x0B)  # bit 0=1, bit 1=1, bit 2=0 (VCRN), bit 3=1, bit 6=0 (signature)
    assert rej["state"] == "rejected"
    assert "VCRN" in rej["reason_en"]
    assert "signature" in rej["reason_en"]
    # Verify binary-proved Gen 1 (0192 0x0015893C/998/9CC) & Gen 2 (0780 0x00097B4E/B98/BD6, 0x0006245E) FS-ID labels
    assert "ACC Low 160" in mrr_fsid_label(0x10003100)[1] and "Basis-ACC" in mrr_fsid_label(0x10003100)[1]
    assert "ACC Low 160" in mrr_fsid_label(0x10003200)[1] and "Follow-to-Stop" in mrr_fsid_label(0x10003200)[1]
    assert "ACC Low 160" in mrr_fsid_label(0x10003300)[1] and "Stop & Go" in mrr_fsid_label(0x10003300)[1]
    assert "no ACC" in mrr_fsid_label(0x10003400)[1]
    assert "ACC High 210" in mrr_fsid_label(0x10003600)[1] and "Basis-ACC" in mrr_fsid_label(0x10003600)[1]
    assert "ACC High 210" in mrr_fsid_label(0x10003700)[1] and "Follow-to-Stop" in mrr_fsid_label(0x10003700)[1]
    assert "ACC High 210" in mrr_fsid_label(0x10003800)[1] and "Stop & Go" in mrr_fsid_label(0x10003800)[1]
    assert "ACC Low 160" in mrr_fsid_label(0x10009001)[1] and "Basis-ACC" in mrr_fsid_label(0x10009001)[1]
    assert "ACC High 210" in mrr_fsid_label(0x10009008)[1] and "Stop & Go" in mrr_fsid_label(0x10009008)[1]
    assert "pACC" in mrr_fsid_label(0x10009103)[1]
    assert "visual & audible" in mrr_fsid_label(0x10009201)[1]
    assert "no Pedestrian" in mrr_fsid_label(0x10009203)[1]
    assert "vFGS" in mrr_fsid_label(0x10009204)[1]
    assert "Gegenverkehr" in mrr_fsid_label(0x10009303)[1]
    assert "Turn-off" in mrr_fsid_label(0x10009306)[1] and "Emergency" in mrr_fsid_label(0x10009306)[1]
    assert "CityANB" in mrr_fsid_label(0x10003500)[1]
    assert "vRFS" in mrr_fsid_label(0x10009205)[1]
    assert "VZE" in mrr_fsid_label(0x10009500)[1]
    assert "FCWP" in mrr_fsid_label(0x10009600)[1]

    empty_parsed = mrr_parse_swap_uds_response(b"\x00\x00\x00\x00\x00", raw_3c0a=b"\xff" * 5)
    assert empty_parsed["active_count"] == 0
    assert empty_parsed["features"] == []
    assert empty_parsed["fes_vcrn_virgin"] is True

    # 2. Live UDS 22 3C 00 on Gen 1 (0192) — including via_gateway=True WITHOUT RAM-Bridge!
    bus_g1 = FakeMrrBus(
        sw_profile="0192",
        swap_3c00_entries=[(0x10003700, 0x4F), (0x10003800, 0x0B)],
        fes_vcrn=bytes.fromhex("1122334455"),
    )
    res_g1 = can_mrr_swap_status("fake", bus=bus_g1, via_gateway=True, gateway_bridge=False)
    assert res_g1["generation"] == 1
    assert res_g1["gateway_bridged"] is False
    sw1 = res_g1["swap_uds"]
    assert sw1["active_fsids"] == ["10003700"]
    assert sw1["rejected_fsids"] == ["10003800"]
    assert sw1["fes_vcrn_hex"] == "1122334455"
    assert "coding_groups" not in sw1  # Gen 1 coding is 12..24B and must NOT be decoded as Gen 2 Byte 12..13

    # 3. Live UDS 22 3C 00 on Gen 2 (X720 dev RSA key & 0780 series RSA key + coding Byte 12..13)
    bus_x720 = FakeMrrBus(sw_profile="X720", swap_3c00_entries=[(0x10009007, 0x4F), (0x10009103, 0x4F)])
    res_x720 = can_mrr_swap_status("fake", bus=bus_x720)
    assert res_x720["generation"] == 2
    assert res_x720["swap_uds"]["rsa_key_kind"] == "dev_x720"
    assert res_x720["swap_uds"]["coding_byte12_13_hex"] == "7340"
    assert res_x720["swap_uds"]["coding_groups"] == [7, 3, 4, 0]

    bus_0780 = FakeMrrBus(sw_profile="0780", swap_3c00_entries=[])
    res_0780 = can_mrr_swap_status("fake", bus=bus_0780)
    assert res_0780["swap_uds"]["rsa_key_kind"] == "series_0780"
    assert res_0780["swap_uds"]["active_count"] == 0
    assert res_0780["swap_uds"]["did_3c00_hex"] == "0000000000"

    # 4. CLI `mrr swap-status` works read-only without --yes
    monkeypatch.setattr(cli_main, "can_mrr_swap_status", lambda port, **kw: can_mrr_swap_status(port, bus=bus_g1, **kw))
    ap = cli_main.build_arg_parser()
    ns = ap.parse_args(["mrr", "swap-status", "--port", "fake"])
    assert cli_main.cmd_mrr(ns) == 0
    out_cli = json.loads(capsys.readouterr().out)
    assert out_cli["swap_uds"]["active_fsids"] == ["10003700"]
    assert out_cli["swap_uds"]["rejected_fsids"] == ["10003800"]


def test_gui_mrr_inplace_points_toggle_swap_uds_and_recent_ecus(tmp_path: Path, monkeypatch) -> None:
    from PySide6.QtCore import QEventLoop, QSettings, QTimer

    from contitool.can import can_identify
    from contitool.gui import main_window
    from contitool.gui.app import create_window
    from contitool.gui.screens import mrr as mrr_mod
    from contitool.gui.screens.start import _summarize_recent_folder
    from contitool.gui.workspace import recent_folders

    set_lang("ru")
    QSettings().setValue("workspace/recent", [])
    app, win = create_window()
    win.conn.out_dir = tmp_path
    win.conn.port = "fake"
    win.conn.interface = "slcan"
    win.conn.wiring_confirmed = True
    win.show()

    bus = FakeMrrBus(
        sw_profile="0192",
        cp_counter=0x0000,
        xcp_gate_open=True,
        swap_3c00_entries=[(0x10003700, 0x4F)],
    )
    real_read_keys = main_window.can_mrr_read_keys
    real_read_dtc = main_window.can_uds_read_dtc
    real_swap_uds = mrr_mod.can_mrr_swap_status
    real_read_mem = mrr_mod.can_mrr_read_memory
    monkeypatch.setattr(main_window, "can_mrr_read_keys", lambda port, **kw: real_read_keys(port, bus=bus, **kw))
    monkeypatch.setattr(main_window, "can_uds_read_dtc", lambda port, tx, rx, **kw: real_read_dtc(port, tx, rx, bus=bus, **kw))
    monkeypatch.setattr(mrr_mod, "can_mrr_swap_status", lambda port, **kw: real_swap_uds(port, bus=bus, **kw))
    monkeypatch.setattr(mrr_mod, "can_mrr_read_memory", lambda port, **kw: real_read_mem(port, bus=bus, **kw))

    # 1. Initial radar read saves dump under <part>_<fazit>/dumps/ and registers in "Недавние блоки"
    ident = can_identify("fake", target="mrr", bus=bus)
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    win._read_mrr_over_can(ident)
    QTimer.singleShot(5000, loop.quit)
    loop.exec()
    for _ in range(10):
        app.processEvents()
    assert win.runner.last_failure is None
    recents = recent_folders()
    assert len(recents) >= 1
    first_dir = recents[0]
    assert (first_dir / "Dflash.bin").is_file()
    assert (first_dir / "mrr_keys.json").is_file()
    meta = _summarize_recent_folder(first_dir)
    assert meta["addr"] == "13"
    assert meta["title"] == "3Q0907572B"
    assert "DF 64K" in meta["tags"]

    # 2. _swap_uds is already populated from initial read, and action_read_swap_uds refreshes it cleanly
    assert win.mrr_screen._swap_uds.get("active_fsids") == ["10003700"]
    bus.swap_3c00_entries = [(0x10003700, 0x4F), (0x10003800, 0x0B)]
    loop2 = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop2.quit())
    win.mrr_screen.action_read_swap_uds()
    QTimer.singleShot(5000, loop2.quit)
    loop2.exec()
    for _ in range(10):
        app.processEvents()
    assert win.runner.last_failure is None
    assert win.mrr_screen._swap_uds.get("rejected_fsids") == ["10003800"]

    # 3. Toggling CP & SWaP points happens IN-PLACE without rebuilding page_area.widget()
    page_before = win.mrr_screen.page_area.widget()
    assert win.mrr_screen._cp_points_table is not None
    assert win.mrr_screen._cp_points_table.isVisible() is False
    win.mrr_screen._toggle_patch_points()
    app.processEvents()
    assert win.mrr_screen.page_area.widget() is page_before
    assert win.mrr_screen._cp_points_table.isVisible() is True

    assert win.mrr_screen._swap_points_table is not None
    assert win.mrr_screen._swap_points_table.isVisible() is False
    win.mrr_screen._toggle_swap_points()
    app.processEvents()
    assert win.mrr_screen.page_area.widget() is page_before
    assert win.mrr_screen._swap_points_table.isVisible() is True

    # 4. Switching to DTC page renders cleanly without creating extra top-level popup windows
    top_before = len(app.topLevelWidgets())
    win.mrr_screen.select("dtc")
    app.processEvents()
    assert len(app.topLevelWidgets()) <= top_before

    # 5. Memory read (dflash) writes mrr_read_report.json and appears at top of recent_folders()
    loop3 = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop3.quit())
    win.mrr_screen.action_read_memory("dflash")
    QTimer.singleShot(5000, loop3.quit)
    loop3.exec()
    for _ in range(10):
        app.processEvents()
    assert win.runner.last_failure is None
    mem_dir = recent_folders()[0]
    assert (mem_dir / "mrr_read_report.json").is_file()
    assert _summarize_recent_folder(mem_dir)["addr"] == "13"

    # 6. Closing radar and clicking the recent folder reopens MrrScreen offline cleanly
    win.close_ecu()
    app.processEvents()
    assert win.stack.currentWidget() is win.start_screen
    assert win.start_screen.recent_wrap.isVisible() is True
    win.open_folder(str(first_dir))
    app.processEvents()
    assert win.stack.currentWidget() is win.mrr_screen
    assert win.mrr_screen._ika_hex == bus.ika.hex()
    assert win.mrr_screen._swap_uds.get("active_fsids") == ["10003700"]

    win.close()


def test_mrr_mpc5675k_flash_write_preserves_overlapping_ks_sram() -> None:
    """Critical C1 regression: MPC5675K flash_driver_addr (0x4007C000) overlaps live KS/IKA/GFA/ECU_BOOT_SUM SRAM."""
    from contitool.core.mrr import mrr_get_profile

    bus = FakeMrrBus(sw_profile="0682")
    prof = mrr_get_profile("0682")
    sram_base = int(prof["sram_addr"])
    sentinel_ika = bytes.fromhex("DEADBEEFCAFEBABE0123456789ABCDEF")
    sentinel_gfa = bytes.fromhex("112233445566778899AABBCCDDEEFF00")
    sentinel_meta = bytes.fromhex("AABBCCDD555555555555550102030405")
    sentinel_bsum = bytes.fromhex("F0E1D2C3B4A5968778695A4B3C2D1E0F")

    for addr, val in (
        (int(prof["sram_ika_addr"]), sentinel_ika),
        (int(prof["sram_gfa_addr"]), sentinel_gfa),
        (int(prof["sram_ks_meta_addr"]), sentinel_meta),
        (int(prof["sram_ecu_boot_sum_addr"]), sentinel_bsum),
    ):
        off = addr - sram_base
        bus.sram[off : off + len(val)] = val

    res = can_mrr_deactivate_cp("fake", bus=bus)
    assert res["cp_patch_state"] == "cp_disabled"

    # Every overlapping KS/IKA/GFA/ECU_BOOT_SUM variable in 0x4007C000..0x4007DFFF MUST be restored, NOT zeroed!
    for addr, val in (
        (int(prof["sram_ika_addr"]), sentinel_ika),
        (int(prof["sram_gfa_addr"]), sentinel_gfa),
        (int(prof["sram_ks_meta_addr"]), sentinel_meta),
        (int(prof["sram_ecu_boot_sum_addr"]), sentinel_bsum),
    ):
        off = addr - sram_base
        assert bytes(bus.sram[off : off + len(val)]) == val


def test_mrr_flash_cp_aborts_on_build_checksum_mismatch_before_erase(monkeypatch) -> None:
    """Critical C2 regression: corrupted sector read must fail XCP BUILD_CHECKSUM before erasing Code Flash."""
    set_lang("en")
    bus = FakeMrrBus(sw_profile="0192")
    orig_cflash = bytes(bus.cflash)
    real_read_fast = MrrCanLink.xcp_read_fast_regions

    def _corrupt_one_byte(self, regions, **kw):
        out = real_read_fast(self, regions, **kw)
        name, data, calls, elapsed = out[0]
        mut = bytearray(data)
        mut[0] ^= 0xFF
        return [(name, bytes(mut), calls, elapsed), *out[1:]]

    monkeypatch.setattr(MrrCanLink, "xcp_read_fast_regions", _corrupt_one_byte)
    with pytest.raises(RuntimeError, match="XCP BUILD_CHECKSUM mismatch"):
        can_mrr_deactivate_cp("fake", bus=bus)
    # Code Flash must remain completely untouched
    assert bytes(bus.cflash) == orig_cflash


def test_mrr_detect_profile_exact_sw_and_5q0_gen1_classification() -> None:
    # Loose substring like "10192" must NOT match verified "0192"
    p_sub = mrr_detect_profile({"part_number": "3Q0907572B", "sw_version": "10192"})
    assert p_sub["verified"] is False
    assert p_sub["flash_write_supported"] is False

    # Unverified 5Q0 MRR1Plus Gen 1 must be classified as MPC5674K (1.5 MiB), not MPC5675K (2.0 MiB)
    p_5q0_g1 = mrr_detect_profile(
        {"part_number": "5Q0907572F", "sw_version": "0400", "system_name": "ACC BOSCH MRR1Plus"}
    )
    assert p_5q0_g1["verified"] is False
    assert p_5q0_g1["mcu"] == "MPC5674K"
    assert p_5q0_g1["cflash_size"] == 0x00180000


def test_mrr_reset_reports_false_on_uds_nrc() -> None:
    from contitool.can.mrr import _reset_and_wait_mrr

    class RejectResetBus(FakeMrrBus):
        def _handle_uds(self, payload: bytes) -> None:
            if payload[:2] == b"\x11\x02":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x11\x22")
                return
            super()._handle_uds(payload)

    bus = RejectResetBus(sw_profile="0192")
    with MrrCanLink("fake", bus=bus) as link:
        assert _reset_and_wait_mrr(link, reset_subfn=0x02, timeout=0.3) is False


def test_mrr_gui_gen1_swap_package_zero_selectable() -> None:
    from contitool.gui.app import create_window

    app, win = create_window()
    try:
        bus = FakeMrrBus(sw_profile="0192")
        st = can_mrr_status("fake", bus=bus)
        win.mrr_screen.open_from_status_result(st)
        app.processEvents()
        idx0 = win.mrr_screen.cmb_swap_gen1_pkg.findData(0)
        assert idx0 >= 0
        win.mrr_screen.cmb_swap_gen1_pkg.setCurrentIndex(idx0)
        app.processEvents()
        assert win.mrr_screen._draft_swap_gen1_pkg == 0
        assert win.mrr_screen.cmb_swap_gen1_pkg.currentData() == 0
    finally:
        win.close()


def test_mrr_via_gateway_bridge_gafl_and_cp_lockout_upgrade(monkeypatch) -> None:
    """Verify MRR via_gateway uses J533CanBridge with ch2 GAFL filter and upgrades write_keys on CP lockout >= 0x23."""
    from contitool.can import mrr as mrr_can_mod

    bus = FakeMrrBus(sw_profile="0192")
    bus.cp_counter = 0x0025  # lockout state!
    bridge_calls: list[dict[str, object]] = []

    class _FakeBridge:
        def __init__(self, **kw):
            bridge_calls.append(kw)
            self.link = type("_L", (), {"bus": bus})()
            self.bus = bus

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    monkeypatch.setattr(mrr_can_mod, "j533_can_bridge", lambda port, **kw: _FakeBridge(**kw))

    new_gfa = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    res = can_mrr_write_keys(
        "fake",
        current_ika=bus.ika,
        new_gfa=new_gfa,
        via_gateway=True,
        gateway_bridge=True,
        gateway_channel=2,
        bus=bus,
    )
    assert "00BD" in res["written"]
    assert res["active_gfa_hex"] == new_gfa.hex()
    assert res["gateway_bridged"] is True
    assert len(bridge_calls) == 1
    assert bridge_calls[0]["target_channel"] == 2
    assert bridge_calls[0]["target_rx_filter"] == mrr_can_mod.MRR_BRIDGE_RX_FILTER
    assert bus.cp_counter == 0
    assert bus.gfa == new_gfa


def test_mrr_3c00_cosmetic_stubs_partial_upgrade_0130_tlb_and_gui_layout(tmp_path: Path, monkeypatch) -> None:
    """Verify Gen 1/2 cosmetic 22 3C 00 stubs, legacy 0x0B upgrade, 0130 indirect_r29 TLB, GUI restore & layout."""
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QLabel, QPushButton

    from contitool.gui.app import create_window
    from contitool.gui.screens import mrr as mrr_mod

    # 1. Gen 1 52B 3C00 stub (`0xFF` active, `0xB0` not activated) encode/decode round-trip
    for idx in (0, 1, 2, 4, 5, 6):
        s = mrr_build_gen1_3c00_stub(idx)
        assert len(s) == 52
        assert mrr_decode_gen1_3c00_stub(s) == idx
    with pytest.raises(ValueError):
        mrr_build_gen1_3c00_stub(3)
    assert mrr_decode_gen1_3c00_stub(b"\x00" * 52) is None

    # 2. Gen 2 10B len + 56B read 3C00 stub encode/decode round-trip
    for grps in ((8, 3, 4, 7), (7, 0, 4, 0), (1, 0, 0, 0), (0, 0, 0, 0)):
        ls = mrr_build_gen2_3c00_len_stub(*grps)
        rs = mrr_build_gen2_3c00_read_stub(*grps)
        assert len(ls) == 10 and mrr_decode_gen2_3c00_len_stub(ls) == sum(1 for g in grps if g > 0)
        assert len(rs) == 56 and mrr_decode_gen2_3c00_read_stub(rs) == grps
    assert mrr_decode_gen2_3c00_len_stub(b"\x00" * 10) is None
    assert mrr_decode_gen2_3c00_read_stub(b"\x00" * 56) is None

    # 3. SW 0130 indirect_r29 TLB1[0x0B] descriptor layout
    blob_0130 = mrr_build_tlb1_0b_descriptor(
        True,
        mmu_load_single_entry=0x0008D3DC,
        tlb1_entry=0x0B,
        mmu_dispatch_mode="indirect_r29",
    )
    assert len(blob_0130) == 0x34
    assert int.from_bytes(blob_0130[0x00:0x04], "big") == MRR_DRIVER_CONTROL + 0x0C
    assert int.from_bytes(blob_0130[0x04:0x08], "big") == MRR_DRIVER_CONTROL + 0x18
    assert int.from_bytes(blob_0130[0x08:0x0C], "big") == 0
    assert int.from_bytes(blob_0130[0x0C:0x10], "big") == 0x0008D3DC
    assert blob_0130[0x10:0x14] == bytes([0x01, 0x0B, 0x00, 0x07])
    assert int.from_bytes(blob_0130[0x18:0x1C], "big") == 0x37
    assert int.from_bytes(blob_0130[0x1C:0x20], "big") == 0x40020000
    assert int.from_bytes(blob_0130[0x20:0x24], "big") == MRR_DRIVER_CONTROL

    # 4. Live upgrade from old 6-site Gen 1 patch (partial 6/9) -> full 9/9 with 22 3C 00 reporting
    bus = FakeMrrBus(sw_profile="0194", cp_counter=0x0000, xcp_gate_open=True, swap_3c00_entries=[(0x10003300, 0xFF)])
    full_img, _ = mrr_apply_swap_patch(bytes(bus.cflash), package_index=5, profile="0194")
    old6_img = bytearray(full_img)
    u3 = MRR_PROFILES["0194"]["swap_config"]["uds_3c00"]
    for pa_k, st_k in (("prepare_pa", "prepare_stock"), ("len_pa", "len_stock"), ("data_pa", "data_stock")):
        sb = bytes.fromhex(u3[st_k])
        old6_img[u3[pa_k] : u3[pa_k] + len(sb)] = sb
    bus.cflash[:] = old6_img
    live_before = can_mrr_read_keys("fake", bus=bus)
    assert live_before["swap_patch_state"] == "partial"
    assert live_before["cflash_swap"]["patched_points"] == 6
    assert live_before["cflash_swap"]["total_points"] == 9
    assert live_before["swap_uds"]["active_fsids"] == ["10003300"]  # factory OEM cert before upgrade

    res_up = can_mrr_activate_swap("fake", package_index=5, session_dir=tmp_path / "up_0194", bus=bus)
    assert res_up["cflash_swap"]["swap_patch_state"] == "swap_activated"
    assert res_up["cflash_swap"]["patched_points"] == 9
    assert res_up["swap_uds"]["active_fsids"] == ["10003700"]
    assert res_up["swap_uds"]["rejected_count"] == 0  # inactive FS-IDs emit 0xB0 ("not activated"), NOT 0x0B!

    # 4b. Live upgrade from earlier 50B 0x0B stub -> detected as partial (8/9) -> upgraded cleanly to 52B 0xB0 (9/9)
    legacy_50b = (
        bytes.fromhex("4904480570c000314800904391539263935348b7")
        + bytes([0x2A, 0x50])
        + bytes.fromhex("e20370e000ff9473204320062a30e202200620002a70e2ef48030004")
    )
    d_pa = int(u3["data_pa"])
    d_stock = bytes.fromhex(u3["data_stock"])
    bus.cflash[d_pa : d_pa + 52] = legacy_50b + d_stock[50:52]
    live_leg = can_mrr_read_keys("fake", bus=bus)
    assert live_leg["swap_patch_state"] == "partial"
    assert live_leg["cflash_swap"]["patched_points"] == 8
    res_up2 = can_mrr_activate_swap("fake", package_index=5, session_dir=tmp_path / "up_leg", bus=bus)
    assert res_up2["cflash_swap"]["swap_patch_state"] == "swap_activated"
    assert res_up2["swap_uds"]["rejected_count"] == 0
    assert res_up2["swap_uds"]["active_fsids"] == ["10003700"]

    # 5. GUI checks: 0130 & 0196 in _PROFILE_CHOICES, 22 3C 00 status pill >= 184 px, partial CTA + action_restore_swap_stock
    choice_codes = [c for c, _ in mrr_mod._PROFILE_CHOICES]
    assert "0130" in choice_codes and "0196" in choice_codes

    set_lang("ru")
    app, win = create_window()
    try:
        win.resize(1100, 800)
        win.conn.out_dir = tmp_path
        win.conn.port = "fake"
        win.conn.interface = "slcan"
        win.conn.wiring_confirmed = True
        win.mrr_screen.open_from_status_result(
            {
                "passport": {"part_number": "3Q0907572B", "sw_version": "0194"},
                "status": mrr_decode_status_dids({"03DE": "0000", "0440": "05010301070000", "0902": "08"}),
                "swap_uds": live_before["swap_uds"],
                "cflash_swap": live_before["cflash_swap"],
            }
        )
        app.processEvents()
        page_w = win.mrr_screen.page_area.widget()
        pills = [w for w in page_w.findChildren(QLabel) if "0xFF" in w.text() or "0xB0" in w.text()]
        assert pills and all(p.width() >= 184 for p in pills)
        btns = [b.text() for b in page_w.findChildren(QPushButton)]
        assert any("Обновить SWaP + 3C00" in t for t in btns)

        # Regression: action_restore_swap_stock must snapshot routing (no NameError: 'port') and run cleanly
        monkeypatch.setattr(mrr_mod, "run_dialog", lambda *_a, **_k: True)
        real_rst = mrr_mod.can_mrr_restore_swap_stock
        monkeypatch.setattr(mrr_mod, "can_mrr_restore_swap_stock", lambda port, **kw: real_rst(port, bus=bus, **kw))
        loop_r = QEventLoop()
        win.runner.operation_finished.connect(lambda *_: loop_r.quit())
        win.mrr_screen.action_restore_swap_stock()
        QTimer.singleShot(5000, loop_r.quit)
        loop_r.exec()
        for _ in range(10):
            app.processEvents()
        assert win.runner.last_failure is None
        assert win.mrr_screen._cflash_swap.get("swap_patch_state") == "stock"
    finally:
        win.close()


def test_mrr_m6c_gen2_group0_rejects_nonexistent_variants_4_and_5() -> None:
    """M6c: Gen 2 SWaP group-0 variants 4 and 5 do not exist in MRR_GEN2_SWAP_GROUPS and must be rejected."""
    for bad_g0 in (4, 5):
        with pytest.raises(ValueError, match="group 0"):
            mrr_build_gen2_swap_group_stub(bad_g0, 0, 0, 0)
        with pytest.raises(ValueError, match="group 0"):
            mrr_build_gen2_3c00_len_stub(bad_g0, 0, 0, 0)
        with pytest.raises(ValueError, match="group 0"):
            mrr_build_gen2_3c00_read_stub(bad_g0, 0, 0, 0)

        # Hand-crafted 82-byte stub encoding bad_g0 must decode as None
        valid_stub = bytearray(mrr_build_gen2_swap_group_stub(3, 0, 0, 0))
        valid_stub[3] = (bad_g0 << 4) | 0x0
        valid_stub[19] = bad_g0
        assert mrr_decode_gen2_swap_group_stub(bytes(valid_stub)) is None

        # Hand-crafted 56-byte 3C00 read stub encoding bad_g0 must decode as None
        valid_r3c = bytearray(mrr_build_gen2_3c00_read_stub(3, 0, 0, 0))
        hi16 = (bad_g0 << 8) | 0
        w_lis = 0x70E0E000 | (((hi16 >> 11) & 0x1F) << 16) | (hi16 & 0x7FF)
        valid_r3c[8:12] = w_lis.to_bytes(4, "big")
        assert mrr_decode_gen2_3c00_read_stub(bytes(valid_r3c)) is None

    # Every valid group-0 variant (0, 1, 2, 3, 6, 7, 8) round-trips cleanly
    for ok_g0 in (0, 1, 2, 3, 6, 7, 8):
        stub = mrr_build_gen2_swap_group_stub(ok_g0, 3, 4, 7)
        assert len(stub) == 82
        assert mrr_decode_gen2_swap_group_stub(stub) == (ok_g0, 3, 4, 7)

    cflash_0780 = _build_synthetic_mrr_cflash("0780", full_image=True)
    with pytest.raises(ValueError, match="group 0"):
        mrr_apply_swap_patch(cflash_0780, profile="0780", groups=(4, 3, 4, 7))


def test_mrr_m6d_xcp_gate_nrc_37_35_connect_stale_disconnect_and_checksum_skip() -> None:
    """M6d: surface NRC 0x37/0x35 on enable_xcp_gate_uds, ignore stale DISCONNECT ACK, harden ADD_44 skip."""
    from contitool.progress import OperationReporter

    set_lang("en")

    # 1. NRC 0x37 (requiredTimeDelayNotExpired) surfaced clearly
    class Nrc37Bus(FakeMrrBus):
        def _handle_uds(self, pdu: bytes) -> None:
            if pdu[:2] == b"\x27\x03":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x27\x37")
                return
            super()._handle_uds(pdu)

    with MrrCanLink("fake", bus=Nrc37Bus(sw_profile="0192", xcp_gate_open=False)) as link37:
        with pytest.raises(RuntimeError, match="0x37.*requiredTimeDelayNotExpired"):
            link37.enable_xcp_gate_uds()

    # 2. NRC 0x35 (invalidKey) surfaced clearly instead of falling through to 2E 0902 NRC 0x33
    class Nrc35Bus(FakeMrrBus):
        def _handle_uds(self, pdu: bytes) -> None:
            if pdu[:2] == b"\x10\x4f":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x10\x12")
                return
            if pdu[:2] == b"\x27\x04":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x27\x35")
                return
            super()._handle_uds(pdu)

    with MrrCanLink("fake", bus=Nrc35Bus(sw_profile="0192", xcp_gate_open=False)) as link35:
        with pytest.raises(RuntimeError, match="0x35.*invalidKey"):
            link35.enable_xcp_gate_uds()

    # 3. Stale/late DISCONNECT ACK (`FF 00 00 00 00 00 00 00`) arriving right before CONNECT DTO must not desync
    class LateDisconnectBus(FakeMrrBus):
        def _on_xcp_frame(self, data: bytes) -> None:
            if data[0] == 0xFF:  # CONNECT: inject a late DISCONNECT ACK right ahead of the real CONNECT reply
                self._enqueue_frame(MRR_XCP_RX_ID, b"\xff\x00\x00\x00\x00\x00\x00\x00")
            super()._on_xcp_frame(data)

    late_bus = LateDisconnectBus(sw_profile="0192", xcp_gate_open=True)
    with MrrCanLink("fake", bus=late_bus) as link_late:
        conn = link_late.xcp_connect_and_unlock()
        assert conn == b"\xff\x04\x80\x08\x08\x00\x01\x01"
        assert late_bus.xcp_unlocked is True

    # 4. Crafted 1 KiB ADD_44 collision (`sum == 0xFFFFFF00` + 7x 0xFF head) must NOT be skipped as blank
    col_bus = FakeMrrBus(sw_profile="0192", xcp_gate_open=True)
    blk_addr = 0x10000
    col_block = bytearray(b"\xff" * 1024)
    col_block[0x10:0x14] = (0xFFFFFFFE).to_bytes(4, "big")  # -1 relative to 0xFFFFFFFF
    col_block[0x3F0:0x3F4] = (0x00000000).to_bytes(4, "big")  # +1 relative to 0xFFFFFFFF -> 1024B ADD_44 == 0xFFFFFF00!
    assert mrr_sum32_be(bytes(col_block)) == 0xFFFFFF00
    col_bus.cflash[blk_addr : blk_addr + 1024] = col_block

    warnings: list[str] = []

    class RecReporter(OperationReporter):
        def warning(self, message: str) -> None:
            warnings.append(message)

    with MrrCanLink("fake", bus=col_bus) as link_col:
        link_col.xcp_connect_and_unlock()
        got = link_col.xcp_read_memory(blk_addr, 1024, use_checksum_skip=True, reporter=RecReporter())
    assert got == bytes(col_block)
    assert any("use_checksum_skip" in w for w in warnings)


def test_mrr_h21_manual_sw_profile_mismatch_refused() -> None:
    """H21: manual sw_profile override conflicting with live ECU SW version must refuse dangerous RAM/Flash writes."""
    set_lang("en")
    bus = FakeMrrBus(sw_profile="0192", cp_counter=0x0023, xcp_gate_open=True)
    orig_cflash = bytes(bus.cflash)
    new_gfa = bytes.fromhex("102030405060708090a0b0c0d0e0f001")

    with pytest.raises(RuntimeError, match="0780.*0192"):
        can_mrr_reset_cp_counter("fake", sw_profile="0780", reset_after=False, bus=bus)
    assert bus.cp_counter == 0x0023

    with pytest.raises(RuntimeError, match="0780.*0192"):
        can_mrr_deactivate_cp("fake", sw_profile="0780", bus=bus)
    assert bytes(bus.cflash) == orig_cflash

    with pytest.raises(RuntimeError, match="0780.*0192"):
        can_mrr_activate_swap("fake", sw_profile="0780", bus=bus)
    assert bytes(bus.cflash) == orig_cflash

    with pytest.raises(RuntimeError, match="0780.*0192"):
        can_mrr_write_keys("fake", current_ika=bus.ika, new_gfa=new_gfa, sw_profile="0780", bus=bus)
    assert bus.cp_counter == 0x0023

    # Exact matching sw_profile still succeeds cleanly
    ok = can_mrr_reset_cp_counter("fake", sw_profile="0192", reset_after=False, bus=bus)
    assert ok["sram_counter_after"] == 0
    assert bus.cp_counter == 0


def test_mrr_h4_dpdu_uds_session_and_29bit_warning() -> None:
    """H4: route UDS through DPduBus.uds_session(0x757, 0x7C1) on uds_only/nonraw and warn on dpdu 29-bit XCP."""
    import contextlib
    from contitool.progress import OperationReporter

    set_lang("en")
    inner = FakeMrrBus(sw_profile="0192", cp_counter=0x0000, xcp_gate_open=True)

    class FakeDpduMrrBus:
        def __init__(self, *, uds_only: bool = False, nonraw: dict[int, int] | None = None) -> None:
            self.uds_only = uds_only
            self.nonraw = dict(nonraw or {})
            self.spent = False
            self.session_calls: list[tuple[int, int]] = []
            self.uds_requests: list[bytes] = []

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
            raise AssertionError("Raw send should not be used when uds_session is active")

        def recv(self, timeout: float | None = None) -> can.Message | None:
            return None

        def shutdown(self) -> None:
            pass

    dpdu_bus = FakeDpduMrrBus(uds_only=True)
    st = can_mrr_status("fake", interface="dpdu", bus=dpdu_bus)
    assert dpdu_bus.session_calls == [(MRR_UDS_TX_ID, MRR_UDS_RX_ID)]
    assert len(dpdu_bus.uds_requests) > 0
    assert st["passport"]["part_number"] == "3Q0907572B"

    nonraw_bus = FakeDpduMrrBus(nonraw={0x710: 1})
    with MrrCanLink("fake", interface="dpdu", bus=nonraw_bus) as link:
        resp = link.request_uds(b"\x10\x03", 0x50)
        assert resp[0] == 0x50
    assert nonraw_bus.session_calls == [(MRR_UDS_TX_ID, MRR_UDS_RX_ID)]

    warnings: list[str] = []

    class RecReporter(OperationReporter):
        def warning(self, message: str) -> None:
            warnings.append(message)

    can_mrr_read_keys("fake", interface="dpdu", bus=inner, reporter=RecReporter())
    assert any("29-bit" in w and "RawMode" in w and "native CAN" in w for w in warnings)


def test_mrr_golden_crypto_and_checksum_vectors() -> None:
    """Golden vectors for MRR XCP LFSR-7, FBLv SA, Dev SA, ADD_44 checksum, ECU_BOOT_SUM, AES-128-ECB, and CP container."""
    # XCP UNLOCK LFSR-7 (poly 0xFB312378)
    assert mrr_xcp_compute_key(0x00000000) == 0x00000000
    assert mrr_xcp_compute_key(0x00000001) == 0x00000002
    assert mrr_xcp_compute_key(0x80000000) == 0x1AA6CB16
    assert mrr_xcp_compute_key(0x3A7F91C2) == 0x74FF2384
    assert mrr_xcp_compute_key(0x12345678) == 0x2468ACF0

    # FBLv SecurityAccess (27 11/12)
    assert mrr_fblv_compute_key(0x00000000) == 0xE304A703
    assert mrr_fblv_compute_key(0x12345678) == 0x82C17183
    assert mrr_fblv_compute_key(0xB97BCBEE) == 0xD44C2D5A
    assert mrr_fblv_compute_key(0xB97BCBEF) == 0xC04367D2
    assert mrr_fblv_compute_key(0xFFFFFFFF) == 0x3EB90C1E

    # Dev additive SA (27 03/04) with 32-bit wrap
    assert mrr_dev_compute_key(0x12345678, MRR_LOGIN_XCP_GATE) == 0x1234B48D
    assert mrr_dev_compute_key(0xFFFFFFFF, 1) == 0x00000000

    # XCP BUILD_CHECKSUM ADD_44 (32-bit BE word sum)
    assert mrr_sum32_be(b"\xff" * 1024) == 0xFFFFFF00
    assert mrr_sum32_be(b"\xff" * 256) == 0xFFFFFFC0
    assert mrr_sum32_be(bytes.fromhex("0102030405060708")) == 0x06080A0C
    assert mrr_sum32_be(bytes.fromhex("ffffffff00000002")) == 0x00000001

    # ECU_BOOT_SUM (512 x 16B chained carry sum over 0x8000..0x9FFF)
    buf = bytearray(0xA000)
    for off in range(0x8000, 0xA000, 4):
        buf[off : off + 4] = ((off * 0x01010101) & 0xFFFFFFFF).to_bytes(4, "big")
    assert mrr_compute_ecu_boot_sum(bytes(buf)) == bytes.fromhex("110ff1001917f8002120010129280901")

    # NIST FIPS-197 Appendix B AES-128-ECB vector & 34-byte 2E 00BD CP key container
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    assert bcm_aes128_ecb_encrypt(key, pt) == bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    assert mrr_build_cp_key_container(key, pt, MRR_CP_KEY_TYPE_GFA) == bytes.fromhex(
        "320b6a19978511dcfb09dc021d842539e421c4b8a73fc719db9350b875dbf74e0200"
    )


def _make_synth_mrr_odx(
    *,
    part_number: str = "3Q0907572B",
    sw_version: str = "0192",
    app_size: int = 0x150000,
    driver_bytes: bytes | None = None,
    app_bytes: bytes | None = None,
    alfid: str = MRR_FBLV_ALFID,
    sa2: str = MRR_FBLV_SA2_BYTECODE,
    corrupt_crc: bool = False,
) -> bytes:
    import zlib

    drv = driver_bytes if driver_bytes is not None else (b"\x42" * MRR_FLASH_DRIVER_SIZE)
    app = app_bytes if app_bytes is not None else (b"\x5A" * app_size)
    drv_crc = zlib.crc32(drv) & 0xFFFFFFFF
    app_crc = (zlib.crc32(app) & 0xFFFFFFFF) ^ (1 if corrupt_crc else 0)
    fake_sig = ("AB" * 128)
    name = f"FL_{part_number}_{sw_version}___S"
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<ODX MODEL-VERSION="2.0.1">
  <FLASH ID="{name}">
    <SHORT-NAME>{name}</SHORT-NAME>
    <ADMIN-DATA><DOC-REVISIONS><DOC-REVISION><REVISION-LABEL>{sw_version}</REVISION-LABEL></DOC-REVISION></DOC-REVISIONS></ADMIN-DATA>
    <ECU-MEMS>
      <ECU-MEM ID="EMEM_{part_number}_{sw_version}___S">
        <SHORT-NAME>EMEM_{part_number}_{sw_version}___S</SHORT-NAME>
        <MEM>
          <SESSIONS>
            <SESSION ID="SES">
              <SECURITYS>
                <SECURITY><SECURITY-METHOD>SA2</SECURITY-METHOD><FW-SIGNATURE>{sa2}</FW-SIGNATURE></SECURITY>
                <SECURITY><SECURITY-METHOD>ALFID</SECURITY-METHOD><FW-SIGNATURE>{alfid}</FW-SIGNATURE></SECURITY>
                <SECURITY><SECURITY-METHOD>SIG_SHA1-RSA1024_S</SECURITY-METHOD><FW-SIGNATURE>{fake_sig}</FW-SIGNATURE><FW-CHECKSUM>{drv_crc:08X}</FW-CHECKSUM><VALIDITY-FOR>DB_99ERASEROUTI</VALIDITY-FOR></SECURITY>
                <SECURITY><SECURITY-METHOD>SIG_SHA1-RSA1024_with_CRC32_S</SECURITY-METHOD><FW-SIGNATURE>{fake_sig}</FW-SIGNATURE><FW-CHECKSUM>{app_crc:08X}</FW-CHECKSUM><VALIDITY-FOR>DB_10FLASHDATA</VALIDITY-FOR></SECURITY>
              </SECURITYS>
              <SDGS><SDG><SD SI="FDS-Project-ID">1317</SD></SDG></SDGS>
            </SESSION>
          </SESSIONS>
          <DATABLOCKS>
            <DATABLOCK ID="DB99" TYPE="ERASE_ROUTINE">
              <SHORT-NAME>DB_99ERASEROUTI</SHORT-NAME>
              <FLASHDATA-REF ID-REF="FD99"/>
              <SEGMENTS><SEGMENT><SOURCE-START-ADDRESS>99</SOURCE-START-ADDRESS><UNCOMPRESSED-SIZE>{len(drv)}</UNCOMPRESSED-SIZE></SEGMENT></SEGMENTS>
            </DATABLOCK>
            <DATABLOCK ID="DB10" TYPE="FLASH_DATA">
              <SHORT-NAME>DB_10FLASHDATA</SHORT-NAME>
              <FLASHDATA-REF ID-REF="FD10"/>
              <SEGMENTS><SEGMENT><SOURCE-START-ADDRESS>10</SOURCE-START-ADDRESS><UNCOMPRESSED-SIZE>{len(app)}</UNCOMPRESSED-SIZE></SEGMENT></SEGMENTS>
            </DATABLOCK>
          </DATABLOCKS>
          <FLASHDATAS>
            <FLASHDATA ID="FD99"><ENCRYPT-COMPRESS-METHOD>00</ENCRYPT-COMPRESS-METHOD><DATA>{drv.hex()}</DATA></FLASHDATA>
            <FLASHDATA ID="FD10"><ENCRYPT-COMPRESS-METHOD>00</ENCRYPT-COMPRESS-METHOD><DATA>{app.hex()}</DATA></FLASHDATA>
          </FLASHDATAS>
        </MEM>
      </ECU-MEM>
    </ECU-MEMS>
    <ECU-MEM-CONNECTORS>
      <ECU-MEM-CONNECTOR>
        <SESSION-DESCS><SESSION-DESC><PARTNUMBER>{part_number} </PARTNUMBER></SESSION-DESC></SESSION-DESCS>
        <LAYER-REFS><LAYER-REF DOCREF="BV_AdaptCruisContrUDS"/><LAYER-REF DOCREF="EV_ACCBOSCHVW48X_001"/></LAYER-REFS>
      </ECU-MEM-CONNECTOR>
    </ECU-MEM-CONNECTORS>
  </FLASH>
</ODX>
"""
    return xml.encode("utf-8")


def _make_synth_mrr_frf_image(
    *,
    part_number: str = "3Q0907572B",
    sw_version: str = "0192",
    app_size: int = 0x150000,
    rsa_valid: bool = True,
) -> MrrFrfImage:
    import zlib

    drv = mrr_get_eraserouti_driver("0192" if app_size == 0x150000 else "0780")
    # Small compressed LZSS-A0 stream? Use raw 0x00 with a compact fake app image of exact target size
    app = _build_synthetic_mrr_cflash("0192" if app_size == 0x150000 else "0780", full_image=False)
    assert len(app) == app_size
    gen = 1 if app_size == 0x150000 else 2
    drv_blk = MrrFrfBlock(
        name="DB_99ERASEROUTI",
        block_id=0x99,
        data_format=0x00,
        uncompressed_size=len(drv),
        stream=drv,
        data=drv,
        signature=b"\x11" * 128,
        crc32=zlib.crc32(drv) & 0xFFFFFFFF,
        sha256=hashlib.sha256(drv).hexdigest(),
        rsa_valid=rsa_valid,
        crc_valid=True,
    )
    app_blk = MrrFrfBlock(
        name="DB_10FLASHDATA",
        block_id=0x10,
        data_format=0x00,
        uncompressed_size=len(app),
        stream=app,
        data=app,
        signature=b"\x22" * 128,
        crc32=zlib.crc32(app) & 0xFFFFFFFF,
        sha256=hashlib.sha256(app).hexdigest(),
        rsa_valid=rsa_valid,
        crc_valid=True,
    )
    return MrrFrfImage(
        name=f"FL_{part_number}_{sw_version}___S",
        kind="FRF",
        part_number=part_number,
        sw_version=sw_version,
        generation=gen,
        mcu="MPC5674K" if gen == 1 else "MPC5675K",
        family="MRR1Plus" if gen == 1 else "MRRevo14F",
        fds_project_id="1317",
        layers=("BV_AdaptCruisContrUDS", "EV_ACCBOSCHVW48X_001"),
        sa2=MRR_FBLV_SA2_BYTECODE,
        alfid=MRR_FBLV_ALFID,
        driver=drv_blk,
        app=app_blk,
        profile_sw=sw_version if sw_version in MRR_PROFILES else None,
        is_engineering=sw_version.upper().startswith("X"),
    )


def test_mrr_frf_parse_decrypt_lzss_and_compatibility() -> None:
    """Verify MRR FRF/ODX decryption (involution), LZSS 0xA0, RSA-1024 check, rejection rules & compatibility."""
    import io
    import zipfile

    from contitool.core.crypto import generate_rsa1024_e3_keypair, rsassa_pkcs1_v15_sign

    # 1. FRF XOR stream cipher is a self-inverse involution for payloads > 727 KiB
    big_plain = bytes((i * 37) & 0xFF for i in range(800_000))
    assert mrr_frf_decrypt(mrr_frf_decrypt(big_plain)) == big_plain

    # 2. LZSS 0xA0 decompression: literal bytes + back-reference copy
    # flags=0x08 (bit 4 set -> 4 literals 'A','B','C','D', then ref len=4 dist=4 -> 'A','B','C','D')
    lzss_stream = bytes([0x08, ord("A"), ord("B"), ord("C"), ord("D"), (4 << 2) | 0, 4])
    assert mrr_lzss_a0_decompress(lzss_stream) == b"ABCDABCD"

    # 3. RSA-1024 PKCS#1 v1.5 SHA-1 verification over BE32(bid) || BE32(uncompressed_size) || stream
    kp = generate_rsa1024_e3_keypair()
    mod_bytes = bytes.fromhex(kp["n_hex"])
    priv_d = int(kp["d_hex"], 16)
    test_stream = b"BoschMRRTestBlock"
    msg = struct.pack(">II", 0x10, 0x150000) + test_stream
    sig = rsassa_pkcs1_v15_sign(msg, int.from_bytes(mod_bytes, "big"), priv_d, "sha1")
    assert mrr_fblv_signature_valid(0x10, 0x150000, test_stream, sig, modulus=mod_bytes) is True
    assert mrr_fblv_signature_valid(0x10, 0x150000, test_stream + b"!", sig, modulus=mod_bytes) is False

    # 4. Synthetic plain ODX & XOR-encrypted FRF parse cleanly
    odx_bytes = _make_synth_mrr_odx(part_number="3Q0907572B", sw_version="0192", app_size=0x150000)
    img_odx = mrr_read_frf(odx_bytes, "FL_3Q0907572B_0192___S.odx")
    assert img_odx.kind == "ODX" and img_odx.part_number == "3Q0907572B" and img_odx.sw_version == "0192"
    assert img_odx.generation == 1 and img_odx.mcu == "MPC5674K"
    assert img_odx.driver.crc_valid and img_odx.app.crc_valid and not img_odx.app.rsa_valid

    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("FL_3Q0907572B_0192___S.odx", odx_bytes)
    frf_bytes = mrr_frf_decrypt(zbuf.getvalue())
    img_frf = mrr_read_frf(frf_bytes, "FL_3Q0907572B_0192___S.frf")
    assert img_frf.kind == "FRF" and img_frf.part_number == "3Q0907572B" and img_frf.app.sha256 == img_odx.app.sha256

    # Reject wrong ALFID (older VW372 / gateway) and corrupt CRC-32
    with pytest.raises(ValueError, match="ALFID"):
        mrr_read_frf(_make_synth_mrr_odx(alfid="014101"), "old.odx")
    with pytest.raises(ValueError, match="CRC-32"):
        mrr_read_frf(_make_synth_mrr_odx(corrupt_crc=True), "corrupt.odx")

    # 5. Compatibility rules
    gen1_frf = _make_synth_mrr_frf_image(part_number="3Q0907572C", sw_version="0196", app_size=0x150000)
    gen2_frf = _make_synth_mrr_frf_image(part_number="5Q0907572S", sw_version="0780", app_size=0x1D0000)
    eng_frf = _make_synth_mrr_frf_image(part_number="5Q0907572M", sw_version="X720", app_size=0x1D0000)
    bad_rsa_frf = _make_synth_mrr_frf_image(rsa_valid=False)

    # Exact match -> no hard errors, no warnings
    h, s = mrr_frf_compatibility(gen2_frf, {"part_number": "5Q0907572S", "sw_version": "0780", "asam_odx": "EV_ACCBOSCHVW416"})
    assert not h and not s
    # Gen 2 onto Gen 1 -> hard blocked!
    h, _ = mrr_frf_compatibility(gen2_frf, {"part_number": "3Q0907572B", "sw_version": "0192", "asam_odx": "EV_ACCBOSCHVW48X"})
    assert h
    # Gen 1 onto Gen 2 (including 5Q0907572H/J!) -> hard blocked!
    h, _ = mrr_frf_compatibility(gen1_frf, {"part_number": "5Q0907572H", "sw_version": "0680", "asam_odx": "EV_ACCBOSCHVW416"})
    assert h
    # Older PQ26/VW372 or Continental 2Q0 -> hard blocked!
    h, _ = mrr_frf_compatibility(gen1_frf, {"part_number": "5Q0907572K", "sw_version": "0402", "asam_odx": "EV_ACCMRRBoschVW372"})
    assert h
    h, _ = mrr_frf_compatibility(gen2_frf, {"part_number": "2Q0907572AA", "sw_version": "0396", "asam_odx": "EV_ACCMRRCONTIVW376"})
    assert h
    # Invalid RSA -> hard blocked!
    h, _ = mrr_frf_compatibility(bad_rsa_frf, {"part_number": "3Q0907572B", "sw_version": "0192"})
    assert h
    # Same-MCU cross-PN -> allowed with soft warning
    h, s = mrr_frf_compatibility(gen1_frf, {"part_number": "3Q0907572B", "sw_version": "0192"})
    assert not h and s
    # Engineering SW -> soft warning
    h, s = mrr_frf_compatibility(eng_frf, {"part_number": "5Q0907572S", "sw_version": "0780"})
    assert not h and len(s) >= 2


def test_mrr_can_flash_frf_normal_gateway_recovery_and_refusals(tmp_path: Path, monkeypatch) -> None:
    """Verify full UDS 10 02 FRF flashing (direct, via_gateway without bridge, FBLv recovery, cross-MCU & RSA refusal)."""
    from contitool.can import mrr as mrr_can_mod

    frf_0196 = _make_synth_mrr_frf_image(part_number="3Q0907572C", sw_version="0196", app_size=0x150000)
    frf_0192 = _make_synth_mrr_frf_image(part_number="3Q0907572B", sw_version="0192", app_size=0x150000)
    frf_0780 = _make_synth_mrr_frf_image(part_number="5Q0907572S", sw_version="0780", app_size=0x1D0000)

    # 1. Direct UDS 10 02 flash of same-PN FRF (0192 -> 0192)
    bus = FakeMrrBus(sw_profile="0192", cp_counter=0x0000, fblv_flash_sw_after="0192")
    s_dir = tmp_path / "frf_direct"
    res = can_mrr_flash_frf("fake", frf_0192, session_dir=s_dir, bus=bus)
    assert res["complete"] is True
    assert res["application_rsa_accepted"] is True
    assert res["reset_confirmed"] is True
    assert res["passport_after"]["sw_version"] == "0192"
    assert bus.fblv_log == [
        "10_02", "27_11", "27_12", "2E_F15A",
        "34_99_00", "37_99", "31_0202_99",
        "31_FF00_10",
        "34_10_00", "37_10", "31_0202_10",
        "31_FF01", "11_01",
    ]
    assert (s_dir / "mrr_frf_result.json").exists()
    assert len(bus.dtcs) == 0  # cleared after flash

    # 2. Cross-PN flash via J533 gateway UDS routing (NO RAM-bridge must be opened!)
    monkeypatch.setattr(mrr_can_mod, "j533_can_bridge", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("RAM bridge must NOT be used for UDS FRF!")))
    bus_gw = FakeMrrBus(sw_profile="0192", cp_counter=0x0000, fblv_flash_sw_after="0196")
    # Without allow_mismatch, cross-PN (3Q0907572C onto 3Q0907572B) refuses before touching FBLv
    with pytest.raises(RuntimeError, match="3Q0907572C"):
        can_mrr_flash_frf("fake", frf_0196, via_gateway=True, bus=bus_gw)
    assert bus_gw.fblv_log == []
    # With allow_mismatch=True, succeeds cleanly via pure UDS!
    res_gw = can_mrr_flash_frf("fake", frf_0196, allow_mismatch=True, via_gateway=True, bus=bus_gw)
    assert res_gw["complete"] is True
    assert res_gw["via_gateway"] is True
    assert res_gw["passport_after"]["sw_version"] == "0196"
    assert res_gw["passport_after"]["part_number"] == "3Q0907572C"

    # 3. Bootloader recovery mode (radar starts stuck in FBLv: 22 F187 -> NRC 31, 10 03 -> NRC 7E)
    bus_rec = FakeMrrBus(sw_profile="0192", in_fblv=True, fblv_flash_sw_after="0192")
    with pytest.raises(RuntimeError, match="FBLv"):
        can_mrr_flash_frf("fake", frf_0192, recovery_mode=False, bus=bus_rec)
    res_rec = can_mrr_flash_frf("fake", frf_0192, recovery_mode=True, bus=bus_rec)
    assert res_rec["complete"] is True
    assert res_rec["recovery_mode"] is True
    assert bus_rec.in_fblv is False
    assert res_rec["passport_after"]["sw_version"] == "0192"

    # 4. Cross-MCU refusal BEFORE 10 02 / erase is ever sent (even with allow_mismatch=True!)
    bus_x = FakeMrrBus(sw_profile="0192")
    with pytest.raises(RuntimeError, match="MPC5675K"):
        can_mrr_flash_frf("fake", frf_0780, allow_mismatch=True, bus=bus_x)
    assert bus_x.fblv_log == [] and bus_x.fblv_erased is False

    # 5. FBLv rejects CheckMemory (71 01 02 02 01) -> clear failure reported
    bus_rej = FakeMrrBus(sw_profile="0192", fblv_reject_rsa=True)
    with pytest.raises(RuntimeError, match="0x01"):
        can_mrr_flash_frf("fake", frf_0192, bus=bus_rej)


def test_mrr_cli_and_gui_flash_frf(tmp_path: Path, monkeypatch, capsys) -> None:
    """Verify CLI `mrr inspect --frf` / `mrr flash-frf` and headless Qt 6 GUI FRF card, dialog & workflow."""
    import importlib
    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QPushButton

    cli_mod = importlib.import_module("contitool.cli.main")
    from contitool.gui.app import create_window
    from contitool.gui.screens import mrr as mrr_mod

    odx_path = tmp_path / "FL_3Q0907572B_0192___S.odx"
    odx_path.write_bytes(_make_synth_mrr_odx(part_number="3Q0907572B", sw_version="0192", app_size=0x150000))

    # 1. CLI `mrr inspect --frf`
    rc = cli_mod.main(["--lang", "en", "mrr", "inspect", "--frf", str(odx_path)])
    assert rc == 0
    rep_in = json.loads(capsys.readouterr().out)
    assert rep_in["frf"]["part_number"] == "3Q0907572B"
    assert rep_in["frf"]["sw_version"] == "0192"
    assert rep_in["frf"]["mcu"] == "MPC5674K"

    # 2. CLI `mrr flash-frf` requires --yes
    rc_no = cli_mod.main(["--lang", "en", "mrr", "flash-frf", "--port", "fake", "--frf", str(odx_path)])
    assert rc_no == 1
    capsys.readouterr()

    # CLI `mrr flash-frf --yes` invokes can_mrr_flash_frf
    called_cli: list[dict[str, Any]] = []
    monkeypatch.setattr(
        cli_mod,
        "can_mrr_flash_frf",
        lambda port, frf_p, **kw: (called_cli.append({"port": port, "frf": str(frf_p), **kw}) or {"complete": True}),
    )
    rc_ok = cli_mod.main(
        [
            "--lang", "en", "mrr", "flash-frf",
            "--port", "fake", "--frf", str(odx_path),
            "--allow-mismatch", "--recovery", "--via-gateway", "--yes",
        ]
    )
    assert rc_ok == 0
    assert len(called_cli) == 1
    assert called_cli[0]["allow_mismatch"] is True
    assert called_cli[0]["recovery_mode"] is True
    assert called_cli[0]["via_gateway"] is True

    # 3. Headless Qt 6 GUI: FRF card in "Память и FRF", MrrFlashFrfDialog & action_flash_frf
    bus = FakeMrrBus(sw_profile="0192", cp_counter=0x0000, fblv_flash_sw_after="0196")
    frf_0196 = _make_synth_mrr_frf_image(part_number="3Q0907572C", sw_version="0196", app_size=0x150000)

    set_lang("ru")
    app, win = create_window()
    try:
        win.resize(1100, 800)
        win.conn.out_dir = tmp_path
        win.conn.port = "fake"
        win.conn.interface = "slcan"
        win.conn.wiring_confirmed = True
        win.mrr_screen.open_from_status_result(
            {
                "passport": {"part_number": "3Q0907572B", "sw_version": "0192", "asam_odx": "EV_ACCBOSCHVW48X"},
                "status": mrr_decode_status_dids({"03DE": "0000", "0440": "02010108005200", "0902": "00"}),
                "cflash_cp": {"cp_patch_state": "cp_disabled", "patched_points": 7, "total_points": 7},
            }
        )
        win.mrr_screen._selected_frf = frf_0196
        win.mrr_screen._selected_frf_path = tmp_path / "FL_3Q0907572C_0196___S.frf"
        win.mrr_screen.select("memory")
        app.processEvents()

        # Verify tab title and FRF flash button exist and are enabled even without XCP
        assert "FRF" in win.mrr_screen.nav_rows["memory"].lbl_name.text()
        page_w = win.mrr_screen.page_area.widget()
        flash_btns = [b for b in page_w.findChildren(QPushButton) if "FRF / ODX-F" in b.text()]
        assert flash_btns and flash_btns[0].isEnabled()

        # Verify confirmation dialog instantiates cleanly
        dlg = mrr_mod.MrrFlashFrfDialog(
            frf=frf_0196,
            part_number="3Q0907572B",
            current_sw="0192",
            warnings=["Cross-flash notice"],
            recovery_mode=True,
            via_gateway=True,
            parent=win,
        )
        dlg.close()

        # Run live action_flash_frf through OperationRunner against FakeMrrBus
        monkeypatch.setattr(mrr_mod, "run_dialog", lambda *_a, **_k: True)
        real_flash = mrr_mod.can_mrr_flash_frf
        monkeypatch.setattr(mrr_mod, "can_mrr_flash_frf", lambda port, frf_arg, **kw: real_flash(port, frf_arg, bus=bus, **kw))
        loop = QEventLoop()
        win.runner.operation_finished.connect(lambda *_: loop.quit())
        win.mrr_screen.action_flash_frf()
        QTimer.singleShot(8000, loop.quit)
        loop.exec()
        for _ in range(10):
            app.processEvents()
        assert win.runner.last_failure is None
        assert win.mrr_screen._passport.get("sw_version") == "0196"
        assert win.mrr_screen._cflash_cp == {}  # stale patch cache cleared after stock FRF flash
        assert win.mrr_screen._last_frf_report.get("complete") is True
    finally:
        win.close()


def test_mrr_unverified_sw_allows_all_reads_with_softer_pn_sw_notice() -> None:
    from contitool.core.mrr import mrr_support_info
    from contitool.progress import OperationReporter

    set_lang("ru")
    # Verified SW -> no warning
    assert mrr_support_info({"part_number": "3Q0907572B", "sw_version": "0192"})["warning"] is None

    # Unverified Bosch MRR family SW -> softer "info" notice with PN + SW, reads still allowed
    sup_bosch = mrr_support_info(
        {"part_number": "3Q0907572C", "sw_version": "0198", "asam_odx": "EV_ACCBOSCHVW48X"}
    )
    assert sup_bosch["verified"] is False
    assert sup_bosch["bosch_family"] is True
    assert sup_bosch["tone"] == "info"
    assert sup_bosch["warning"] and "3Q0907572C" in sup_bosch["warning"] and "0198" in sup_bosch["warning"]
    assert "официально не поддерживается" in sup_bosch["warning"]

    # Alien radar platform (e.g. Continental 2Q0) -> amber "warn" notice with PN + SW
    sup_alien = mrr_support_info({"part_number": "2Q0907572R", "sw_version": "0372", "system_name": "ACC CONTI"})
    assert sup_alien["verified"] is False
    assert sup_alien["bosch_family"] is False
    assert sup_alien["tone"] == "warn"
    assert sup_alien["warning"] and "2Q0907572R" in sup_alien["warning"] and "0372" in sup_alien["warning"]

    class UnverifiedMrrBus(FakeMrrBus):
        def _handle_uds(self, payload: bytes) -> None:
            if payload[:3] == b"\x22\xf1\x87":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x62\xf1\x87" + b"3Q0907572C ")
                return
            if payload[:3] == b"\x22\xf1\x89":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x62\xf1\x89" + b"0198")
                return
            super()._handle_uds(payload)

    bus = UnverifiedMrrBus(sw_profile="0192", xcp_gate_open=True)
    warns: list[str] = []

    class RecRep(OperationReporter):
        def warning(self, message: str) -> None:
            warns.append(message)

    st = can_mrr_status("fake", bus=bus, reporter=RecRep())
    assert st["officially_supported"] is False
    assert st["support_warning"] and "3Q0907572C" in st["support_warning"] and "0198" in st["support_warning"]

    keys = can_mrr_read_keys("fake", bus=bus, reporter=RecRep())
    assert keys["officially_supported"] is False
    assert keys["ika_hex"] == bus.ika.hex()
    assert keys["gfa_hex"] == bus.gfa.hex()
    assert keys["cp_patch_state"] == "unsupported_sw"
    assert any("3Q0907572C" in w and "0198" in w for w in warns)

    # Code Flash CP patching still refuses unknown SW
    with pytest.raises(RuntimeError):
        can_mrr_deactivate_cp("fake", bus=bus)


def test_mrr_review_flash_frf_recovery_reset_and_uninterruptible(tmp_path: Path) -> None:
    """B.1: FRF flash sends 11 01 on pre-erase abort (unless recovery_mode) and defers cancel across Erase..11 01."""
    from contitool.progress import OperationCancelledError, OperationReporter

    set_lang("en")
    frf_0192 = _make_synth_mrr_frf_image(part_number="3Q0907572B", sw_version="0192", app_size=0x150000)

    # 1. Cancel right before EraseMemory (at step 4) -> must send 11 01 reset in finally so radar exits FBLv!
    bus_cancel = FakeMrrBus(sw_profile="0192", cp_counter=0x0000)

    class CancelAtStep4(OperationReporter):
        def step(self, index: int, total: int, title: str) -> None:
            if index == 4:
                self.cancel()
            super().step(index, total, title)

    with pytest.raises(OperationCancelledError):
        can_mrr_flash_frf("fake", frf_0192, bus=bus_cancel, reporter=CancelAtStep4())
    assert bus_cancel.fblv_erased is False
    assert "31_FF00_10" not in bus_cancel.fblv_log
    assert "11_01" in bus_cancel.fblv_log
    assert bus_cancel.in_fblv is False

    # 2. In recovery_mode=True, pre-erase failure must NOT send 11 01 reset
    bus_rec = FakeMrrBus(sw_profile="0192", in_fblv=True)
    with pytest.raises(OperationCancelledError):
        can_mrr_flash_frf("fake", frf_0192, recovery_mode=True, bus=bus_rec, reporter=CancelAtStep4())
    assert "11_01" not in bus_rec.fblv_log

    # 3. Cancel triggered mid-Step 5 (after EraseMemory) must be deferred by uninterruptible() until AFTER 11 01 reset!
    bus_mid = FakeMrrBus(sw_profile="0192", cp_counter=0x0000, fblv_flash_sw_after="0192")

    class CancelDuringStep5(OperationReporter):
        def step(self, index: int, total: int, title: str) -> None:
            if index == 5:
                self.cancel()
            super().step(index, total, title)

    with pytest.raises(OperationCancelledError):
        can_mrr_flash_frf("fake", frf_0192, bus=bus_mid, reporter=CancelDuringStep5())
    assert bus_mid.fblv_log == [
        "10_02", "27_11", "27_12", "2E_F15A",
        "34_99_00", "37_99", "31_0202_99",
        "31_FF00_10",
        "34_10_00", "37_10", "31_0202_10",
        "31_FF01", "11_01",
    ]
    assert bus_mid.in_fblv is False


def test_mrr_review_xcp_flash_uninterruptible_and_pre_post_checksum(tmp_path: Path, monkeypatch) -> None:
    """B.2: xcp_flash_write_sectors verifies pre_data before backup, post_data after write, and wraps write in uninterruptible()."""
    from contitool.core.mrr import mrr_get_profile
    from contitool.progress import OperationCancelledError, OperationReporter

    set_lang("en")
    prof = mrr_get_profile("0192")
    sec_addr, sec_size = prof["cp_affected_sectors"][0]

    # 1. Corrupted pre_data fails verify_region_checksum BEFORE writing backup_sector_*.bin or erasing
    bus_bad_pre = FakeMrrBus(sw_profile="0192", xcp_gate_open=True)
    orig_sec = bytes(bus_bad_pre.cflash[sec_addr : sec_addr + sec_size])
    target_sec = bytearray(orig_sec)
    target_sec[0x10] ^= 0x55
    real_fast = MrrCanLink.xcp_read_fast_regions

    def _corrupt_pre(self, regions, **kw):
        out = real_fast(self, regions, **kw)
        name, data, calls, sec = out[0]
        if name.startswith("pre_"):
            mut = bytearray(data)
            mut[0] ^= 0xFF
            return [(name, bytes(mut), calls, sec), *out[1:]]
        return out

    monkeypatch.setattr(MrrCanLink, "xcp_read_fast_regions", _corrupt_pre)
    bkp_dir = tmp_path / "bad_pre_bkp"
    with MrrCanLink("fake", bus=bus_bad_pre) as lnk:
        lnk.xcp_connect_and_unlock()
        with pytest.raises(RuntimeError, match="BUILD_CHECKSUM mismatch"):
            lnk.xcp_flash_write_sectors([(sec_addr, bytes(target_sec))], profile=prof, backup_dir=bkp_dir)
    assert not (bkp_dir / f"backup_sector_0x{sec_addr:06X}.bin").exists()
    assert bytes(bus_bad_pre.cflash[sec_addr : sec_addr + sec_size]) == orig_sec
    monkeypatch.undo()

    # 2. Verify post_data also calls verify_region_checksum AND cancel mid-sector-write defers until SRAM cleanup finishes!
    bus_ok = FakeMrrBus(sw_profile="0192", xcp_gate_open=True)
    orig_synch = bytes(bus_ok._read_mem(int(prof["xcp_synch_slot"]), 4))
    verified_addrs: list[int] = []
    real_vrc = MrrCanLink.verify_region_checksum

    def _spy_vrc(self, address: int, data: bytes, **kw):
        verified_addrs.append(address)
        return real_vrc(self, address, data, **kw)

    monkeypatch.setattr(MrrCanLink, "verify_region_checksum", _spy_vrc)

    class CancelDuringWrite(OperationReporter):
        def info(self, message: str) -> None:
            if "Erasing and programming Code Flash sector" in message:
                self.cancel()
            super().info(message)

    with MrrCanLink("fake", bus=bus_ok) as lnk:
        lnk.xcp_connect_and_unlock()
        with pytest.raises(OperationCancelledError):
            lnk.xcp_flash_write_sectors(
                [(sec_addr, bytes(target_sec))],
                profile=prof,
                reporter=CancelDuringWrite(),
            )
    # Pre-check verified before write, write completed cleanly, AND SYNCH handler was restored in finally despite cancel!
    assert sec_addr in verified_addrs
    assert bytes(bus_ok.cflash[sec_addr : sec_addr + sec_size]) == bytes(target_sec)
    assert bytes(bus_ok._read_mem(int(prof["xcp_synch_slot"]), 4)) == orig_synch

    # Normal run verifies BOTH pre_data and post_data via verify_region_checksum
    verified_addrs.clear()
    with MrrCanLink("fake", bus=bus_ok) as lnk:
        lnk.xcp_connect_and_unlock()
        lnk.xcp_flash_write_sectors([(sec_addr, orig_sec)], profile=prof)
    assert verified_addrs.count(sec_addr) == 2


def test_mrr_review_xcp_gate_nrc36_sw_guard_1003_restore_bridge_log_and_uds_only(tmp_path: Path, monkeypatch) -> None:
    """B.3: NRC 0x36, no 10 4F retry after NRC 0x35 on SW!=0192, restore 10 03, raise if !unlocked, bridge log_path, uds_only."""
    import contextlib
    from contitool.can import mrr as mrr_can_mod

    set_lang("en")

    # 1. NRC 0x36 (exceededNumberOfAttempts) handled alongside 0x37
    class Nrc36Bus(FakeMrrBus):
        def _handle_uds(self, pdu: bytes) -> None:
            if pdu[:2] == b"\x27\x04":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x27\x36")
                return
            super()._handle_uds(pdu)

    with MrrCanLink("fake", bus=Nrc36Bus(sw_profile="0192", xcp_gate_open=False)) as lnk36:
        with pytest.raises(RuntimeError, match="0x36.*exceededNumberOfAttempts"):
            lnk36.enable_xcp_gate_uds()

    # 2. On SW != 0192, after NRC 0x35 on 27 04 in 10 03, must NOT try 10 4F or send a second 27 04!
    seen_reqs: list[bytes] = []

    class Nrc35Non0192Bus(FakeMrrBus):
        def _handle_uds(self, pdu: bytes) -> None:
            seen_reqs.append(bytes(pdu))
            if pdu[:2] == b"\x27\x04":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x27\x35")
                return
            super()._handle_uds(pdu)

    with MrrCanLink("fake", bus=Nrc35Non0192Bus(sw_profile="0780", xcp_gate_open=False)) as lnk780:
        with pytest.raises(RuntimeError, match="0x35.*invalidKey"):
            lnk780.enable_xcp_gate_uds()
    assert b"\x10\x4f" not in seen_reqs
    assert sum(1 for r in seen_reqs if r[:2] == b"\x27\x04") == 1

    # 3. On SW 0192, if 10 4F entered and failed to unlock, must restore 10 03 before raising!
    seen_0192: list[bytes] = []

    class Fail4F0192Bus(FakeMrrBus):
        def _handle_uds(self, pdu: bytes) -> None:
            seen_0192.append(bytes(pdu))
            if pdu[:2] == b"\x10\x4f":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x50\x4f\x00\x32\x01\xf4")
                return
            if pdu[:2] == b"\x27\x04":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x27\x35")
                return
            super()._handle_uds(pdu)

    with MrrCanLink("fake", bus=Fail4F0192Bus(sw_profile="0192", xcp_gate_open=False)) as lnk4f:
        with pytest.raises(RuntimeError, match="0x35"):
            lnk4f.enable_xcp_gate_uds()
    assert b"\x10\x4f" in seen_0192
    assert seen_0192[-1] == b"\x10\x03"

    # 4. If neither 10 03 nor 10 4F unlocks (e.g. NRC 0x22 on 27 03), must raise BEFORE 2E 09 02!
    seen_22: list[bytes] = []

    class Nrc22SeedBus(FakeMrrBus):
        def _handle_uds(self, pdu: bytes) -> None:
            seen_22.append(bytes(pdu))
            if pdu[:2] == b"\x27\x03":
                self._enqueue_isotp(MRR_UDS_RX_ID, b"\x7f\x27\x22")
                return
            super()._handle_uds(pdu)

    with MrrCanLink("fake", bus=Nrc22SeedBus(sw_profile="0192", xcp_gate_open=False)) as lnk22:
        with pytest.raises(RuntimeError, match="SecurityAccess"):
            lnk22.enable_xcp_gate_uds()
    assert not any(r[:3] == b"\x2e\x09\x02" for r in seen_22)

    # 5. _managed_mrr_session passes log_path=None to j533_can_bridge and log_path=log_path, bus=bridge.bus to MrrCanLink
    bridge_kwargs: list[dict[str, Any]] = []
    br_bus = FakeMrrBus(sw_profile="0192", xcp_gate_open=True)

    class _SpyBridge:
        def __init__(self, **kw: Any) -> None:
            bridge_kwargs.append(kw)
            self.bus = br_bus

        def __enter__(self) -> _SpyBridge:
            return self

        def __exit__(self, *a: Any) -> None:
            return None

    monkeypatch.setattr(mrr_can_mod, "j533_can_bridge", lambda port, **kw: _SpyBridge(**kw))
    trace_file = tmp_path / "mrr_bridge_trace.jsonl"
    can_mrr_read_keys(
        "fake",
        via_gateway=True,
        gateway_bridge=True,
        log_path=trace_file,
        bus=br_bus,
    )
    assert len(bridge_kwargs) == 1
    assert bridge_kwargs[0]["log_path"] is None
    assert trace_file.is_file() and trace_file.stat().st_size > 0
    monkeypatch.undo()

    # 6. uds_only=True with uds_session yielding False raises TimeoutError immediately
    class RefusingDpduMrrBus:
        uds_only = True
        nonraw: dict[int, int] = {}
        uds_refusal = "mrr link refused"

        @contextlib.contextmanager
        def uds_session(self, tx_id: int = 0x710, rx_id: int = 0x77A):
            yield False

        def send(self, msg: can.Message, timeout: float | None = None) -> None:
            raise AssertionError("Must not fall back to raw send on uds_only bus")

        def recv(self, timeout: float | None = None) -> can.Message | None:
            return None

        def shutdown(self) -> None:
            pass

    with pytest.raises(TimeoutError, match="mrr link refused"):
        can_mrr_status("fake", interface="dpdu", bus=RefusingDpduMrrBus())
    with MrrCanLink("fake", interface="dpdu", bus=RefusingDpduMrrBus()) as lnk_u:
        with pytest.raises(TimeoutError, match="mrr link refused"):
            lnk_u.request_uds(b"\x10\x03", 0x50)


def test_mrr_review_core_prefixes_fee_bounds_redundant_copy_vle_and_zipbomb() -> None:
    """B.4: 3QF/5QF907561 prefixes, Fee data_offset>=0x18, redundant 0x2C/computed boot_sum fallback, VLE bounds, zip bomb."""
    import io
    import zipfile
    from contitool.core.mrr import (
        MRR_FRF_MAX_BYTES,
        _VleBuilder,
        mrr_compute_ecu_boot_sum,
        mrr_fee_directory,
        mrr_support_info,
    )

    set_lang("en")

    # 1. 3QF907561 / 5QF907561 recognized as Bosch MRR family
    for pn in ("3QF907561D", "5QF907561A"):
        sup = mrr_support_info({"part_number": pn, "sw_version": "0799"})
        assert sup["bosch_family"] is True
        assert sup["tone"] == "info"

    # 2. mrr_fee_directory rejects entries with data_offset < 0x18 (header overlap)
    bad_df = bytearray(b"\xff" * MRR_DFLASH_SIZE)
    bad_df[0x7FF8:0x8000] = struct.pack(">HBBI", 0x0010, 0x2A, 0x00, 0x00000000)
    bad_df[0x7FF0:0x7FF8] = struct.pack(">HBBI", 0x0018, 0x2B, 0x00, 0x00000000)
    entries = mrr_fee_directory(bytes(bad_df), 0)
    assert len(entries) == 1 and entries[0]["block_id"] == 0x2B and entries[0]["data_offset"] == 0x0018

    # 3. mrr_parse_dflash_fee falls back to computed_boot_sum AND redundant Fee copy of 0x2C
    boot_img = bytes((i * 13 + 7) & 0xFF for i in range(0x10000))
    true_boot_sum = mrr_compute_ecu_boot_sum(boot_img)
    ika = bytes.fromhex("112233445566778899aabbccddeeff00")
    gfa = bytes.fromhex("aabbccddeeff00112233445566778899")
    df_base = bytearray(_build_synthetic_mrr_dflash(ika=ika, gfa=gfa, ecu_boot_sum=true_boot_sum))
    # Corrupt cached_boot_sum inside block 0x40 (5th block in _build_synthetic_mrr_dflash)
    dir_entries = mrr_fee_directory(bytes(df_base), 0)
    e40 = next(e for e in dir_entries if e["block_id"] == 0x40)
    df_corrupt_40 = bytearray(df_base)
    df_corrupt_40[e40["data_offset"] + 1] ^= 0xFF
    parsed_comp = mrr_parse_dflash_fee(bytes(df_corrupt_40), cflash_or_boot_bytes=boot_img)
    assert parsed_comp["encryption_scheme"] == "aes128-ecb-ecu-boot-sum"
    assert parsed_comp["ika_hex"] == ika.hex()
    assert parsed_comp["gfa_hex"] == gfa.hex()

    # Corrupt newest copy (copy 1) of 0x2C while keeping valid copy 0 -> must recover via copy 0!
    df_2c = bytearray(df_base)
    lowest_dir = min(e["directory_offset"] for e in dir_entries)
    new_dir = lowest_dir - 8
    bad_2c_off = 0x0200
    df_2c[bad_2c_off : bad_2c_off + 17] = b"\x01" + (b"\x00" * 16)
    df_2c[new_dir : new_dir + 8] = struct.pack(">HBBI", bad_2c_off, (1 << 7) | 0x2C, 0x00, 0x00000000)
    parsed_2c = mrr_parse_dflash_fee(bytes(df_2c))
    assert parsed_2c["encryption_scheme"] == "aes128-ecb-ecu-boot-sum"
    assert parsed_2c["ika_hex"] == ika.hex()

    # 4. _VleBuilder.finish() validates alignment and signed range for 4-byte e_b/e_bl and e_bc
    b_odd = _VleBuilder()
    b_odd.ebranch("b", "t")
    b_odd.labels["t"] = 3
    with pytest.raises(ValueError, match="e_b/e_bl"):
        b_odd.finish()

    b_range_b = _VleBuilder()
    b_range_b.ebranch("bl", "t")
    b_range_b.labels["t"] = 1 << 24  # max is (1 << 24) - 2
    with pytest.raises(ValueError, match="e_b/e_bl"):
        b_range_b.finish()

    b_range_bc = _VleBuilder()
    b_range_bc.ebranch("bne", "t")
    b_range_bc.labels["t"] = 1 << 15  # max is (1 << 15) - 2
    with pytest.raises(ValueError, match="e_bc"):
        b_range_bc.finish()

    b_ok = _VleBuilder()
    b_ok.ebranch("bne", "t")
    b_ok.labels["t"] = (1 << 15) - 2
    assert len(b_ok.finish()) == 4

    # 5. mrr_read_frf rejects zip bomb (> MRR_FRF_MAX_BYTES uncompressed) before zf.read()
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.odx", b"A" * (MRR_FRF_MAX_BYTES + 1024))
    bomb_frf = mrr_frf_decrypt(zbuf.getvalue())
    assert len(bomb_frf) < MRR_FRF_MAX_BYTES  # highly compressed zeros/As
    with pytest.raises(ValueError, match="too large"):
        mrr_read_frf(bomb_frf, "bomb.frf")



