"""MQB 13 ACC Radar / J428 (Bosch MRR1Plus 3Q0 & MRRevo14F 5Q0/3QF) offline & cryptographic core.

Hardware & firmware references:
  - MRR1Plus (3Q0 907 572 A/B/C, SW 0130/0192/0194/0196): NXP MPC5674K (e200z7d VLE, 1.5 MiB CFlash, 64 KiB DFlash, 384 KiB SRAM).
  - MRRevo14F (3QF 907 561 D SW 0682, 5Q0 907 572 M/R/S SW X720/0771/0780): NXP MPC5675K (2.0 MiB CFlash, 64 KiB DFlash, 512 KiB SRAM).
  - Diagnostics: UDS ISO-TP 0x757 -> 0x7C1 (Extended CAN, J533 RSCAN0 channel 2).
  - Calibration / Memory: ASAM XCP on CAN 0x1BFEBA00 -> 0x1BFEBA01 (29-bit Extended ID), Fast CAN burst 0x77E.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
import dataclasses
from functools import lru_cache
import hashlib
import io
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
import zlib
from typing import Any

from contitool.core.bcm import (
    bcm_aes128_ecb_decrypt,
    bcm_aes128_ecb_encrypt,
    bcm_build_cp_key_container,
    bcm_unpack_cp_key_container,
)
from contitool.core.crypto import rsassa_pkcs1_v15_verify
from contitool.i18n import tr

# ── CAN & UDS Identifiers ───────────────────────────────────────────────────
MRR_UDS_TX_ID = 0x757
MRR_UDS_RX_ID = 0x7C1
MRR_UDS_FUNC_ID = 0x7DF
MRR_KS_RX_ID = 0x17FC0157
MRR_KS_TX_ID = 0x17FE0157
MRR_KS_STATUS_ID = 0x17FE0257
MRR_XCP_TX_ID = 0x1BFEBA00
MRR_XCP_RX_ID = 0x1BFEBA01
MRR_FAST_CAN_ID = 0x77E

# ── Security Access Logins & Addends ────────────────────────────────────────
MRR_LOGIN_CODING = 20103       # 0x4E87: Coding DID 0x0600 & Dataset DID 0x7200
MRR_LOGIN_XCP_GATE = 24085     # 0x5E15: Adaptation DID 0x0902 bit 3 (XcpGate)
MRR_LOGIN_ALIGN = 46470        # 0xB586: Radar alignment service routines
MRR_DEV_ADDEND_0192 = 0x11C67  # Bosch Development Session (10 4F) addend on 3Q0

# ── Component Protection Constants ──────────────────────────────────────────
MRR_CP_KEY_TYPE_IKA = 0x01
MRR_CP_KEY_TYPE_GFA = 0x02
MRR_VIRGIN_IKA_PT = bytes.fromhex("56765434256789afdbca987523465fba")
MRR_VIRGIN_IKA_CT = bytes.fromhex("fb1691ce6b50ca63a0fa86836c0fd11f")
MRR_KS_META_MAGIC = bytes.fromhex("aabbccdd55555555555555")
MRR_SHADOW_SECRET_MAGIC_A = 0x0BADC0DE
MRR_SHADOW_SECRET_MAGIC_B = 0x0BAEC0DE

# ── Standard UDS SWaP / FES Diagnostics (Gen 1 0130..0196 & Gen 2 0682..0780) ─
MRR_SWAP_STATUS_DID = 0x3C00    # RO, 5 B per FS-ID: uint32 BE FS-ID + uint8 status
MRR_SWAP_RSA_KEY_DID = 0x3C05   # RO, 160 B: active RSA-1024 public key (128 B N + 32 B exp)
MRR_SWAP_VCRN_DID = 0x3C0A      # RO, 5 B: bound SWaP/FES VCRN (FF*5 = virgin)
MRR_SWAP_STATUS_ACTIVE = 0x4F   # VW SWaP-SF v1.6 active mask (0x4F or 0xFF)
MRR_GEN2_RSA_DEV_PREFIX = bytes.fromhex("9c4773ec8dbbb844")     # X720 Entwicklungsschluessel
MRR_GEN2_RSA_SERIES_PREFIX = bytes.fromhex("c2f72f35535ee217")  # 0771/0780 Serienschluessel

# ── Memory Map & Driver Workspace (MPC5674K / MPC5675K) ─────────────────────
MRR_BOOT_BASE = 0x00000000
MRR_BOOT_SIZE = 0x00030000
MRR_APP_BASE = 0x00030000
MRR_DFLASH_ADDR = 0x00800000
MRR_DFLASH_SIZE = 0x00010000
MRR_SRAM_ADDR = 0x40000000

MRR_DRIVER_CONTROL = 0x40039800
MRR_DRIVER_ADDRESS = 0x40039900
MRR_DRIVER_CONTROL_SAVE_SIZE = 0x68
MRR_FAST_CAN_CHUNK_SIZE = 512
MRR_FAST_CAN_MAX_FRAMES = 64
MRR_FAST_CAN_TIMEOUT_LOOPS = 0x00200000
MRR_FLASH_STREAM_TIMEOUT_LOOPS = 0x00800000
MRR_FLASH_STREAM_BATCH_BYTES = 64
MRR_FAST_WRITE_CHUNK_BYTES = 4096

MRR_FLASH_DRIVER_ADDRESS = 0x4005C000
MRR_FLASH_DRIVER_UPPER_PHYS = 0x4005A000
MRR_FLASH_DRIVER_HALF_SIZE = 0x2000
MRR_FLASH_DRIVER_SIZE = 0x4000
MRR_FLASH_SECTOR_DRIVER_ADDR = 0x40038800
MRR_FLASH_STAGE_BUFFER = 0x40058000

C90FL_SECTORS_5674K: tuple[tuple[int, int], ...] = (
    (0x00000000, 0x00004000),
    (0x00004000, 0x00004000),
    (0x00008000, 0x00008000),
    (0x00010000, 0x00008000),
    (0x00018000, 0x00004000),
    (0x0001C000, 0x00004000),
    (0x00020000, 0x00010000),
    (0x00030000, 0x00010000),
    (0x00040000, 0x00004000),
    (0x00044000, 0x00004000),
    (0x00048000, 0x00008000),
    (0x00050000, 0x00008000),
    (0x00058000, 0x00004000),
    (0x0005C000, 0x00004000),
    (0x00060000, 0x00010000),
    (0x00070000, 0x00010000),
    (0x00080000, 0x00040000),
    (0x000C0000, 0x00040000),
    (0x00100000, 0x00040000),
    (0x00140000, 0x00040000),
)

C90FL_SECTORS_5675K: tuple[tuple[int, int], ...] = C90FL_SECTORS_5674K + (
    (0x00180000, 0x00040000),
    (0x001C0000, 0x00040000),
)

# ── Verified Firmware Profiles (3Q0 / 3QF / 5Q0) ───────────────────────────
MRR_PROFILES: dict[str, dict[str, Any]] = {
    "0130": {
        "sw": "0130",
        "unit": "3Q0907572A",
        "family": "MRR1Plus",
        "mcu": "MPC5674K",
        "odx_name": "EV_ACCBOSCHVW48X",
        "cflash_size": 0x00180000,
        "boot_size": 0x00030000,
        "app_base": 0x00030000,
        "app_size": 0x00150000,
        "dflash_addr": 0x00800000,
        "dflash_size": 0x00010000,
        "sram_addr": 0x40000000,
        "sram_size": 0x00060000,
        "ram_safe_end": 0x4005E000,
        "user_stack_canary_addr": 0x4005E000,
        "stock_app_sha256": "a1aac51bac55939c5fb2b219cc2b31495892505cdd1cec48ec74fc23c8d30822",
        "cp_disable_app_sha256": "6f417057b3a79d37bd33dc6fe5b9ab35d3165396328a3597741ef360e6b85af7",
        "eraserouti_sha256": "5f750bf4fc505f1251f85f0f2badd0e6c76d282c03faca160d908c8f901272d6",
        "fast_driver_supported": True,
        "flash_write_supported": True,
        "xcp_synch_slot": 0x40013954,
        "xcp_synch_default": 0x000E79E8,
        "xcp_r3_arg_state": 0x40039F38,
        "xcp_dto_buffer": 0x40039ED8,
        "mmu_dispatch_wrapper": 0x0010DE7C,
        "mmu_load_single_entry": 0x0008D3DC,
        "mmu_dispatch_mode": "indirect_r29",
        "sbc_last_tb_addr": 0x40024D30,
        "tlb1_sram_entry": 0x0B,
        "flash_driver_addr": 0x4005C000,
        "flash_driver_upper_phys": 0x4005A000,
        "sram_ika_addr": 0x400562B0,
        "sram_ika_inv_addr": 0x400562C0,
        "sram_gfa_addr": 0x400562A0,
        "sram_ks_meta_addr": 0x40056270,
        "sram_ecu_boot_sum_addr": 0x40056004,
        "sram_cp_active_addr": None,
        "sram_cp_counter_addr": 0x40056200,
        "sram_auth_success_trigger_addr": 0x4005620C,
        "cp_affected_sectors": (
            (0x00044000, 0x00004000),
            (0x00140000, 0x00040000),
        ),
        "swap_affected_sectors": (
            (0x00100000, 0x00040000),
            (0x00140000, 0x00040000),
        ),
        "swap_config": {
            "generation": 1,
            "swap_main_pa": 0x001336F4,
            "fsid_table_pa": 0x0004AE38,
            "default_package_index": 6,
            "pkg_index_rels": (0x50, 0x58),
            "rel_sites": (
                (0x2A, "e607", "e807", "SWaP_MainFunction skip FES donor cert check"),
                (0x40, "e20f", "e808", "SWaP_MainFunction unconditional branch to ApplyFeatureLevel"),
                (0x50, "8831", "4863", "SWaP_MainFunction active FS-ID index load"),
                (0x58, "4833", "4863", "SWaP_MainFunction fallback FS-ID index 3"),
                (0x6A, "74841fff", "48044400", "SWaP_MainFunction Dem 0x126 (no valid FSC)"),
                (0x7C, "4814", "4804", "SWaP_MainFunction Dem 0x127 (invalid FSC)"),
            ),
            "uds_3c00": {
                "prepare_pa": 0x0016D1AC,
                "prepare_stock": "1800d000",
                "len_pa": 0x0016D288,
                "len_stock": "7088e0051c847c8aa364",
                "data_pa": 0x0016D20C,
                "data_stock": (
                    "1800d000182106e01ba1091473a8e0051fbd7a5c7088e0051c847c8aa3e42a0e"
                    "e61c24031bfd84ff01e567fee60918ff000118e3"
                ),
            },
        },
        "patches": (
            ("KS_GetCpActive returns zero", 0x00168984, "7088e005", "48030004"),
            ("KS_Auth accepts any J533 response", 0x0016A122, "e222", "4400"),
            ("KS_State_AuthFail returns immediately", 0x00168928, "182106f0", "00044400"),
            ("KS_State does not increment cp_counter", 0x00168B2A, "2004", "4804"),
            ("KS_KeyMgr_IsVirginIKA returns zero", 0x0016A7C4, "7088e005", "48030004"),
            ("KS_KeyMgr_IsGfaMissing returns zero", 0x0016A7E4, "70e8e005", "48030004"),
            (
                "FiM CP event masks are cleared",
                0x0004596C,
                "40040008004004000800400400080081002000004004000800",
                "00" * 25,
            ),
        ),
    },
    "0192": {
        "sw": "0192",
        "unit": "3Q0907572B",
        "family": "MRR1Plus",
        "mcu": "MPC5674K",
        "odx_name": "EV_ACCBOSCHVW48X",
        "cflash_size": 0x00180000,
        "boot_size": 0x00030000,
        "app_base": 0x00030000,
        "app_size": 0x00150000,
        "dflash_addr": 0x00800000,
        "dflash_size": 0x00010000,
        "sram_addr": 0x40000000,
        "sram_size": 0x00060000,
        "ram_safe_end": 0x4005E000,
        "user_stack_canary_addr": 0x4005E000,
        "stock_app_sha256": "01f3151c3c6c83d775f0a154ae4fcff06471df78a8134dc04c18d4df0fec8de9",
        "cp_disable_app_sha256": "f9060fa637eeb4f06d9faedcea11088e86ba5c30d396e5e889482f09de4df7c3",
        "eraserouti_sha256": "5f750bf4fc505f1251f85f0f2badd0e6c76d282c03faca160d908c8f901272d6",
        "fast_driver_supported": True,
        "flash_write_supported": True,
        "xcp_synch_slot": 0x400136E4,
        "xcp_synch_default": 0x000FE8FC,
        "xcp_r3_arg_state": 0x400154AC,
        "xcp_dto_buffer": 0x4003A26C,
        "mmu_dispatch_wrapper": 0x000568CC,
        "mmu_load_single_entry": 0x0009AF58,
        "sbc_last_tb_addr": 0x40025E28,
        "tlb1_sram_entry": 0x0B,
        "flash_driver_addr": 0x4005C000,
        "flash_driver_upper_phys": 0x4005A000,
        "sram_ika_addr": 0x40056294,
        "sram_ika_inv_addr": 0x400562A4,
        "sram_gfa_addr": 0x40056284,
        "sram_ks_meta_addr": 0x40056254,
        "sram_ecu_boot_sum_addr": 0x40056004,
        "sram_cp_active_addr": 0x40014BE2,
        "sram_cp_counter_addr": 0x400561E4,
        "sram_auth_success_trigger_addr": 0x400561F0,
        "cp_affected_sectors": (
            (0x00048000, 0x00008000),
            (0x00140000, 0x00040000),
        ),
        "swap_affected_sectors": (
            (0x00140000, 0x00040000),
        ),
        "swap_config": {
            "generation": 1,
            "swap_main_pa": 0x00146118,
            "fsid_table_pa": 0x0004E463,
            "default_package_index": 6,
            "uds_3c00": {
                "prepare_pa": 0x0016C25C,
                "prepare_stock": "182106e0",
                "len_pa": 0x0016C334,
                "len_stock": "7088e0051c847c82a264",
                "data_pa": 0x0016C2B8,
                "data_stock": (
                    "182106e01ba1091473a8e0057088e0051c847c82a2e41fbd7a302a0ee61c2403"
                    "1bfd84ff01e567fee60918ff000118be84ff18e3"
                ),
            },
        },
        "patches": (
            ("KS_GetCpActive returns zero", 0x001645A4, "7088e005", "48030004"),
            ("KS_Auth accepts any J533 response", 0x00165C2E, "e222", "4400"),
            ("KS_State_AuthFail returns immediately", 0x0016454C, "182106f0", "00044400"),
            ("KS_State does not increment cp_counter", 0x00164736, "2004", "4804"),
            ("KS_KeyMgr_IsVirginIKA returns zero", 0x001662A8, "7088e005", "48030004"),
            ("KS_KeyMgr_IsGfaMissing returns zero", 0x001662C8, "70e8e005", "48030004"),
            (
                "FiM CP event masks are cleared",
                0x00048E64,
                "801000200000801000200000801000200000010180000000801000200000",
                "00" * 30,
            ),
        ),
    },
    "0194": {
        "sw": "0194",
        "unit": "3Q0907572B",
        "family": "MRR1Plus",
        "mcu": "MPC5674K",
        "odx_name": "EV_ACCBOSCHVW48X",
        "cflash_size": 0x00180000,
        "boot_size": 0x00030000,
        "app_base": 0x00030000,
        "app_size": 0x00150000,
        "dflash_addr": 0x00800000,
        "dflash_size": 0x00010000,
        "sram_addr": 0x40000000,
        "sram_size": 0x00060000,
        "ram_safe_end": 0x4005E000,
        "user_stack_canary_addr": 0x4005E000,
        "stock_app_sha256": "d35508b5e7a66faf5d63965bf0f0dda68c2538fdb220712774f25ba8386fba5a",
        "cp_disable_app_sha256": "b7d32db179b0519ff07f58c0cb978cd1395d7c135a4a76b8cc1d8a20493ac496",
        "eraserouti_sha256": "5f750bf4fc505f1251f85f0f2badd0e6c76d282c03faca160d908c8f901272d6",
        "fast_driver_supported": True,
        "flash_write_supported": True,
        "xcp_synch_slot": 0x400136E4,
        "xcp_synch_default": 0x000FE8E0,
        "xcp_r3_arg_state": 0x400154B4,
        "xcp_dto_buffer": 0x4003A2A4,
        "mmu_dispatch_wrapper": 0x000570C8,
        "mmu_load_single_entry": 0x0009AF58,
        "sbc_last_tb_addr": 0x40025E48,
        "tlb1_sram_entry": 0x0B,
        "flash_driver_addr": 0x4005C000,
        "flash_driver_upper_phys": 0x4005A000,
        "sram_ika_addr": 0x40056298,
        "sram_ika_inv_addr": 0x400562A8,
        "sram_gfa_addr": 0x40056288,
        "sram_ks_meta_addr": 0x40056258,
        "sram_ecu_boot_sum_addr": 0x40056004,
        "sram_cp_active_addr": 0x40014BE2,
        "sram_cp_counter_addr": 0x400561E4,
        "sram_auth_success_trigger_addr": 0x400561F0,
        "cp_affected_sectors": (
            (0x00048000, 0x00008000),
            (0x00140000, 0x00040000),
        ),
        "swap_affected_sectors": (
            (0x00140000, 0x00040000),
        ),
        "swap_config": {
            "generation": 1,
            "swap_main_pa": 0x001462F4,
            "fsid_table_pa": 0x0004E46F,
            "default_package_index": 6,
            "uds_3c00": {
                "prepare_pa": 0x0016C5BC,
                "prepare_stock": "182106e0",
                "len_pa": 0x0016C694,
                "len_stock": "7088e0051c847c9aa264",
                "data_pa": 0x0016C618,
                "data_stock": (
                    "182106e01ba1091473a8e0057088e0051c847c9aa2e41fbd7a482a0ee61c2403"
                    "1bfd84ff01e567fee60918ff000118be84ff18e3"
                ),
            },
        },
        "patches": (
            ("KS_GetCpActive returns zero", 0x0016458C, "7088e005", "48030004"),
            ("KS_Auth accepts any J533 response", 0x00165D82, "e21e", "4400"),
            ("KS_State_AuthFail returns immediately", 0x00164534, "182106f0", "00044400"),
            ("KS_State does not increment cp_counter", 0x0016472A, "2004", "4804"),
            ("KS_KeyMgr_IsVirginIKA returns zero", 0x001664E0, "7088e005", "48030004"),
            ("KS_KeyMgr_IsGfaMissing returns zero", 0x00166500, "70e8e005", "48030004"),
            (
                "FiM CP event masks are cleared",
                0x00048E70,
                "801000200000801000200000801000200000010180000000801000200000",
                "00" * 30,
            ),
        ),
    },
    "0196": {
        "sw": "0196",
        "unit": "3Q0907572C",
        "family": "MRR1Plus",
        "mcu": "MPC5674K",
        "odx_name": "EV_ACCBOSCHVW48X",
        "cflash_size": 0x00180000,
        "boot_size": 0x00030000,
        "app_base": 0x00030000,
        "app_size": 0x00150000,
        "dflash_addr": 0x00800000,
        "dflash_size": 0x00010000,
        "sram_addr": 0x40000000,
        "sram_size": 0x00060000,
        "ram_safe_end": 0x4005E000,
        "user_stack_canary_addr": 0x4005E000,
        "stock_app_sha256": "66d9ed180379351e1f4eafb245bae25d37a77a49a5c1ef909fceaf1dd124b5cd",
        "cp_disable_app_sha256": "cf2d888ca26ae9a288fc66efdb827acdd73ef1dd780c0a54f0a6895494d043d7",
        "eraserouti_sha256": "5f750bf4fc505f1251f85f0f2badd0e6c76d282c03faca160d908c8f901272d6",
        "fast_driver_supported": True,
        "flash_write_supported": True,
        "xcp_synch_slot": 0x40013710,
        "xcp_synch_default": 0x000FEB84,
        "xcp_r3_arg_state": 0x400154DC,
        "xcp_dto_buffer": 0x4003A3E0,
        "mmu_dispatch_wrapper": 0x000594EC,
        "mmu_load_single_entry": 0x0009AF68,
        "sbc_last_tb_addr": 0x40025E70,
        "tlb1_sram_entry": 0x0B,
        "flash_driver_addr": 0x4005C000,
        "flash_driver_upper_phys": 0x4005A000,
        "sram_ika_addr": 0x40056298,
        "sram_ika_inv_addr": 0x400562A8,
        "sram_gfa_addr": 0x40056288,
        "sram_ks_meta_addr": 0x40056258,
        "sram_ecu_boot_sum_addr": 0x40056004,
        "sram_cp_active_addr": 0x40014C12,
        "sram_cp_counter_addr": 0x400561E4,
        "sram_auth_success_trigger_addr": 0x400561F0,
        "cp_affected_sectors": (
            (0x00048000, 0x00008000),
            (0x00140000, 0x00040000),
        ),
        "swap_affected_sectors": (
            (0x00140000, 0x00040000),
        ),
        "swap_config": {
            "generation": 1,
            "swap_main_pa": 0x0014833C,
            "fsid_table_pa": 0x0004E4DF,
            "default_package_index": 6,
            "uds_3c00": {
                "prepare_pa": 0x0016C5BC,
                "prepare_stock": "182106e0",
                "len_pa": 0x0016C694,
                "len_stock": "7088e0051c847c9aa264",
                "data_pa": 0x0016C618,
                "data_stock": (
                    "182106e01ba1091473a8e0057088e0051c847c9aa2e41fbd7a482a0ee61c2403"
                    "1bfd84ff01e567fee60918ff000118be84ff18e3"
                ),
            },
        },
        "patches": (
            ("KS_GetCpActive returns zero", 0x0016458C, "7088e005", "48030004"),
            ("KS_Auth accepts any J533 response", 0x00165D82, "e21e", "4400"),
            ("KS_State_AuthFail returns immediately", 0x00164534, "182106f0", "00044400"),
            ("KS_State does not increment cp_counter", 0x0016472A, "2004", "4804"),
            ("KS_KeyMgr_IsVirginIKA returns zero", 0x001664E0, "7088e005", "48030004"),
            ("KS_KeyMgr_IsGfaMissing returns zero", 0x00166500, "70e8e005", "48030004"),
            (
                "FiM CP event masks are cleared",
                0x00048ED0,
                "801000200000801000200000801000200000010180000000801000200000",
                "00" * 30,
            ),
        ),
    },
    "0682": {
        "sw": "0682",
        "unit": "3QF907561D",
        "family": "MRRevo14F",
        "mcu": "MPC5675K",
        "odx_name": "EV_ACCBOSCHVW416",
        "cflash_size": 0x00200000,
        "boot_size": 0x00030000,
        "app_base": 0x00030000,
        "app_size": 0x001D0000,
        "dflash_addr": 0x00800000,
        "dflash_size": 0x00010000,
        "sram_addr": 0x40000000,
        "sram_size": 0x00080000,
        "ram_safe_end": 0x4007E000,
        "user_stack_canary_addr": 0x4007E000,
        "stock_app_sha256": None,
        "cp_disable_app_sha256": None,
        "eraserouti_sha256": "b23b82945a5cd353e73ab2f3781ddc1a2e09deae239042e7da20ba81cc1421e9",
        "fast_driver_supported": True,
        "flash_write_supported": True,
        "xcp_synch_slot": 0x40015A44,
        "xcp_synch_default": 0x00124CBA,
        "xcp_r3_arg_state": 0x4001A8A0,
        "xcp_dto_buffer": 0x4001A858,
        "mmu_dispatch_wrapper": 0x00099652,
        "mmu_load_single_entry": 0x00057BD8,
        "sbc_last_tb_addr": 0x40016F68,
        "tlb1_sram_entry": 0x14,
        "flash_driver_addr": 0x4007C000,
        "flash_driver_upper_phys": 0x4007A000,
        "sram_ika_addr": 0x4007C308,
        "sram_ika_inv_addr": 0x4007C318,
        "sram_gfa_addr": 0x4007C2F8,
        "sram_ks_meta_addr": 0x4007C328,
        "sram_ecu_boot_sum_addr": 0x4007C378,
        "sram_cp_active_addr": None,
        "sram_cp_counter_addr": 0x4007C258,
        "sram_auth_success_trigger_addr": 0x4007C254,
        "cp_affected_sectors": (
            (0x00140000, 0x00040000),
            (0x001C0000, 0x00040000),
        ),
        "swap_affected_sectors": (
            (0x00060000, 0x00010000),
            (0x00100000, 0x00040000),
        ),
        "swap_config": {
            "generation": 2,
            "coord_base_pa": 0x000602FE,
            "e_bl_aff066": "78a9e8c5",
            "fsid_table_pa": 0x00166444,
            "default_groups": (8, 3, 4, 7),
            "uds_3c00": {
                "cond_pa": 0x0012C4DE,
                "len_pa": 0x0012C57E,
                "data_pa": 0x0012C51C,
                "data_stock": (
                    "0080182106e0d4c1013cd6e1d5d1d7f1d90173e8e0081c7fd5dc789d0d5773a8"
                    "e0081c7dd5e0789d0d23581fd5dc716001807000a9807cab"
                ),
            },
        },
        "patches": (
            ("KS_GetCpActive returns zero", 0x001F572A, "7188e008", "48030004"),
            ("KS_Auth accepts any J533 response", 0x001F6628, "e215", "4400"),
            ("KS_State_AuthFail returns immediately", 0x001F56C4, "0080", "0004"),
            ("KS_State does not increment cp_counter", 0x001F5336, "2003", "4803"),
            ("KS_KeyMgr_IsVirginIKA returns zero", 0x001F8640, "7188e008", "48030004"),
            ("KS_KeyMgr_IsGfaMissing returns zero", 0x001F865C, "70e8e008", "48030004"),
            (
                "FiM CP event masks are cleared",
                0x0017B61C,
                "002100000100002100000100002100000100010200010000002100000100",
                "00" * 30,
            ),
        ),
    },
    "X720": {
        "sw": "X720",
        "unit": "5Q0907572M",
        "family": "MRRevo14F",
        "mcu": "MPC5675K",
        "odx_name": "EV_ACCBOSCHVW416",
        "cflash_size": 0x00200000,
        "boot_size": 0x00030000,
        "app_base": 0x00030000,
        "app_size": 0x001D0000,
        "dflash_addr": 0x00800000,
        "dflash_size": 0x00010000,
        "sram_addr": 0x40000000,
        "sram_size": 0x00080000,
        "ram_safe_end": 0x4007E000,
        "user_stack_canary_addr": 0x4007E000,
        "stock_app_sha256": "b7533c6e75308bb4d08cfc8e5062ecd1835407d599b54f45c287ac4068cbe5c6",
        "cp_disable_app_sha256": "c32b084435d4c53ed7571354c6e6b5e03d5e33b496a4f6db8fe2de758e09604c",
        "eraserouti_sha256": "b23b82945a5cd353e73ab2f3781ddc1a2e09deae239042e7da20ba81cc1421e9",
        "fast_driver_supported": True,
        "flash_write_supported": True,
        "xcp_synch_slot": 0x4001624C,
        "xcp_synch_default": 0x00134DA0,
        "xcp_r3_arg_state": 0x4001A44C,
        "xcp_dto_buffer": 0x4001A404,
        "mmu_dispatch_wrapper": 0x0009AE16,
        "mmu_load_single_entry": 0x00058744,
        "sbc_last_tb_addr": 0x40017760,
        "tlb1_sram_entry": 0x14,
        "flash_driver_addr": 0x4007C000,
        "flash_driver_upper_phys": 0x4007A000,
        "sram_ika_addr": 0x4007C38C,
        "sram_ika_inv_addr": 0x4007C39C,
        "sram_gfa_addr": 0x4007C37C,
        "sram_ks_meta_addr": 0x4007C3AC,
        "sram_ecu_boot_sum_addr": 0x4007C3FC,
        "sram_cp_active_addr": None,
        "sram_cp_counter_addr": 0x4007C2DC,
        "sram_auth_success_trigger_addr": 0x4007C2D8,
        "cp_affected_sectors": (
            (0x00180000, 0x00040000),
            (0x001C0000, 0x00040000),
        ),
        "swap_affected_sectors": (
            (0x00060000, 0x00010000),
            (0x00100000, 0x00040000),
        ),
        "swap_config": {
            "generation": 2,
            "coord_base_pa": 0x00060EF0,
            "e_bl_aff066": "78a9dcdb",
            "fsid_table_pa": 0x00176BA4,
            "default_groups": (8, 3, 4, 7),
            "uds_3c00": {
                "cond_pa": 0x0013C682,
                "len_pa": 0x0013C722,
                "data_pa": 0x0013C6C0,
                "data_stock": (
                    "0080182106e0d4c1013cd6e1d5d1d7f1d90173e8e0081c7fd8c4789c0bbb73a8"
                    "e0081c7dd8c8789c0b87581fd8c4716001807000a9807cab"
                ),
            },
        },
        "patches": (
            ("KS_GetCpActive returns zero", 0x001F5730, "7188e008", "48030004"),
            ("KS_Auth accepts any J533 response", 0x001F662E, "e215", "4400"),
            ("KS_State_AuthFail returns immediately", 0x001F56CA, "0080", "0004"),
            ("KS_State does not increment cp_counter", 0x001F533C, "2003", "4803"),
            ("KS_KeyMgr_IsVirginIKA returns zero", 0x001F8646, "7188e008", "48030004"),
            ("KS_KeyMgr_IsGfaMissing returns zero", 0x001F8662, "70e8e008", "48030004"),
            (
                "FiM CP event masks are cleared",
                0x0018E24E,
                "002100000100002100000100002100000100010200010000002100000100",
                "00" * 30,
            ),
        ),
    },
    "0771": {
        "sw": "0771",
        "unit": "5Q0907572R",
        "family": "MRRevo14F",
        "mcu": "MPC5675K",
        "odx_name": "EV_ACCBOSCHVW416",
        "cflash_size": 0x00200000,
        "boot_size": 0x00030000,
        "app_base": 0x00030000,
        "app_size": 0x001D0000,
        "dflash_addr": 0x00800000,
        "dflash_size": 0x00010000,
        "sram_addr": 0x40000000,
        "sram_size": 0x00080000,
        "ram_safe_end": 0x4007E000,
        "user_stack_canary_addr": 0x4007E000,
        "stock_app_sha256": "4d722821f1a524541d4b15fd2189c8c0f55f6c9c7dd913ccaf9f35b15dfe319a",
        "cp_disable_app_sha256": "c0971df75f0afb10dbb8f3bf5cc1cc8dde1a5618ce8df953024fa6de1e8eb631",
        "eraserouti_sha256": "b23b82945a5cd353e73ab2f3781ddc1a2e09deae239042e7da20ba81cc1421e9",
        "fast_driver_supported": True,
        "flash_write_supported": True,
        "xcp_synch_slot": 0x40016854,
        "xcp_synch_default": 0x00139910,
        "xcp_r3_arg_state": 0x4001AA64,
        "xcp_dto_buffer": 0x4001AA1C,
        "mmu_dispatch_wrapper": 0x0009C922,
        "mmu_load_single_entry": 0x000599DC,
        "sbc_last_tb_addr": 0x40017CE8,
        "tlb1_sram_entry": 0x14,
        "flash_driver_addr": 0x4007C000,
        "flash_driver_upper_phys": 0x4007A000,
        "sram_ika_addr": 0x4007C9A8,
        "sram_ika_inv_addr": 0x4007C9B8,
        "sram_gfa_addr": 0x4007C998,
        "sram_ks_meta_addr": 0x4007C9C8,
        "sram_ecu_boot_sum_addr": 0x4007CA38,
        "sram_cp_active_addr": 0x40019C7F,
        "sram_cp_counter_addr": 0x4007C8F8,
        "sram_auth_success_trigger_addr": 0x4007C8F4,
        "cp_affected_sectors": (
            (0x00180000, 0x00040000),
            (0x001C0000, 0x00040000),
        ),
        "swap_affected_sectors": (
            (0x00060000, 0x00010000),
            (0x00140000, 0x00040000),
        ),
        "swap_config": {
            "generation": 2,
            "coord_base_pa": 0x000621B2,
            "e_bl_aff066": "78a9ca1d",
            "fsid_table_pa": 0x0017BBBC,
            "default_groups": (8, 3, 4, 7),
            "uds_3c00": {
                "cond_pa": 0x001411B2,
                "len_pa": 0x00141252,
                "data_pa": 0x001411F0,
                "data_stock": (
                    "0080182106e0d4c1013cd6e1d5d1d7f1d90173e8e0081c7fdbc4789bc08f73a8"
                    "e0081c7ddbc8789bc05b581fdbc4716001807000a9807cab"
                ),
            },
        },
        "patches": (
            ("KS_GetCpActive returns zero", 0x001F5736, "7188e008", "48030004"),
            ("KS_Auth accepts any J533 response", 0x001F6634, "e215", "4400"),
            ("KS_State_AuthFail returns immediately", 0x001F56D0, "0080", "0004"),
            ("KS_State does not increment cp_counter", 0x001F5342, "2003", "4803"),
            ("KS_KeyMgr_IsVirginIKA returns zero", 0x001F864C, "7188e008", "48030004"),
            ("KS_KeyMgr_IsGfaMissing returns zero", 0x001F8668, "70e8e008", "48030004"),
            (
                "FiM CP event masks are cleared",
                0x00192554,
                "002100000100002100000100002100000100010200010000002100000100",
                "00" * 30,
            ),
        ),
    },
    "0780": {
        "sw": "0780",
        "unit": "5Q0907572S",
        "family": "MRRevo14F",
        "mcu": "MPC5675K",
        "odx_name": "EV_ACCBOSCHVW416",
        "cflash_size": 0x00200000,
        "boot_size": 0x00030000,
        "app_base": 0x00030000,
        "app_size": 0x001D0000,
        "dflash_addr": 0x00800000,
        "dflash_size": 0x00010000,
        "sram_addr": 0x40000000,
        "sram_size": 0x00080000,
        "ram_safe_end": 0x4007E000,
        "user_stack_canary_addr": 0x4007E000,
        "stock_app_sha256": "4692badce5528cf6346c21e1ee23416c1e61c6397c049d1c9504afccbd6385b5",
        "cp_disable_app_sha256": "a9f2e79486cdba48517aa8afc1c55337b27cb479ce699b6a46a56a38ca86d281",
        "eraserouti_sha256": "b23b82945a5cd353e73ab2f3781ddc1a2e09deae239042e7da20ba81cc1421e9",
        "fast_driver_supported": True,
        "flash_write_supported": True,
        "xcp_synch_slot": 0x40016868,
        "xcp_synch_default": 0x00139C5C,
        "xcp_r3_arg_state": 0x4001AA84,
        "xcp_dto_buffer": 0x4001AA3C,
        "mmu_dispatch_wrapper": 0x0009CB46,
        "mmu_load_single_entry": 0x00059B3C,
        "sbc_last_tb_addr": 0x40017D00,
        "tlb1_sram_entry": 0x14,
        "flash_driver_addr": 0x4007C000,
        "flash_driver_upper_phys": 0x4007A000,
        "sram_ika_addr": 0x4007C9A8,
        "sram_ika_inv_addr": 0x4007C9B8,
        "sram_gfa_addr": 0x4007C998,
        "sram_ks_meta_addr": 0x4007C9C8,
        "sram_ecu_boot_sum_addr": 0x4007CA38,
        "sram_cp_active_addr": 0x40019C7F,
        "sram_cp_counter_addr": 0x4007C8F8,
        "sram_auth_success_trigger_addr": 0x4007C8F4,
        "cp_affected_sectors": (
            (0x00180000, 0x00040000),
            (0x001C0000, 0x00040000),
        ),
        "swap_affected_sectors": (
            (0x00060000, 0x00010000),
            (0x00140000, 0x00040000),
        ),
        "swap_config": {
            "generation": 2,
            "coord_base_pa": 0x0006231A,
            "e_bl_aff066": "78a9c8b5",
            "fsid_table_pa": 0x0017BF1C,
            "default_groups": (8, 3, 4, 7),
            "uds_3c00": {
                "cond_pa": 0x00141434,
                "len_pa": 0x001414D0,
                "data_pa": 0x00141470,
                "data_stock": (
                    "0080182106e0d4c1013cd6e1d5d1d7f1d90173e8e0081c7fdbc4789bbdbb73a8"
                    "e0081c7ddbc8789bbd89581fdbc47160001423307cab005e"
                ),
            },
        },
        "patches": (
            ("KS_GetCpActive returns zero", 0x001F5736, "7188e008", "48030004"),
            ("KS_Auth accepts any J533 response", 0x001F6634, "e215", "4400"),
            ("KS_State_AuthFail returns immediately", 0x001F56D0, "0080", "0004"),
            ("KS_State does not increment cp_counter", 0x001F5342, "2003", "4803"),
            ("KS_KeyMgr_IsVirginIKA returns zero", 0x001F864C, "7188e008", "48030004"),
            ("KS_KeyMgr_IsGfaMissing returns zero", 0x001F8668, "70e8e008", "48030004"),
            (
                "FiM CP event masks are cleared",
                0x001928EA,
                "002100000100002100000100002100000100010200010000002100000100",
                "00" * 30,
            ),
        ),
    },
}


# ── Seed & Key / Checksum Algorithms ────────────────────────────────────────
def mrr_xcp_compute_key(seed: int) -> int:
    """Compute XCP UNLOCK (0xF7) 32-bit key from GET_SEED (0xF8) big-endian seed (LFSR-7 0xFB312378)."""
    acc = seed & 0xFFFFFFFF
    for _ in range(7):
        msb = acc >> 31
        acc = ((acc << 1) & 0xFFFFFFFF) | msb
        if not msb:
            return acc
        acc ^= 0xFB312378
    return acc


def mrr_fblv_compute_key(seed: int) -> int:
    """Compute UDS Programming Session (10 02) FBLv SecurityAccess (27 11/12) key."""
    value = seed & 0xFFFFFFFF
    for _ in range(7):
        original = value
        value = (value + 0x46843411) & 0xFFFFFFFF
        if original <= 0xB97BCBEE:
            value = (((value << 13) | (value >> 19)) & 0xFFFFFFFF) ^ 0xB1487614
        else:
            value = (((value >> 10) | (value << 22)) & 0xFFFFFFFF) ^ 0x79BD36FA
    return (value + 0xE98CA418) & 0xFFFFFFFF


def mrr_dev_compute_key(seed: int, addend: int = MRR_DEV_ADDEND_0192) -> int:
    """Compute UDS SecurityAccess (27 03/04) additive key."""
    return (seed + addend) & 0xFFFFFFFF


def mrr_sum32_be(data: bytes) -> int:
    """Compute XCP BUILD_CHECKSUM (0xF3, ADD_44) 32-bit big-endian word sum."""
    if len(data) % 4:
        raise ValueError("ADD_44 input must contain whole 32-bit words")
    return sum(
        int.from_bytes(data[offset:offset + 4], "big")
        for offset in range(0, len(data), 4)
    ) & 0xFFFFFFFF


def mrr_compute_ecu_boot_sum(cflash_or_boot_bytes: bytes) -> bytes:
    """Compute 16-byte ECU_BOOT_SUM over bootloader window 0x00008000..0x00009FFF (512 x 16 B)."""
    if len(cflash_or_boot_bytes) < 0xA000:
        raise ValueError(
            f"Bootloader/CodeFlash image must be at least 0xA000 bytes, got 0x{len(cflash_or_boot_bytes):X}"
        )
    s = [0, 0, 0, 0]
    carry = 0
    for off in range(0x8000, 0xA000, 16):
        w0, w1, w2, w3 = struct.unpack(">4I", cflash_or_boot_bytes[off:off + 16])
        s[0] = (s[0] + w0 + carry) & 0xFFFFFFFF
        t1 = s[1] + w1
        s[1], carry = t1 & 0xFFFFFFFF, t1 >> 32
        t2 = s[2] + w2 + carry
        s[2], carry = t2 & 0xFFFFFFFF, t2 >> 32
        t3 = s[3] + w3 + carry
        s[3], carry = t3 & 0xFFFFFFFF, t3 >> 32
    return struct.pack(">4I", *s)


def mrr_is_virgin_ika(ika_16b: bytes) -> bool:
    """Return True if IKA matches the unpersonalized Bosch factory test pair (PT -> CT)."""
    if len(ika_16b) != 16:
        return False
    return bcm_aes128_ecb_encrypt(ika_16b, MRR_VIRGIN_IKA_PT) == MRR_VIRGIN_IKA_CT


def mrr_build_cp_key_container(
    current_ika_16b: bytes,
    new_key_16b: bytes,
    key_type: int = MRR_CP_KEY_TYPE_IKA,
) -> bytes:
    """Build 34-byte UDS 2E 00BE (IKA, key_type=1) or 2E 00BD (GFA, key_type=2) container."""
    return bcm_build_cp_key_container(current_ika_16b, new_key_16b, key_type)


def mrr_unpack_cp_key_container(current_ika_16b: bytes, container_34b: bytes) -> dict[str, Any]:
    """Decrypt and verify a 34-byte UDS 2E 00BE / 00BD key container under current_ika_16b."""
    return bcm_unpack_cp_key_container(current_ika_16b, container_34b)


# ── Profile Detection & Status DID Decoding ─────────────────────────────────
def _build_unverified_profile(
    *,
    sw: str = "UNKNOWN",
    part_number: str = "",
    is_5674k: bool = False,
) -> dict[str, Any]:
    """Return a safe read-only profile descriptor for an unrecognized/unverified MRR SW version."""
    cflash_size = 0x00180000 if is_5674k else 0x00200000
    sram_size = 0x00060000 if is_5674k else 0x00080000
    return {
        "sw": sw or "UNKNOWN",
        "unit": part_number or ("3Q0907572" if is_5674k else "5Q0907572"),
        "family": "MRR1Plus" if is_5674k else "MRRevo14F",
        "mcu": "MPC5674K" if is_5674k else "MPC5675K",
        "odx_name": "EV_ACCBOSCHVW48X" if is_5674k else "EV_ACCBOSCHVW416",
        "cflash_size": cflash_size,
        "boot_size": MRR_BOOT_SIZE,
        "app_base": MRR_APP_BASE,
        "app_size": cflash_size - MRR_BOOT_SIZE,
        "dflash_addr": MRR_DFLASH_ADDR,
        "dflash_size": MRR_DFLASH_SIZE,
        "sram_addr": MRR_SRAM_ADDR,
        "sram_size": sram_size,
        "ram_safe_end": MRR_SRAM_ADDR + sram_size - 0x2000,
        "user_stack_canary_addr": None,
        "stock_app_sha256": None,
        "cp_disable_app_sha256": None,
        "eraserouti_sha256": None,
        "fast_driver_supported": False,
        "flash_write_supported": False,
        "verified": False,
        "sram_ika_addr": None,
        "sram_ika_inv_addr": None,
        "sram_gfa_addr": None,
        "sram_ks_meta_addr": None,
        "sram_ecu_boot_sum_addr": None,
        "sram_cp_active_addr": None,
        "sram_cp_counter_addr": None,
        "sram_auth_success_trigger_addr": None,
        "cp_affected_sectors": (),
        "swap_affected_sectors": (),
        "swap_config": None,
        "patches": (),
    }


def mrr_get_profile(sw_profile: str = "0192") -> dict[str, Any]:
    key = (sw_profile or "0192").strip().upper()
    if key in MRR_PROFILES:
        out = dict(MRR_PROFILES[key])
        out["verified"] = True
        return out
    raise ValueError(f"Unknown MRR firmware profile: {sw_profile!r}")


def _app_slice_matches_swap_sites(app_slice: bytes, prof: dict[str, Any]) -> bool:
    swap_cfg = prof.get("swap_config")
    if not swap_cfg or len(app_slice) != prof["app_size"]:
        return False
    gen = int(swap_cfg.get("generation") or 0)
    uds_3c00 = swap_cfg.get("uds_3c00") or {}
    if gen == 1:
        main_pa = int(swap_cfg["swap_main_pa"])
        rel_sites = swap_cfg.get("rel_sites") or _MRR_GEN1_SWAP_REL_SITES
        pkg_rels = tuple(swap_cfg.get("pkg_index_rels") or (0x4C, 0x50))
        for rel, stock_hex, patched_hex, _ in rel_sites:
            off = (main_pa + rel) - MRR_APP_BASE
            stock = bytes.fromhex(stock_hex)
            actual = app_slice[off:off + len(stock)]
            if rel in pkg_rels:
                allowed = {stock} | {
                    bytes([0x48, ((idx & 0x7) << 4) | 0x03]) for idx in (0, 1, 2, 4, 5, 6)
                }
                if actual not in allowed:
                    return False
            else:
                if actual not in (stock, bytes.fromhex(patched_hex)):
                    return False
        if uds_3c00:
            prep_off = int(uds_3c00["prepare_pa"]) - MRR_APP_BASE
            prep_stock = bytes.fromhex(str(uds_3c00["prepare_stock"]))
            if app_slice[prep_off:prep_off + len(prep_stock)] not in (prep_stock, MRR_GEN1_3C00_PREPARE_PATCHED):
                return False
            len_off = int(uds_3c00["len_pa"]) - MRR_APP_BASE
            len_stock = bytes.fromhex(str(uds_3c00["len_stock"]))
            if app_slice[len_off:len_off + len(len_stock)] not in (len_stock, MRR_GEN1_3C00_LEN_PATCHED):
                return False
            data_off = int(uds_3c00["data_pa"]) - MRR_APP_BASE
            data_stock = bytes.fromhex(str(uds_3c00["data_stock"]))
            data_actual = app_slice[data_off:data_off + len(data_stock)]
            if (
                data_actual != data_stock
                and mrr_decode_gen1_3c00_stub(data_actual) is None
                and _mrr_decode_gen1_3c00_legacy_0b_stub(data_actual, data_stock) is None
            ):
                return False
        return True
    if gen == 2:
        coord_pa = int(swap_cfg["coord_base_pa"])
        for rel, stock_hex, patched_hex, _ in _MRR_GEN2_SWAP_FIXED_REL_SITES:
            off = (coord_pa + rel) - MRR_APP_BASE
            stock = bytes.fromhex(stock_hex)
            actual = app_slice[off:off + len(stock)]
            if actual not in (stock, bytes.fromhex(patched_hex)):
                return False
        bl_off = (coord_pa + 0x498) - MRR_APP_BASE
        bl_stock = bytes.fromhex(str(swap_cfg["e_bl_aff066"]))
        if app_slice[bl_off:bl_off + 4] not in (bl_stock, bytes.fromhex("48034400")):
            return False
        stub_off = (coord_pa + MRR_GEN2_SWAP_STUB_REL) - MRR_APP_BASE
        stub = app_slice[stub_off:stub_off + 82]
        if stub != MRR_GEN2_SWAP_STUB_STOCK and mrr_decode_gen2_swap_group_stub(stub) is None:
            return False
        if uds_3c00:
            cond_off = int(uds_3c00["cond_pa"]) - MRR_APP_BASE
            if app_slice[cond_off:cond_off + 8] not in (MRR_GEN2_3C00_COND_STOCK, MRR_GEN2_3C00_COND_PATCHED):
                return False
            len_off = int(uds_3c00["len_pa"]) - MRR_APP_BASE
            len_actual = app_slice[len_off:len_off + 10]
            if len_actual != MRR_GEN2_3C00_LEN_STOCK and mrr_decode_gen2_3c00_len_stub(len_actual) is None:
                return False
            data_off = int(uds_3c00["data_pa"]) - MRR_APP_BASE
            data_stock = bytes.fromhex(str(uds_3c00["data_stock"]))
            data_actual = app_slice[data_off:data_off + len(data_stock)]
            if data_actual != data_stock and mrr_decode_gen2_3c00_read_stub(data_actual) is None:
                return False
        return True
    return False


def mrr_detect_profile(
    passport: dict[str, Any] | None = None,
    *,
    sw_version: str = "",
    part_number: str = "",
    image_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Detect Bosch MRR firmware profile from UDS passport, SW version, or binary dump.

    Returns a copy with `verified=True` only when the SW version or binary image matches a verified profile in
    `MRR_PROFILES`. Unrecognized firmware returns a safe read-only profile with `verified=False`,
    `fast_driver_supported=False`, `flash_write_supported=False`, and no hardcoded SRAM/patch addresses.
    """
    if image_bytes is not None:
        app_slices: list[bytes] = []
        if len(image_bytes) in (0x150000, 0x1D0000):
            app_slices.append(image_bytes)
        elif len(image_bytes) == 0x180000:
            app_slices.append(image_bytes[MRR_APP_BASE:])
        elif len(image_bytes) == 0x200000:
            app_slices.append(image_bytes[MRR_APP_BASE:])
            if image_bytes[0x180000:] == b"\xFF" * 0x80000:
                app_slices.append(image_bytes[MRR_APP_BASE:0x180000])
        for app_slice in app_slices:
            app_sha = hashlib.sha256(app_slice).hexdigest()
            for prof in MRR_PROFILES.values():
                if app_sha in (prof.get("stock_app_sha256"), prof.get("cp_disable_app_sha256")):
                    out = dict(prof)
                    out["verified"] = True
                    return out
            cp_candidates: list[dict[str, Any]] = []
            for prof in MRR_PROFILES.values():
                if len(app_slice) != prof["app_size"]:
                    continue
                matched_all = True
                for _, addr, orig_hex, repl_hex in prof["patches"]:
                    off = addr - MRR_APP_BASE
                    orig = bytes.fromhex(orig_hex)
                    repl = bytes.fromhex(repl_hex)
                    chunk = app_slice[off:off + len(orig)]
                    if chunk not in (orig, repl):
                        matched_all = False
                        break
                if matched_all:
                    cp_candidates.append(prof)
            if len(cp_candidates) == 1:
                out = dict(cp_candidates[0])
                out["verified"] = True
                return out
            if len(cp_candidates) > 1:
                for prof in cp_candidates:
                    if _app_slice_matches_swap_sites(app_slice, prof):
                        out = dict(prof)
                        out["verified"] = True
                        return out
                out = dict(cp_candidates[0])
                out["verified"] = True
                return out
            for prof in MRR_PROFILES.values():
                if _app_slice_matches_swap_sites(app_slice, prof):
                    out = dict(prof)
                    out["verified"] = True
                    return out
        return _build_unverified_profile(
            sw=sw_version.strip().upper() or "UNKNOWN",
            part_number=part_number.strip().upper().replace(" ", ""),
            is_5674k=len(image_bytes) in (0x150000, 0x180000),
        )

    p = passport or {}
    sw = (
        sw_version
        or str(p.get("sw_version") or p.get("F189") or "")
    ).strip().upper()
    pn = (
        part_number
        or str(p.get("part_number") or p.get("F187") or p.get("hw_part_number") or p.get("F191") or "")
    ).strip().upper().replace(" ", "")

    for candidate in ("0130", "0192", "0194", "0196", "0682", "X720", "0771", "0780"):
        if sw == candidate:
            out = dict(MRR_PROFILES[candidate])
            out["verified"] = True
            return out

    if sw or pn:
        sys_name = str(p.get("system_name") or p.get("F197") or "").upper()
        asam_odx = str(p.get("asam_odx") or p.get("F19E") or "").upper()
        is_5674k = (
            pn.startswith("3Q0")
            or "MRR1PLUS" in sys_name
            or "VW48X" in asam_odx
            or "VW372" in asam_odx
        ) and "MRREVO14F" not in sys_name and "VW416" not in asam_odx
        return _build_unverified_profile(sw=sw or "UNKNOWN", part_number=pn, is_5674k=is_5674k)

    # Empty/initial UI state before any ECU has been polled: provide safe display metadata (unverified)
    out = dict(MRR_PROFILES["0192"])
    out["verified"] = False
    out["fast_driver_supported"] = False
    out["flash_write_supported"] = False
    return out


def mrr_support_info(
    ident_or_passport: dict[str, Any] | list[dict[str, str]] | None = None,
    *,
    sw_version: str = "",
    part_number: str = "",
) -> dict[str, Any]:
    """Return official support status and a clear `(PN + SW)` notice for a `13 ACC` radar.

    Radar checks are intentionally lighter than gateway checks: reading (UDS & XCP memory/DFLASH0/keys),
    standard UDS IKA/GFA writes, and compatible FRF flashing are never blocked on unverified SW versions.
    """
    p: dict[str, Any] = {}
    if isinstance(ident_or_passport, list):
        vals = {str(it.get("did", "")).upper(): str(it.get("value", "")).strip() for it in ident_or_passport}
        p = {
            "part_number": vals.get("F187") or "",
            "hw_part_number": vals.get("F191") or "",
            "sw_version": vals.get("F189") or "",
            "system_name": vals.get("F197") or "",
            "asam_odx": vals.get("F19E") or "",
        }
    elif isinstance(ident_or_passport, dict):
        p = dict(ident_or_passport)

    pn = (
        part_number
        or str(p.get("part_number") or p.get("F187") or p.get("hw_part_number") or p.get("F191") or "")
    ).strip()
    sw = (sw_version or str(p.get("sw_version") or p.get("F189") or "")).strip()
    if not pn and not sw:
        return {
            "verified": True,
            "bosch_family": True,
            "part_number": "",
            "sw_version": "",
            "warning": None,
            "tone": "ok",
        }

    prof = mrr_detect_profile(p, sw_version=sw, part_number=pn)
    verified = bool(prof.get("verified", False))
    if verified:
        return {
            "verified": True,
            "bosch_family": True,
            "part_number": pn,
            "sw_version": sw or str(prof.get("sw") or ""),
            "warning": None,
            "tone": "ok",
        }

    pn_norm = "".join(pn.split()).upper()
    sys_name = str(p.get("system_name") or p.get("F197") or "").upper()
    asam = str(p.get("asam_odx") or p.get("F19E") or "").upper()
    alien_platform = (
        pn_norm.startswith(("2Q0", "5WA", "7N0"))
        or "CONTI" in sys_name
        or "ARS" in sys_name
        or (bool(asam) and not asam.startswith(("EV_ACCBOSCHVW48", "EV_ACCBOSCHVW416", "EV_ACCBOSCHVW372")))
    )
    bosch_family = (not alien_platform) and (
        pn_norm.startswith(("3Q0907572", "3QF907572", "5QF907572", "5Q0907572", "5Q0907561", "561907567"))
        or "MRR" in sys_name
        or asam.startswith(("EV_ACCBOSCHVW48", "EV_ACCBOSCHVW416", "EV_ACCBOSCHVW372"))
    )

    unit_id_ru = f"{pn} (ПО {sw})" if (pn and sw) else (pn or f"ПО {sw}")
    unit_id_en = f"{pn} (SW {sw})" if (pn and sw) else (pn or f"SW {sw}")
    if bosch_family:
        warning = tr(
            f"Блок {unit_id_ru} официально не поддерживается для патчей CP/SWaP. "
            "Чтение памяти по XCP, ключи IKA/GFA, диагностика и прошивка FRF доступны.",
            f"Unit {unit_id_en} is not officially supported for CP/SWaP patches. "
            "XCP memory reads, IKA/GFA keys, diagnostics, and FRF flashing remain available.",
        )
        tone = "info"
    else:
        warning = tr(
            f"Блок {unit_id_ru} официально не поддерживается (другая платформа радара). "
            "Можно попробовать чтение по UDS, но XCP и прошивка Bosch MRR не подойдут.",
            f"Unit {unit_id_en} is not officially supported (different radar platform). "
            "You can still try UDS reading, but Bosch MRR XCP and flashing will not apply.",
        )
        tone = "warn"

    return {
        "verified": False,
        "bosch_family": bosch_family,
        "part_number": pn,
        "sw_version": sw,
        "warning": warning,
        "tone": tone,
    }


def mrr_decode_status_dids(raw_dids: dict[str, str]) -> dict[str, Any]:
    """Decode MRR Component Protection & XcpGate UDS DIDs (03DE, 0440, 043F, 02E0, 02F9, 0902)."""
    decoded: dict[str, Any] = {}

    if "03DE" in raw_dids:
        b = bytes.fromhex(raw_dids["03DE"])
        if len(b) >= 2:
            cnt = int.from_bytes(b[:2], "big")
            decoded["cp_counter"] = cnt
            decoded["cp_active_by_counter"] = cnt > 0x001E

    if "043F" in raw_dids:
        b = bytes.fromhex(raw_dids["043F"])
        if len(b) >= 2:
            decoded["ks_options"] = int.from_bytes(b[:2], "big")
            decoded["ks_options_hex"] = b[:2].hex()

    if "0440" in raw_dids:
        b = bytes.fromhex(raw_dids["0440"])
        decoded["ks_info_hex"] = b.hex()
        if len(b) >= 7:
            flags = b[6]
            decoded["ks_info_flags"] = flags
            decoded["ika_virgin"] = bool(flags & 0x01)
            decoded["gfa_missing"] = bool(flags & 0x02)
            decoded["ika_personalized"] = not bool(flags & 0x01)
            decoded["gfa_learned"] = not bool(flags & 0x02)

    if "02E0" in raw_dids:
        decoded["ks_nonce_hex"] = raw_dids["02E0"].lower()

    if "02F9" in raw_dids:
        decoded["ks_vcrn_hex"] = raw_dids["02F9"].lower()

    if "0902" in raw_dids:
        b = bytes.fromhex(raw_dids["0902"])
        if b:
            decoded["xcp_gate_byte"] = b[0]
            decoded["xcp_gate_enabled"] = bool(b[0] & 0x08)

    cp_cnt = decoded.get("cp_counter")
    has_cp_signal = (cp_cnt is not None) or ("ks_info_flags" in decoded)
    if not has_cp_signal:
        decoded["cp_active"] = None
    else:
        gfa_missing = decoded.get("gfa_missing", False)
        ika_virgin = decoded.get("ika_virgin", False)
        decoded["cp_active"] = bool((cp_cnt is not None and cp_cnt > 0x001E) or gfa_missing or ika_virgin)
    return decoded


# ── DFLASH0 AUTOSAR Fee Parser & Key Extraction ─────────────────────────────
def mrr_fee_directory(dflash_64k: bytes, cluster_offset: int = 0) -> list[dict[str, int]]:
    """Parse 8-byte AUTOSAR Fee directory entries growing downward from cluster_offset + 0x7FF8."""
    if len(dflash_64k) != MRR_DFLASH_SIZE:
        raise ValueError(f"DFLASH0 image must be exactly 64 KiB, got {len(dflash_64k)} bytes")
    if cluster_offset not in (0, 0x8000):
        raise ValueError(f"Invalid Fee cluster offset: 0x{cluster_offset:X}")
    entries: list[dict[str, int]] = []
    for relative_offset in range(0x7FF8, 0x17, -8):
        directory_offset = cluster_offset + relative_offset
        raw = dflash_64k[directory_offset:directory_offset + 8]
        if raw == b"\xFF" * 8:
            break
        data_offset, block_and_copy, crc8, status = struct.unpack(">HBBI", raw)
        if status == 0 and data_offset < 0x8000:
            entries.append({
                "directory_offset": directory_offset,
                "data_offset": data_offset,
                "block_id": block_and_copy & 0x7F,
                "copy": block_and_copy >> 7,
                "crc8": crc8,
            })
    return entries


def _fee_cluster_header(dflash_64k: bytes, cluster_offset: int) -> tuple[int, bool]:
    """Parse Bosch AUTOSAR Fee 24-byte cluster header (`[crc8][cycle24][00000000][dup8][A5A5A5A500000000]`)."""
    hdr = dflash_64k[cluster_offset:cluster_offset + 24]
    if hdr[0:4] != b"\xFF\xFF\xFF\xFF" and hdr[4:8] == b"\x00\x00\x00\x00":
        cycle = int.from_bytes(hdr[1:4], "big")
        finalized = hdr[8:16] == hdr[0:8]
        return cycle, finalized
    return -1, False


def mrr_parse_dflash_fee(
    dflash_64k: bytes,
    cflash_or_boot_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Parse 64 KiB DFLASH0 AUTOSAR Fee clusters and decrypt IKA, GFA, ECU_BOOT_SUM, and KS_META."""
    if len(dflash_64k) != MRR_DFLASH_SIZE:
        raise ValueError(f"DFLASH0 image must be 65536 bytes, got {len(dflash_64k)}")

    block_sizes = {0x2A: 17, 0x2B: 17, 0x2C: 17, 0x2D: 17, 0x40: 22}
    cluster_candidates: list[dict[str, Any]] = []

    for cluster_offset in (0, 0x8000):
        entries = mrr_fee_directory(dflash_64k, cluster_offset)
        if not entries:
            continue
        cycle, finalized = _fee_cluster_header(dflash_64k, cluster_offset)
        blocks: dict[int, dict[int, dict[str, Any]]] = {}
        for bid, size in block_sizes.items():
            copies: dict[int, dict[str, Any]] = {}
            for entry in entries:
                if entry["block_id"] != bid:
                    continue
                start = cluster_offset + entry["data_offset"]
                if start + size <= cluster_offset + 0x8000:
                    payload = dflash_64k[start:start + size]
                    # Directory grows downward from +0x7FF8; iterating entries keeps the latest (lowest dir_off) per copy
                    copies[entry["copy"]] = {
                        "directory_offset": entry["directory_offset"],
                        "data_offset": start,
                        "payload": payload,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
            if copies:
                blocks[bid] = copies
        cluster_candidates.append({
            "offset": cluster_offset,
            "cycle": cycle,
            "finalized": finalized,
            "entries": entries,
            "blocks": blocks,
        })

    # Prefer the higher Fee erase/cycle counter (active cluster after swap); if headers are absent (cycle == -1),
    # fall back to block coverage and entry count.
    cluster_candidates.sort(
        key=lambda c: (c["cycle"], len(c["blocks"]), int(c["finalized"]), len(c["entries"])),
        reverse=True,
    )

    active_cluster_offset: int | None = None
    active_entries: list[dict[str, int]] = []
    active_blocks: dict[int, dict[int, dict[str, Any]]] = {}
    fallback_blocks: dict[int, dict[int, dict[str, Any]]] = {}

    if cluster_candidates:
        primary = cluster_candidates[0]
        active_cluster_offset = primary["offset"]
        active_entries = primary["entries"]
        active_blocks = primary["blocks"]
        # During a mid-compaction swap (`not finalized`), blocks not yet migrated still reside in the older cluster
        if len(cluster_candidates) > 1 and not primary["finalized"]:
            fallback_blocks = cluster_candidates[1]["blocks"]

    # Check optional factory ShadowFlashSecret_t at 0x0080C000 (+0x4000 in cluster 1)
    shadow_ika: bytes | None = None
    shadow_valid = False
    if len(dflash_64k) >= 0x401C:
        for sh_off in (0x4000, 0xC000):
            if sh_off + 28 <= len(dflash_64k):
                m_head, m_tail = (
                    int.from_bytes(dflash_64k[sh_off:sh_off + 4], "big"),
                    int.from_bytes(dflash_64k[sh_off + 24:sh_off + 28], "big"),
                )
                if m_head in (MRR_SHADOW_SECRET_MAGIC_A, MRR_SHADOW_SECRET_MAGIC_B) and m_head == m_tail:
                    uid_key = dflash_64k[sh_off + 4:sh_off + 20]
                    chk = int.from_bytes(dflash_64k[sh_off + 20:sh_off + 24], "big")
                    w_sum = sum(
                        int.from_bytes(uid_key[i:i + 4], "big") for i in range(0, 16, 4)
                    ) & 0xFFFFFFFF
                    if chk == w_sum:
                        shadow_ika = uid_key
                        shadow_valid = True
                        break

    def _slot_payload(bid: int) -> bytes | None:
        copies = active_blocks.get(bid) or fallback_blocks.get(bid)
        if not copies:
            return None
        # Directory grows downward from +0x7FF8, so lowest directory_offset is the most recently written copy
        best_copy = min(copies.items(), key=lambda kv: (kv[1]["directory_offset"], kv[0]))[1]
        return best_copy["payload"]

    raw_40 = _slot_payload(0x40)
    raw_2a = _slot_payload(0x2A)
    raw_2b = _slot_payload(0x2B)
    raw_2c = _slot_payload(0x2C)
    raw_2d = _slot_payload(0x2D)

    computed_boot_sum: bytes | None = None
    if cflash_or_boot_bytes is not None and len(cflash_or_boot_bytes) >= 0xA000:
        computed_boot_sum = mrr_compute_ecu_boot_sum(cflash_or_boot_bytes)

    cached_boot_sum: bytes | None = raw_40[1:17] if (raw_40 and len(raw_40) >= 17) else None
    ecu_boot_sum = cached_boot_sum or computed_boot_sum

    cnt_00be = int.from_bytes(raw_40[18:20], "big") if (raw_40 and len(raw_40) >= 22) else 0
    cnt_00bd = int.from_bytes(raw_40[20:22], "big") if (raw_40 and len(raw_40) >= 22) else 0

    ika_bytes: bytes | None = None
    gfa_bytes: bytes | None = None
    prng_seed_bytes: bytes | None = None
    ks_meta_bytes: bytes | None = None
    encryption_scheme = "unknown"

    if ecu_boot_sum and len(ecu_boot_sum) == 16:
        dec_2c = bcm_aes128_ecb_decrypt(ecu_boot_sum, raw_2c[1:17]) if (raw_2c and len(raw_2c) >= 17) else None
        if dec_2c is not None and dec_2c.startswith(MRR_KS_META_MAGIC):
            encryption_scheme = "aes128-ecb-ecu-boot-sum"
            ks_meta_bytes = dec_2c
            if raw_2a and len(raw_2a) >= 17:
                ika_bytes = bcm_aes128_ecb_decrypt(ecu_boot_sum, raw_2a[1:17])
            if raw_2b and len(raw_2b) >= 17:
                prng_seed_bytes = bcm_aes128_ecb_decrypt(ecu_boot_sum, raw_2b[1:17])
            if raw_2d and len(raw_2d) >= 17:
                gfa_bytes = bcm_aes128_ecb_decrypt(ecu_boot_sum, raw_2d[1:17])

    if (
        encryption_scheme == "unknown"
        and raw_2a
        and len(raw_2a) >= 17
        and raw_2a[1:17].startswith(MRR_KS_META_MAGIC)
        and raw_2b
        and len(raw_2b) >= 17
    ):
        # Unencrypted / XOR-inverted NvM 0x2B layout (confirmed by plaintext KS_META magic in 0x2A)
        encryption_scheme = "xor-ff-nvm"
        ks_meta_bytes = raw_2a[1:17]
        ika_bytes = bytes(b ^ 0xFF for b in raw_2b[1:17])
        if raw_2c and len(raw_2c) >= 17:
            gfa_bytes = raw_2c[1:17]

    if ika_bytes is None and shadow_ika is not None:
        encryption_scheme = (
            "shadow-flash-virgin"
            if encryption_scheme == "unknown"
            else f"{encryption_scheme}+shadow-virgin"
        )
        ika_bytes = shadow_ika

    gfa_learned = False
    ks_options = 0
    cp_counter = 0
    if ks_meta_bytes and len(ks_meta_bytes) == 16:
        if ks_meta_bytes.startswith(MRR_KS_META_MAGIC):
            gfa_learned = bool(ks_meta_bytes[0x0B] & 0x01)
            ks_options = int.from_bytes(ks_meta_bytes[0x0C:0x0E], "big")
            cp_counter = int.from_bytes(ks_meta_bytes[0x0E:0x10], "big")

    ika_virgin = mrr_is_virgin_ika(ika_bytes) if ika_bytes else False
    gfa_is_blank = (gfa_bytes in (None, b"\xFF" * 16, b"\x00" * 16))
    cp_active = bool(cp_counter > 0x001E or not gfa_learned or gfa_is_blank or ika_virgin)

    copies_match = all(
        len(copies) < 2 or copies[0]["sha256"] == copies[1]["sha256"]
        for copies in active_blocks.values()
    )

    return {
        "dflash_sha256": hashlib.sha256(dflash_64k).hexdigest(),
        "active_cluster_offset": (
            f"0x{active_cluster_offset:04X}" if active_cluster_offset is not None else None
        ),
        "directory_entry_count": len(active_entries),
        "encryption_scheme": encryption_scheme,
        "copies_match": copies_match,
        "ecu_boot_sum_hex": ecu_boot_sum.hex() if ecu_boot_sum else None,
        "cached_boot_sum_hex": cached_boot_sum.hex() if cached_boot_sum else None,
        "computed_boot_sum_hex": computed_boot_sum.hex() if computed_boot_sum else None,
        "boot_sum_matches_cflash": (
            (cached_boot_sum == computed_boot_sum)
            if (cached_boot_sum and computed_boot_sum)
            else None
        ),
        "ika_hex": ika_bytes.hex() if ika_bytes else None,
        "ika_inv_hex": bytes(b ^ 0xFF for b in ika_bytes).hex() if ika_bytes else None,
        "ika_virgin": ika_virgin,
        "ika_personalized": bool(ika_bytes) and not ika_virgin,
        "gfa_hex": gfa_bytes.hex() if gfa_bytes else None,
        "gfa_learned": gfa_learned and not gfa_is_blank,
        "prng_seed_hex": prng_seed_bytes.hex() if prng_seed_bytes else None,
        "ks_meta_hex": ks_meta_bytes.hex() if ks_meta_bytes else None,
        "ks_options": ks_options,
        "ks_options_hex": f"0x{ks_options:04X}",
        "cp_counter": cp_counter,
        "cp_active": cp_active,
        "cnt_00be": cnt_00be,
        "cnt_00bd": cnt_00bd,
        "shadow_secret_present": shadow_valid,
        "shadow_ika_hex": shadow_ika.hex() if shadow_ika else None,
    }


# ── CodeFlash / Application CP-Disable Inspection & Patching ────────────────
def _resolve_cflash_or_app_base(image_bytes: bytes, profile_data: dict[str, Any]) -> int:
    if len(image_bytes) == profile_data["app_size"]:
        return profile_data["app_base"]
    if len(image_bytes) == profile_data["cflash_size"]:
        return 0
    if (
        profile_data["cflash_size"] == 0x00180000
        and len(image_bytes) == 0x00200000
        and image_bytes[0x00180000:] == b"\xFF" * 0x00080000
    ):
        return 0
    raise ValueError(
        f"Expected {profile_data['app_size']} (Application) or {profile_data['cflash_size']} "
        f"(full CodeFlash) bytes for profile {profile_data['sw']}, got {len(image_bytes)}"
    )


def mrr_inspect_cflash_cp_state(
    image_bytes: bytes,
    *,
    profile: str | None = None,
) -> dict[str, Any]:
    """Inspect a CodeFlash (1.5/2.0 MiB) or Application (0x150000/0x1D0000) dump for CP patch state."""
    prof = mrr_get_profile(profile) if profile else mrr_detect_profile(image_bytes=image_bytes)
    base = _resolve_cflash_or_app_base(image_bytes, prof)
    points: list[dict[str, Any]] = []
    stock_count = 0
    patched_count = 0

    for name, address, expected_hex, replacement_hex in prof["patches"]:
        offset = address - base
        expected = bytes.fromhex(expected_hex)
        replacement = bytes.fromhex(replacement_hex)
        actual = image_bytes[offset:offset + len(expected)]
        if actual == expected:
            state = "stock"
            stock_count += 1
        elif actual == replacement:
            state = "cp_disabled"
            patched_count += 1
        else:
            state = "unknown"
        points.append({
            "name": name,
            "physical_address": f"0x{address:08X}",
            "file_offset": f"0x{offset:X}",
            "stock_hex": expected_hex,
            "patched_hex": replacement_hex,
            "actual_hex": actual.hex(),
            "state": state,
        })

    total = len(points)
    if not prof.get("verified", True) or total == 0:
        overall = "unsupported_sw"
    elif patched_count == total:
        overall = "cp_disabled"
    elif stock_count == total:
        overall = "stock"
    elif patched_count > 0 and stock_count > 0:
        overall = "partial"
    else:
        overall = "unknown"

    fazit_ascii: str | None = None
    ecu_boot_sum_hex: str | None = None
    if base == 0 and len(image_bytes) >= 0xA000:
        ecu_boot_sum_hex = mrr_compute_ecu_boot_sum(image_bytes).hex()
        raw_fazit = image_bytes[0x02D6:0x02D6 + 23]
        if all(32 <= b < 127 for b in raw_fazit):
            fazit_ascii = raw_fazit.decode("ascii", errors="replace").strip()

    return {
        "unit": prof["unit"],
        "sw": prof["sw"],
        "family": prof["family"],
        "mcu": prof["mcu"],
        "verified": bool(prof.get("verified", True)),
        "image_kind": "cflash" if base == 0 else "application",
        "image_size": len(image_bytes),
        "image_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "cp_patch_state": overall,
        "stock_points": stock_count,
        "patched_points": patched_count,
        "total_points": total,
        "fazit": fazit_ascii,
        "ecu_boot_sum_hex": ecu_boot_sum_hex,
        "points": points,
    }


def mrr_apply_cp_disable_patch(
    image_bytes: bytes,
    *,
    restore_stock: bool = False,
    profile: str | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Apply or revert the 7-point Component Protection deactivation patch on an App or CodeFlash image."""
    prof = mrr_get_profile(profile) if profile else mrr_detect_profile(image_bytes=image_bytes)
    if not prof.get("verified", True) or not prof.get("patches"):
        raise ValueError(
            tr(
                "Образ прошивки не совпадает ни с одним проверенным профилем MRR (0130, 0192, 0194, 0196, 0682, X720, 0771, 0780) — патч CP отклонён.",
                "Firmware image does not match any verified MRR profile (0130, 0192, 0194, 0196, 0682, X720, 0771, 0780) — refusing to patch CP.",
            )
        )
    base = _resolve_cflash_or_app_base(image_bytes, prof)
    source_sha = hashlib.sha256(image_bytes).hexdigest()
    output = bytearray(image_bytes)
    records: list[dict[str, Any]] = []

    for name, address, stock_hex, patched_hex in prof["patches"]:
        offset = address - base
        stock_bytes = bytes.fromhex(stock_hex)
        patched_bytes = bytes.fromhex(patched_hex)
        target_bytes = stock_bytes if restore_stock else patched_bytes
        allowed_prev = (stock_bytes, patched_bytes)
        actual = bytes(output[offset:offset + len(stock_bytes)])
        if actual not in allowed_prev:
            raise ValueError(
                f"Unexpected bytes at 0x{address:08X} (+0x{offset:X}) for profile {prof['sw']}: "
                f"got {actual.hex()}, expected {stock_hex} or {patched_hex}"
            )
        output[offset:offset + len(target_bytes)] = target_bytes
        records.append({
            "name": name,
            "physical_address": f"0x{address:08X}",
            "file_offset": f"0x{offset:X}",
            "before": actual.hex(),
            "after": target_bytes.hex(),
            "changed": actual != target_bytes,
        })

    result_bytes = bytes(output)
    changed_bytes = sum(a != b for a, b in zip(image_bytes, result_bytes))
    return result_bytes, {
        "unit": prof["unit"],
        "sw": prof["sw"],
        "family": prof["family"],
        "mcu": prof["mcu"],
        "mode": "restore_stock" if restore_stock else "cp_disable",
        "image_kind": "cflash" if base == 0 else "application",
        "source_sha256": source_sha,
        "output_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "image_size": len(result_bytes),
        "patch_count": len(records),
        "changed_bytes": changed_bytes,
        "patches": records,
    }


def mrr_extract_cp_affected_sectors(
    image_bytes: bytes,
    *,
    profile: str | None = None,
) -> list[tuple[int, bytes]]:
    """Extract the C90FL Code Flash erase sectors touched by the 7-point CP patch."""
    prof = mrr_get_profile(profile) if profile else mrr_detect_profile(image_bytes=image_bytes)
    base = _resolve_cflash_or_app_base(image_bytes, prof)
    sectors: list[tuple[int, bytes]] = []
    for addr, size in prof["cp_affected_sectors"]:
        off = addr - base
        if off < 0 or off + size > len(image_bytes):
            raise ValueError(f"Sector 0x{addr:08X}..0x{addr + size - 1:08X} out of image range")
        sectors.append((addr, image_bytes[off:off + size]))
    return sectors


# ── CodeFlash / Application Direct SWaP / FSC Activation & Inspection ───────
# Verified directly against Bosch MRR1Plus 0192 consumers (0x0004E463 table,
# 0x0015893C speed cap 0x2C72=160 vs 0x6F1C=210, 0x00158998 Basis/FTS/S&G,
# 0x001589CC ACC enable) and official VAG MRR-Paket 1..8 definitions.
MRR_GEN1_SWAP_PACKAGES: dict[int, dict[str, Any]] = {
    0: {
        "index": 0,
        "fsid": 0x10003100,
        "fsid_hex": "10003100",
        "level": 2,
        "title_ru": "ACC Low 160 км/ч (Basis-ACC) + Front Assist (CityANB)",
        "title_en": "ACC Low 160 km/h (Basis-ACC) + Front Assist (CityANB)",
    },
    1: {
        "index": 1,
        "fsid": 0x10003200,
        "fsid_hex": "10003200",
        "level": 4,
        "title_ru": "ACC Low 160 км/ч (Follow-to-Stop) + Front Assist (CityANB)",
        "title_en": "ACC Low 160 km/h (Follow-to-Stop) + Front Assist (CityANB)",
    },
    2: {
        "index": 2,
        "fsid": 0x10003300,
        "fsid_hex": "10003300",
        "level": 3,
        "title_ru": "ACC Low 160 км/ч (Stop & Go) + Front Assist (CityANB)",
        "title_en": "ACC Low 160 km/h (Stop & Go) + Front Assist (CityANB)",
    },
    3: {
        "index": 3,
        "fsid": 0x10003400,
        "fsid_hex": "10003400",
        "level": 1,
        "title_ru": "Только Front Assist (CityANB), без ACC",
        "title_en": "Front Assist (CityANB) only, no ACC",
    },
    4: {
        "index": 4,
        "fsid": 0x10003600,
        "fsid_hex": "10003600",
        "level": 5,
        "title_ru": "ACC High 210 км/ч (Basis-ACC) + Front Assist (CityANB)",
        "title_en": "ACC High 210 km/h (Basis-ACC) + Front Assist (CityANB)",
    },
    5: {
        "index": 5,
        "fsid": 0x10003700,
        "fsid_hex": "10003700",
        "level": 7,
        "title_ru": "ACC High 210 км/ч (Follow-to-Stop) + Front Assist (CityANB)",
        "title_en": "ACC High 210 km/h (Follow-to-Stop) + Front Assist (CityANB)",
    },
    6: {
        "index": 6,
        "fsid": 0x10003800,
        "fsid_hex": "10003800",
        "level": 6,
        "title_ru": "ACC High 210 км/ч (Stop & Go) + Front Assist (CityANB)",
        "title_en": "ACC High 210 km/h (Stop & Go) + Front Assist (CityANB)",
    },
}

_MRR_GEN1_SWAP_REL_SITES: tuple[tuple[int, str, str, str], ...] = (
    (0x26, "e607", "e807", "SWaP_MainFunction skip FES donor cert check"),
    (0x3C, "e20d", "e808", "SWaP_MainFunction unconditional branch to ApplyFeatureLevel"),
    (0x4C, "8831", "4863", "SWaP_MainFunction active FS-ID index load"),
    (0x50, "4833", "4863", "SWaP_MainFunction fallback FS-ID index 3"),
    (0x62, "74841fff", "48044400", "SWaP_MainFunction Dem 0x12B (no valid FSC)"),
    (0x70, "4814", "4804", "SWaP_MainFunction Dem 0x12C (invalid FSC)"),
)

# Verified directly against Bosch MRRevo14F 0780 (0x0017BF1C table, 0x00097B4E
# speed cap, 0x00097B98 Basis/FTS/S&G, 0x00097BD6 ACC enable, 0x0006245E AWV).
MRR_GEN2_SWAP_GROUPS: tuple[dict[str, Any], ...] = (
    {
        "group_index": 0,
        "title_ru": "Группа 0 — Базовый пакет ACC / Front Assist (1000900x)",
        "title_en": "Group 0 — Base Package ACC / Front Assist (1000900x)",
        "variants": {
            0: (0x00000000, "Отключено (без ACC)", "Disabled (no ACC)"),
            1: (0x10009001, "10009001 · ACC Low 160 км/ч (Basis-ACC) + Front Assist (CityANB)", "10009001 · ACC Low 160 km/h (Basis-ACC) + Front Assist (CityANB)"),
            2: (0x10009002, "10009002 · ACC Low 160 км/ч (Follow-to-Stop) + Front Assist (CityANB)", "10009002 · ACC Low 160 km/h (Follow-to-Stop) + Front Assist (CityANB)"),
            3: (0x10009003, "10009003 · ACC Low 160 км/ч (Stop & Go) + Front Assist (CityANB)", "10009003 · ACC Low 160 km/h (Stop & Go) + Front Assist (CityANB)"),
            6: (0x10009006, "10009006 · ACC High 210 км/ч (Basis-ACC) + Front Assist (CityANB)", "10009006 · ACC High 210 km/h (Basis-ACC) + Front Assist (CityANB)"),
            7: (0x10009007, "10009007 · ACC High 210 км/ч (Follow-to-Stop) + Front Assist (CityANB)", "10009007 · ACC High 210 km/h (Follow-to-Stop) + Front Assist (CityANB)"),
            8: (0x10009008, "10009008 · ACC High 210 км/ч (Stop & Go) + Front Assist (CityANB)", "10009008 · ACC High 210 km/h (Stop & Go) + Front Assist (CityANB)"),
        },
    },
    {
        "group_index": 1,
        "title_ru": "Группа 1 — Расширения ACC: pACC / StauAssistent (1000910x)",
        "title_en": "Group 1 — ACC Extensions: pACC / Traffic Jam Assist (1000910x)",
        "variants": {
            0: (0x00000000, "Отключено", "Disabled"),
            1: (0x10009101, "10009101 · Предиктивный круиз (pACC)", "10009101 · Predictive ACC (pACC)"),
            2: (0x10009102, "10009102 · Ассистент движения в пробках (StauAssistent / TJA)", "10009102 · Traffic Jam Assist (StauAssistent / TJA)"),
            3: (0x10009103, "10009103 · pACC + Ассистент пробок (StauAssistent / TJA)", "10009103 · pACC + Traffic Jam Assist (StauAssistent / TJA)"),
        },
    },
    {
        "group_index": 2,
        "title_ru": "Группа 2 — AWV / Защита пешеходов vFGS (1000920x)",
        "title_en": "Group 2 — AWV / Pedestrian Protection vFGS (1000920x)",
        "variants": {
            0: (0x00000000, "Отключено", "Disabled"),
            1: (0x10009201, "10009201 · AWV 1, 2 (только визуальное и звуковое предупреждение)", "10009201 · AWV 1, 2 (visual & audible warning only)"),
            2: (0x10009202, "10009202 · AWV 1, 2 (предупреждение + торможение)", "10009202 · AWV 1, 2 (warning + braking)"),
            3: (0x10009203, "10009203 · AWV 1, 2, 3 (без защиты пешеходов)", "10009203 · AWV 1, 2, 3 (no Pedestrian Protection)"),
            4: (0x10009204, "10009204 · AWV 1, 2, 3 + Пешеходы (vFGS)", "10009204 · AWV 1, 2, 3 + Pedestrian Protection (vFGS)"),
        },
    },
    {
        "group_index": 3,
        "title_ru": "Группа 3 — Расширения AWV: Emergency / Поворот / Встречка (1000930x)",
        "title_en": "Group 3 — AWV Extensions: Emergency / Turn / Oncoming (1000930x)",
        "variants": {
            0: (0x00000000, "Отключено", "Disabled"),
            1: (0x10009301, "10009301 · Emergency Assist", "10009301 · Emergency Assist"),
            2: (0x10009302, "10009302 · Abbiegeassistent (ассистент поворота)", "10009302 · Turn-off Assist (Abbiegeassistent)"),
            3: (0x10009303, "10009303 · AWV-Gegenverkehr (встречный поток)", "10009303 · Oncoming Vehicle Braking (AWV-Gegenverkehr)"),
            4: (0x10009304, "10009304 · Abbiegeassistent + AWV-Gegenverkehr", "10009304 · Turn-off Assist + Oncoming Braking"),
            5: (0x10009305, "10009305 · Emergency Assist + AWV-Gegenverkehr", "10009305 · Emergency Assist + Oncoming Braking"),
            6: (0x10009306, "10009306 · Emergency Assist + Abbiegeassistent", "10009306 · Emergency Assist + Turn-off Assist"),
            7: (0x10009307, "10009307 · Emergency + Поворот + Встречный поток (Полный)", "10009307 · Emergency + Turn-off + Oncoming (Full)"),
        },
    },
)

MRR_GEN2_SWAP_PRESETS: tuple[dict[str, Any], ...] = (
    {
        "id": "full_pacc",
        "groups": (8, 3, 4, 7),
        "title_ru": "Максимум: ACC High (Stop & Go) + pACC + TJA + AWV+vFGS + Расш. AWV (8, 3, 4, 7)",
        "title_en": "Maximum: ACC High (Stop & Go) + pACC + TJA + AWV+vFGS + AWV Ext. (8, 3, 4, 7)",
    },
    {
        "id": "acc_high_pacc",
        "groups": (8, 3, 4, 1),
        "title_ru": "ACC High (Stop & Go) + pACC + TJA + AWV+vFGS + Emergency (8, 3, 4, 1)",
        "title_en": "ACC High (Stop & Go) + pACC + TJA + AWV+vFGS + Emergency (8, 3, 4, 1)",
    },
    {
        "id": "acc_high_fts_pacc",
        "groups": (7, 3, 4, 1),
        "title_ru": "ACC High (Follow-to-Stop) + pACC + TJA + AWV+vFGS + Emergency (7, 3, 4, 1)",
        "title_en": "ACC High (Follow-to-Stop) + pACC + TJA + AWV+vFGS + Emergency (7, 3, 4, 1)",
    },
    {
        "id": "acc_high_no_pacc",
        "groups": (8, 0, 4, 0),
        "title_ru": "ACC High (Stop & Go) + Front Assist + AWV+vFGS без pACC (8, 0, 4, 0)",
        "title_en": "ACC High (Stop & Go) + Front Assist + AWV+vFGS without pACC (8, 0, 4, 0)",
    },
    {
        "id": "acc_low_pacc",
        "groups": (3, 3, 4, 7),
        "title_ru": "ACC Low (Stop & Go) + Front Assist + pACC + TJA + AWV+vFGS + Расш. AWV (3, 3, 4, 7)",
        "title_en": "ACC Low (Stop & Go) + Front Assist + pACC + TJA + AWV+vFGS + AWV Ext. (3, 3, 4, 7)",
    },
    {
        "id": "awv_only",
        "groups": (0, 0, 4, 0),
        "title_ru": "Только Front Assist (AWV 1, 2, 3 + vFGS), без ACC (0, 0, 4, 0)",
        "title_en": "Front Assist only (AWV 1, 2, 3 + vFGS), no ACC (0, 0, 4, 0)",
    },
)

# Extra VAG ADAS FS-IDs that may appear in UDS 22 3C 00 on other VAG radar/camera variants
# (not present in Bosch MRR1Plus 0130..0196 or MRRevo14F 0682..0780 tables).
_MRR_EXTRA_FSID_LABELS: dict[int, tuple[str, str]] = {
    0x10003500: ("Только CityANB (без ACC)", "CityANB only (no ACC)"),
    0x10003900: ("ACC High конс. (Basis-ACC) + Front Assist (CityANB)", "ACC High conservative (Basis-ACC) + Front Assist (CityANB)"),
    0x10003A00: ("ACC High конс. (Follow-to-Stop) + Front Assist (CityANB)", "ACC High conservative (Follow-to-Stop) + Front Assist (CityANB)"),
    0x10003B00: ("ACC High конс. (Stop & Go) + Front Assist (CityANB)", "ACC High conservative (Stop & Go) + Front Assist (CityANB)"),
    0x10006100: ("Предиктивный круиз (pACC)", "Predictive ACC (pACC)"),
    0x10006200: ("Ассистент движения в пробках (StauAssistent / TJA)", "Traffic Jam Assist (StauAssistent / TJA)"),
    0x10006300: ("pACC + Ассистент пробок (StauAssistent / TJA)", "pACC + Traffic Jam Assist (StauAssistent / TJA)"),
    0x10007100: ("AWV 1, 2 (только визуальное и звуковое предупреждение)", "AWV 1, 2 (visual & audible warning only)"),
    0x10007200: ("AWV 1, 2 (предупреждение + торможение)", "AWV 1, 2 (warning + braking)"),
    0x10007300: ("AWV 1, 2, 3 (без защиты пешеходов)", "AWV 1, 2, 3 (no Pedestrian Protection)"),
    0x10007400: ("AWV 1, 2, 3 + Пешеходы (vFGS)", "AWV 1, 2, 3 + Pedestrian Protection (vFGS)"),
    0x10008100: ("Emergency Assist", "Emergency Assist"),
    0x10008200: ("Abbiegeassistent (ассистент поворота)", "Turn-off Assist (Abbiegeassistent)"),
    0x10008300: ("AWV-Gegenverkehr (встречный поток)", "Oncoming Vehicle Braking (AWV-Gegenverkehr)"),
    0x10008400: ("Abbiegeassistent + AWV-Gegenverkehr", "Turn-off Assist + Oncoming Braking"),
    0x10008500: ("Emergency Assist + AWV-Gegenverkehr", "Emergency Assist + Oncoming Braking"),
    0x10008600: ("Emergency Assist + Abbiegeassistent", "Emergency Assist + Turn-off Assist"),
    0x10008700: ("Emergency + Поворот + Встречный поток (Полный)", "Emergency + Turn-off + Oncoming (Full)"),
    0x10009004: ("Только Front Assist (CityANB), без ACC", "Front Assist (CityANB) only, no ACC"),
    0x10009005: ("Только CityANB (без ACC)", "CityANB only (no ACC)"),
    0x10009205: ("AWV 1, 2, 3 + Пешеходы (vFGS) + Велосипедисты (vRFS)", "AWV 1, 2, 3 + Pedestrian (vFGS) + Cyclist (vRFS)"),
    0x10009500: ("Распознавание дорожных знаков (VZE)", "Traffic Sign Recognition (VZE)"),
    0x10009600: ("Превентивная защита пешеходов (VFS / FCWP)", "Predictive Pedestrian Protection (VFS / FCWP)"),
}

_MRR_SWAP_STATUS_CHECKS: tuple[tuple[int, str, str], ...] = (
    (0x02, "сторнирована", "cancelled"),
    (0x04, "сертификат для другого блока (VCRN)", "certificate is for another ECU (VCRN)"),
    (0x08, "истёк срок или не выполнено условие", "expired or validity condition not met"),
    (0x10, "не подходит к конфигурации блока", "does not fit ECU configuration"),
    (0x20, "функции нет в прошивке", "feature not supported by firmware"),
    (0x40, "подпись сертификата не прошла проверку", "certificate signature check failed"),
)


def mrr_fsid_label(fsid: int) -> tuple[str, str]:
    """Return human-readable `(ru, en)` description for a Bosch MRR Gen 1 or Gen 2 SWaP FS-ID."""
    code = int(fsid) & 0xFFFFFFFF
    for pkg in MRR_GEN1_SWAP_PACKAGES.values():
        if int(pkg["fsid"]) == code:
            return (str(pkg["title_ru"]), str(pkg["title_en"]))
    for grp in MRR_GEN2_SWAP_GROUPS:
        for _v, (v_fsid, ru_txt, en_txt) in grp["variants"].items():
            if int(v_fsid) == code and code != 0:
                ru_clean = ru_txt.split("·", 1)[-1].strip() if "·" in ru_txt else ru_txt
                en_clean = en_txt.split("·", 1)[-1].strip() if "·" in en_txt else en_txt
                return (ru_clean, en_clean)
    if code in _MRR_EXTRA_FSID_LABELS:
        return _MRR_EXTRA_FSID_LABELS[code]
    if code in (0x10009000, 0x10009100, 0x10009200, 0x10009300):
        return ("Функция отключена (базовый код 0)", "Feature disabled (base variant 0)")
    return (f"Неизвестный код FS-ID 0x{code:08X}", f"Unknown FS-ID 0x{code:08X}")


def mrr_decode_swap_status_byte(status_byte: int) -> dict[str, Any]:
    """Decode one VW SWaP-SF v1.6 status byte from UDS 22 3C 00."""
    st = int(status_byte) & 0xFF
    if (st & MRR_SWAP_STATUS_ACTIVE) == MRR_SWAP_STATUS_ACTIVE:
        return {
            "status": st,
            "status_hex": f"0x{st:02X}",
            "state": "active",
            "tone": "ok",
            "label_ru": "активна",
            "label_en": "active",
            "reason_ru": "",
            "reason_en": "",
        }
    if not (st & 0x01):
        return {
            "status": st,
            "status_hex": f"0x{st:02X}",
            "state": "not_activated",
            "tone": "muted",
            "label_ru": "не активирована",
            "label_en": "not activated",
            "reason_ru": "",
            "reason_en": "",
        }
    reasons_ru = [ru for bit, ru, _en in _MRR_SWAP_STATUS_CHECKS if not (st & bit)]
    reasons_en = [en for bit, _ru, en in _MRR_SWAP_STATUS_CHECKS if not (st & bit)]
    return {
        "status": st,
        "status_hex": f"0x{st:02X}",
        "state": "rejected",
        "tone": "err",
        "label_ru": "не принята",
        "label_en": "rejected",
        "reason_ru": "; ".join(reasons_ru),
        "reason_en": "; ".join(reasons_en),
    }


def mrr_parse_swap_uds_response(
    raw_3c00: bytes,
    *,
    raw_3c0a: bytes | None = None,
    raw_3c05: bytes | None = None,
    raw_0600: bytes | None = None,
    generation: int | None = None,
) -> dict[str, Any]:
    """Parse standard UDS 22 3C 00 (plus optional 3C0A VCRN, 3C05 RSA public key, Gen 2 0600 coding) from 13 ACC Radar."""
    payload = bytes(raw_3c00)
    if len(payload) % 5 != 0:
        raise ValueError(f"Unexpected UDS 22 3C 00 payload length ({len(payload)} B, expected multiple of 5): {payload.hex()}")

    features: list[dict[str, Any]] = []
    for off in range(0, len(payload), 5):
        fsid_raw = payload[off:off + 4]
        if fsid_raw in (b"\x00\x00\x00\x00", b"\xff\xff\xff\xff"):
            continue
        fsid_int = int.from_bytes(fsid_raw, "big")
        st_info = mrr_decode_swap_status_byte(payload[off + 4])
        name_ru, name_en = mrr_fsid_label(fsid_int)
        features.append({
            "fsid": fsid_int,
            "fsid_hex": f"{fsid_int:08X}",
            "name_ru": name_ru,
            "name_en": name_en,
            **st_info,
        })

    active_fsids = [f["fsid_hex"] for f in features if f["state"] == "active"]
    rejected_fsids = [f["fsid_hex"] for f in features if f["state"] == "rejected"]

    out: dict[str, Any] = {
        "did_3c00_hex": payload.hex(),
        "features": features,
        "total_count": len(features),
        "active_count": len(active_fsids),
        "rejected_count": len(rejected_fsids),
        "active_fsids": active_fsids,
        "rejected_fsids": rejected_fsids,
    }

    if raw_3c0a is not None:
        v_raw = bytes(raw_3c0a)
        out["fes_vcrn_hex"] = v_raw.hex()
        out["fes_vcrn_virgin"] = bool(len(v_raw) == 5 and v_raw == b"\xff\xff\xff\xff\xff")

    if raw_3c05 is not None and len(raw_3c05) >= 8:
        k_raw = bytes(raw_3c05)
        prefix = k_raw[:8]
        if prefix == MRR_GEN2_RSA_DEV_PREFIX:
            key_kind = "dev_x720"
        elif prefix == MRR_GEN2_RSA_SERIES_PREFIX:
            key_kind = "series_0780"
        else:
            key_kind = "other"
        out["rsa_key_kind"] = key_kind
        out["rsa_modulus_prefix_hex"] = prefix.hex()
        out["rsa_key_len"] = len(k_raw)

    decode_gen2_coding = (
        raw_0600 is not None
        and len(raw_0600) >= 14
        and (generation == 2 or (generation is None and len(raw_0600) >= 25))
    )
    if decode_gen2_coding:
        assert raw_0600 is not None
        b12 = raw_0600[12]
        b13 = raw_0600[13]
        g_tup = ((b12 >> 4) & 0xF, b12 & 0xF, (b13 >> 4) & 0xF, b13 & 0xF)
        out["coding_byte12_13_hex"] = f"{b12:02X}{b13:02X}"
        out["coding_groups"] = list(g_tup)
        out["coding_group_details"] = mrr_describe_gen2_swap_groups(g_tup)["group_details"]

    return out

_MRR_GEN2_SWAP_FIXED_REL_SITES: tuple[tuple[int, str, str, str], ...] = (
    (0x106, "4813", "4803", "SWaP_CheckBaseActivation Dem (base SWaP)"),
    (0x11A, "8043", "4804", "SWaP_ReportCodingConsistencyDem #0"),
    (0x122, "814f", "4804", "SWaP_ReportCodingConsistencyDem #1"),
    (0x12A, "824f", "4804", "SWaP_ReportCodingConsistencyDem #2"),
    (0x132, "834f", "4804", "SWaP_ReportCodingConsistencyDem #3"),
    (0x234, "4813", "4803", "SWaP_ReportPaccConsistencyDem"),
    (0x248, "8043", "4804", "SWaP_ReportDependentGroupDem Group 1"),
    (0x252, "814f", "4804", "SWaP_ReportDependentGroupDem Group 3"),
    (0x2F8, "8043", "4804", "SWaP_ReportGroupCodingMatchDem Group 0"),
    (0x300, "814f", "4804", "SWaP_ReportGroupCodingMatchDem Group 1"),
    (0x308, "824f", "4804", "SWaP_ReportGroupCodingMatchDem Group 2"),
    (0x310, "834f", "4804", "SWaP_ReportGroupCodingMatchDem Group 3"),
    (0x434, "e212", "4400", "SWaP_MainFunction skip FES_IsReady wait"),
    (0x454, "e202", "4400", "SWaP_MainFunction run CheckAll every tick"),
    (0x46A, "0104", "4804", "SWaP_ReportInvalidFscDem"),
    (0x482, "e214", "4400", "SWaP_CyclicTask skip KS_IsReady wait"),
    (0x48E, "e20e", "4400", "SWaP_CyclicTask skip init flag wait"),
)

MRR_GEN2_SWAP_STUB_REL = 0x344
MRR_GEN2_SWAP_STUB_STOCK = bytes.fromhex(
    "180aa8ff300b000de20b314c011b7409"
    "e73f7c0a4840e60771200001e8067000"
    "c8f0e2fb7120000035210008314c0130"
    "312b000d180aa8ffe20b314c012b7520"
    "073f7c0a0040e60771400001e8067120"
    "c80f"
)

# Cosmetic UDS 22 3C 00 reporting stubs (Gen 1: FES_3C00_* 66 B, Gen 2: DID 0x3C00 DCM callbacks 74 B)
MRR_GEN1_3C00_PREPARE_PATCHED = bytes.fromhex("48030004")
MRR_GEN1_3C00_LEN_PATCHED = bytes.fromhex("70c00023b06348030004")
MRR_GEN1_3C00_STUB_PREFIX = bytes.fromhex("4904480570c000314800904391539263935370e000b0")
MRR_GEN1_3C00_STUB_SUFFIX = bytes.fromhex(
    "e20370e000ff9473204320062a30e202200620002a70e2ee48030004"
)
# Earlier 50-byte Gen 1 stub that emitted 0x0B instead of 0xB0 — accepted for clean 1-click upgrade / stock restore
_MRR_GEN1_3C00_LEGACY_0B_PREFIX = bytes.fromhex("4904480570c000314800904391539263935348b7")
_MRR_GEN1_3C00_LEGACY_0B_SUFFIX = bytes.fromhex(
    "e20370e000ff9473204320062a30e202200620002a70e2ef48030004"
)

MRR_GEN2_3C00_COND_STOCK = bytes.fromhex("0080182106f0d3f1")
MRR_GEN2_3C00_COND_PATCHED = bytes.fromhex("4804904348030004")
MRR_GEN2_3C00_LEN_STOCK = bytes.fromhex("0080182106f0d3f1013f")
MRR_GEN2_3C00_LEN_SUFFIX = bytes.fromhex("b04348030004")
MRR_GEN2_3C00_READ_PREFIX = bytes.fromhex("4904480570c00090")
MRR_GEN2_3C00_READ_SUFFIX = bytes.fromhex(
    "74e7403f74e0063f2a00e60890439153926393034cf094032043200674c0073f2a40e2ef48030004"
)


def mrr_build_gen1_3c00_stub(package_index: int) -> bytes:
    """Build 52-byte PowerPC VLE stub for Gen 1 FES_3C00_GetData (`0xFF` active, `0xB0` not activated)."""
    idx = int(package_index)
    if idx not in MRR_GEN1_SWAP_PACKAGES or idx == 3:
        raise ValueError(
            f"Invalid Gen 1 SWaP package index {package_index}; allowed values: 0, 1, 2, 4, 5, 6"
        )
    return MRR_GEN1_3C00_STUB_PREFIX + bytes([0x2A, (idx & 0x7) << 4]) + MRR_GEN1_3C00_STUB_SUFFIX


def mrr_decode_gen1_3c00_stub(stub: bytes) -> int | None:
    """Decode active package index from a 52-byte Gen 1 FES_3C00_GetData stub, or return None."""
    if (
        len(stub) != 52
        or stub[:22] != MRR_GEN1_3C00_STUB_PREFIX
        or stub[24:] != MRR_GEN1_3C00_STUB_SUFFIX
        or stub[22] != 0x2A
        or (stub[23] & 0x0F) != 0x00
    ):
        return None
    idx = (stub[23] >> 4) & 0x07
    if idx in MRR_GEN1_SWAP_PACKAGES and idx != 3:
        return idx
    return None


def _mrr_decode_gen1_3c00_legacy_0b_stub(actual_52b: bytes, stock_52b: bytes) -> int | None:
    """Detect earlier 50-byte Gen 1 stub (`0x0B` inactive byte) followed by 2 stock tail bytes."""
    if (
        len(actual_52b) != 52
        or len(stock_52b) != 52
        or actual_52b[50:52] != stock_52b[50:52]
        or actual_52b[:20] != _MRR_GEN1_3C00_LEGACY_0B_PREFIX
        or actual_52b[22:50] != _MRR_GEN1_3C00_LEGACY_0B_SUFFIX
        or actual_52b[20] != 0x2A
        or (actual_52b[21] & 0x0F) != 0x00
    ):
        return None
    idx = (actual_52b[21] >> 4) & 0x07
    if idx in MRR_GEN1_SWAP_PACKAGES and idx != 3:
        return idx
    return None


def _validate_gen2_swap_groups(g0: int, g1: int, g2: int, g3: int) -> None:
    """Validate `(g0, g1, g2, g3)` against the exact allowed variants in `MRR_GEN2_SWAP_GROUPS`."""
    vals = (g0, g1, g2, g3)
    for g_idx, val in enumerate(vals):
        allowed = MRR_GEN2_SWAP_GROUPS[g_idx]["variants"]
        if val not in allowed:
            allowed_str = ", ".join(str(k) for k in sorted(allowed))
            raise ValueError(
                f"Invalid Gen 2 SWaP group {g_idx} variant {val} in {vals}; "
                f"allowed variants for group {g_idx}: {allowed_str}"
            )


def _is_valid_gen2_swap_groups(g0: int, g1: int, g2: int, g3: int) -> bool:
    return all(
        val in MRR_GEN2_SWAP_GROUPS[g_idx]["variants"]
        for g_idx, val in enumerate((g0, g1, g2, g3))
    )


def mrr_build_gen2_3c00_len_stub(g0: int, g1: int, g2: int, g3: int) -> bytes:
    """Build 10-byte PowerPC VLE stub for Gen 2 DID 0x3C00 ReadDataLength (`5 * active_groups`)."""
    _validate_gen2_swap_groups(g0, g1, g2, g3)
    active_count = sum(1 for g in (g0, g1, g2, g3) if g > 0)
    return bytes([0x70, 0x80, 0x00, 5 * active_count]) + MRR_GEN2_3C00_LEN_SUFFIX


def mrr_decode_gen2_3c00_len_stub(stub: bytes) -> int | None:
    """Decode active group count (0..4) from a 10-byte Gen 2 DID 0x3C00 ReadDataLength stub, or return None."""
    if (
        len(stub) != 10
        or stub[0:3] != b"\x70\x80\x00"
        or stub[4:10] != MRR_GEN2_3C00_LEN_SUFFIX
        or stub[3] not in (0, 5, 10, 15, 20)
    ):
        return None
    return stub[3] // 5


def mrr_build_gen2_3c00_read_stub(g0: int, g1: int, g2: int, g3: int) -> bytes:
    """Build 56-byte PowerPC VLE stub for Gen 2 DID 0x3C00 ReadData reporting active (g0..g3) with status 0x4F."""
    _validate_gen2_swap_groups(g0, g1, g2, g3)
    hi16 = ((g0 & 0xFF) << 8) | (g1 & 0xFF)
    lo16 = ((g2 & 0xFF) << 8) | (g3 & 0xFF)
    w_lis = 0x70E0E000 | (((hi16 >> 11) & 0x1F) << 16) | (hi16 & 0x7FF)
    w_or2i = 0x70E0C000 | (((lo16 >> 11) & 0x1F) << 16) | (lo16 & 0x7FF)
    return (
        MRR_GEN2_3C00_READ_PREFIX
        + w_lis.to_bytes(4, "big")
        + w_or2i.to_bytes(4, "big")
        + MRR_GEN2_3C00_READ_SUFFIX
    )


def mrr_decode_gen2_3c00_read_stub(stub: bytes) -> tuple[int, int, int, int] | None:
    """Decode (g0, g1, g2, g3) from a 56-byte Gen 2 DID 0x3C00 ReadData stub, or return None."""
    if (
        len(stub) != 56
        or stub[:8] != MRR_GEN2_3C00_READ_PREFIX
        or stub[16:] != MRR_GEN2_3C00_READ_SUFFIX
    ):
        return None
    w_lis = int.from_bytes(stub[8:12], "big")
    w_or2i = int.from_bytes(stub[12:16], "big")
    if (w_lis & 0xFFE0F800) != 0x70E0E000 or (w_or2i & 0xFFE0F800) != 0x70E0C000:
        return None
    hi16 = (((w_lis >> 16) & 0x1F) << 11) | (w_lis & 0x7FF)
    lo16 = (((w_or2i >> 16) & 0x1F) << 11) | (w_or2i & 0x7FF)
    g0, g1, g2, g3 = (hi16 >> 8) & 0xFF, hi16 & 0xFF, (lo16 >> 8) & 0xFF, lo16 & 0xFF
    if not _is_valid_gen2_swap_groups(g0, g1, g2, g3):
        return None
    if stub == mrr_build_gen2_3c00_read_stub(g0, g1, g2, g3):
        return (g0, g1, g2, g3)
    return None


def mrr_get_swap_patch_stats(prof: dict[str, Any]) -> tuple[int, int]:
    """Return `(site_count, total_bytes)` for a profile's Code Flash SWaP / FSC + UDS 22 3C 00 patch."""
    swap_cfg = prof.get("swap_config") or {}
    gen = int(swap_cfg.get("generation") or (1 if prof.get("mcu") == "MPC5674K" else 2))
    has_3c00 = bool(swap_cfg.get("uds_3c00"))
    if gen == 1:
        rel_sites = swap_cfg.get("rel_sites") or _MRR_GEN1_SWAP_REL_SITES
        n_sites = len(rel_sites) + (3 if has_3c00 else 0)
        n_bytes = sum(len(bytes.fromhex(s_hex)) for _, s_hex, _, _ in rel_sites)
        if has_3c00:
            n_bytes += 4 + 10 + 52
        return n_sites, n_bytes
    n_sites = len(_MRR_GEN2_SWAP_FIXED_REL_SITES) + 2 + (3 if has_3c00 else 0)
    n_bytes = sum(len(bytes.fromhex(s_hex)) for _, s_hex, _, _ in _MRR_GEN2_SWAP_FIXED_REL_SITES) + 4 + 82
    if has_3c00:
        n_bytes += 8 + 10 + 56
    return n_sites, n_bytes


def mrr_build_gen2_swap_group_stub(g0: int, g1: int, g2: int, g3: int) -> bytes:
    """Build 82-byte PowerPC VLE stub at coord_base_pa + 0x344 that activates Gen 2 SWaP groups (g0, g1, g2, g3)."""
    _validate_gen2_swap_groups(g0, g1, g2, g3)
    b12 = ((g0 & 0xF) << 4) | (g1 & 0xF)
    b13 = ((g2 & 0xF) << 4) | (g3 & 0xF)
    st0 = 0x4F if g0 else 0xFF
    st1 = 0x4F if g1 else 0xFF
    st2 = 0x4F if g2 else 0xFF
    st3 = 0x4F if g3 else 0xFF

    stub = bytearray()
    stub += bytes([0x70, 0x00, 0x00, b12])
    stub += bytes.fromhex("340b000d")
    stub += bytes([0x70, 0x00, 0x00, b13])
    stub += bytes.fromhex("340b000e")
    stub += bytes([0x70, 0x00, 0x00, g0])
    stub += bytes.fromhex("340c011b")
    stub += bytes([0x70, 0x00, 0x00, g1])
    stub += bytes.fromhex("340c012b")
    stub += bytes([0x70, 0x00, 0x00, g2])
    stub += bytes.fromhex("340c013b")
    stub += bytes([0x70, 0x00, 0x00, g3])
    stub += bytes.fromhex("340c014b")
    stub += bytes([0x70, 0x00, 0x00, st0])
    stub += bytes.fromhex("340c0120")
    stub += bytes([0x70, 0x00, 0x00, st1])
    stub += bytes.fromhex("340c0130")
    stub += bytes([0x70, 0x00, 0x00, st2])
    stub += bytes.fromhex("340c0140")
    stub += bytes([0x70, 0x00, 0x00, st3])
    stub += bytes.fromhex("340c0150")
    stub += bytes.fromhex("e82e")
    return bytes(stub)


def mrr_decode_gen2_swap_group_stub(stub: bytes) -> tuple[int, int, int, int] | None:
    """Decode (g0, g1, g2, g3) from an 82-byte Gen 2 SWaP group stub, or return None if not a valid stub."""
    if (
        len(stub) != 82
        or stub[0:3] != b"\x70\x00\x00"
        or stub[4:8] != bytes.fromhex("340b000d")
        or stub[8:11] != b"\x70\x00\x00"
        or stub[12:16] != bytes.fromhex("340b000e")
        or stub[80:82] != bytes.fromhex("e82e")
    ):
        return None
    b12 = stub[3]
    b13 = stub[11]
    g0, g1, g2, g3 = (b12 >> 4) & 0xF, b12 & 0xF, (b13 >> 4) & 0xF, b13 & 0xF
    if not _is_valid_gen2_swap_groups(g0, g1, g2, g3):
        return None
    if stub == mrr_build_gen2_swap_group_stub(g0, g1, g2, g3):
        return (g0, g1, g2, g3)
    return None


def mrr_describe_gen2_swap_groups(groups: tuple[int, int, int, int]) -> dict[str, Any]:
    """Return active FS-ID list, Coding Byte 12..13 hex, and human-readable summary for Gen 2 groups."""
    g0, g1, g2, g3 = (int(groups[0]), int(groups[1]), int(groups[2]), int(groups[3]))
    active_fsids: list[str] = []
    group_details: list[dict[str, Any]] = []
    for idx, val in enumerate((g0, g1, g2, g3)):
        meta = MRR_GEN2_SWAP_GROUPS[idx]
        fsid_int, ru_txt, en_txt = meta["variants"].get(val, (0, f"Вариант {val}", f"Variant {val}"))
        fsid_hex = f"{fsid_int:08X}" if fsid_int else None
        if fsid_hex:
            active_fsids.append(fsid_hex)
        group_details.append({
            "group": idx,
            "variant": val,
            "fsid_hex": fsid_hex,
            "label_ru": ru_txt,
            "label_en": en_txt,
        })
    b12 = ((g0 & 0xF) << 4) | (g1 & 0xF)
    b13 = ((g2 & 0xF) << 4) | (g3 & 0xF)
    return {
        "groups": [g0, g1, g2, g3],
        "coding_byte12_13_hex": f"{b12:02X}{b13:02X}",
        "active_fsids": active_fsids,
        "group_details": group_details,
    }


def mrr_inspect_swap_sites(
    prof: dict[str, Any],
    read_fn: Callable[[int, int], bytes],
    *,
    file_base: int | None = None,
) -> dict[str, Any]:
    """Inspect all SWaP / FSC + cosmetic UDS 22 3C 00 patch sites via `read_fn(phys_addr, length)`."""
    swap_cfg = prof.get("swap_config")
    if not prof.get("verified", True) or not swap_cfg:
        return {
            "unit": prof["unit"],
            "sw": prof["sw"],
            "family": prof["family"],
            "mcu": prof["mcu"],
            "verified": False,
            "generation": 1 if prof["mcu"] == "MPC5674K" else 2,
            "swap_patch_state": "unsupported_sw",
            "stock_points": 0,
            "patched_points": 0,
            "total_points": 0,
            "points": [],
        }

    def _mk_point(
        desc: str,
        address: int,
        stock_hex: str,
        patched_hex: str,
        actual: bytes,
        state: str,
    ) -> dict[str, Any]:
        pt: dict[str, Any] = {
            "name": desc,
            "physical_address": f"0x{address:08X}",
            "stock_hex": stock_hex,
            "patched_hex": patched_hex,
            "actual_hex": actual.hex(),
            "state": state,
        }
        if file_base is not None:
            pt["file_offset"] = f"0x{address - file_base:X}"
        return pt

    gen = int(swap_cfg["generation"])
    uds_3c00 = swap_cfg.get("uds_3c00") or {}
    points: list[dict[str, Any]] = []
    stock_count = 0
    patched_count = 0

    if gen == 1:
        main_pa = int(swap_cfg["swap_main_pa"])
        rel_sites = swap_cfg.get("rel_sites") or _MRR_GEN1_SWAP_REL_SITES
        pkg_rels = tuple(swap_cfg.get("pkg_index_rels") or (0x4C, 0x50))
        default_pkg = int(swap_cfg.get("default_package_index", 6))
        detected_pkg_idx: int | None = None

        for rel, stock_hex, default_patched_hex, desc in rel_sites:
            address = main_pa + rel
            stock_b = bytes.fromhex(stock_hex)
            actual = read_fn(address, len(stock_b))
            patched_hex_display = default_patched_hex
            if rel in pkg_rels:
                if actual == stock_b:
                    state = "stock"
                    stock_count += 1
                elif len(actual) == 2 and actual[0] == 0x48 and (actual[1] & 0x0F) == 0x03:
                    cand_idx = (actual[1] >> 4) & 0x07
                    if cand_idx in MRR_GEN1_SWAP_PACKAGES and cand_idx != 3:
                        state = "swap_activated"
                        patched_count += 1
                        patched_hex_display = actual.hex()
                        if detected_pkg_idx is None:
                            detected_pkg_idx = cand_idx
                        elif detected_pkg_idx != cand_idx:
                            state = "unknown"
                            patched_count -= 1
                    else:
                        state = "unknown"
                else:
                    state = "unknown"
            else:
                pat_b = bytes.fromhex(default_patched_hex)
                if actual == stock_b:
                    state = "stock"
                    stock_count += 1
                elif actual == pat_b:
                    state = "swap_activated"
                    patched_count += 1
                else:
                    state = "unknown"
            points.append(_mk_point(desc, address, stock_hex, patched_hex_display, actual, state))

        if uds_3c00:
            # Site 7: FES_3C00_Prepare
            prep_addr = int(uds_3c00["prepare_pa"])
            prep_stock_hex = str(uds_3c00["prepare_stock"])
            prep_stock_b = bytes.fromhex(prep_stock_hex)
            prep_actual = read_fn(prep_addr, len(prep_stock_b))
            if prep_actual == prep_stock_b:
                prep_state = "stock"
                stock_count += 1
            elif prep_actual == MRR_GEN1_3C00_PREPARE_PATCHED:
                prep_state = "swap_activated"
                patched_count += 1
            else:
                prep_state = "unknown"
            points.append(
                _mk_point(
                    "FES_3C00_Prepare returns E_OK (UDS 22 3C 00)",
                    prep_addr,
                    prep_stock_hex,
                    MRR_GEN1_3C00_PREPARE_PATCHED.hex(),
                    prep_actual,
                    prep_state,
                )
            )

            # Site 8: FES_3C00_GetLen
            len_addr = int(uds_3c00["len_pa"])
            len_stock_hex = str(uds_3c00["len_stock"])
            len_stock_b = bytes.fromhex(len_stock_hex)
            len_actual = read_fn(len_addr, len(len_stock_b))
            if len_actual == len_stock_b:
                len_state = "stock"
                stock_count += 1
            elif len_actual == MRR_GEN1_3C00_LEN_PATCHED:
                len_state = "swap_activated"
                patched_count += 1
            else:
                len_state = "unknown"
            points.append(
                _mk_point(
                    "FES_3C00_GetLen reports 35 bytes (7 FS-IDs)",
                    len_addr,
                    len_stock_hex,
                    MRR_GEN1_3C00_LEN_PATCHED.hex(),
                    len_actual,
                    len_state,
                )
            )

            # Site 9: FES_3C00_GetData 52B VLE stub
            data_addr = int(uds_3c00["data_pa"])
            data_stock_hex = str(uds_3c00["data_stock"])
            data_stock_b = bytes.fromhex(data_stock_hex)
            data_actual = read_fn(data_addr, len(data_stock_b))
            stub_pkg_idx = mrr_decode_gen1_3c00_stub(data_actual)
            legacy_pkg_idx = _mrr_decode_gen1_3c00_legacy_0b_stub(data_actual, data_stock_b)
            ref_pkg = detected_pkg_idx if detected_pkg_idx is not None else default_pkg
            has_legacy_3c00 = False
            if data_actual == data_stock_b:
                data_state = "stock"
                stock_count += 1
                data_pat_hex = mrr_build_gen1_3c00_stub(ref_pkg).hex()
            elif stub_pkg_idx is not None:
                data_pat_hex = data_actual.hex()
                if detected_pkg_idx is None:
                    detected_pkg_idx = stub_pkg_idx
                    data_state = "swap_activated"
                    patched_count += 1
                elif detected_pkg_idx == stub_pkg_idx:
                    data_state = "swap_activated"
                    patched_count += 1
                else:
                    data_state = "unknown"
            elif legacy_pkg_idx is not None:
                has_legacy_3c00 = True
                data_state = "legacy"
                if detected_pkg_idx is None:
                    detected_pkg_idx = legacy_pkg_idx
                data_pat_hex = mrr_build_gen1_3c00_stub(detected_pkg_idx).hex()
            else:
                data_state = "unknown"
                data_pat_hex = mrr_build_gen1_3c00_stub(ref_pkg).hex()
            points.append(
                _mk_point(
                    "FES_3C00_GetData 52B VLE UDS 22 3C 00 status stub",
                    data_addr,
                    data_stock_hex,
                    data_pat_hex,
                    data_actual,
                    data_state,
                )
            )
        else:
            has_legacy_3c00 = False

        total = len(points)
        if patched_count == total:
            overall = "swap_activated"
        elif stock_count == total:
            overall = "stock"
        elif patched_count > 0 and (stock_count > 0 or has_legacy_3c00):
            overall = "partial"
        else:
            overall = "unknown"

        pkg_meta = MRR_GEN1_SWAP_PACKAGES.get(detected_pkg_idx) if detected_pkg_idx is not None else None
        return {
            "unit": prof["unit"],
            "sw": prof["sw"],
            "family": prof["family"],
            "mcu": prof["mcu"],
            "verified": True,
            "generation": 1,
            "swap_patch_state": overall,
            "stock_points": stock_count,
            "patched_points": patched_count,
            "total_points": total,
            "package_index": detected_pkg_idx,
            "active_fsids": [pkg_meta["fsid_hex"]] if (overall == "swap_activated" and pkg_meta) else [],
            "feature_level": pkg_meta["level"] if (overall == "swap_activated" and pkg_meta) else None,
            "package_title_ru": pkg_meta["title_ru"] if (overall == "swap_activated" and pkg_meta) else None,
            "package_title_en": pkg_meta["title_en"] if (overall == "swap_activated" and pkg_meta) else None,
            "points": points,
        }

    # Generation 2 (MPC5675K: 0682, X720, 0771, 0780)
    coord_pa = int(swap_cfg["coord_base_pa"])
    for rel, stock_hex, patched_hex, desc in _MRR_GEN2_SWAP_FIXED_REL_SITES:
        address = coord_pa + rel
        stock_b = bytes.fromhex(stock_hex)
        pat_b = bytes.fromhex(patched_hex)
        actual = read_fn(address, len(stock_b))
        if actual == stock_b:
            state = "stock"
            stock_count += 1
        elif actual == pat_b:
            state = "swap_activated"
            patched_count += 1
        else:
            state = "unknown"
        points.append(_mk_point(desc, address, stock_hex, patched_hex, actual, state))

    # Site 18: +0x498 e_bl_aff066 -> 48034400
    bl_addr = coord_pa + 0x498
    bl_stock_hex = str(swap_cfg["e_bl_aff066"])
    bl_stock_b = bytes.fromhex(bl_stock_hex)
    bl_pat_b = bytes.fromhex("48034400")
    bl_actual = read_fn(bl_addr, 4)
    if bl_actual == bl_stock_b:
        bl_state = "stock"
        stock_count += 1
    elif bl_actual == bl_pat_b:
        bl_state = "swap_activated"
        patched_count += 1
    else:
        bl_state = "unknown"
    points.append(
        _mk_point(
            "SWaP_CyclicTask force CheckBaseActivation==1",
            bl_addr,
            bl_stock_hex,
            "48034400",
            bl_actual,
            bl_state,
        )
    )

    # Site 19: +0x344 82-byte group activation stub
    stub_addr = coord_pa + MRR_GEN2_SWAP_STUB_REL
    stub_actual = read_fn(stub_addr, 82)
    decoded_groups = mrr_decode_gen2_swap_group_stub(stub_actual)
    default_groups = tuple(swap_cfg.get("default_groups") or (8, 3, 4, 7))
    if stub_actual == MRR_GEN2_SWAP_STUB_STOCK:
        stub_state = "stock"
        stock_count += 1
        stub_pat_hex = mrr_build_gen2_swap_group_stub(*default_groups).hex()
    elif decoded_groups is not None:
        stub_state = "swap_activated"
        patched_count += 1
        stub_pat_hex = stub_actual.hex()
    else:
        stub_state = "unknown"
        stub_pat_hex = mrr_build_gen2_swap_group_stub(*default_groups).hex()
    points.append(
        _mk_point(
            "SWaP_CheckCodingMatchesNvm42 82B VLE group-activation stub",
            stub_addr,
            MRR_GEN2_SWAP_STUB_STOCK.hex(),
            stub_pat_hex,
            stub_actual,
            stub_state,
        )
    )

    if uds_3c00:
        ref_groups = decoded_groups if decoded_groups is not None else default_groups
        # Site 20: DID 0x3C00 ConditionCheckRead (8 B)
        cond_addr = int(uds_3c00["cond_pa"])
        cond_actual = read_fn(cond_addr, 8)
        if cond_actual == MRR_GEN2_3C00_COND_STOCK:
            cond_state = "stock"
            stock_count += 1
        elif cond_actual == MRR_GEN2_3C00_COND_PATCHED:
            cond_state = "swap_activated"
            patched_count += 1
        else:
            cond_state = "unknown"
        points.append(
            _mk_point(
                "DID 0x3C00 ConditionCheckRead returns E_OK",
                cond_addr,
                MRR_GEN2_3C00_COND_STOCK.hex(),
                MRR_GEN2_3C00_COND_PATCHED.hex(),
                cond_actual,
                cond_state,
            )
        )

        # Site 21: DID 0x3C00 ReadDataLength (10 B)
        len_addr = int(uds_3c00["len_pa"])
        len_actual = read_fn(len_addr, 10)
        decoded_active_cnt = mrr_decode_gen2_3c00_len_stub(len_actual)
        if len_actual == MRR_GEN2_3C00_LEN_STOCK:
            len_state = "stock"
            stock_count += 1
            len_pat_hex = mrr_build_gen2_3c00_len_stub(*ref_groups).hex()
        elif decoded_active_cnt is not None:
            len_pat_hex = len_actual.hex()
            if decoded_groups is None or decoded_active_cnt == sum(1 for g in decoded_groups if g > 0):
                len_state = "swap_activated"
                patched_count += 1
            else:
                len_state = "unknown"
        else:
            len_state = "unknown"
            len_pat_hex = mrr_build_gen2_3c00_len_stub(*ref_groups).hex()
        points.append(
            _mk_point(
                "DID 0x3C00 ReadDataLength reports 5*N bytes",
                len_addr,
                MRR_GEN2_3C00_LEN_STOCK.hex(),
                len_pat_hex,
                len_actual,
                len_state,
            )
        )

        # Site 22: DID 0x3C00 ReadData (56 B)
        data_addr = int(uds_3c00["data_pa"])
        data_stock_hex = str(uds_3c00["data_stock"])
        data_stock_b = bytes.fromhex(data_stock_hex)
        data_actual = read_fn(data_addr, len(data_stock_b))
        read_groups = mrr_decode_gen2_3c00_read_stub(data_actual)
        if data_actual == data_stock_b:
            data_state = "stock"
            stock_count += 1
            data_pat_hex = mrr_build_gen2_3c00_read_stub(*ref_groups).hex()
        elif read_groups is not None:
            data_pat_hex = data_actual.hex()
            if decoded_groups is None:
                decoded_groups = read_groups
                data_state = "swap_activated"
                patched_count += 1
            elif decoded_groups == read_groups:
                data_state = "swap_activated"
                patched_count += 1
            else:
                data_state = "unknown"
        else:
            data_state = "unknown"
            data_pat_hex = mrr_build_gen2_3c00_read_stub(*ref_groups).hex()
        points.append(
            _mk_point(
                "DID 0x3C00 ReadData 56B VLE UDS 22 3C 00 status stub",
                data_addr,
                data_stock_hex,
                data_pat_hex,
                data_actual,
                data_state,
            )
        )

    total = len(points)
    if patched_count == total:
        overall = "swap_activated"
    elif stock_count == total:
        overall = "stock"
    elif patched_count > 0 and stock_count > 0:
        overall = "partial"
    else:
        overall = "unknown"

    grp_info = (
        mrr_describe_gen2_swap_groups(decoded_groups)
        if (overall == "swap_activated" and decoded_groups is not None)
        else None
    )
    return {
        "unit": prof["unit"],
        "sw": prof["sw"],
        "family": prof["family"],
        "mcu": prof["mcu"],
        "verified": True,
        "generation": 2,
        "swap_patch_state": overall,
        "stock_points": stock_count,
        "patched_points": patched_count,
        "total_points": total,
        "groups": list(decoded_groups) if decoded_groups is not None else None,
        "coding_byte12_13_hex": grp_info["coding_byte12_13_hex"] if grp_info else None,
        "active_fsids": grp_info["active_fsids"] if grp_info else [],
        "group_details": grp_info["group_details"] if grp_info else [],
        "points": points,
    }


def mrr_apply_swap_sites(
    prof: dict[str, Any],
    read_fn: Callable[[int, int], bytes],
    write_fn: Callable[[int, bytes], None],
    *,
    restore_stock: bool = False,
    package_index: int = 6,
    groups: tuple[int, int, int, int] = (8, 3, 4, 7),
    file_base: int | None = None,
) -> dict[str, Any]:
    """Validate and apply/revert all SWaP / FSC + UDS 22 3C 00 patch sites via `read_fn`/`write_fn`."""
    swap_cfg = prof.get("swap_config")
    if not prof.get("verified", True) or not swap_cfg:
        raise ValueError(
            tr(
                "Образ прошивки не совпадает ни с одним проверенным профилем MRR (0130, 0192, 0194, 0196, 0682, X720, 0771, 0780) — патч SWaP отклонён.",
                "Firmware image does not match any verified MRR profile (0130, 0192, 0194, 0196, 0682, X720, 0771, 0780) — refusing to patch SWaP.",
            )
        )

    def _loc(address: int) -> str:
        return f"0x{address:08X} (+0x{address - file_base:X})" if file_base is not None else f"0x{address:08X}"

    def _record(desc: str, address: int, before: bytes, after: bytes) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "name": desc,
            "physical_address": f"0x{address:08X}",
            "before": before.hex(),
            "after": after.hex(),
            "changed": before != after,
        }
        if file_base is not None:
            rec["file_offset"] = f"0x{address - file_base:X}"
        return rec

    gen = int(swap_cfg["generation"])
    uds_3c00 = swap_cfg.get("uds_3c00") or {}
    records: list[dict[str, Any]] = []

    if gen == 1:
        if not restore_stock and (package_index not in MRR_GEN1_SWAP_PACKAGES or package_index == 3):
            raise ValueError(
                f"Invalid Gen 1 SWaP package index {package_index}; allowed values: 0, 1, 2, 4, 5, 6"
            )
        main_pa = int(swap_cfg["swap_main_pa"])
        rel_sites = swap_cfg.get("rel_sites") or _MRR_GEN1_SWAP_REL_SITES
        pkg_rels = tuple(swap_cfg.get("pkg_index_rels") or (0x4C, 0x50))
        li_r3 = bytes([0x48, ((package_index & 0x7) << 4) | 0x03])
        allowed_li_r3 = {
            bytes([0x48, ((idx & 0x7) << 4) | 0x03]) for idx in (0, 1, 2, 4, 5, 6)
        }
        for rel, stock_hex, default_patched_hex, desc in rel_sites:
            address = main_pa + rel
            stock_bytes = bytes.fromhex(stock_hex)
            patched_bytes = li_r3 if rel in pkg_rels else bytes.fromhex(default_patched_hex)
            target_bytes = stock_bytes if restore_stock else patched_bytes
            actual = read_fn(address, len(stock_bytes))
            valid_prev = (
                ({stock_bytes} | allowed_li_r3)
                if rel in pkg_rels
                else {stock_bytes, patched_bytes}
            )
            if actual not in valid_prev:
                raise ValueError(
                    f"Unexpected bytes at {_loc(address)} for profile {prof['sw']}: "
                    f"got {actual.hex()}, expected {stock_hex} or {patched_bytes.hex()}"
                )
            write_fn(address, target_bytes)
            records.append(_record(desc, address, actual, target_bytes))

        if uds_3c00:
            # Site 7: FES_3C00_Prepare
            prep_addr = int(uds_3c00["prepare_pa"])
            prep_stock = bytes.fromhex(str(uds_3c00["prepare_stock"]))
            prep_target = prep_stock if restore_stock else MRR_GEN1_3C00_PREPARE_PATCHED
            prep_actual = read_fn(prep_addr, len(prep_stock))
            if prep_actual not in (prep_stock, MRR_GEN1_3C00_PREPARE_PATCHED):
                raise ValueError(
                    f"Unexpected bytes at {_loc(prep_addr)} for profile {prof['sw']}: "
                    f"got {prep_actual.hex()}, expected {prep_stock.hex()} or {MRR_GEN1_3C00_PREPARE_PATCHED.hex()}"
                )
            write_fn(prep_addr, prep_target)
            records.append(_record("FES_3C00_Prepare returns E_OK (UDS 22 3C 00)", prep_addr, prep_actual, prep_target))

            # Site 8: FES_3C00_GetLen
            len_addr = int(uds_3c00["len_pa"])
            len_stock = bytes.fromhex(str(uds_3c00["len_stock"]))
            len_target = len_stock if restore_stock else MRR_GEN1_3C00_LEN_PATCHED
            len_actual = read_fn(len_addr, len(len_stock))
            if len_actual not in (len_stock, MRR_GEN1_3C00_LEN_PATCHED):
                raise ValueError(
                    f"Unexpected bytes at {_loc(len_addr)} for profile {prof['sw']}: "
                    f"got {len_actual.hex()}, expected {len_stock.hex()} or {MRR_GEN1_3C00_LEN_PATCHED.hex()}"
                )
            write_fn(len_addr, len_target)
            records.append(_record("FES_3C00_GetLen reports 35 bytes (7 FS-IDs)", len_addr, len_actual, len_target))

            # Site 9: FES_3C00_GetData 52B VLE stub
            data_addr = int(uds_3c00["data_pa"])
            data_stock = bytes.fromhex(str(uds_3c00["data_stock"]))
            data_target = data_stock if restore_stock else mrr_build_gen1_3c00_stub(package_index)
            data_actual = read_fn(data_addr, len(data_stock))
            if (
                data_actual != data_stock
                and mrr_decode_gen1_3c00_stub(data_actual) is None
                and _mrr_decode_gen1_3c00_legacy_0b_stub(data_actual, data_stock) is None
            ):
                raise ValueError(
                    f"Unexpected 52-byte FES_3C00_GetData bytes at {_loc(data_addr)} for profile {prof['sw']}"
                )
            write_fn(data_addr, data_target)
            records.append(
                _record(
                    "FES_3C00_GetData 52B VLE UDS 22 3C 00 status stub",
                    data_addr,
                    data_actual,
                    data_target,
                )
            )

        pkg_meta = MRR_GEN1_SWAP_PACKAGES.get(package_index, MRR_GEN1_SWAP_PACKAGES[6])
        return {
            "unit": prof["unit"],
            "sw": prof["sw"],
            "family": prof["family"],
            "mcu": prof["mcu"],
            "generation": 1,
            "mode": "restore_swap_stock" if restore_stock else "swap_activate",
            "patch_count": len(records),
            "package_index": None if restore_stock else package_index,
            "active_fsids": [] if restore_stock else [pkg_meta["fsid_hex"]],
            "feature_level": None if restore_stock else pkg_meta["level"],
            "patches": records,
        }

    # Generation 2 (MPC5675K: 0682, X720, 0771, 0780)
    g_tuple = (int(groups[0]), int(groups[1]), int(groups[2]), int(groups[3]))
    target_stub = MRR_GEN2_SWAP_STUB_STOCK if restore_stock else mrr_build_gen2_swap_group_stub(*g_tuple)
    coord_pa = int(swap_cfg["coord_base_pa"])

    for rel, stock_hex, patched_hex, desc in _MRR_GEN2_SWAP_FIXED_REL_SITES:
        address = coord_pa + rel
        stock_bytes = bytes.fromhex(stock_hex)
        patched_bytes = bytes.fromhex(patched_hex)
        target_bytes = stock_bytes if restore_stock else patched_bytes
        actual = read_fn(address, len(stock_bytes))
        if actual not in (stock_bytes, patched_bytes):
            raise ValueError(
                f"Unexpected bytes at {_loc(address)} for profile {prof['sw']}: "
                f"got {actual.hex()}, expected {stock_hex} or {patched_hex}"
            )
        write_fn(address, target_bytes)
        records.append(_record(desc, address, actual, target_bytes))

    # Site 18: +0x498 e_bl_aff066 -> 48034400
    bl_addr = coord_pa + 0x498
    bl_stock_bytes = bytes.fromhex(str(swap_cfg["e_bl_aff066"]))
    bl_patched_bytes = bytes.fromhex("48034400")
    bl_target = bl_stock_bytes if restore_stock else bl_patched_bytes
    bl_actual = read_fn(bl_addr, 4)
    if bl_actual not in (bl_stock_bytes, bl_patched_bytes):
        raise ValueError(
            f"Unexpected bytes at {_loc(bl_addr)} for profile {prof['sw']}: "
            f"got {bl_actual.hex()}, expected {bl_stock_bytes.hex()} or 48034400"
        )
    write_fn(bl_addr, bl_target)
    records.append(_record("SWaP_CyclicTask force CheckBaseActivation==1", bl_addr, bl_actual, bl_target))

    # Site 19: +0x344 82-byte group activation stub
    stub_addr = coord_pa + MRR_GEN2_SWAP_STUB_REL
    stub_actual = read_fn(stub_addr, 82)
    if stub_actual != MRR_GEN2_SWAP_STUB_STOCK and mrr_decode_gen2_swap_group_stub(stub_actual) is None:
        raise ValueError(f"Unexpected 82-byte stub at {_loc(stub_addr)} for profile {prof['sw']}")
    write_fn(stub_addr, target_stub)
    records.append(
        _record(
            "SWaP_CheckCodingMatchesNvm42 82B VLE group-activation stub",
            stub_addr,
            stub_actual,
            target_stub,
        )
    )

    if uds_3c00:
        # Site 20: DID 0x3C00 ConditionCheckRead (8 B)
        cond_addr = int(uds_3c00["cond_pa"])
        cond_target = MRR_GEN2_3C00_COND_STOCK if restore_stock else MRR_GEN2_3C00_COND_PATCHED
        cond_actual = read_fn(cond_addr, 8)
        if cond_actual not in (MRR_GEN2_3C00_COND_STOCK, MRR_GEN2_3C00_COND_PATCHED):
            raise ValueError(
                f"Unexpected bytes at {_loc(cond_addr)} for profile {prof['sw']}: "
                f"got {cond_actual.hex()}, expected {MRR_GEN2_3C00_COND_STOCK.hex()} or {MRR_GEN2_3C00_COND_PATCHED.hex()}"
            )
        write_fn(cond_addr, cond_target)
        records.append(_record("DID 0x3C00 ConditionCheckRead returns E_OK", cond_addr, cond_actual, cond_target))

        # Site 21: DID 0x3C00 ReadDataLength (10 B)
        len_addr = int(uds_3c00["len_pa"])
        len_target = MRR_GEN2_3C00_LEN_STOCK if restore_stock else mrr_build_gen2_3c00_len_stub(*g_tuple)
        len_actual = read_fn(len_addr, 10)
        if len_actual != MRR_GEN2_3C00_LEN_STOCK and mrr_decode_gen2_3c00_len_stub(len_actual) is None:
            raise ValueError(f"Unexpected 10-byte DID 0x3C00 ReadDataLength at {_loc(len_addr)} for profile {prof['sw']}")
        write_fn(len_addr, len_target)
        records.append(_record("DID 0x3C00 ReadDataLength reports 5*N bytes", len_addr, len_actual, len_target))

        # Site 22: DID 0x3C00 ReadData (56 B)
        data_addr = int(uds_3c00["data_pa"])
        data_stock = bytes.fromhex(str(uds_3c00["data_stock"]))
        data_target = data_stock if restore_stock else mrr_build_gen2_3c00_read_stub(*g_tuple)
        data_actual = read_fn(data_addr, len(data_stock))
        if data_actual != data_stock and mrr_decode_gen2_3c00_read_stub(data_actual) is None:
            raise ValueError(f"Unexpected 56-byte DID 0x3C00 ReadData at {_loc(data_addr)} for profile {prof['sw']}")
        write_fn(data_addr, data_target)
        records.append(
            _record(
                "DID 0x3C00 ReadData 56B VLE UDS 22 3C 00 status stub",
                data_addr,
                data_actual,
                data_target,
            )
        )

    grp_info = mrr_describe_gen2_swap_groups(g_tuple)
    return {
        "unit": prof["unit"],
        "sw": prof["sw"],
        "family": prof["family"],
        "mcu": prof["mcu"],
        "generation": 2,
        "mode": "restore_swap_stock" if restore_stock else "swap_activate",
        "patch_count": len(records),
        "groups": None if restore_stock else list(g_tuple),
        "coding_byte12_13_hex": None if restore_stock else grp_info["coding_byte12_13_hex"],
        "active_fsids": [] if restore_stock else grp_info["active_fsids"],
        "patches": records,
    }


def mrr_inspect_cflash_swap_state(
    image_bytes: bytes,
    *,
    profile: str | None = None,
) -> dict[str, Any]:
    """Inspect a CodeFlash (1.5/2.0 MiB) or Application (0x150000/0x1D0000) dump for SWaP / FSC patch state."""
    prof = mrr_get_profile(profile) if profile else mrr_detect_profile(image_bytes=image_bytes)
    base = _resolve_cflash_or_app_base(image_bytes, prof)
    res = mrr_inspect_swap_sites(
        prof,
        lambda addr, n: image_bytes[addr - base:addr - base + n],
        file_base=base,
    )
    res["image_kind"] = "cflash" if base == 0 else "application"
    res["image_size"] = len(image_bytes)
    res["image_sha256"] = hashlib.sha256(image_bytes).hexdigest()
    return res


def mrr_apply_swap_patch(
    image_bytes: bytes,
    *,
    restore_stock: bool = False,
    profile: str | None = None,
    package_index: int = 6,
    groups: tuple[int, int, int, int] = (8, 3, 4, 7),
) -> tuple[bytes, dict[str, Any]]:
    """Apply or revert the direct Code Flash SWaP / FSC + UDS 22 3C 00 activation patch on an App or CodeFlash image."""
    prof = mrr_get_profile(profile) if profile else mrr_detect_profile(image_bytes=image_bytes)
    if not prof.get("verified", True) or not prof.get("swap_config"):
        raise ValueError(
            tr(
                "Образ прошивки не совпадает ни с одним проверенным профилем MRR (0130, 0192, 0194, 0196, 0682, X720, 0771, 0780) — патч SWaP отклонён.",
                "Firmware image does not match any verified MRR profile (0130, 0192, 0194, 0196, 0682, X720, 0771, 0780) — refusing to patch SWaP.",
            )
        )
    base = _resolve_cflash_or_app_base(image_bytes, prof)
    source_sha = hashlib.sha256(image_bytes).hexdigest()
    output = bytearray(image_bytes)

    def _read(addr: int, n: int) -> bytes:
        off = addr - base
        return bytes(output[off:off + n])

    def _write(addr: int, data: bytes) -> None:
        off = addr - base
        output[off:off + len(data)] = data

    manifest = mrr_apply_swap_sites(
        prof,
        _read,
        _write,
        restore_stock=restore_stock,
        package_index=package_index,
        groups=groups,
        file_base=base,
    )
    result_bytes = bytes(output)
    manifest["image_kind"] = "cflash" if base == 0 else "application"
    manifest["source_sha256"] = source_sha
    manifest["output_sha256"] = hashlib.sha256(result_bytes).hexdigest()
    manifest["image_size"] = len(result_bytes)
    manifest["changed_bytes"] = sum(a != b for a, b in zip(image_bytes, result_bytes))
    return result_bytes, manifest


def mrr_extract_swap_affected_sectors(
    image_bytes: bytes,
    *,
    profile: str | None = None,
) -> list[tuple[int, bytes]]:
    """Extract the C90FL Code Flash erase sector(s) touched by the direct SWaP / FSC patch."""
    prof = mrr_get_profile(profile) if profile else mrr_detect_profile(image_bytes=image_bytes)
    base = _resolve_cflash_or_app_base(image_bytes, prof)
    sectors: list[tuple[int, bytes]] = []
    for addr, size in prof["swap_affected_sectors"]:
        off = addr - base
        if off < 0 or off + size > len(image_bytes):
            raise ValueError(f"Sector 0x{addr:08X}..0x{addr + size - 1:08X} out of image range")
        sectors.append((addr, image_bytes[off:off + size]))
    return sectors


# ── PowerPC VLE Assembler & Return-Safe SRAM/Flash Drivers ──────────────────
class _VleBuilder:
    def __init__(self) -> None:
        self.data = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, int, str, int]] = []

    @property
    def offset(self) -> int:
        return len(self.data)

    def label(self, name: str) -> None:
        self.labels[name] = self.offset

    def emit(self, hex_bytes: str, _text: str = "") -> None:
        self.data.extend(bytes.fromhex(hex_bytes))

    def word(self, value: int, _text: str = "") -> None:
        self.emit(f"{value & 0xFFFFFFFF:08x}")

    def lwz(self, rd: int, ra: int, offset: int) -> None:
        self.word((0x50 << 24) | (rd << 21) | (ra << 16) | (offset & 0xFFFF))

    def stw(self, rs: int, ra: int, offset: int) -> None:
        self.word((0x54 << 24) | (rs << 21) | (ra << 16) | (offset & 0xFFFF))

    def lis(self, rd: int, imm16: int) -> None:
        imm16 &= 0xFFFF
        val = 0x7000E000 | (rd << 21) | (((imm16 >> 11) & 0x1F) << 16) | (imm16 & 0x7FF)
        self.word(val)

    def or2i(self, rd: int, imm16: int) -> None:
        imm16 &= 0xFFFF
        val = 0x7000C000 | (rd << 21) | (((imm16 >> 11) & 0x1F) << 16) | (imm16 & 0x7FF)
        self.word(val)

    def li32(self, rd: int, value: int) -> None:
        value &= 0xFFFFFFFF
        self.lis(rd, (value >> 16) & 0xFFFF)
        if value & 0xFFFF:
            self.or2i(rd, value & 0xFFFF)

    def branch(self, condition: str, target: str) -> None:
        base = {
            "b": 0xE8,
            "bge": 0xE0,
            "ble": 0xE1,
            "bne": 0xE2,
            "blt": 0xE4,
            "bgt": 0xE5,
            "beq": 0xE6,
        }[condition]
        self.fixups.append((self.offset, base, target, 2))
        self.data.extend(b"\x00\x00")

    def ebranch(self, condition: str, target: str) -> None:
        base = {
            "b": 0x78000000,
            "bl": 0x78000001,
            "bge": 0x7A000000,
            "ble": 0x7A010000,
            "bne": 0x7A020000,
            "blt": 0x7A100000,
            "bgt": 0x7A110000,
            "beq": 0x7A120000,
        }[condition]
        self.fixups.append((self.offset, base, target, 4))
        self.data.extend(b"\x00\x00\x00\x00")

    def finish(self) -> bytes:
        for offset, base, target, width in self.fixups:
            delta = self.labels[target] - offset
            if width == 2:
                if delta & 1 or not -256 <= delta <= 254:
                    raise ValueError(f"Invalid branch distance {delta} at 0x{offset:x}")
                self.data[offset] = base
                self.data[offset + 1] = (delta // 2) & 0xFF
            else:
                if base in (0x78000000, 0x78000001):
                    word = base | (delta & 0x01FFFFFE)
                else:
                    word = base | (delta & 0xFFFE)
                self.data[offset:offset + 4] = word.to_bytes(4, "big")
        return bytes(self.data)


def _ppc_or(ra: int, rs: int, rb: int) -> int:
    return (31 << 26) | (rs << 21) | (ra << 16) | (rb << 11) | (444 << 1)


def _ppc_and(ra: int, rs: int, rb: int) -> int:
    return (31 << 26) | (rs << 21) | (ra << 16) | (rb << 11) | (28 << 1)


def _ppc_xor(ra: int, rs: int, rb: int) -> int:
    return (31 << 26) | (rs << 21) | (ra << 16) | (rb << 11) | (316 << 1)


def _ppc_mfspr(rd: int, spr: int) -> int:
    split = ((spr & 0x1F) << 5) | ((spr >> 5) & 0x1F)
    return (31 << 26) | (rd << 21) | (split << 11) | (339 << 1)


def _ppc_cmplw(ra: int, rb: int) -> int:
    return (31 << 26) | (ra << 16) | (rb << 11) | (32 << 1)


def _ppc_subfc(rd: int, ra: int, rb: int) -> int:
    return (31 << 26) | (rd << 21) | (ra << 16) | (rb << 11) | (8 << 1)


def _ppc_subfe(rd: int, ra: int, rb: int) -> int:
    return (31 << 26) | (rd << 21) | (ra << 16) | (rb << 11) | (136 << 1)


def _e_rlwinm(ra: int, rs: int, sh: int, mb: int, me: int) -> int:
    return (29 << 26) | (rs << 21) | (ra << 16) | (sh << 11) | (mb << 6) | (me << 1) | 1


def _e_addi8(rd: int, ra: int, imm8: int) -> int:
    return 0x18008000 | (rd << 21) | (ra << 16) | (imm8 & 0xFF)


def _emit_sbc_wd_helpers(b: _VleBuilder, sbc_last_tb_addr: int = 0x40025E28) -> None:
    sbc_kick_period_ticks = 0x0017597E
    sbc_exit_safe_ticks = 0x0015EF3C
    dspi2_base = 0xFFF98000
    dspi2_poll_loops = 0x00040000

    b.label("sbc_wd_poll")
    b.emit("182106c0")
    b.emit("0080")
    b.emit("54010044")
    b.emit("7c000026")
    b.stw(0, 1, 0x08)
    b.stw(3, 1, 0x0C)
    b.stw(4, 1, 0x10)
    b.stw(5, 1, 0x14)
    b.stw(6, 1, 0x18)
    b.stw(7, 1, 0x1C)

    b.label("sbc_wd_read_tb")
    b.word(_ppc_mfspr(4, 0x10D))
    b.word(_ppc_mfspr(5, 0x10C))
    b.word(_ppc_mfspr(6, 0x10D))
    b.word(_ppc_cmplw(4, 6))
    b.branch("bne", "sbc_wd_read_tb")

    b.li32(3, sbc_last_tb_addr)
    b.lwz(6, 3, 0x00)
    b.lwz(7, 3, 0x04)
    b.word(_ppc_subfc(7, 7, 5))
    b.word(_ppc_subfe(6, 6, 4))
    b.emit("2a06")
    b.branch("bne", "sbc_wd_do_kick")
    b.li32(6, sbc_kick_period_ticks)
    b.word(_ppc_cmplw(7, 6))
    b.ebranch("blt", "sbc_wd_fast_ret")

    b.label("sbc_wd_do_kick")
    b.emit("1b010920")
    b.li32(25, dspi2_base)
    b.lwz(24, 25, 0x00)
    b.lwz(30, 25, 0x30)

    b.word(_ppc_or(3, 24, 24))
    b.or2i(3, 0x0C01)
    b.stw(3, 25, 0x00)
    b.stw(3, 25, 0x00)
    b.li32(3, 0x9A0A0000)
    b.stw(3, 25, 0x2C)
    b.emit("4803")
    b.stw(3, 25, 0x30)
    b.li32(4, 0xFFFFF3FE)
    b.word(_ppc_and(3, 24, 4))
    b.stw(3, 25, 0x00)

    b.li32(3, 0x9100)
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.li32(3, 0x6800)
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.li32(3, 0x6400)
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.word(_e_rlwinm(26, 3, 0, 26, 31))
    b.li32(3, 0x6100)
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.word(_e_rlwinm(27, 3, 0, 24, 31))
    b.li32(3, 0x5D00)
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.word(_e_rlwinm(28, 3, 0, 24, 31))
    b.li32(3, 0x0400)
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.word(_e_rlwinm(29, 3, 0, 24, 31))

    b.li32(3, 0x91FF)
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.word(_ppc_or(3, 26, 26))
    b.or2i(3, 0x6A00)
    b.ebranch("bl", "sbc_odd_parity")
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.word(_ppc_or(3, 27, 27))
    b.or2i(3, 0x6600)
    b.ebranch("bl", "sbc_odd_parity")
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.word(_ppc_or(3, 28, 28))
    b.or2i(3, 0x6200)
    b.ebranch("bl", "sbc_odd_parity")
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.word(_ppc_or(3, 29, 29))
    b.or2i(3, 0x5E00)
    b.ebranch("bl", "sbc_odd_parity")
    b.li32(4, 0x00010000)
    b.ebranch("bl", "dspi2_xfer16")
    b.li32(3, 0x04FF)
    b.li32(4, 0x08010000)
    b.ebranch("bl", "dspi2_xfer16")

    b.word(_ppc_or(3, 24, 24))
    b.or2i(3, 0x0C01)
    b.stw(3, 25, 0x00)
    b.li32(3, 0x9A0A0000)
    b.stw(3, 25, 0x2C)
    b.stw(30, 25, 0x30)
    b.stw(24, 25, 0x00)

    b.label("sbc_wd_stamp_tb")
    b.word(_ppc_mfspr(4, 0x10D))
    b.word(_ppc_mfspr(5, 0x10C))
    b.word(_ppc_mfspr(6, 0x10D))
    b.word(_ppc_cmplw(4, 6))
    b.branch("bne", "sbc_wd_stamp_tb")
    b.li32(3, sbc_last_tb_addr)
    b.stw(4, 3, 0x00)
    b.stw(5, 3, 0x04)

    b.li32(3, MRR_DRIVER_CONTROL + 0x60)
    b.lwz(4, 3, 0x00)
    b.emit("2004")
    b.stw(4, 3, 0x00)
    b.word(_ppc_or(5, 26, 26))
    b.emit("6c85")
    b.word(_ppc_or(5, 5, 27))
    b.emit("6c85")
    b.word(_ppc_or(5, 5, 28))
    b.emit("6c85")
    b.word(_ppc_or(5, 5, 29))
    b.stw(5, 3, 0x04)

    b.emit("1b010820")

    b.label("sbc_wd_fast_ret")
    b.lwz(3, 1, 0x0C)
    b.lwz(4, 1, 0x10)
    b.lwz(5, 1, 0x14)
    b.lwz(6, 1, 0x18)
    b.lwz(7, 1, 0x1C)
    b.lwz(0, 1, 0x08)
    b.emit("7c0ff120")
    b.emit("50010044")
    b.emit("0090")
    b.emit("18218040")
    b.emit("0004")

    b.label("sbc_odd_parity")
    b.emit("00e3")
    b.emit("0134")
    b.emit("6884")
    b.word(_ppc_xor(4, 3, 4))
    b.emit("0145")
    b.emit("6845")
    b.word(_ppc_xor(4, 4, 5))
    b.emit("0145")
    b.emit("6825")
    b.word(_ppc_xor(4, 4, 5))
    b.emit("0145")
    b.emit("6815")
    b.word(_ppc_xor(4, 4, 5))
    b.emit("67f4")
    b.branch("bne", "sbc_parity_done")
    b.emit("6573")
    b.label("sbc_parity_done")
    b.emit("0004")

    b.label("dspi2_xfer16")
    b.emit("00e3")
    b.word(_ppc_or(3, 3, 4))
    b.li32(4, 0x9A0A0000)
    b.stw(4, 25, 0x2C)
    b.stw(3, 25, 0x34)
    b.li32(5, dspi2_poll_loops)
    b.label("dspi2_wait_rfdf")
    b.lwz(4, 25, 0x2C)
    b.emit("66e4")
    b.branch("bne", "dspi2_got_rx")
    b.emit("2405")
    b.emit("2a05")
    b.branch("bne", "dspi2_wait_rfdf")
    b.label("dspi2_got_rx")
    b.lwz(3, 25, 0x38)
    b.emit("00e3")
    b.emit("62e4")
    b.stw(4, 25, 0x2C)
    b.emit("0004")

    b.label("sbc_wd_exit_wait")
    b.li32(3, MRR_DRIVER_CONTROL + 0x60)
    b.lwz(4, 3, 0x00)
    b.emit("2a04")
    b.branch("beq", "sbc_exit_done")
    b.li32(3, sbc_last_tb_addr)
    b.label("sbc_exit_loop")
    b.word(_ppc_mfspr(4, 0x10D))
    b.word(_ppc_mfspr(5, 0x10C))
    b.word(_ppc_mfspr(6, 0x10D))
    b.word(_ppc_cmplw(4, 6))
    b.branch("bne", "sbc_exit_loop")
    b.lwz(6, 3, 0x00)
    b.lwz(7, 3, 0x04)
    b.word(_ppc_subfc(7, 7, 5))
    b.word(_ppc_subfe(6, 6, 4))
    b.emit("2a06")
    b.branch("bne", "sbc_exit_done")
    b.li32(6, sbc_exit_safe_ticks)
    b.word(_ppc_cmplw(7, 6))
    b.branch("blt", "sbc_exit_loop")
    b.label("sbc_exit_done")
    b.emit("0004")


def _emit_dto_return_epilogue(b: _VleBuilder, dto_buffer_addr: int = 0x4003A26C) -> None:
    dto_off = dto_buffer_addr - MRR_DRIVER_CONTROL
    if 0 <= dto_off <= 0x7FE0:
        b.emit("70800200")
        b.word((0x5C << 24) | (4 << 21) | (31 << 16) | (dto_off & 0xFFFF))
        b.emit("708000ff")
        b.word((0x34 << 24) | (4 << 21) | (31 << 16) | ((dto_off + 4) & 0xFFFF))
        b.word((0x34 << 24) | (3 << 21) | (31 << 16) | ((dto_off + 5) & 0xFFFF))
    else:
        b.li32(5, dto_buffer_addr)
        b.emit("70800200")
        b.word((0x5C << 24) | (4 << 21) | (5 << 16) | 0x0000)
        b.emit("708000ff")
        b.word((0x34 << 24) | (4 << 21) | (5 << 16) | 0x0004)
        b.word((0x34 << 24) | (3 << 21) | (5 << 16) | 0x0005)


def mrr_build_fast_read_ram_driver(
    *,
    dto_buffer_addr: int = 0x4003A26C,
) -> bytes:
    """Build return-safe PowerPC VLE CAN burst reader (0x77E, 64 frames / call)."""
    b = _VleBuilder()
    b.emit("182106d0")
    b.emit("0080")
    b.emit("1b010910")
    b.emit("dd01")
    b.emit("73e8e004")
    b.emit("1fff9800")
    b.emit("c06f")
    b.emit("c17f")
    b.emit("017d")
    b.emit("2a07")
    b.branch("beq", "invalid_length")
    b.word(0x18000000 | (29 << 16) | 0xA800 | MRR_FAST_CAN_MAX_FRAMES)
    b.branch("bgt", "invalid_length")

    b.emit("709fe7fc")
    b.lwz(24, 4, 0x270)
    b.stw(24, 31, 0x08)
    b.lwz(25, 4, 0x274)
    b.stw(25, 31, 0x0C)
    b.lwz(26, 4, 0x28)
    b.stw(26, 31, 0x10)
    b.lwz(27, 31, 0x2C)
    b.word((31 << 26) | (26 << 21) | (0 << 16) | (27 << 11) | (60 << 1))
    b.stw(0, 4, 0x28)
    b.lwz(28, 31, 0x20)
    b.stw(28, 4, 0x274)
    b.lwz(29, 31, 0x24)
    b.stw(29, 4, 0x270)
    b.lwz(30, 31, 0x28)
    b.emit("4803")
    b.stw(3, 31, 0x14)

    b.label("loop")
    b.stw(27, 4, 0x30)
    b.emit("c006")
    b.stw(0, 4, 0x278)
    b.emit("c106")
    b.stw(0, 4, 0x27C)
    b.emit("2076")
    b.stw(30, 4, 0x270)
    b.lwz(3, 31, 0x30)

    b.label("wait_tx")
    b.emit("cc04")
    b.emit("6600")
    b.branch("bne", "tx_done")
    b.emit("2403")
    b.emit("2a03")
    b.branch("bne", "wait_tx")
    b.branch("b", "tx_timeout")

    b.label("tx_done")
    b.stw(27, 4, 0x30)
    b.emit("2407")
    b.emit("2a07")
    b.branch("bne", "loop")
    b.emit("d06f")
    b.branch("b", "restore")

    b.label("tx_timeout")
    b.emit("4823")
    b.stw(3, 31, 0x14)

    b.label("restore")
    b.stw(25, 4, 0x274)
    b.stw(24, 4, 0x270)
    b.stw(27, 4, 0x30)
    b.stw(26, 4, 0x28)
    b.branch("b", "return")

    b.label("invalid_length")
    b.emit("4813")
    b.stw(3, 31, 0x14)

    b.label("return")
    b.lwz(3, 31, 0x14)
    _emit_dto_return_epilogue(b, dto_buffer_addr)
    b.emit("cd01")
    b.emit("1b010810")
    b.emit("0090")
    b.emit("18218030")
    b.emit("0004")
    return b.finish()


def mrr_build_fast_read_control_block(
    source: int,
    length: int,
    timeout_loops: int = MRR_FAST_CAN_TIMEOUT_LOOPS,
) -> bytes:
    if source & 3:
        raise ValueError("Fast read source address must be 4-byte aligned")
    if not 1 <= length <= MRR_FAST_CAN_MAX_FRAMES * 8:
        raise ValueError(f"Fast read chunk length must be 1..{MRR_FAST_CAN_MAX_FRAMES * 8}")
    values = (
        source,
        (length + 7) // 8,
        0,
        0,
        0,
        0,
        0,
        0,
        0x1DF80000,
        0x08080000,
        0x0C080000,
        0x80000000,
        timeout_loops,
    )
    return b"".join(v.to_bytes(4, "big") for v in values)


def mrr_build_tlb1_0b_descriptor(
    executable: bool = True,
    mmu_load_single_entry: int = 0x0009AF58,
    *,
    tlb1_entry: int = 0x0B,
    mmu_dispatch_mode: str = "direct",
) -> bytes:
    """Build MMU TLB1 descriptor block at 0x40039808 for Gen 1 (TLB1[0x0B]) or Gen 2 (TLB1[0x14])."""
    perms = 0x00000037 if executable else 0x00000007
    if tlb1_entry == 0x0B and mmu_dispatch_mode == "indirect_r29":
        # SW 0130 wrapper (0x0010DE7C): r7=*(r3+0), r31=*(r7+0), r29=*(r31+0x10)=MAS2.EPN, CTR=*(r29+0x14)
        blob = bytearray(0x34)
        blob[0x00:0x04] = (MRR_DRIVER_CONTROL + 0x0C).to_bytes(4, "big")
        blob[0x04:0x08] = (MRR_DRIVER_CONTROL + 0x18).to_bytes(4, "big")
        blob[0x08:0x0C] = (0).to_bytes(4, "big")
        blob[0x0C:0x10] = mmu_load_single_entry.to_bytes(4, "big")
        blob[0x10:0x14] = bytes([0x01, 0x0B, 0x00, 0x07])
        blob[0x14:0x18] = bytes([0x30, 0x00, 0x00, 0x00])
        blob[0x18:0x1C] = perms.to_bytes(4, "big")
        blob[0x1C:0x20] = (0x40020000).to_bytes(4, "big")
        blob[0x20:0x24] = MRR_DRIVER_CONTROL.to_bytes(4, "big")
        return bytes(blob)
    if tlb1_entry == 0x0B:
        blob = bytearray(0x34)
        blob[0x00:0x04] = (MRR_DRIVER_CONTROL + 0x0C).to_bytes(4, "big")
        blob[0x08:0x0C] = (MRR_DRIVER_CONTROL + 0x14).to_bytes(4, "big")
        blob[0x0C:0x10] = bytes([0x01, 0x0B, 0x00, 0x07])
        blob[0x10:0x14] = bytes([0x30, 0x00, 0x00, 0x00])
        blob[0x14:0x18] = perms.to_bytes(4, "big")
        blob[0x18:0x1C] = (0x40020000).to_bytes(4, "big")
        blob[0x1C:0x20] = (0x40020000).to_bytes(4, "big")
        blob[0x30:0x34] = mmu_load_single_entry.to_bytes(4, "big")
        return bytes(blob)
    blob = bytearray(0x68)
    blob[0x00:0x04] = b"\xFF\x00\x00\x00"
    blob[0x04:0x08] = (0x40000000).to_bytes(4, "big")
    blob[0x0C:0x10] = bytes([0x01, tlb1_entry & 0xFF, 0x00, 0x06])
    blob[0x10:0x14] = bytes([0x30, 0x00, 0x00, 0x00])
    blob[0x14:0x18] = perms.to_bytes(4, "big")
    blob[0x18:0x1C] = (0x40020000).to_bytes(4, "big")
    blob[0x1C:0x20] = (0x40020000).to_bytes(4, "big")
    blob[0x64:0x68] = mmu_load_single_entry.to_bytes(4, "big")
    return bytes(blob)


def mrr_build_fast_write_ram_driver(
    *,
    sbc_last_tb_addr: int = 0x40025E28,
    dto_buffer_addr: int = 0x4003A26C,
) -> bytes:
    """Build return-safe VLE driver that streams 8-frame (64 B) batches into SRAM."""
    b = _VleBuilder()
    b.emit("182106d0")
    b.emit("0080")
    b.emit("1b010910")
    b.emit("dd01")
    b.emit("7c000146")
    b.emit("73e8e004")
    b.emit("1fff9800")
    b.lwz(6, 31, 0x00)
    b.lwz(7, 31, 0x04)
    b.emit("2a07")
    b.ebranch("beq", "invalid_len")

    b.emit("709fe7fc")
    b.lwz(24, 4, 0x28)
    b.stw(24, 31, 0x10)
    b.lwz(25, 4, 0x274)
    b.stw(25, 31, 0x14)
    b.lwz(26, 4, 0x270)
    b.stw(26, 31, 0x18)
    b.lwz(27, 4, 0x264)
    b.stw(27, 31, 0x1C)
    b.lwz(28, 4, 0x260)
    b.stw(28, 31, 0x20)
    b.li32(5, 0xFFF3C000)
    b.lwz(0, 5, 0x00)
    b.stw(0, 31, 0x24)
    b.emit("61f0")
    b.stw(0, 5, 0x00)
    b.emit("4800")
    b.stw(0, 31, 0x60)
    b.stw(0, 31, 0x64)

    b.li32(29, 0x3FFFFFFF)
    b.word((31 << 26) | (24 << 21) | (0 << 16) | (29 << 11) | (28 << 1))
    b.stw(0, 4, 0x28)

    b.li32(0, 0x00200000)
    b.stw(0, 4, 0x260)
    b.li32(0, MRR_XCP_TX_ID)
    b.stw(0, 4, 0x264)
    b.li32(28, 0x04200000)
    b.stw(28, 4, 0x260)
    b.lwz(0, 4, 0x08)

    b.li32(0, 0x08000000)
    b.stw(0, 4, 0x270)
    b.li32(0, 0x1DF80000)
    b.stw(0, 4, 0x274)
    b.li32(29, 0x80000000)
    b.li32(30, 0x40000000)
    b.stw(29, 4, 0x30)
    b.stw(30, 4, 0x30)
    b.li32(27, 0x0C080000)

    b.label("batch_loop")
    b.stw(6, 1, 0x04)
    b.stw(7, 1, 0x0C)
    b.emit("4900")
    b.stw(0, 1, 0x08)

    b.label("batch_retry")
    b.ebranch("bl", "sbc_wd_poll")
    b.stw(29, 4, 0x30)
    b.stw(6, 4, 0x278)
    b.stw(7, 4, 0x27C)
    b.stw(27, 4, 0x270)
    b.lwz(3, 31, 0x0C)
    b.label("wait_tx")
    b.lwz(0, 4, 0x30)
    b.emit("6600")
    b.branch("bne", "tx_done")
    b.emit("2403")
    b.emit("0130")
    b.emit("00e0")
    b.emit("2a00")
    b.branch("bne", "wait_tx_no_wd")
    b.ebranch("bl", "sbc_wd_poll")
    b.label("wait_tx_no_wd")
    b.emit("2a03")
    b.branch("bne", "wait_tx")
    b.emit("4823")
    b.ebranch("b", "set_status")

    b.label("tx_done")
    b.stw(29, 4, 0x30)
    b.emit("4885")

    b.label("rx_frame_loop")
    b.li32(3, 0x00080000)
    b.label("wait_rx")
    b.lwz(0, 4, 0x30)
    b.emit("6610")
    b.branch("bne", "rx_got")
    b.emit("2403")
    b.emit("0130")
    b.emit("00e0")
    b.emit("2a00")
    b.branch("bne", "wait_rx_no_wd")
    b.ebranch("bl", "sbc_wd_poll")
    b.label("wait_rx_no_wd")
    b.emit("2a03")
    b.branch("bne", "wait_rx")
    b.lwz(0, 1, 0x08)
    b.emit("2400")
    b.stw(0, 1, 0x08)
    b.emit("2a00")
    b.branch("beq", "rx_timeout_fail")
    b.lwz(6, 1, 0x04)
    b.lwz(7, 1, 0x0C)
    b.ebranch("b", "batch_retry")

    b.label("rx_timeout_fail")
    b.emit("4833")
    b.ebranch("b", "set_status")

    b.label("rx_got")
    b.lwz(0, 4, 0x260)
    b.lwz(0, 4, 0x268)
    b.stw(0, 6, 0x00)
    b.lwz(0, 4, 0x26C)
    b.stw(0, 6, 0x04)
    b.emit("7c0030ac")
    b.stw(28, 4, 0x260)
    b.lwz(0, 4, 0x08)
    b.stw(30, 4, 0x30)
    b.emit("2076")
    b.emit("2407")
    b.emit("2a07")
    b.branch("beq", "all_done")
    b.emit("2405")
    b.emit("2a05")
    b.branch("bne", "rx_frame_loop")
    b.ebranch("b", "batch_loop")

    b.label("all_done")
    b.stw(6, 31, 0x00)
    b.emit("4803")
    b.branch("b", "set_status")

    b.label("invalid_len")
    b.emit("4813")
    b.stw(3, 31, 0x08)
    b.branch("b", "return")

    b.label("set_status")
    b.stw(3, 31, 0x08)
    b.emit("7c0004ac")
    b.emit("0001")
    b.emit("7c73faa6")
    b.emit("7060c002")
    b.emit("7c73fba6")
    b.label("fast_wr_wait_icinv")
    b.emit("7c73faa6")
    b.emit("2e23")
    b.emit("2a23")
    b.branch("beq", "fast_wr_wait_icinv")
    b.emit("0001")
    b.lwz(0, 31, 0x14)
    b.stw(0, 4, 0x274)
    b.lwz(0, 31, 0x18)
    b.stw(0, 4, 0x270)
    b.lwz(0, 31, 0x1C)
    b.stw(0, 4, 0x264)
    b.lwz(0, 31, 0x20)
    b.stw(0, 4, 0x260)
    b.lwz(0, 4, 0x08)
    b.stw(29, 4, 0x30)
    b.stw(30, 4, 0x30)
    b.lwz(0, 31, 0x10)
    b.stw(0, 4, 0x28)
    b.ebranch("bl", "sbc_wd_exit_wait")
    b.li32(5, 0xFFF3C000)
    b.lwz(0, 31, 0x24)
    b.stw(0, 5, 0x00)

    b.label("return")
    b.emit("7c008146")
    b.lwz(3, 31, 0x08)
    _emit_dto_return_epilogue(b, dto_buffer_addr)
    b.emit("cd01")
    b.emit("1b010810")
    b.emit("0090")
    b.emit("18218030")
    b.emit("0004")
    _emit_sbc_wd_helpers(b, sbc_last_tb_addr=sbc_last_tb_addr)
    return b.finish()


def mrr_build_flash_sector_write_driver(
    *,
    mcu: str = "MPC5674K",
    sbc_last_tb_addr: int = 0x40025E28,
    dto_buffer_addr: int = 0x4003A26C,
) -> bytes:
    """Build return-safe VLE driver that erases and streams a C90FL Code Flash sector."""
    is_5674k = mcu == "MPC5674K"
    if is_5674k:
        flash_init = 0x4005CD10
        flash_unlock_all = 0x4005CD8E
        flash_lock_all = 0x4005CE24
        flash_sector_map = 0x4005CEBA
        flash_clear_err = 0x4005CCA8
        ssd_config = 0x4005F560
        ssd_flash_erase = 0x4005C4DC
        ssd_blank_check = 0x4005F364
        ssd_flash_program = 0x4005D70C
        ssd_program_verify = 0x4005CA94
    else:
        flash_init = 0x4007CD10
        flash_unlock_all = 0x4007CD8E
        flash_lock_all = 0x4007CE24
        flash_sector_map = 0x4007CEBA
        flash_clear_err = 0x4007CCA8
        ssd_config = 0x4007F588
        ssd_flash_erase = 0x4007C4DC
        ssd_blank_check = 0x4007F38C
        ssd_flash_program = 0x4007D734
        ssd_program_verify = 0x4007CA94
    flash_sector_wd_callback = MRR_FLASH_SECTOR_DRIVER_ADDR + 4

    b = _VleBuilder()
    b.ebranch("b", "main_entry")
    _emit_sbc_wd_helpers(b, sbc_last_tb_addr=sbc_last_tb_addr)

    b.label("main_entry")
    b.emit("182106b0")
    b.emit("0080")
    b.emit("1b010928")
    b.emit("54010054")
    b.emit("7c000146")

    b.emit("73e8e004")
    b.emit("1fff9800")
    b.li32(30, 0xFFFC0000)

    b.lwz(3, 30, 0x28)
    b.stw(3, 31, 0x3C)
    b.lwz(4, 30, 0x274)
    b.stw(4, 31, 0x40)
    b.lwz(4, 30, 0x270)
    b.stw(4, 31, 0x44)
    b.lwz(4, 30, 0x264)
    b.stw(4, 31, 0x48)
    b.lwz(4, 30, 0x260)
    b.stw(4, 31, 0x4C)
    b.li32(5, 0xC3F88000)
    b.lwz(4, 5, 0x1C)
    b.stw(4, 31, 0x54)
    b.li32(5, 0xC3FB0000)
    b.lwz(4, 5, 0x1C)
    b.stw(4, 31, 0x58)
    b.li32(5, 0xFFF3C000)
    b.lwz(4, 5, 0x00)
    b.stw(4, 31, 0x5C)
    b.emit("61f4")
    b.stw(4, 5, 0x00)
    b.emit("4800")
    b.stw(0, 31, 0x60)
    b.stw(0, 31, 0x64)

    b.li32(4, 0x3FFFFFFF)
    b.word((31 << 26) | (3 << 21) | (0 << 16) | (4 << 11) | (28 << 1))
    b.stw(0, 30, 0x28)

    b.li32(0, 0x00200000)
    b.stw(0, 30, 0x260)
    b.li32(0, MRR_XCP_TX_ID)
    b.stw(0, 30, 0x264)
    b.li32(0, 0x04200000)
    b.stw(0, 30, 0x260)
    b.lwz(0, 30, 0x08)

    b.li32(0, 0x08000000)
    b.stw(0, 30, 0x270)
    b.li32(0, 0x1DF80000)
    b.stw(0, 30, 0x274)
    b.li32(0, 0xC0000000)
    b.stw(0, 30, 0x30)
    b.emit("4810")
    b.stw(0, 31, 0x50)
    b.ebranch("bl", "sbc_wd_poll")

    b.emit("7068e000")
    b.emit("7080e006" if is_5674k else "7080e008")
    b.emit("70a0e000")
    b.label("flush_sram_dcache")
    b.emit("7c0328ac")
    b.emit("21f5")
    b.emit("0d45")
    b.branch("blt", "flush_sram_dcache")
    b.emit("0001")
    b.emit("7c0004ac")

    b.emit("4803")
    b.emit("7c72fba6")
    b.emit("0001")
    b.emit("7c73fba6")
    b.emit("4823")
    b.emit("7c73fba6")
    b.label("wait_entry_icinv")
    b.emit("7c73faa6")
    b.emit("2e23")
    b.emit("2a23")
    b.branch("beq", "wait_entry_icinv")
    b.emit("0001")

    esel_lo = "7062e012" if is_5674k else "7062e019"
    esel_hi = "7062e013" if is_5674k else "7062e01a"
    lis_r5_hi = "70a8e005" if is_5674k else "70a8e007"
    lis_r6_hi = "70c8e005" if is_5674k else "70c8e007"

    b.emit(esel_lo)
    b.emit("7c709ba6")
    b.emit("7098e000")
    b.emit("7080c180")
    b.emit("7c919ba6")
    b.emit(lis_r5_hi)
    b.emit("70b8c030")
    b.emit("7cb29ba6")
    b.emit(lis_r6_hi)
    b.emit("70d8c037")
    b.emit("7cd39ba6")
    b.emit("7c0007a4")
    b.emit(esel_hi)
    b.emit("7c709ba6")
    b.emit(lis_r5_hi)
    b.emit("70bcc030")
    b.emit("7cb29ba6")
    b.emit(lis_r6_hi)
    b.emit("70d4c037")
    b.emit("7cd39ba6")
    b.emit("7c0007a4")
    b.li32(3, 0x10000000)
    b.emit("7c709ba6")
    b.li32(4, 0xC0000580)
    b.emit("7c919ba6")
    b.li32(5, 0x00000030)
    b.emit("7cb29ba6")
    b.li32(6, 0x00000017)
    b.emit("7cd39ba6")
    b.emit("7c0007a4")
    b.emit("7c0004ac")
    b.emit("0001")

    b.emit("6367")
    b.stw(7, 31, 0x00)
    b.emit("70e000a5")
    b.stw(7, 31, 0x04)
    b.emit("4807")
    b.stw(7, 31, 0x14)
    b.stw(7, 31, 0x20)
    b.stw(7, 31, 0x24)
    b.li32(4, flash_init)
    b.emit("01f3")
    b.emit("00b4")
    b.emit("0007")
    b.lwz(7, 31, 0x04)
    b.emit("2a07")
    b.branch("beq", "init_ok")
    b.emit("4903")
    b.ebranch("b", "fail_no_lock")

    b.label("init_ok")
    b.emit("4820")
    b.stw(0, 31, 0x50)
    b.ebranch("bl", "sbc_wd_poll")
    b.lwz(28, 31, 0x28)
    b.lwz(29, 31, 0x2C)

    b.li32(4, flash_unlock_all)
    b.emit("00b4")
    b.emit("0007")
    b.emit("00e3")
    b.emit("2a03")
    b.branch("beq", "unlock_ok")
    b.emit("0137")
    b.emit("4913")
    b.ebranch("b", "fail_with_detail")

    b.label("unlock_ok")
    b.emit("4830")
    b.stw(0, 31, 0x50)
    b.word(_ppc_or(3, 28, 28))
    b.word(_ppc_or(4, 29, 29))
    b.word(_e_addi8(5, 1, 0x08))
    b.word(_e_addi8(6, 1, 0x0C))
    b.word(_e_addi8(7, 1, 0x10))
    b.li32(24, flash_sector_map)
    b.word(_ppc_or(0, 24, 24))
    b.emit("00b0")
    b.emit("0007")
    b.emit("00e3")
    b.emit("2a03")
    b.branch("beq", "map_ok")
    b.emit("0137")
    b.emit("4923")
    b.ebranch("b", "fail_with_detail")

    b.label("map_ok")
    b.emit("4840")
    b.stw(0, 31, 0x50)
    b.li32(4, flash_clear_err)
    b.emit("00b4")
    b.emit("0007")
    b.li32(3, ssd_config)
    b.emit("4804")
    b.lwz(5, 1, 0x08)
    b.lwz(6, 1, 0x0C)
    b.lwz(7, 1, 0x10)
    b.li32(24, flash_sector_wd_callback)
    b.word(_ppc_or(8, 24, 24))
    b.li32(25, ssd_flash_erase)
    b.word(_ppc_or(0, 25, 25))
    b.emit("00b0")
    b.emit("0007")
    b.emit("2a03")
    b.branch("beq", "erase_ok")
    b.emit("0137")
    b.emit("70600020")
    b.ebranch("b", "fail_with_detail")

    b.label("erase_ok")
    b.emit("4850")
    b.stw(0, 31, 0x50)
    b.ebranch("bl", "sbc_wd_poll")
    b.li32(4, flash_clear_err)
    b.emit("00b4")
    b.emit("0007")
    b.li32(3, ssd_config)
    b.word(_ppc_or(4, 28, 28))
    b.word(_ppc_or(5, 29, 29))
    b.word(_e_addi8(6, 1, 0x08))
    b.word(_e_addi8(7, 1, 0x10))
    b.word(_ppc_or(8, 24, 24))
    b.li32(25, ssd_blank_check)
    b.word(_ppc_or(0, 25, 25))
    b.emit("00b0")
    b.emit("0007")
    b.emit("2a03")
    b.branch("beq", "blank_ok")
    b.emit("0137")
    b.emit("70600021")
    b.ebranch("b", "fail_with_detail")

    b.label("blank_ok")
    b.emit("4860")
    b.stw(0, 31, 0x50)

    b.label("batch_loop")
    b.emit("4870")
    b.stw(0, 31, 0x50)
    b.emit("4900")
    b.stw(0, 1, 0x20)

    b.label("batch_retry")
    b.ebranch("bl", "sbc_wd_poll")
    b.li32(4, 0x80000000)
    b.stw(4, 30, 0x30)
    b.stw(28, 30, 0x278)
    b.stw(29, 30, 0x27C)
    b.li32(5, 0x0C080000)
    b.stw(5, 30, 0x270)
    b.lwz(3, 31, 0x38)
    b.label("wait_tx")
    b.lwz(0, 30, 0x30)
    b.emit("6600")
    b.branch("bne", "tx_done")
    b.emit("2403")
    b.emit("0130")
    b.emit("00e0")
    b.emit("2a00")
    b.branch("bne", "wait_tx_no_wd")
    b.ebranch("bl", "sbc_wd_poll")
    b.label("wait_tx_no_wd")
    b.emit("2a03")
    b.branch("bne", "wait_tx")
    b.emit("70600040")
    b.emit("01c7")
    b.ebranch("b", "fail_with_detail")

    b.label("tx_done")
    b.stw(4, 30, 0x30)
    b.li32(6, MRR_FLASH_STAGE_BUFFER)
    b.emit("4885")
    b.li32(4, 0x40000000)
    b.li32(7, 0x04200000)

    b.label("rx_frame_loop")
    b.li32(3, 0x00080000)
    b.label("wait_rx")
    b.lwz(0, 30, 0x30)
    b.emit("6610")
    b.branch("bne", "rx_got")
    b.emit("2403")
    b.emit("0130")
    b.emit("00e0")
    b.emit("2a00")
    b.branch("bne", "wait_rx_no_wd")
    b.ebranch("bl", "sbc_wd_poll")
    b.label("wait_rx_no_wd")
    b.emit("2a03")
    b.branch("bne", "wait_rx")
    b.lwz(0, 1, 0x20)
    b.emit("2400")
    b.stw(0, 1, 0x20)
    b.emit("2a00")
    b.ebranch("bne", "batch_retry")
    b.emit("70600050")
    b.emit("01c7")
    b.ebranch("b", "fail_with_detail")

    b.label("rx_got")
    b.lwz(0, 30, 0x260)
    b.lwz(0, 30, 0x268)
    b.stw(0, 6, 0x00)
    b.lwz(0, 30, 0x26C)
    b.stw(0, 6, 0x04)
    b.stw(7, 30, 0x260)
    b.lwz(0, 30, 0x08)
    b.stw(4, 30, 0x30)
    b.emit("2076")
    b.emit("2405")
    b.emit("2a05")
    b.branch("bne", "rx_frame_loop")

    b.li32(4, flash_clear_err)
    b.emit("00b4")
    b.emit("0007")
    b.li32(3, ssd_config)
    b.word(_ppc_or(4, 28, 28))
    b.emit("70a00040")
    b.li32(6, MRR_FLASH_STAGE_BUFFER)
    b.word(_ppc_or(7, 24, 24))
    b.li32(25, ssd_flash_program)
    b.word(_ppc_or(0, 25, 25))
    b.emit("00b0")
    b.emit("0007")
    b.emit("2a03")
    b.branch("beq", "prog_ok")
    b.emit("0137")
    b.emit("70600030")
    b.ebranch("b", "fail_with_detail")

    b.label("prog_ok")
    b.li32(4, flash_clear_err)
    b.emit("00b4")
    b.emit("0007")
    b.li32(3, ssd_config)
    b.word(_ppc_or(4, 28, 28))
    b.emit("70a00040")
    b.li32(6, MRR_FLASH_STAGE_BUFFER)
    b.word(_e_addi8(7, 1, 0x08))
    b.word(_e_addi8(8, 1, 0x10))
    b.word(_e_addi8(9, 1, 0x18))
    b.word(_ppc_or(10, 24, 24))
    b.li32(25, ssd_program_verify)
    b.word(_ppc_or(0, 25, 25))
    b.emit("00b0")
    b.emit("0007")
    b.emit("2a03")
    b.branch("beq", "write_ok")
    b.emit("0137")
    b.emit("70600031")
    b.ebranch("b", "fail_with_detail")

    b.label("write_ok")
    b.emit("1f9c0040")
    b.emit("1fbdffc0")
    b.emit("01d0")
    b.emit("2a00")
    b.ebranch("bne", "batch_loop")

    b.emit("4880")
    b.stw(0, 31, 0x50)
    b.emit("4803")
    b.emit("4807")

    b.label("fail_with_detail")
    b.emit("013c")
    b.emit("017d")
    b.li32(4, flash_lock_all)
    b.emit("00b4")
    b.emit("0007")
    b.branch("b", "restore_hw")

    b.label("fail_no_lock")
    b.emit("013c")
    b.emit("017d")

    b.label("restore_hw")
    b.lwz(0, 31, 0x40)
    b.stw(0, 30, 0x274)
    b.lwz(0, 31, 0x44)
    b.stw(0, 30, 0x270)
    b.lwz(0, 31, 0x48)
    b.stw(0, 30, 0x264)
    b.lwz(0, 31, 0x4C)
    b.stw(0, 30, 0x260)
    b.lwz(0, 30, 0x08)
    b.li32(0, 0xC0000000)
    b.stw(0, 30, 0x30)
    b.lwz(0, 31, 0x3C)
    b.stw(0, 30, 0x28)
    b.li32(5, 0xC3F88000)
    b.lwz(4, 31, 0x54)
    b.stw(4, 5, 0x1C)
    b.li32(5, 0xC3FB0000)
    b.lwz(4, 31, 0x58)
    b.stw(4, 5, 0x1C)

    b.emit(esel_lo)
    b.emit("7c709ba6")
    b.emit("7098e000")
    b.emit("7080c180")
    b.emit("7c919ba6")
    b.emit(lis_r5_hi)
    b.emit("70b8c030")
    b.emit("7cb29ba6")
    b.emit(lis_r6_hi)
    b.emit("70d8c007")
    b.emit("7cd39ba6")
    b.emit("7c0007a4")
    b.emit(esel_hi)
    b.emit("7c709ba6")
    b.emit(lis_r5_hi)
    b.emit("70bcc020")
    b.emit("7cb29ba6")
    b.emit(lis_r6_hi)
    b.emit("70dcc00f")
    b.emit("7cd39ba6")
    b.emit("7c0007a4")
    b.li32(3, 0x10000000)
    b.emit("7c709ba6")
    b.li32(4, 0xC0000580)
    b.emit("7c919ba6")
    b.li32(5, 0x00000030)
    b.emit("7cb29ba6")
    b.li32(6, 0x00000013)
    b.emit("7cd39ba6")
    b.emit("7c0007a4")
    b.emit("0001")

    b.emit("4803")
    b.emit("7c72fba6")
    b.emit("4823")
    b.emit("7c72fba6")
    b.label("wait_dcinv")
    b.emit("7c72faa6")
    b.emit("2e23")
    b.emit("2a23")
    b.branch("beq", "wait_dcinv")
    b.emit("62b4")
    b.emit("65f4")
    b.emit("7c92fba6")
    b.emit("4803")
    b.emit("7c73fba6")
    b.emit("4823")
    b.emit("7c73fba6")
    b.label("wait_icinv")
    b.emit("7c73faa6")
    b.emit("2e23")
    b.emit("2a23")
    b.branch("beq", "wait_icinv")
    b.emit("4813")
    b.emit("7c73fba6")
    b.emit("0001")

    b.ebranch("bl", "sbc_wd_exit_wait")
    b.li32(5, 0xFFF3C000)
    b.lwz(4, 31, 0x5C)
    b.stw(4, 5, 0x00)

    b.stw(28, 31, 0x30)
    b.stw(29, 31, 0x34)
    b.emit("7c008146")

    b.emit("01c3")
    _emit_dto_return_epilogue(b, dto_buffer_addr)
    b.emit("50010054")
    b.emit("1b010828")
    b.emit("0090")
    b.emit("18218050")
    b.emit("0004")
    return b.finish()


MRR_FAST_READ_RAM_DRIVER = mrr_build_fast_read_ram_driver()
MRR_FAST_WRITE_RAM_DRIVER = mrr_build_fast_write_ram_driver()
MRR_FLASH_SECTOR_WRITE_DRIVER = mrr_build_flash_sector_write_driver()

MRR_ERASEROUTI_0192_B85 = (
    'c-rk-3v^V~x!!x`WFBEMGsI~)Nrq%%vsg6E(ufd(3NvY@c(@HP3>c!KlEze9^(JKE%<xENhT2=WdNH'
    'WC#)=57*J5w$r6_7u;7leVK@=xKUOeIuG#u};S11=u1)2NrefB((5XAPbKGtH^I%n_w?|=XM`~SW7z'
    'h7rCQYdXH?-}7)XG?kC2G50P(hvE&FrTN|k{!@G)*v)x2}b33j$jDs3(!!xs6T{*`fl8+@4+E`FRnK'
    'B;dXsL-m5>1JM>3zr~WA3r$2_xRmkW?=vQ{@KHRN;2lwdr<6iw<{DEFvkjbr8nl*j|k{0mXTCN)l2&'
    '9p?MwTd`es~VUGe+WVc5C~<z94tB`#|e~y<OaU9}Gw-_ypwK40Rpg*K9+pa*z?9;ZYbN1$pB$ivp;;'
    '@$u7^?1080P7Gqyj5x%8plbwlH41t$Bp&r_;lA0B^W>fa{ZNXi<58Cw)(Lt6bt?fQJiSWK7RAzr+!|'
    '{^?a;)Cy5Rbu36b=I+(?RKD0n=QCZ!6NZl$CZmcv^m*x;=c{M}FrFKo!2Yb{tfWMZY#XsL9Nqn8Y>N'
    'Q9Gg@YYCLcpD`Zym?6pZ~Va-&lcr}V115Y0C|=kWgUuW(hSE{b-5>pxl=zh_A2oS(9W25nrK!wtEjw'
    'e?!2ODMRVt}_S~LzTw6%m^DxG9@O*qb{*mW(m6iW|n`TuSO08b#Mfj+o6AaFaNXL7K74as@;gK!Mxb'
    'Z4In&R1_vKF90g<uxvcwSIhJwH)d@z3zDKt?yV!utuvtw<`Vgp${hlGhq($p!qq&=0EpXq1E}sRRcr'
    '#U)8d0SSH)dS82~$Q{CMxB)?1WJ6m#Fk}F$etRf2qA$n>t4=6*G@_N%!ndIf9*{WUdy+zUv=H&nZnx'
    'NMz7kZDg!^A;t&_3US8}xI5~yfC`qFNd?qWDpNto1tsd%&%(EHdro_^>RkW>=4y&nBwOzDl6Dg7{%&'
    'K$=!Sz{#Kimj5OdLguFeyknGjEt#dWMm!J6pkJl@$nJPuF{&JZ!C0)5#zl14Ss0DqCu{3gODcW)0AT'
    '{1@e^h(j;?(+&6gPeVSuqd`6mD9_Q20blo5)JT6=m(m1PVXg~-<$<(kf9_L&E1(H%l!*?TLgScmnC>'
    '70(*tdrbIFwzbF^dxsNBjEX@_1ig;qy7x<lX+yldI4pS^ud;%!m2$9K}L>2fiP#R8A0d^;-}s-inMQ'
    'tk{YyEHtx_hjB0f<G@X9rf3oeoX3D3L{pvcxO)^!-90r{NasU3AGk=5xMh_NWkH<u`6&>e191$YQOb'
    'mv24aO0sZRm&^CbhsR5X?fF^<MkAf_QPsGHPQ2_XmJvidC%BhZ%<Opv~}ej7!3KdBwk4+5Qsuns~qg'
    'bff{AoM~=^4GY}siW>5m9;ns8t?H%q1=O6J=-l!uf1C2tJq!wJQhZ;i_<eG-OT6>ae6VO^FXsu`{=1'
    'v%q(t(IM3q7X;7bRLzD&nyRs;NjGc=*s`jq%BIVO|Yt02d`V#RAsrU>~en9lD%V<{S^!SPXMMQr{6B'
    '|rtHYg!B0GbA9w=g@{h#j1}k*TR?n*-=}W)Fecqnz2p!R)cbeOA58y%X#KJ>dR-t^W`-+=}d3J3+(l'
    '-xT?7+g3vRgsizhHQx!Ee}mFv7AcR@XHYs1GA#VV%p$<Y;%12REN+|zHPX0jk)mXaD1HJK`IK2?I<b'
    'gi3BQW+PQfSKAHk^p5Aa4$1N~0mJeq7fMS<tvRaW;-^=c-43)q9$rf`3kG=U&)e0G}+=sLx#jq8;!B'
    'DHfDLhhX@56Jw{h@3{V-8;GGD<IDDf6I_-T#*z+WIA_(Ew>^Qjdvr9y9dp#fKcXF|2|%x<!AMTG0hL'
    'kWk{T1js6v|nv<}a8CLT+Sj`NpISH$oVco^BZX@)%Z$Ka2>HoXM3}HUQJJ#R(iNBY<qXv!i`PA2!YI'
    '*Sl{!H8>q-8JfG?8_OYl{*|*AkBnK3NwGHHiLPdrCpdpt3+clyT_p?j}hcQUa$j^vm3zqljpz2{$0_'
    '`LLl7g>{fRC8zMg>{1O+ymoAj^4*bZl&#u);;;MUHOewY?V%O7VPv{35AnB^BD3t3K|7<b_}4^RUG_'
    'KDYI1oSu?7cu8sEb^OuoAYO>yt72QL75jn6^rn31LNxjq|sVjgIk#!Wz*jC74Z2U;4^RM$%P`CdEWZ'
    '94ag*WIn&!z}nhwNJW}$ZLFVJCo5V%NRh$#!cIqj7}n>@(SxJBG{o9X&A4$@i~$3n)nMZF+MSdX)?h'
    'CcziJ*0^TczO#|4{@Il<BJlj^)zG4wZ{GvQ$hMB(<TQA!SEOgf2s>#3Pte>=I#Ip~T;yV?!*sIhkvj'
    'p9Iy<m_m;%sq3nsP|*@~hF(*AWuag0s6y!WwZx@aC>rVXbtHWwzz!LX?&|q)q#5P_1}D9u>I*$YC+G'
    ';rlIVhK~ktXym$s_6bJ??Gtt06T>x1(RH7Ch!b5k>aYvqlW2TW*af-g#p?T1m&$`V!+YXSj*#D6b#4'
    'i~9VZ~>SpsiTs>4<Fd9SOZy2{;KjX1lVtpAZeJE-ORF}4bmx?HZ#h$?qLw1}>TlZxwk^-GGuZ+`N7L'
    'Aj>>{EKT`=U@D!tM2}Y%3OVRd0ii1RE4VruB+^WvhTlmu)2EEAy;=<Pg!r-JXK$He;L}1)CI~xrJ(N'
    'e?ZeqY4Ud}18r^OO3Ls^*S7~+q*d;-|(X-2i2{MA<DYV=5)bXvZwZVz_j9?d1@LnoyD$w6J5pum4x)'
    'JD0@J`%A>1MPW()U7I<}=ZBLp)!HcGvX`?f}{&cxPQ(>$QYBq!6+_)g0{8U`3^q(S03Mh2x+C`Uq5U'
    'K87lupM<I~<ttE8?}Q)3t6c(Mxg-3xkh}Ozyk_xX?B}NEbKF3_K5foNQ_~iFG)2&dKMoItPkK6FeSC'
    '6@X-!A?I^UZ&nbL|sx+d7j-IuRUyY*vz>qFvM`?+vU=ppd}gb%hoB%X)x0l{F=d-kfV-z@$p;yJ-ti'
    'QnS${6!RnNNrOHt4ceb<5~wuHnkmfL7&K7edb;-%DZ7@^y0VC3D80*<VwY`v)$^~w9es!ejR_@Z~SB'
    'v%e!8h>e>dScAZ_mGWz8;=<U`;#M+^%wiUV2Q%~W80;f1dZFJ4b=!G-rt=0vhyFrQxr11D4%TvO5<m'
    'T;>6!ZS8>mt;AE0aE{tH}Wf!G49P8L->NV7JQHdv!AQcb@Vh%L+hJ%OvDTC9S^eJO%1OZAcDN+I-i|'
    '1fQ>*Hy{-xuwPgT*cX!i5xS?XHg|wv$0sSe49J}Y$QOq00o0nd+Dz;>X68}+gABhO@b3ov2f99k+J7'
    '3y?;DL@c1||(!U<<(i_sKG4valXehtUyNRy!XV`YsAni!*5;xt9PMq8YwjMMya8W&?pg2%=1CBfrj_'
    '>$aiN=%d{i5A0WOrpi`CEy`dtjYvDq#mKO{L_qpA%oP7pvf`gNNAMTG=`>N`>o|<zm<ix%h_IQ8NNk'
    'PerS>6Aw`pNf|74sy4Wjd1%r?(eww=*-QrvZb8|hN%f8?nXsFAMcImu`E3UV~+Ikr>WjSGOJ?*KYrY'
    'D+9e0MzQt@j=OBFFX2GZl>p)fYuj#cYHQy<86_sF;HU7M8m|fU*8ZdPZS%-i1(>Gt5;$$l?kTmvp3#'
    '#;4bj)tbKP)3>~Ay#{%1C#*^9>3VIz*@T3ODl{F!atKSDBz`ACjZZe)K)%UIXm`SFPtq_Gg9a0vlR<'
    '`2eZGQ(VZd^VU{Nk-^xqRY>~kE>y8$n(XPof3ov@p9!fvt@Rti<HQ*gz1ka~#AJ4h46)MU>9`$h}wA'
    'YnZO`$h}wAW19*Vj2=-)-%Vgx3jr~*rqrSnWRRj&FH?vpF6D-))}(>b7%>ud9=Ny$%NXp@u{NvT$#h'
    'U2KHCZ76;`_2hM3SC)9_sKUk~G9q=R4x^%|^Ey`9Nt46e(5n66CX}Jp6t<^&ps>p%Xlf!ZrI#{@bg_'
    'T#*szj$8C&F&0%Icf-q&Jo>hLGy}N3g0niagUmR(*1x!>xptXnE8l_fqI5xul=?zp9_y4gI7P`o`VR'
    'PfDRr+>IO%-U8tg2yGBnLTGmqp4HHQo@gQchonm&&9U@!Cn>WUR*G^u-$}}@hLxb4CjHG0{mnR{zsX'
    'q66AO%ICC@C?Y^LEZreSz=o52nSbX_yaZyQpL)wC|X1r42IdRmyC`ApBLOwU55XOWZezyfqldW&t4^'
    'rC!7aWs|TB>Y~ap(%rtl=31SO=+B@tQQ$cYDh`7gC65{fp(4ZXsR=A!-Hxvma>eX8-&@jI=^(9VU=4'
    'q&MJ2qUFBlU@=<Hd(s@PGZit^3)lvTy)ZWkh*S&Q2aVM-ZRtcJ=7zy-kr*E5}{O|@rGY}9o$KW{%&k'
    '=YI!_yB>A3VMA%)}_2z9$OG=~c)m7{m=d0dYee->l5#{ir(-+T6B*YXOPNLL0LB)@pKkZ1l`0xVcrP'
    'FY!%2Y=Y1coYVLmPj(4ei}R3UG2}EpBa&T0s=z}H#?S`dOL{cU32vbK2s0|6T=JeGr*%W)vy|U7qC7'
    'eEt%b(;x$li5UVEoU3A>7FYRA-SAJEtGt4T_;N?Nw}hR}kdtzh3C+_3^?0myv@TVaKNOa9ID6e35nL'
    '`p5x&|M4J1GCls-hjBy!^0lfOUKF}OaE5Ji}GnY1NOxI-1B<_;g;%qZUl?f^bxyxk-C2G4dRchhCP{'
    'buDGFd9oVB>+}ydoYPfGbEv;0~XjsYefnEc2(6U_I(APro>!Wi)(rck)%PfmorfsxkmNCmbD7OjQ@l'
    'A!CN>;|qpMOa%0WAZ2?#jlN?WDv_e~#_dImGtYd6_+oo)%~WZ=wxU7v(lkog0BCpU6t|n#O179#sEf'
    '*TC<N1))?{T-zyt&=K04n+aS$lW{EFiiD-$OO^(Z&5Kh0CrJ7vC*#GHL^7j1BkxE@@$V)QgPXH60nN'
    '`S$4!L8c^nCp%K0XV4l-H@zbxs)0O)O3zcD~VuJc#`<hbKC8Cgxsh#cSmIdz%MoVsPS6c>tc2^ql+*'
    '(GZ=M>ihWNGa=mnSG8Ufdd->iQShuX!1>JH6123>Bf~y@y6xmK{@j~regu;MZ{(Gt|cdoMUbZ<QfVF'
    'gxR%2K8FPPNe}L3<V55(J)5Nu?-{>RhLL%irz&G<96W7VD@7)Nl?=f0J!+OMvvfi{cNxSJ1?Z$n7j7'
    '_flu<QMea(PwDK;T#~p*7Ptz;zNWxhZ2gNgYIodND%6LYbG+jpXe5z{dRn8To$D5b(D2f+XcpnS=H<'
    '9r`EG%E2g4%Xp7=9r@j1z^mMGwCi2DPNS;jNZ@cVA$xy7mdkZgnd|zy`hM3-$}|y6vOYdH=2sj+Bsh'
    '*E8~7Ft=rS8yNqbqm#P>qXMq@ToGM~ik;3d*)hKY|o5MZ)yX}<ydV9Qz!k@tSpdn;sF%G22Te!$}WF'
    'z_C{kAa@KnbF~a0F@vS3DBSI?4;;rh?lVVFZOTbS5nC>?*=@)>T_1loaB1mt$HU`&w6Zq7i1%t5#E8'
    'C4ukIb-XpZ0?98xYW*$mUlA}l8*&jn*60<^*w3|WN4Y|roNt5-CTTzeRW;W2H9e}@(;eW9+hJVw(aq'
    ';h~>R>f0_F?NjsHs2DLAB@&bV7}Nfg1sLb_w8zI`<{xpW7L?d<=h*wACPu%1M@&TM`}a+nCTno;eg*'
    'gyP|0MJ3Do4a_83dY(3VCdq)A#GN#gWWY=!YkMt8CuRyZj||K62rd{s&rA!Vba#(xb}@wF24|mqOCW'
    'CUfO(~t%quOP67>uZ&pl6WGnQr`MDnsHg>l87kXfEzdRrLoT@3dNmzn|FN6mokRCas@yq4x?qS>BV-'
    '1F@T<fLa#luFuVtpG>+#_)Q%Ejqs>wj+4txzGuS+{0*g?|NAl;AXN2PYvi3!wVysoWd89z61Uvqt!('
    'HREvz|!jDMJY%a<{kAPi<!7j%Wb|LwmNzhL6O`>V<MsYo@uLP`0@R9t4JxuK+KSMo(Se@XZ`I+j~tY'
    '4<nHhY6;M@q-hQmuN|@7uuSj9t~;OILM4&Hb0T%RiXCr89$`U5iR2Wjt&?wMSIeY^UeY<Wxo_s>3Qv'
    'v1O*kkoNxZFCb4oqrSvFy5n;9=&(xkya6lk;lw?<qFhK73~W`FqtMfQrVHa8d5a#qxBaflieJMWAYm'
    'rC16Od2Tai?9<SlyEsC(kL1bmj>qPMbAT#^KGQ@lA*qdAC-=Hukd7zeSn2-cI$6FP8MC+d6f-cph4#'
    '_jSwduENb;D_{{{af^&J(J$Euc!Cy-;z|q4<$~RCn<#WV=*PwaTm7wADwm_8GZa4CC!gIFCf$r_)bg'
    'HaL5~e4Dw?rRY{1+9sBZ2A~uXbe3^RD$0O?%AA`|g_VI5)t<wB>3+hqxrRqVyy5f2oFH=wEIIS_J{n'
    '1SM-u^OUV9c$3{GNV-fSOgpeDW2^yan;Q`o{%*(p`NdqMWBsx~qRLepgTU5_k17U*fL*--M{3_x)J9'
    '&f_Qd^FvC(*sSvThf8dcuo}NI;!gh7@{!{vsGUm2O+UNaIaJlXBKejbwbFZz9<`69=?WO9lJ8N-O^a'
    '{l4tlHO$~`&k<9C?ot<Obv>*Gn>`dq;+%{FqcoZ#z=@o5r#^p?g?>pS=KFykHXmZq}0Rw`oX_b~M2W'
    '@ZYh2QX@U?l)ujuB2Xa>!TsJI&F*EtJq!60R7J3(tRPH`NOG~xyuo=OSMz+&4)^11pY|S2`HSlaD!l'
    'w(#cH@R}@Yg=eEWhzpeQchq6l(b<j30Tb%se#h-l+h;x$80rh0f{Fj{rUgDI<GR_%^@vnG3n3jA#D9'
    '2T2Mx7Nt!FXn{v%<B1i?c!)cc#C|Y2g!p`Dx)_()L$&ig-~Pb&3c*79SpUia7WWbBdUje2OT?p;unQ'
    'V!$(FoD;>P{}3mNX~`#wavU@rbGjHCeP91{k^02>PI|T|-=X&70_9MK7pWTAo$+JBt@*E@*9GoS8UJ'
    'IIuBB|1B|0ojs_TrXrVpL1+=pZL!;HUDP&JRar>>JA@8sD^|9yBtLB`<3g0hH#4{gyg`eVMKn_vv9W'
    '^`G@p9zy%M%+AuoKwhu@N{?VX1CH`3o<fEc}97Rt6k?Sm^5erxoKXM@`qp)PfxRctW=$mRJ`xiC|3s'
    'SJY_o$okq=;_<eEj>Hd*2`Af*ugG}8gyK%8-O{@MmC0NT9chyQtRW*^g4|klFQOffc%qf04r<7_1Hm'
    'BI}&E(rvMN{LXGOv;s48Ggm^!ldn@K$U^(<=g~sNN4gEP&Es=Tb<%*sHfe8hn{F!x^C8Wfj&hN0?BX'
    'UTG;I9*mSA-~BbYe&KC${@UAA|D>1oYa@*MbmjrlX<w^Cg>Kid)xCHadh)OjJbxkSv%qI$e58yK#tq'
    'E!(Pr^T?lBmVZ!r(2$GZA^z{5Gg!+~EXzCFu%(3XgYH8d{w`spy*Y~lgWCeGkV_viXHJ?RY}V0?;Ln'
    'Itdrzc9W8I+E@}<!&c;J;aG0&u@GpOh)^)&X_OHK^a6d>d$n@?mDhUQcj#xe@RYE<`l}Qr4%_=LnsW'
    '#`6Nu9L>vW@;yw}wfB8c1R?-GN8(I61eflGDy@?K0a-8IYl`T-`MCOf5WS-650p4a8cpI?q71}hP*p'
    'qk@2<?BaU8%=vM3wG(?s|7U(o-8(QBP}5n)@we7Gz#_JiAwdPcleTN0pv7qV#3jf|ef97KHM3+k)7Y'
    '_1uZf#$=B3f{pWIqhO5Zvs2Gksu4!rtCW|~^`Puyx-s)%Z?BAgakd@T`6D^Pjdjg!e&RJ&M$Z>XpW5'
    'xxe^cMae3Eb@(03Ln2dB6q%Moxx8BzkM%6DrULh9&IE99yjQRHtpd8@VHr-KvaxI%sJtxF)*S{qCAC'
    'lBffCE=&oS~#4Yr!^6OatPzu_<O<ySd(g-pB4WgzU;Xj=CqaaX?*B8c2coU$`LXle{;>B$k|GGv$(n'
    'HlUU3%E9C*krzihD$k(mXM?a01Ef=55?w9AqB<VS5`q!1XFD7wpYZ&Q&8}c-!5%bVor~Dn2@8thFLL'
    'zF|tIFl~cHO=N;*Jv{syev@-Xy2y9HG%UCknjxiCoP8j<pqD2DU=YWRIyM_QEIdtGFE|=bt3wj-CU3'
    'm}YTHOcUp4x5X?GFE@X@a$iT^*x66-Y4MCFqWT>6v|3L@y&86?`4H}cv<1Q_gnBuj?p!&>lP*}AImy'
    '6sIKcraji{`Nu+t)Aa|)45<P2$rB2q5pTU3Uvnd>;6d{(shEBCy&VfuCXs9kM#2K$b2?2a+^9i#ng>'
    '>ls*y$-w4bMf713+zT0UGX=JS5{9^>`Uyg*c}r**DyT3q}{PLw!<agKL0=Mar3nK^m|2EA>h@5ZvM-'
    '#!_5=t2k$CW7NRx3%<``BE4=n1(vB{_3WfXWcZ)ZLQ>AoEBkX@Cu>J3=@%`@|bpKlf``=@*|IJH$FG'
    '<_`JF>r{|C@qe^y=^G@9OXB@9OXB@9OXB@9OXB@9*sQe?vUz(*'
)

MRR_ERASEROUTI_0780_B85 = (
    'c-rk-4|G(;xu4m+**{^kyTom{NtR?|b2v23(TMyBD(t4&!sRu<vS2_(C5@@J>PyJR-Q`cRyVSnI(}z'
    'KQHC8}qeH8mzA4O2B0(Y|s38J_W@{d1p2^y~N*e8^NsUZ8lnLGO@2|;Y%X<yG_&$)MIzM1*v_kA<-&'
    '3rR=F;XaO>i3NBthK4%x50BMn)E~d4$SANwqysij@1ZFScFj-o+%hY`T{giChCvipuQ6~>$`AB-;FD'
    'cJ-Aihi}&k~;x_#;+^#>459m)|a|JSb5&D(gdH{Fo-@#q_gScD2AAg`1=VfwhlxB?|0jGI9w}$J)0s'
    '?L%u8}zks2852@QmPir`_7xcOb|e?>y9eXnzOy-UoeB3O)rnw?kWp_|@Cd${b|G=XexGNI~BC+=2iq'
    'tAFaOB|D&Th+~5oH6jkNAIKU3S&f2T42j1*Texr5<vg>mKtGTo>Uh*4hIN8oK%Gj!2v4`tvqiDEF1N'
    '~BP(3g<qAs|3U`!;vAUBdC848|?q)DlQrBf+sg=O$o2{w2u1%D^h!t?8LXITs8513f3G+HYi_~<2rD'
    '-z)(9lSM?7T!il1#ezb!W(~Z&a*}NA!wf?7=WLpOId>=nl!^nRZZ^cLGH{CjonIo3ZygUoh6c$PA@7'
    'eoi(RuQqingtUq^TozxbR{yd8DOgtCgg@5FEU1jAz->zAihEgl%dl5b^=mdlFGScxLqD8!smhi|LWu'
    '@^-J(}RzqOumCeuZEbXL?>zSv@~dS@F;CuYgA<w!-^qR$7r%QwcS1A~kO`(wg)52Vfjj`q3~B&rl8y'
    'R*OsGkOCb1B8<M)5|KNCTW}qMzQ~5YczD17TK)DwYD8a<4O$&j@I*u_sfBMtA3Q8^!uKSF@I)cvU)W'
    ')>*?h&QI0^T^&{oG|tFQQY(G^h9eDtN=D&5O)sFE<L0n^msT0rk(>uB<!SAkP;T=#nPgAuhiT&4D7P'
    '&;!J-DHj6G#gtbMdf_x)BIRJj+hw}$;`+)sVN*jGvf0joL!+c!`PVb5+lYrbL;%jheiEd;d&uW%BLw'
    'ue+uL&=cGyII(cmH!uvGG#>yFKYFWIThNf%!IpHbcvXI7EMME7z7;2`5eepQw3Mi12DjL2U2^++Ht3'
    '|13R>Zy|Y`~%H3XNGDi#R&g7na4x`f{Jou{!Ure;!|f9?$wuEn+szk7p|8<Gb-gc!hF|psU@2(A2HS'
    'NW${1$ihN13wf9aeJ~H)L}!WyvCnw|=s`5m36Hx=vDn>JWrcJ;r1PN^84-7^)S)bhlQBO5;xi$RAv8'
    '*v5Ys@cP$KOqfPcPZfS8KLQX$6CSPH~6BnEAh)|NoXLAbPbOT-BDWdswXAE@0<Q9eXkhx8*r=OL_t&'
    '<tT6gcb<B5R&}W?hERuyGv!A8U%^=`Jzzok*uyAmWJ1M75U0{6hj#cqu0dg8I*2j^tw2GDy8#4vrzr'
    '$saDJ^ZiYC|;>JnPo~%QZ1@?PMQ2-g+7qnIEU+zW9=j_(1OMLWYVi!{JIiUQ2$X%1ssLbi|6ZwmX{E'
    '#L(n9OugOmqM=4bbjjdaw~aIQJq`L)Uf((Cthg0@Fts(}#oUW0Cv3dXIZI=mSQ;L;qU)AxO9t*|T<o'
    'gq^=B^4+<;n2rfqa)C;|8zlb*rN=Z<7N<|4bRKwE_{W$=pd5>vA<nb7aT2sh<FZDIk~O0E325X~rjf'
    '}+BZ@`*N?LXTKIQ%hX7zu7HF^%{_dv<x$+}Y%c>Y~wb?;WMV%)cYK8S7#4|Ygn2;%w|w%dTNQ|zi=r'
    '`(3r&OHdZcc(lomybr|G@9Yw&AnI-ahCsEhFs%{q#(l6xf^u36`5$f6It9{Xhu1Na(VUd<Mmm7R#zC'
    '){GeQi#2MD;-vFyQ39Ff5HIIVT%&?l1u$mdxJq+u1La+G-jM3fx|F@VS%x8E<+Iv5-_p)`=prJOO+W'
    'HbLFP_4miTi}K>}BmHvhQ$hQ6lL^VzI#{>w=*=(VuHiDM;y87N`d@j@;MTAgM!2C}|A+GWX{wA{wf~'
    'b%=X0Y$!xw9i-04DSSA)M8gxS9owUPcjz8vt2Uq5>mGTJvQ$xhWci&KneNO({GBDpEL&xe&gh%^Ya*'
    '>K`x|RCxx9^NgM&Pc@3EaG-@W~&xb@b96@a|@P0%}LWU1fOV*^Xf15H!E5oqI)uKwphOGBE<YUx4WY'
    'p1*o7hd(cJJtJ`24AZ5N%s(b^_zAu9_=!ZK4h%lxP$R%Cp?y1V_QW8JB%U?D{HRbB$Bcw{?f~=oEXD'
    '2o?rqzzL*UG>lMSM0c>gbFm6$vZ>eZqz5pYBK^`*0%3p%5R~-cwy6SJ$<X>^sPuer$8AnR+J&J1VRc'
    'e)4f^M!}Fh~}0hBzioIiPp>)oAhS2#IOI86Cx8jW{NFd&l&!R=UA5!*Y8eN=qHkrhV40R=gz7irhZr'
    'uoznKLzXndM}0Unbl*Y8grl5}i5l;z!78QbdQd&UiLNSj*ah)%G(Ilug4~N@<%6m#<-wZaJ@sct$Zx'
    'K=un69cQxNkkf;Xwv=BoI-+tpTC;qI<PoZU|L|Hz*m)bhO;TZM5QE?0X*liMd+L|5Hu#m&6>WkvrtK'
    'l#0&TwQx{+iKUvZJ%`1JQUHGE6=a3=>d$YaHYU?lzve9{cVRUE5{vib(VIOc9+gk^;GtjqP<96pzK!'
    ')>JHxloE_BgsFCc^?RKC5Qr3EfR@aMN60{pVzg8F{BM6>BdtJ|--0E5r9E;Bhb|D4tr`#q2{f$#0*S'
    '65DKwpG+<1R`!qrH%R0Mc?f6HV8}^L1!%O;`U;pgoRv*R(X>NT>q}A=^{Qfu9CDDxHk(>!2ze1r^YT'
    'po*7csN(ras0vfQ0u{AR_z}FyB><MY!*2_@3*W>qEj)_1bCdHqt}kDoHuIy2Y4bjsAn3y%hX=x^J#D'
    'Z*KE1`Xx-EQ@@6FpxX;VMCAz05nn6FNo{jt9JQSrR}LbxjQsCWs&M_L{gFGBdRV6f;t`&HI&mVXrSo'
    'Z_s+Zt;2kB8oz!x+#QRr5(?7tpy|-TaLS6OysUQ_oNr)-L)cm`P=9eNTC#RrK#ZAZuM)LXYxV6jz8%'
    ')ezK9}-7HOXZHHQW&aYh&{qhF%cJl(F?NCL_^4#c|xA9?tQ=FkXx?x51(mC{2^Ssb~z{Lbyczl@UDP'
    'cZxbM{G!Isesh8CssrxR2{-Z~#KkUm<D)?6wiutuprR$ujnLp7kQj^MIt9ambO1n|(KV3e^4DkQ}D8'
    '_->j8HeWfXPbx@YzqA;z&nM#}bbm{AZXdypPg8UmkUJfa&kx-Xs5LFsnb>d4%%k}G8Gb$B-wXH;b$k'
    'Y`|1^%@HypogoNVNU6UNFGqbZUM7<-cJ8jjJCCPDMZ>KYR?F-Eh*X^MD@wm3~0r}^VFE><K79v8!x1'
    'dog1OESADF;<!+S`42ti5A0`fQMAECKK?GdWg*OPcsCD3{p3QCdZ6Jq0zFY5i|wjN6<KA9zoMEzib)'
    't%d)U`8S}}O;yV;&M;0g^RWvBaDEa!u3%!C?FbJvQr@4F49nPh&hS$<H?+d<;hPv!%ht7+*skK(vgD'
    '*v<EGO*2Cp}x#@N{Fb@9t;3wZ4;I<hY)HzPuix+M)<5pMlVkS8733<uj4M!ZP;<U=#jG&oYe8dlAZV'
    'hPiSGSzJNll8&@d|J+)#tJ61p`j(gN>mbkVguQDm-PiRw8<0?5fhI#(24S(2#P30<{+UJ_@HaUL?H<'
    '?_kTk5=Ai)^tc;I1FUo0nK7_ginSd_~c{r7|p{*c3YAK-<3j}soZ6TD6*c%3D%qo@Fn!WH*4^$?dmO'
    '%ue_#J2$d(gL0)?3=*9w1B5cVkr>QkQmdRIj+6kjm1PaQ}d8Xs)yE$?z{cDlS*JeBI`eg)_|6W>suO'
    '6s0|yQEvn6xOE_19ALeXw(30s;a*|vU+C$kNtWoCn`4Q<|>e)b#vK`9GAw6e=o*Pekt{l9&S{Op*In'
    'aA@SjIvJ3m36)$+h$<ktxTCu-mD!`ldhQjiskTNag(_Xw@7=o=L!~HhIk9W<pE!JnE81DU6d`GEV$o'
    'HBRn>aZ&<f<31QCB`_xLLk<Y<fN&9nHVBtMXm^q_t6=;*-9*L@Nf$$!W9i9GQfC$HDCKm%lhj=WJ4Q'
    'K8#+x0+n{mi^ld)VR8W>GWp6RL?Ou{`(!tn4u15XEJT|Lfk8&Hjuv?jd?4V+<eT9};qOwNf+&O#<<k'
    '&~2xjq2+3CR;xlMfs58Xez@=%6pN9rVLI}%Zqe0rE!wFUSuSx0VS0VMvU79($&kesm8b+_p8ZV$})m'
    '%5N1zr|I%rO-Ehq)yWypDH;gsQhV4a5<`hl3C4R0{L+w{k`w+8V4^S`V9@vkp6f}!566o7b-!?({;V'
    'puuFCb`6z;hg)WAGe>rx%_cc)H=4hEY0wj}?@YE09qzi0iuo;`$oCQJKs8QD-2uxn(`q1RR%!)@Svs'
    '(d2a5=-E(kbF)le<Qsp~1fe51vwjm#yos!ZdC0L4a_XNKi8qld@X&%Ww4V2p5sh<#>#4tCMg_E#?0e'
    ')iudjcBmNyNlPfmxcp)-E&d*hhb-tJL?_fbjpm|E!r`Wk)}NoiI}OZVRrnpd<H^xK8omcuFlxzA%Oc'
    'mj9i-%d{}ax{yi)ItsQZiuhUyn_7!ajl03U)f9NN<T~gR>q6+X*vUZ=U(o`{ef^(<^8vU#;SUV-n>X'
    '%yZ;vP#}$K~OgUFv-@X>~Q6_F~Uso~MvyRqQs;AVgVEI6=0y;=pCa&*kqWJaES-|PFP_ky0#x&D1Tr'
    '*3VW*(9Ign5P&A!iAzW9BcuEZ2aZ0pEN{ebWw7<F>y<_v##?`<uK>A4X3T^no|g2dc|*AE+)2!IMvT'
    'B}PsC^VC<>f7sFYyAwgEl@*tE0w8pRHs@wSsh`O>7H>tuVz4EP1IXq@DgP5BW0I5c;w6MLqdYHruEW'
    'ajB^-mBvoitB&uEF;ND1djBv2~n8z(x*Y$4@kP9Fw9ZoB%8J{ofECj!979dF6VT3Sl@KndVeliA3rn'
    '}&07p$M1Y5nP{Lyhd|;!=Vk7vd)*;<2V*Lv;mOVeVP3x-?(PeQPPrbRK65%oNpe~Grwax5pZ5cTvqo'
    'QauQhtc^bl%wsC-KIvS8M_XZ9INK1z{`1m(XT$B2Z9+EC3Tn+_%)7~+0?cBQV4Pg47q%|~bL~N7gro'
    'Bn}O_%65?)xKja?^($?{ARntD5=(CxQv7nY;n6ok+<|7+I3EL1d^EBP1-8%Tl_LoN*u8a4;YvKL`>6'
    '-llHgq&zN{pkqyk{t2XVFv@c>-s2s|es>h`Dt8|5cvo)IsA@VEI2ugwJ{XYsa_yAo+TM<y-*uBZ4Md'
    'Y{jL(YM6-N*Wj+4j+wnYQ7%)nOCUluR1y%4j}n2prTCowx%iS(*LVq*^l7_U28Zvi{lv_?bty<hR(a'
    '+#O%EVjNMuy{WVya(?SAZKo7bg(Z#IY@*9jAuJLQF;a9#Vr1dgB$o2lylR&0S~YGoV7DExt(__-ifu'
    'd4qM*^-UwENcc7)CAbY;|7;PszGpv}FhtiYy=+So$#*i1sw2;K@cHnkPuJTIUWVz#7)T6hV4)kaz;4'
    'ftOx3$OcZ#*z6{sR?ltVP8EY&`%i^#<Cg6y1S#Xt5`7E8xy92K><Gfn@x%+T)s!;ZNeW3b;`|$^3GQ'
    'qk}yg5;Djuha!tmJUr~EWPZPal|)O=-G;9u8L*PLlU9-pSV?4QZzSo&O2O8VL3tg)1;f{wNkNqE?o!'
    'Q|3Zb~(*(2X3h@0DBUFjz4N|UEpJ;lRwFOpl2#Tf{ZyzFsdT>fWdme-f=CWd<t!~N2gR>0O_D_|?-9'
    'bW-&r1_a>hG#nWVrv398JT0H;#OHIz|p!PyiV?m_AiO<2p)MYbOIvxAezy=PUZ!;881?%3gn65g_%r'
    'F>kG-)0sE2BY@&9mNyc*NN2F!87UiJFK`(=#my-#-kbKWL=qLHc(X@YqxQ@103|b}lNPa>erdE=lp`'
    'JptPVmtDO!X=@F4JkBy+NcSwc}{1RNd<itY>^i?&=<(ySkv}p{v~aAI{#=o<YyJMJ19l9y6cWCn~FU'
    '(DQ0?dZQB6VU=a7Wtzp1_WsE)AWuHazQTRG<7)TquuJs30Xy%(#C^M>Oh^?BY*&_}(9?V-3oASHwmo'
    '*g`(2e4zlPg@!!&YNuHaZ{MN-Y7x9wTO?vvvj@OgUM-pp!oNgT+H^5#T~<{&bfPm;4`9K_Zl*iSZ&X'
    '~SWisPDr2OGK^{x61eNnN`+;AJY5yZ_)esOnM)`j^4+AOHv6xlsI9Iq!8AP#FW&=z1Zr1V$w-u^zm;'
    'LH$LIKgiu@HJ53FPA#eCe$d92^B_Sqv@yo7=*f0d~RoX=#4{cX`5@v(h$G-)wN^|2qs7H-gY6t!5n%'
    'k+rN;{dO^u~z(N7Ll{{j1D@5x4vC`}{EiYE%hx$=4=x=Ed*ypAz&*clwcta*jUfPXE35ojxg-xYL)*'
    'CGPb9O^6D5-;br6JbrSIKcEzhjVhmiu-Fy}tMRKt?(S!o4V^bZ?L;zfdf6S&k&4dc$+z*SncjzVseL'
    'R>cfdH6e78bwWPH<h(%T<b?&(1vztco-hc2_*Ay49V=o)Twwv+qkM7f?=IZdJ*z0L8{_AWd($jXj(o'
    '3o^{S}J1b_c8S324@0k2QX@U?l)ujuBBaaJES4EKP?MdE7+Y+AN?NT%3~p)*~5ufx$_aTOSBX5?MF&'
    'r2L4FU2`HR4f4yLk(#eevR}@Yg<yOZVzt#B^hq6l&ZO}e0U6}lR#$S96h;x$80rh0h{MVfWUg4C;GR'
    'hf=@o#uOn3jA#D92UjhMg5Y&B{z+XN7D29%qFx?@WJ})553!`qRR{rth!q6!Ee&>=Y43EIvBy6tVvw'
    '<`gk4`4mx(!>GK1#-PlUQBD+(|3jQ8rX`;!%5ji%#OY#e_I>@+MQRi0I_cS>eAn8G3zP#HUZkpLcgw'
    'qk+4--c*9GoKDgR@YuBmjTB|0dKt7(sDCJ&tVAHcDDWLDlUs2WGyXV*xOclx~F{~(@MkkLQ3pfqCOL'
    'tAu=zRNdo8_Z$Vln!h7GhtlQkQ-{?a|ZbjpY4p@0Q>#bz$25?XOvxB^;%!SxPAlhP4l9ZKLn$Aa+>v'
    'HrRtod;(fcKTq*4Hl&v^)7ByPp_sZR8dx!GmufS6eJawP!#ZyIVTII(n!D?=5N42C>RT7Q|aNAiKrM'
    'zyzn&PKxN{LorYl<D;PQGzfG}MnP^(uM6;JfopuW#~BZ~0a<xjcZ1YW-lt0w^6kmqPMoU#$(&V9TT_'
    '&H(*>tFU$%!i3uJYEv<>V5A25KCr>{3vYw-*WQNOXS{4&8)4R`GYgPT$65s{bh`$v?uCOek_UZY`3u'
    'RIg>pt#j?^*2yn$6d+9)2&JpnWFEoR~LSXX;LSU4wGII!!)wr4pH+Y<4xhQ{SlKN)75O+4h;$QeB8{'
    '#@V2XT0G<tehfNC&`NZ3FenTXVSf>%<bfEhB&d~`SnkS$!x#T8MEa%D1%5w?U@eQT_@E@%88fMU$G='
    '6YYHu?r4%_=LnsW##UxCgL>vW@;yw}wd-+oLR?-Ju8(9AkKmGBz+(d>7IZpCH%NA&JEVD)?vd(7j1Z'
    '%SgtPSY*8g-ga^hvA<g!aEwuhe4Iqb2TI?q+u_(o-E*P)lo0TKg?z6=YU+G`%kYn`DqC4y!$BNbRfi'
    '1+6`#F9_x9_65-^8@Xedj>#J51s&(dX2A%{XQ!60L?aBlS1Bu{`$5^pbYf=1K3Wm|;(RNv@kermTWc'
    'Cy{KRUkh+Zs`KDFDW|E9K$*(BjspzkhF_D^s{mLVt&bw~}MD&MWH3#p^Wt&ppBM3KMl^lWRvPy5Hpa'
    'fSMU*^407TpdgErw{80C1I!7UO1ecr!^6Kas=ZU_<O=7*pq4-Ul9KwzT&wH*0dG!X?$oCJE>SJ<p`O'
    'Ozq#tq<ZLCpS=?OlNi61>p7Jm&rzihX$k(mZM?a0%EfY6o_sZ*H689W5`Rj5#5aT$qH;nW@5P2HYka'
    'cL5Q~ut{clu9`kcjH`t8)4M9d|8)xZ{+FDo!tgH_55GKxlN$i9*>2MJ{H4N9qbM1zn*=;$!NFzVIo$'
    '3%A1J{F7wd(F-6ClPs=@N#fk>mY62u_2!ON@9W4LJNxNAE1vU2RG))StMx?GtH49ehj0(1Ef7W_)XV'
    'wQbLCi>bivZdNd}g~2@XhUL}gWkofa7zQwU$eXFw|yk$NfLqC9MkT-({?v!aDx>GR%+=~w8(yxQyx_'
    'Pygsk1_VWqy1}mkN5aq2XFL3+#78IZ*;*mf9rT{?G(kn*!~LdnBcjA;qfJT$J&^OOTLl*Kk{+&wE6V'
    'AM%W?XRf2BrE8yYgiF1SZ7AgzT>R)DgSNj!SdlBhJmtTd#z4ZIW+rp_*x}_fc-!aVp-4*wL@23855%'
    '|9+!2iuld{;^P`#Z9|qyMjhU-bI#`tSPh`tSPh`tSPh`tSPh`tNV_`(H;Z#WV'
)


def mrr_get_eraserouti_driver(sw_profile: str = "0192") -> bytes:
    """Return the verified 16 KiB HIS Flash Driver (DB_99ERASEROUTI.bin) for 3Q0 (0130..0196) or 5Q0/3QF."""
    prof = mrr_get_profile(sw_profile)
    b85 = MRR_ERASEROUTI_0192_B85 if prof["mcu"] == "MPC5674K" else MRR_ERASEROUTI_0780_B85
    if not b85:
        raise RuntimeError(tr("Встроенный драйвер DB_99ERASEROUTI не загружен", "Embedded DB_99ERASEROUTI driver missing"))
    raw = zlib.decompress(base64.b85decode(b85))
    if len(raw) != MRR_FLASH_DRIVER_SIZE or hashlib.sha256(raw).hexdigest() != prof["eraserouti_sha256"]:
        raise RuntimeError("DB_99ERASEROUTI SHA-256 verification failed")
    return raw


# ── ODIS FRF / ODX-F Flash Containers (Bosch MRR1Plus 3Q0 & MRRevo14F 5Q0/3QF) ──
MRR_FBLV_RSA_MODULUS = bytes.fromhex(
    "b9bd4d3130a92f3d7051b1e924d9d878"
    "aef2bee910ea5dac401b775903f8e178"
    "6212c4acfeb88bcb938df7d04d88d1e1"
    "9bd1d5a32136f67a915d85be7fe1e9bf"
    "e5feae14feb7dda1d20e7794ba05c35e"
    "c2c2e9cd4716ff8d90a57d4d6b248ba9"
    "a10feb9eab8add5163c5489dd6f45123"
    "b03afb38c88afd1c0f6d4e3f7d374cd3"
)
MRR_FBLV_SA2_BYTECODE = "680793468434114A0B680A82498779BD36FA6B09680D814987B1487614498416735BE84C"
MRR_FBLV_ALFID = "0141"
MRR_FRF_MAX_BYTES = 16 * 1024 * 1024
_MRR_XML_LEAD = b"\xef\xbb\xbf \t\r\n"

_MRR_FRF_KEY_LEN = 4095
_MRR_FRF_KEY_SHA256 = "08909854ee0856571035b53bb0b260d13a01fb66a0357f84540a5892376a1ee3"
_MRR_FRF_KEY_B85 = (
    'c-jrr1Ck>F006*>W@6j6ZF^&T<Be^8{q7H4Z5H))3|4r#Cy-RH0Wxx)Y!06oClbNC5<OTFdvlDlruNS?Tw$XJq`Gs;u`V@hGT8~n'
    '0zyASBCiqL($X=a$6$^J<zl#=Oz8rhV+p*Ed+c%nm(4m(MR@V-u7A!oXwU*frV-F1TWVdTn6zxFnZ0st&|qZ0k3THFjaUfCz9Iig'
    'qH$8xztE_1dye*p=!>JZ6U|QT!)?cpt;sK;C*k>GpUo{c-XI}oOYI8+dpB6>)nWSzjG4*s#I2txD8PN@W^SVjj3|2%@w+ooN28&V'
    'd2P$En-qBrkJ<-%X#YknKEe~?Ws>I+<PO3s7WR`}#_Z3!>9L^~6%|tGD!f%^xAG--$KvsgNk=hD6SAG`ciwFPaNp|<`%HNCsQFrR'
    'h$ps(o$j;F%gMe7(xqiDwYs3W(G>o7>W;!;?qRbk-t@2SQuPCUjs(H-iqYpZQijk*)xXPh5@<&M&>+c42282(jmlW_eR<Y+`eOfC'
    '*qV7f6>)6RGQRr>qDIs~=ff<^Rp1%yXRx98<l5L9`{u)i!y$SwCm+=hw~#m}0xX&$N~YjiJ4(m3-xh_RMxB=BQ378&_yA_EUAa+&'
    '7=Zkz;3o(ICAQ(`V2JwQeOGfqL(|YVY_M%}u8Pb}i1^>Va*g5#Uy?#`_>1B-HCf^t8YJuJO?1HFob4~Jxfq?IhmSV`*ew8q_ylhn'
    '>FM?$#h6egn8|2kUk4Dycq*SWmEVwNEez3#Q#&dtuPFaDH2U$elV=BZtG8Y#bD>0<q^+iiSfj1mChj*wpNJbrXPT?zD$(?-wx|%p'
    'HH+i!v71La_I}dYPDAiHJ5=kw=P!UPK%s`r$(Yv{+AT$HfG`)e1F3SHfa69F?qPu}e8_u434uux*RlX#w-hQ0=)=fQC9>=?>+qJS'
    '8p0F{?!z)F-OvHPahljc`#E%=`MwTdVPj(v{AcHDKm>6DmCLS3&s3mWUrkLZ)>L-<cXkMoB?;Xdge1U^h&0))2y|h|<ATGg-0u)o'
    'R@pOPSpt&ct!pBKEz=KDV+muEq;4h|U(xkcTacPsJ-#Y_uFNy3m^@nAG(;h*HyE0!;g2jrBYXj7FKd+5!UtEaVH5ct@WxqAG!4*%'
    'gLLjKFy)VH>~7tOGcGY|^27X#AK=a+18y;9WuenSZhc)pcGgSq-3s3s0V9o-yy2bu+-!rzmt%d8;VC&EU{ksYOQ~CwTGuTM`Jc+z'
    '6e<1)GUu*JN85~#LP&L3H2EOPyuHcJe(%T@&9}+J3f=T$r(sI>^QIj^>&4upS}R&nC*OUUPkn4Kp}xo8h%J1lmAl^MT$E_RpmGux'
    'QKHxqDXj-a*>{mG_k8&pr~2IWV#7lf32W;bL)_Zy*<xKF@`{|)4KKQ<Jg#hfb3`oQbk|0Nq(Wx6#SDm}3sO|w+>k+>J@jpSR7v-k'
    'd@*|%n512Ij%A-j$#Auf$e^X3Z4L1wJ3c*@f-&HI_EiT?+sXSxhFUualfKM6#WhR~JLq<tAH=}DY#D;sI9aDFrxNR~!j#+;JE!W`'
    'N)An{&DT#{f#%~La|i62oz(mtMP(B+vC><sr)dP?sJ;K{_weaNNw`+!len|O<2_IQ1G=sVWD9!ye~jf#ZT|HumZf9Zx?dB@&cE}j'
    'Xa#6M;_@xuOU)p-*>74x-WIEAwiF+ez$h59#zXHg)JrduB3lM3nKnZIr%?WIHEZPO(QEwe#pTf}ysLj^!LeZ4!O!koJ}!@nqLMVo'
    '?tzX%uA$1aL|t2cY5JiDVu@h4pB_5P;RkRqHJTefET~oF-CQ#}&}|>;&Y?m(B~t(UM{YGU1=dBef?EwgL32ZT1<duP9uFC$#@QBf'
    'j}!e$QCbiE2c=%>UtW`P|7x1Sn%N?Jc)mG^orf&Hv*IKx^}>-d_jJ(=S@2fw!Z+E4*4@9hs#jQrMX5aCC?1OlDfh#IvWQ|3SWZ>_'
    'Sy)S!;<)On=VmEX-GH+xV1TyW>BJwWgF>V7hh&lld+IFYmDpH|^tKSye%zWI!ctG|IN2_Nj*grkhn5_<xRY)OSowNBkxMcNT~b*e'
    'Im3(!Hjp+WSM4gU#|1$0WchHdML0VVXG>B~0F(+;X|@k9Ot%*bh5nH7D*3)NX(F~X6G*y_#PcS*5(~B=a2Aur_B%W8R;ITu*(tL)'
    'Fe09W-enD64^oN_@r93-_?S0VB>1u>JrXcXgy1(;(Lw11`<qwPiRvf15xbHO<vA@FB{bF;yb$iKUV>O|C}1Suw2l&F#0`;Z+}GI<'
    'lQbQLUhQHOiMUHWRG?}j<!IVV?vqi{dGjAD2rA1R27#0GQ`?>NU}AIwwMTptWC+N}zv~LyiyBakkj<yFyOO{o-q_l=2;DODC^{}R'
    'TxD5G462gV#2^MqS2a1t3Sny6=MSO7rJfb<c|L0rPa%H+^o0Db+L8)ucxDhw-VVhE9O7f*<L$uc@B|NMpzgqSmz%7b29fwW%Qf0j'
    'Mv%_^ShZ6~6G_pl%-QqR+IY5usOk@EUgtU_n6m2Ge8zQfhJkqD`(p2reWRo#EDWDcrpQ^M;t3`KGoDxKIWcA0wjvwa;n#Ld;2Snc'
    'mA-6g!JC<!QZ-}RU`*1+P}qJQNfuC+xQntpbuQO33xk~n`I}x;hA~y7wrkAcUgHiW%N77Cyv2rJp1AQOkn<&|LK>?`q+BlQ@yxdB'
    'e9X^*07*meu!#e%+Q-yivI0sNhwgPG<f1nvUm(jD?s>LhF8y-(`3O;)exYjs>=>d$@7Tk2qJI6=6Xi`HkZUi9s_4fuIVed?IPS=N'
    '@$fL3@OA)EOvGyE(zh<%|HjVS(sVlf;|RM}*Zc26OKPvZ=+S1}7J?IyGdARe$T5alV-}m-JuG!_FqwP}*I;E|M^MvYtEOB<Bo(uK'
    'b5(eA4=q)ly}&1BFvNK2N9<@-eX{ROTaWo*D2$Ym-<_Z2--CL9dw~VYGllqL<1O0;kA`@@qj#dB<PllX#Dqt!S{nX1G#t9&+BC{='
    'YX@38MX^k8QWs|&oUU33xwivTV&e>iUGe=ENrMBG8Jk*XTG1b!2h=v}La$tsT^GcM0tU)^rx$O4*Uw3<(ML%-FSBFz$$e%<z7xx`'
    '@1A(SG%utQq4Cu#*9Jae@dD{FW47ZOO!#wJH6e>HOkfRzY;}5NNuOwdlGMekK3~)FPIL{-S(snOc+!;Kq(69zJY8OW`=XQlB6jJ{'
    'MV1$COq9koBsR0LQ@^pnW}gGOo~3@)1(EzPNw~M#p>(0NR|>tm#}Jvn%`2wK!-ZnzT}n4ths@OuUH(*(=8v&xGOp1T+C37))+gBi'
    'u*sGofiMg5nJl|8keyw)b62Sq!EAlyXzXe=FaXm>P_42zt}~MZ+0O-edqEDebde8AWy+FP%yb;AY3M)!XJMngmD@$nd!Y+$G7UJ_'
    '$}8a`Fe=WJshbJ}mjJOST!Shhy()7~+Q$P0U`J6>D1f~<R03e3khxv<gxVOQ83@dsH~XhJ^d|j{IqRN&$i|aDA2K~(Ss*ow1ZboC'
    'fahuZgUe+6hIa{NZ0Q4=7V-q0RP_6v>I2Z!VcED+l73XBXDVf_%5b0!May(P2&O(uNN8;(-6xAMzwu>YDag_+^76{kOYQYw0Ny6)'
    '6T*7$%tHg0)zWTM_zwcjQ=sI=rE0Y(RVNRI;lG~QN#3F>Ou8w@xgx1j!iFml4{wU|p9b#Nc@E7rDD~3XD4i^vvotx<G;$khWuS(|'
    'Na-e3TWNhA)oJd`DR#?}Y-qYRsx3{btM{oH{OXBFQkR7DFJu_O`VnTDoKHY|Rd1E>jjld*Qjp;O)qT*7R7Yw%R>%s21#&hi&r?Uj'
    'GvHQ)Wp$umG%W|;szqef8rC_KrTQkbI!{*UlvY($<X(vzdPFTJdy&Ad-TXC<S)TJ8B4Ri(=|;6_@Iv)sA<f91ikInJA$<p^3r80s'
    'p3J-GdgaR_;j;_co-N7GR*!S}RnLOj&&8O*{2*vNl%kD^7)B+6lKt*7z$EDY!c};t&rIoaJmnm~6y0z-0f>UZW^XP#7J}idefdc5'
    'pC!VdBL*%0+5DbV?34`HyKEQKlk7N8;pjvy87g&NY@5aNL%Se*D$*|Sx-6+15<K&IyPn~jY~rVO8g(Nh$XAfg<%F@WLCkoCO?ROl'
    'Bt+d8=Siu|>d*P7NN(0>qO$%1<WFwrYvKeR7r7vP)Yf5BuQKkIUys5+7S9}}dutS(c>2pU;SHqpSwKY!%zp;*tnurh#PRUy(ALO1'
    'l5%jis{Oepvv)Du{taNW0XKXU)M1y%qcBMC)i$*+m2nh7=xc^+uyn?(B}IBgZ<vbtX`QUG0oO5^^(lfe=GyxFw!(z8oW%;{%G}v*'
    'GMD|>iGqw&pYQu+ZTU8$U&(X9rlrqVp3iuhIZ}nh(=M$>c1Zc=SD@!n1;OV5D)pLS;_nKP3I*R87wg1tD|AR95qU=q<-B1wXN(ev'
    'w5~xZK5k?I#WQWVPOUny?(>L5jz{6w;Fu3DhU(yYJi*ggR}ulEOREaoI*XoP-`Vjy!BdAfpZI;3@C@l2pCbi`;tGKBTg!ku=J2o;'
    'eqA?NaqhI<)u?o1(-WgM!;HS(`R;->W2pZbjX#;NQ8`(WltDt?3c4th;8L;F?%tp6>c}`as{>#yS)>CrK@Qiw-fY^9LU*+>3Qr~C'
    '{H4U3>2<;K57Mjr%K'
)


@lru_cache(maxsize=1)
def _mrr_frf_key() -> bytes:
    raw = zlib.decompress(base64.b85decode(_MRR_FRF_KEY_B85))
    if len(raw) != _MRR_FRF_KEY_LEN or hashlib.sha256(raw).hexdigest() != _MRR_FRF_KEY_SHA256:
        raise RuntimeError("Embedded VW FRF key table is damaged")
    return raw


def mrr_frf_decrypt(data: bytes) -> bytes:
    """Decrypt a VW ODIS `.frf` container of arbitrary length into its plain ZIP archive."""
    key = _mrr_frf_key()
    klen = len(key)
    out = bytearray(len(data))
    first, second = 0, 1
    for idx, b in enumerate(data):
        k = key[idx % klen]
        first = ((first + k) * 3) & 0xFF
        out[idx] = b ^ first ^ 0xFF ^ second ^ k
        second = ((second + 1) * first) & 0xFF
    return bytes(out)


def mrr_lzss_a0_decompress(src: bytes, expected_size: int | None = None) -> bytes:
    """Decompress a Bosch/VW `ENCRYPT-COMPRESS-METHOD = 0xA0` LZSS stream (1 KiB window of 0x20, MSB-first flags)."""
    win = bytearray(b"\x20" * 1024)
    out = bytearray()
    nxt = 0
    pos = 0
    flags = 0
    nbits = 0
    slen = len(src)
    limit = (expected_size + 4096) if expected_size is not None else (32 * 1024 * 1024)
    while True:
        if nbits == 0:
            if pos >= slen:
                break
            flags = src[pos]
            nbits = 8
            pos += 1
        bit = flags & 0x80
        flags = (flags << 1) & 0xFF
        nbits -= 1
        if not bit:
            if pos >= slen:
                break
            c = src[pos]
            pos += 1
            out.append(c)
            win[nxt] = c
            nxt = (nxt + 1) & 1023
        else:
            if pos + 1 >= slen:
                break
            b0 = src[pos]
            b1 = src[pos + 1]
            pos += 2
            length = b0 >> 2
            off = 1024 - (b1 | ((b0 & 3) << 8))
            for i in range(length):
                c = win[(nxt + off + i) & 1023]
                out.append(c)
                win[(nxt + i) & 1023] = c
            nxt = (nxt + length) & 1023
        if len(out) > limit:
            raise ValueError(tr("Поток LZSS 0xA0 повреждён (превышен размер блока)", "LZSS 0xA0 stream is damaged (size exceeded)"))
    return bytes(out)


def mrr_fblv_signature_valid(
    block_id: int,
    uncompressed_size: int,
    stream: bytes,
    signature: bytes,
    modulus: bytes = MRR_FBLV_RSA_MODULUS,
) -> bool:
    """Verify the Bosch MRR FBLv CheckMemory (`31 01 02 02`) RSA-1024 PKCS#1 v1.5 SHA-1 signature (`e = 3`)."""
    if len(signature) != 128:
        return False
    msg = struct.pack(">II", block_id & 0xFFFFFFFF, uncompressed_size & 0xFFFFFFFF) + stream
    return rsassa_pkcs1_v15_verify(msg, signature, modulus, 3, "sha1")


@dataclasses.dataclass(frozen=True)
class MrrFrfBlock:
    """One logical block inside a Bosch MRR ODX-F flash container (`DB_99ERASEROUTI` or `DB_10FLASHDATA`)."""

    name: str
    block_id: int
    data_format: int
    uncompressed_size: int
    stream: bytes
    data: bytes
    signature: bytes
    crc32: int
    sha256: str
    rsa_valid: bool
    crc_valid: bool

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "block_id": f"0x{self.block_id:02X}",
            "data_format": f"0x{self.data_format:02X}",
            "stream_bytes": len(self.stream),
            "uncompressed_size": self.uncompressed_size,
            "crc32": f"0x{self.crc32:08X}",
            "sha256": self.sha256,
            "rsa_valid": self.rsa_valid,
            "crc_valid": self.crc_valid,
        }


@dataclasses.dataclass(frozen=True)
class MrrFrfImage:
    """Validated ODIS FRF / ODX-F flash container for Bosch MRR1Plus (3Q0) or MRRevo14F (5Q0/3QF)."""

    name: str
    kind: str  # "FRF" or "ODX"
    part_number: str
    sw_version: str
    generation: int  # 1 (MPC5674K, 0x150000) or 2 (MPC5675K, 0x1D0000)
    mcu: str
    family: str
    fds_project_id: str
    layers: tuple[str, ...]
    sa2: str
    alfid: str
    driver: MrrFrfBlock
    app: MrrFrfBlock
    profile_sw: str | None
    is_engineering: bool

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "part_number": self.part_number,
            "sw_version": self.sw_version,
            "generation": self.generation,
            "mcu": self.mcu,
            "family": self.family,
            "fds_project_id": self.fds_project_id,
            "layers": list(self.layers),
            "profile_sw": self.profile_sw,
            "is_engineering": self.is_engineering,
            "driver": self.driver.summary(),
            "app": self.app.summary(),
        }


def _odx_local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _odx_child_text(el: ET.Element, name: str) -> str:
    for child in el:
        if _odx_local(child.tag) == name and child.text:
            return child.text.strip()
    return ""


def _mrr_parse_odx_root(root: ET.Element, name: str, kind: str) -> MrrFrfImage:
    flash_name = ""
    ecu_mem_name = ""
    part_number = ""
    sw_version = ""
    fds_project_id = ""
    layers: list[str] = []
    sa2 = ""
    alfid = ""
    fd_map: dict[str, ET.Element] = {}
    sec_by_vf: dict[str, dict[str, Any]] = {}
    datablocks: list[ET.Element] = []

    for el in root.iter():
        tag = _odx_local(el.tag)
        if tag == "FLASH" and not flash_name:
            flash_name = _odx_child_text(el, "SHORT-NAME")
        elif tag == "ECU-MEM" and not ecu_mem_name:
            ecu_mem_name = _odx_child_text(el, "SHORT-NAME")
        elif tag == "PARTNUMBER" and not part_number and el.text:
            part_number = el.text.strip()
        elif tag == "REVISION-LABEL" and not sw_version and el.text:
            sw_version = el.text.strip()
        elif tag == "SD" and el.get("SI") == "FDS-Project-ID" and not fds_project_id and el.text:
            fds_project_id = el.text.strip()
        elif tag == "LAYER-REF":
            docref = (el.get("DOCREF") or "").strip()
            if docref and docref not in layers:
                layers.append(docref)
        elif tag == "FLASHDATA":
            fid = el.get("ID") or ""
            if fid:
                fd_map[fid] = el
        elif tag == "DATABLOCK":
            datablocks.append(el)
        elif tag == "SECURITY":
            method = _odx_child_text(el, "SECURITY-METHOD")
            vf = _odx_child_text(el, "VALIDITY-FOR")
            sig_hex = "".join(_odx_child_text(el, "FW-SIGNATURE").split())
            crc_hex = "".join(_odx_child_text(el, "FW-CHECKSUM").split())
            if method == "SA2":
                sa2 = sig_hex.upper()
            elif method == "ALFID":
                alfid = sig_hex.upper()
            elif vf:
                try:
                    sig_bytes = bytes.fromhex(sig_hex) if sig_hex else b""
                except ValueError:
                    sig_bytes = b""
                try:
                    crc_val = int(crc_hex, 16) if crc_hex else None
                except ValueError:
                    crc_val = None
                sec_by_vf[vf] = {"method": method, "signature": sig_bytes, "crc32": crc_val}

    if alfid != MRR_FBLV_ALFID or sa2 != MRR_FBLV_SA2_BYTECODE:
        hint_layers = ", ".join(layers) if layers else (flash_name or ecu_mem_name or name or kind)
        raise ValueError(
            tr(
                f"Файл {hint_layers} не является контейнером Bosch MRR1Plus (3Q0) / MRRevo14F (5Q0/3QF) "
                f"(ожидаются ALFID=0141 и SA2 FBLv, получено ALFID={alfid or '—'})",
                f"File {hint_layers} is not a Bosch MRR1Plus (3Q0) / MRRevo14F (5Q0/3QF) container "
                f"(expected ALFID=0141 and FBLv SA2, got ALFID={alfid or '—'})",
            )
        )

    blocks_by_name: dict[str, MrrFrfBlock] = {}
    for db in datablocks:
        db_name = _odx_child_text(db, "SHORT-NAME")
        fref = ""
        for ch in db.iter():
            if _odx_local(ch.tag) == "FLASHDATA-REF":
                fref = ch.get("ID-REF") or ""
                break
        fd = fd_map.get(fref)
        if fd is None:
            continue
        method_hex = _odx_child_text(fd, "ENCRYPT-COMPRESS-METHOD") or "00"
        try:
            data_format = int(method_hex, 16)
        except ValueError as exc:
            raise ValueError(tr(f"Неизвестный формат сжатия в {db_name}: {method_hex}", f"Unknown compression format in {db_name}: {method_hex}")) from exc
        if data_format not in (0x00, 0xA0):
            raise ValueError(
                tr(
                    f"Неподдерживаемый формат сжатия 0x{data_format:02X} в блоке {db_name}",
                    f"Unsupported compression format 0x{data_format:02X} in block {db_name}",
                )
            )
        data_hex = "".join(_odx_child_text(fd, "DATA").split())
        try:
            stream = bytes.fromhex(data_hex)
        except ValueError as exc:
            raise ValueError(tr(f"Повреждены hex-данные блока {db_name}", f"Corrupt hex payload in block {db_name}")) from exc

        segs = [c for c in db.iter() if _odx_local(c.tag) == "SEGMENT"]
        if len(segs) != 1:
            raise ValueError(tr(f"Блок {db_name} содержит {len(segs)} сегментов (ожидается 1)", f"Block {db_name} has {len(segs)} segments (expected 1)"))
        seg = segs[0]
        try:
            block_id = int(_odx_child_text(seg, "SOURCE-START-ADDRESS"), 16)
            uncompressed_size = int(_odx_child_text(seg, "UNCOMPRESSED-SIZE"))
        except ValueError as exc:
            raise ValueError(tr(f"Некорректный заголовок сегмента в {db_name}", f"Invalid segment header in {db_name}")) from exc

        sec = sec_by_vf.get(db_name) or {}
        signature = bytes(sec.get("signature") or b"")
        expected_crc = sec.get("crc32")
        if len(signature) != 128:
            raise ValueError(tr(f"В блоке {db_name} отсутствует подпись RSA-1024 (128 Б)", f"Block {db_name} is missing its 128-byte RSA-1024 signature"))

        plain = mrr_lzss_a0_decompress(stream, expected_size=uncompressed_size) if data_format == 0xA0 else stream
        if len(plain) != uncompressed_size:
            raise ValueError(
                tr(
                    f"Размер распакованного блока {db_name} ({len(plain):,} Б) не совпадает с заголовком ({uncompressed_size:,} Б)",
                    f"Unpacked {db_name} size ({len(plain):,} B) does not match header ({uncompressed_size:,} B)",
                )
            )
        calc_crc = zlib.crc32(plain) & 0xFFFFFFFF
        crc_valid = (expected_crc is None) or (calc_crc == expected_crc)
        if not crc_valid:
            raise ValueError(
                tr(
                    f"Повреждена контрольная сумма CRC-32 блока {db_name}: 0x{calc_crc:08X} != 0x{expected_crc:08X}",
                    f"CRC-32 mismatch in block {db_name}: 0x{calc_crc:08X} != 0x{expected_crc:08X}",
                )
            )
        rsa_valid = mrr_fblv_signature_valid(block_id, uncompressed_size, stream, signature)
        blocks_by_name[db_name] = MrrFrfBlock(
            name=db_name,
            block_id=block_id,
            data_format=data_format,
            uncompressed_size=uncompressed_size,
            stream=stream,
            data=plain,
            signature=signature,
            crc32=calc_crc,
            sha256=hashlib.sha256(plain).hexdigest(),
            rsa_valid=rsa_valid,
            crc_valid=crc_valid,
        )

    driver = blocks_by_name.get("DB_99ERASEROUTI")
    app = blocks_by_name.get("DB_10FLASHDATA")
    if driver is None or driver.block_id != 0x99 or driver.uncompressed_size != MRR_FLASH_DRIVER_SIZE:
        raise ValueError(
            tr(
                f"В {kind} отсутствует flash-драйвер радара MRR (DB_99ERASEROUTI, 16 КиБ, ID 0x99)",
                f"{kind} is missing the MRR flash driver (DB_99ERASEROUTI, 16 KiB, ID 0x99)",
            )
        )
    if app is None or app.block_id != 0x10 or app.uncompressed_size not in (0x150000, 0x1D0000):
        raise ValueError(
            tr(
                f"В {kind} отсутствует приложение радара MRR1Plus/MRRevo14F (DB_10FLASHDATA, 1.5 или 2.0 МиБ, ID 0x10)",
                f"{kind} is missing the MRR1Plus/MRRevo14F application (DB_10FLASHDATA, 1.5 or 2.0 MiB, ID 0x10)",
            )
        )

    generation = 1 if app.uncompressed_size == 0x150000 else 2
    mcu = "MPC5674K" if generation == 1 else "MPC5675K"
    family = "MRR1Plus" if generation == 1 else "MRRevo14F"
    container_name = flash_name or name or (f"FL_{part_number}_{sw_version}_S" if part_number else kind)
    if not part_number or not sw_version:
        m = re.match(r"(?:FL|EMEM)_([A-Za-z0-9]+)_([A-Za-z0-9]{4})", flash_name or ecu_mem_name or container_name)
        if m:
            part_number = part_number or m.group(1)
            sw_version = sw_version or m.group(2)

    profile_sw: str | None = None
    for sw_key, prof in MRR_PROFILES.items():
        if prof.get("stock_app_sha256") == app.sha256:
            profile_sw = sw_key
            break

    return MrrFrfImage(
        name=container_name,
        kind=kind,
        part_number=part_number,
        sw_version=sw_version,
        generation=generation,
        mcu=mcu,
        family=family,
        fds_project_id=fds_project_id,
        layers=tuple(layers),
        sa2=sa2,
        alfid=alfid,
        driver=driver,
        app=app,
        profile_sw=profile_sw,
        is_engineering=sw_version.upper().startswith("X"),
    )


def mrr_read_frf(data: bytes, name: str = "") -> MrrFrfImage:
    """Parse and cryptographically validate a Bosch MRR ODIS `.frf` or plain `.odx`/`.odx-f` flash file."""
    if len(data) > MRR_FRF_MAX_BYTES:
        raise ValueError(
            tr(
                f"Файл слишком велик для FRF / ODX радара: {len(data):,} Б",
                f"File is too large for a radar FRF / ODX: {len(data):,} B",
            )
        )
    head = data[:256].lstrip(_MRR_XML_LEAD)
    clean_name = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].rsplit(".", 1)[0] if name else ""
    if head.startswith((b"<?xml", b"<ODX")):
        try:
            root = ET.fromstring(data.lstrip(_MRR_XML_LEAD))  # noqa: S314 - user-selected flash container
        except ET.ParseError as exc:
            raise ValueError(tr("Это не ODX-файл или он повреждён", "Not an ODX file, or it is damaged")) from exc
        return _mrr_parse_odx_root(root, clean_name, "ODX")

    plain = mrr_frf_decrypt(data)
    try:
        with zipfile.ZipFile(io.BytesIO(plain)) as zf:
            odx_name = next(n for n in zf.namelist() if n.lower().endswith((".odx", ".odx-f")))
            odx_raw = zf.read(odx_name)
        root = ET.fromstring(odx_raw.lstrip(_MRR_XML_LEAD))  # noqa: S314 - user-selected flash container
    except (zipfile.BadZipFile, StopIteration, ET.ParseError, KeyError, zlib.error) as exc:
        raise ValueError(tr("Это не FRF ODIS или файл повреждён", "Not an ODIS FRF, or the file is damaged")) from exc
    odx_stem = odx_name.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    return _mrr_parse_odx_root(root, odx_stem or clean_name, "FRF")


def _mrr_infer_target_mcu(passport: dict[str, Any]) -> tuple[str | None, str | None]:
    """Infer `(mcu, rejection_reason)` from a live MRR passport (`F187`, `F189`, `F191`, `F19E`)."""
    asam = str(passport.get("asam_odx") or "").strip().upper()
    if asam and not asam.startswith(("EV_ACCBOSCHVW48", "EV_ACCBOSCHVW416")):
        return None, tr(
            f"Несовместимая платформа радара ({asam}); поддерживаются только Bosch MRR1Plus (EV_ACCBOSCHVW48X) и MRRevo14F (EV_ACCBOSCHVW416)",
            f"Incompatible radar platform ({asam}); only Bosch MRR1Plus (EV_ACCBOSCHVW48X) and MRRevo14F (EV_ACCBOSCHVW416) are supported",
        )
    sw = str(passport.get("sw_version") or "").strip().upper()
    if sw in MRR_PROFILES:
        return str(MRR_PROFILES[sw]["mcu"]), None
    pn = "".join(str(passport.get("part_number") or passport.get("hw_part_number") or "").upper().split())
    if pn.startswith(("2Q0", "5WA")):
        return None, tr(
            f"Радар {pn} относится к платформе Continental — контейнеры Bosch MRR несовместимы",
            f"Radar {pn} uses the Continental platform — Bosch MRR containers are incompatible",
        )
    if pn.startswith("7N0"):
        return None, tr(
            f"Радар {pn} относится к платформе PQ35/PQ46 (VW361) — контейнеры MQB MRR несовместимы",
            f"Radar {pn} belongs to the PQ35/PQ46 (VW361) platform — MQB MRR containers are incompatible",
        )
    if pn.startswith("3Q0"):
        return "MPC5674K", None
    if pn.startswith(("3QF", "5QF", "561907567")):
        return "MPC5675K", None
    if pn.startswith("5Q0907572"):
        suffix = pn[9:]
        if suffix and suffix[0] in ("H", "J", "M", "N", "P", "Q", "R", "S"):
            return "MPC5675K", None
        if sw.startswith(("06", "07", "X7", "08")):
            return "MPC5675K", None
        if suffix and suffix[0] in ("A", "B", "C", "D", "E", "F", "G", "K", "L"):
            return None, tr(
                f"Радар {pn} относится к старому семейству PQ26/VW372 — контейнеры MRR1Plus (3Q0) / MRRevo14F несовместимы",
                f"Radar {pn} belongs to the older PQ26/VW372 family — MRR1Plus (3Q0) / MRRevo14F containers are incompatible",
            )
    if pn.startswith("5Q0907561"):
        suffix = pn[9:]
        if suffix and suffix[0] in ("G", "H", "N"):
            return "MPC5675K", None
        if suffix and suffix[0] in ("A", "B", "C", "D", "E", "F"):
            return None, tr(
                f"Радар {pn} относится к старому семейству PQ26/VW372 — контейнеры MRR1Plus (3Q0) / MRRevo14F несовместимы",
                f"Radar {pn} belongs to the older PQ26/VW372 family — MRR1Plus (3Q0) / MRRevo14F containers are incompatible",
            )
    if sw.startswith(("01", "X1")):
        return "MPC5674K", None
    if sw.startswith(("06", "07", "X7", "08")):
        return "MPC5675K", None
    if asam.startswith("EV_ACCBOSCHVW48"):
        return "MPC5674K", None
    if asam.startswith("EV_ACCBOSCHVW416"):
        return "MPC5675K", None
    return None, None


def mrr_frf_compatibility(
    frf: MrrFrfImage,
    passport: dict[str, Any] | None = None,
    *,
    recovery_mode: bool = False,
) -> tuple[list[str], list[str]]:
    """Return `(hard_errors, warnings)` comparing a parsed MRR FRF/ODX against a target radar passport."""
    hard: list[str] = []
    soft: list[str] = []

    if not frf.driver.rsa_valid:
        hard.append(
            tr(
                "Подпись RSA-1024 драйвера DB_99ERASEROUTI не прошла проверку ключом FBLv — загрузчик отклонит драйвер",
                "DB_99ERASEROUTI RSA-1024 signature failed FBLv verification — bootloader will reject the flash driver",
            )
        )
    if not frf.app.rsa_valid:
        hard.append(
            tr(
                "Подпись RSA-1024 приложения DB_10FLASHDATA не прошла проверку ключом FBLv — загрузчик отклонит прошивку после стирания",
                "DB_10FLASHDATA RSA-1024 signature failed FBLv verification — bootloader would reject the app after erase",
            )
        )
    if not frf.driver.crc_valid or not frf.app.crc_valid:
        hard.append(tr("Нарушена контрольная сумма CRC-32 внутри контейнера", "CRC-32 checksum inside the container is invalid"))

    p = passport or {}
    ecu_pn = "".join(str(p.get("part_number") or "").upper().split())
    ecu_hw = "".join(str(p.get("hw_part_number") or "").upper().split())
    ecu_sw = str(p.get("sw_version") or "").strip().upper()
    target_mcu, platform_err = _mrr_infer_target_mcu(p)
    if platform_err:
        hard.append(platform_err)
    elif target_mcu is not None and target_mcu != frf.mcu:
        hard.append(
            tr(
                f"Несовместимый микроконтроллер: в радаре {target_mcu}, а в {frf.kind} прошивка для {frf.mcu} "
                f"({frf.family}, {frf.app.uncompressed_size // 1024} КиБ). Прошивка заблокирована.",
                f"Incompatible MCU: target radar is {target_mcu}, while {frf.kind} is for {frf.mcu} "
                f"({frf.family}, {frf.app.uncompressed_size // 1024} KiB). Flash blocked.",
            )
        )

    if not ecu_pn and not ecu_sw:
        if recovery_mode:
            soft.append(
                tr(
                    "Режим восстановления (FBLv): паспорт приложения не считан — убедитесь вручную, что поколение радара "
                    f"соответствует {frf.mcu} ({frf.family}).",
                    "Recovery mode (FBLv): application passport could not be read — verify manually that the radar "
                    f"hardware matches {frf.mcu} ({frf.family}).",
                )
            )
        else:
            soft.append(
                tr(
                    "Паспорт радара (F187 / F189) не прочитан — перед записью сверьте поколение блока "
                    f"({frf.mcu} / {frf.family}).",
                    "Radar passport (F187 / F189) was not read — verify hardware generation "
                    f"({frf.mcu} / {frf.family}) before flashing.",
                )
            )
    else:
        frf_pn = "".join(frf.part_number.upper().split())
        if frf_pn and ecu_pn and frf_pn != ecu_pn:
            soft.append(
                tr(
                    f"Кросс-прошивка номера детали: в радаре {ecu_pn} (HW {ecu_hw or '—'}, ПО {ecu_sw or '—'}), "
                    f"в файле {frf_pn} (ПО {frf.sw_version}). МК совпадает ({frf.mcu}).",
                    f"Part number cross-flash: radar has {ecu_pn} (HW {ecu_hw or '—'}, SW {ecu_sw or '—'}), "
                    f"file has {frf_pn} (SW {frf.sw_version}). MCU matches ({frf.mcu}).",
                )
            )
    if frf.is_engineering:
        soft.append(
            tr(
                f"В файле инженерное ПО {frf.sw_version} (с тестовым ключом SWaP/FES).",
                f"Container holds engineering firmware {frf.sw_version} (development SWaP/FES key).",
            )
        )
    return hard, soft
