"""Core firmware constants, flash geometry, RH850 opcodes, VAG CP slots, and bench pinout."""

from __future__ import annotations

import dataclasses
from pathlib import Path
import re
import os
import sys

from contitool.i18n import get_lang

AUTHOR_CREDIT = "Made by PerkTheFox"
AUTHOR_SITE_URL = "https://vwhacking.antonperk.com"
AUTHOR_SITE_SHORT = "vwhacking.antonperk.com"
AUTHOR_DRIVE2_URL = "https://www.drive2.ru/users/perkthefox/"
AUTHOR_TG_URL = "https://t.me/perkthefox"

# Flash geometry (Continental 3Q0 907 530 xx, Renesas RH850/F1L R7F7010543AFP / R7F7010563AFP)
APP_BASE = 0x0000C200
CFLASH_SIZE = 0x00180000
APP_SIZE = CFLASH_SIZE - APP_BASE   # 1,523,200 bytes (FD_0DATA)
DFLASH_SIZE = 0x00010000            # 65,536 bytes (DataFlash @ 0xFF200000..0xFF20FFFF)
UFLASH_SIZE = 0x00008000            # 32,768 bytes (Extended User Area FBL @ 0x01000000..0x01007FFF)
EEPROM_SIZE = 0x00002000            # 8,192 bytes (External ST M95640 SPI EEPROM, NvM 0x00..0x5F)
OPBT_LEGACY_SIZE = 32               # 32 bytes (OPBT0..OPBT7 @ 0xFF300070..0xFF30008F)
OPBT_SIZE = 36                      # 36 bytes (OPBT0..OPBT8 @ 0xFF300070..0xFF300093)
EXTRA_AREA_SIZE = 256               # 256 bytes (Extra Area @ 0xFF300000..0xFF3000FF)

CFLASH_ADDR_START = 0x00000000
UFLASH_ADDR_START = 0x01000000
DFLASH_ADDR_START = 0xFF200000

DEFAULT_CAVE_VADDR = 0x0016FF80
CAVE_SIZE = 0x26                    # 38 bytes

STOCK_MOVEA_0X40 = b"\x20\x7e\x40\x00"
PATCH_MOVEA_0X10 = b"\x20\x7e\x10\x00"
FBL_PRESENCE_MAGIC = 0x90482442
SHE_M1_RAMKEY_KEY2 = bytes.fromhex("000000000000000000000000000000e5")

# Engineering Mode & Bootloader offsets / RH850 instruction encodings
OTP_ENG_FLAG_OFFSET = 0x0000A167
STOCK_ENG_GATE_HEAD = b"\x40\x0e\xe0\xfe"        # movhi 0xfee0, r0, r1
PATCH_ENG_GATE_HEAD = b"\x00\x52\x7f\x00"        # mov 0, r10; jmp [lp]
STOCK_CCP_BLACKLIST_CMOV = b"\xe0\xe7\x06\xe3"   # cmov nh, 0, r28, r28
PATCH_CCP_BLACKLIST_NOP = b"\x00\x00\x00\x00"    # nop; nop
STOCK_A167_BE = b"\xd2\x0d"                      # be +26
PATCH_A167_NOP = b"\x00\x00"                     # nop
UFLASH_RSA_CMP_OFFSET = 0x342A                   # 0x0100342A in Uflash.bin
STOCK_UFLASH_RSA_CMOV = b"\xe2\x57\x14\xeb"      # cmov ne, 2, r10, r29
PATCH_UFLASH_RSA_OK = b"\x00\xea\x00\x00"        # mov 0, r29; nop

# RSA-1024 (e = 3) key locations & stock VAG public moduli
FBL_EXP_OFFSET = 0x0000A277
FBL_MOD_OFFSET = 0x0000A2F7
SWAP_KEY_HDR = bytes.fromhex("001b00ffffff") + (b"\x00" * 31) + b"\x03"

DFLASH_SWAP_NVM_OFF = 0xDB00
DFLASH_SWAP_PAY_SIZE = 0x01E0                    # 480 bytes (0xDB04..0xDCE3)
DFLASH_SWAP_CRC_OFF = 0xDCE4
DFLASH_FSC_BASE_OFF = 0xDD00                     # 15 FSC slots (NvM 0x7D..0x8B)
DFLASH_FSC_STRIDE = 0x00C0
DFLASH_FSC_PAY_SIZE = 0x00AB                     # 171 bytes
FSC_SIGNED_BODY_SIZE = 43                        # 0x2B bytes hashed with RIPEMD-160
FSC_TOTAL_SIZE = DFLASH_FSC_PAY_SIZE             # 171 bytes

STOCK_SWAP_MODULUS = bytes.fromhex(
    "99197020dda91d140abba490b5ed099732668677b6fc36c90f44997f58bf1c99"
    "828cdd35b4f5bb764f282e4a4baa9844d565199d70bd6e67c7b2d6c9377757dd"
    "ce12d4a1153259885e5c054bc4b9d58f18830eba93c143560fa4b6b93c79668f"
    "d75b337034841e8ed7aecdb8e60e29fcd560b3f6ecfde2d32b1a7d78418878f9"
)
STOCK_FBL_MODULUS = bytes.fromhex(
    "917de2f4cdf720c951755cfd3d8ae05552eaf22e800d11f8e55102febbe0b1d2"
    "4ffe44ef013dd8cde52cd78d49fa867b0e92c92521be93585186090581a2494c"
    "d34a4d29a8dd99e53bdb9878f9782219c37bc846d4e34bf3ab7cfa4414ee9a3e"
    "7087ebd4702856fffee1031d15f91579c0d24295dfde32e12b7f93aab06dade1"
)

PKCS1_DIGESTINFO_RIPEMD160 = bytes.fromhex("3021300906052b2403020105000414")
PKCS1_DIGESTINFO_SHA1 = bytes.fromhex("3021300906052b0e03021a05000414")

KNOWN_GATEWAY_FECS: dict[int, tuple[str, str]] = {
    0x10000100: ("Круиз-контроль GRA (0x10000100)", "Cruise Control / Speed Regulation GRA (0x10000100)"),
    0x10000200: ("Адаптивный круиз-контроль ACC — резерв VAG (0x10000200)", "Adaptive Cruise Control ACC — VAG reserved (0x10000200)"),
    0x10000300: ("Ассистент распознавания усталости MKE (0x10000300)", "Driver Alert / Fatigue Detection MKE (0x10000300)"),
    0x10001100: ("Профиль движения FPA 1 — Comfort (0x10001100)", "Driving Profile FPA 1 — Comfort (0x10001100)"),
    0x10001200: ("Профиль движения FPA 2 — Normal (0x10001200)", "Driving Profile FPA 2 — Normal (0x10001200)"),
    0x10001300: ("Профиль движения FPA 3 — Sport (0x10001300)", "Driving Profile FPA 3 — Sport (0x10001300)"),
    0x10001400: ("Профиль движения FPA 4 — Offroad (0x10001400)", "Driving Profile FPA 4 — Offroad (0x10001400)"),
    0x10001500: ("Профиль движения FPA 5 — Eco (0x10001500)", "Driving Profile FPA 5 — Eco (0x10001500)"),
    0x10001600: ("Профиль движения FPA 6 — Race / Cupra (0x10001600)", "Driving Profile FPA 6 — Race / Cupra (0x10001600)"),
    0x10001700: ("Профиль движения FPA 7 — Individual (0x10001700)", "Driving Profile FPA 7 — Individual (0x10001700)"),
    0x10001800: ("Профиль движения FPA 8 — Offroad Individual / Snow (0x10001800)", "Driving Profile FPA 8 — Offroad Individual / Snow (0x10001800)"),
    0x10001900: ("Профиль движения FPA 9 — Allroad / Доп. профиль (0x10001900)", "Driving Profile FPA 9 — Allroad / Extra Profile (0x10001900)"),
    0x10001A00: ("Профиль движения FPA 10 — EV / E-Mode (0x10001A00)", "Driving Profile FPA 10 — EV / E-Mode (0x10001A00)"),
    0x10001B00: ("Профиль движения FPA 11 — GTE / Hybrid (0x10001B00)", "Driving Profile FPA 11 — GTE / Hybrid (0x10001B00)"),
}

# Canonical 13-slot SWaP registration order in Continental J533 firmware (slots 0..12 in NvM 0x7C & 0x7D..0x89)
GATEWAY_SWAP_SLOT_ORDER: tuple[int, ...] = (
    0x10000300,  # Slot  0: MKE
    0x10000100,  # Slot  1: GRA
    0x10001100,  # Slot  2: FPA Profile 1 (Comfort)
    0x10001200,  # Slot  3: FPA Profile 2 (Normal)
    0x10001300,  # Slot  4: FPA Profile 3 (Sport)
    0x10001400,  # Slot  5: FPA Profile 4 (Offroad)
    0x10001500,  # Slot  6: FPA Profile 5 (Eco)
    0x10001600,  # Slot  7: FPA Profile 6 (Race / Cupra)
    0x10001700,  # Slot  8: FPA Profile 7 (Individual)
    0x10001800,  # Slot  9: FPA Profile 8 (Offroad Individual / Snow)
    0x10001900,  # Slot 10: FPA Profile 9 (Allroad / Extra)
    0x10001A00,  # Slot 11: FPA Profile 10 (EV / E-Mode)
    0x10001B00,  # Slot 12: FPA Profile 11 (GTE / Hybrid)
)

# DataFlash linear ZDC parameterization datasets (0x0000..0x303F)
ZDC_PASSPORT_PN_OFF = 0x0010     # DID 0xF1A0 (11 ASCII chars)
ZDC_PASSPORT_VER_OFF = 0x0020    # DID 0xF1A1 (4 ASCII chars)
ZDC_PASSPORT_EQUIP_OFF = 0x0028  # DID 0xF1A4 (12 bytes PR / equipment code)
ZDC_MAINGW_FPA_MAP_OFF = 0x032C        # 13-byte Inst0 FPA profile map (S028: 1..9 -> FeC 0x10001100..1900, 10..12 -> 4Motion rotary)
ZDC_MAINGW_FPA_MASK_OFF = 0x0345       # 2-byte BE S030 in ZDC #4: slots kept as the user's last profile (not the menu)
ZDC_MAINGW_FPA_INST1_MAP_OFF = 0x0D0B  # 7-byte Inst1 EV/Hybrid FPA profile map (S153: 1 -> FeC 0x10001A00, 2 -> FeC 0x10001B00)

ZDC_DATASET_SPECS: tuple[tuple[int, str, int, int, str, str], ...] = (
    (0, "RESERVE_0", 0x0080, 0x0080, "Резервный слот датасета #0 (не используется)", "Reserved Dataset Slot #0 (unused)"),
    (1, "MKE", 0x0100, 0x0100, "Распознавание усталости водителя (MKE)", "Driver Alert / Fatigue Detection (MKE)"),
    (2, "SSA_REASONS", 0x0200, 0x0800, "Индикация причин Старт-Стоп на ГУ (BAP 0x27)", "Start-Stop Inhibition Reasons HMI (BAP 0x27)"),
    (3, "RESERVE_3", 0x0A00, 0x0400, "Резервный блок параметрии #3 (Byte 19 Bit 0)", "Reserved Parameter Block #3 (Byte 19 Bit 0)"),
    (4, "MAIN_GW", 0x1340, 0x1100, "Профили вождения FPA и координатор MultiKo", "Driving Profile Selection (FPA / MultiKo)"),
    (5, "RESERVE_5", 0x1200, 0x012E, "Резервный блок параметрии #5 (Byte 29 Bit 0)", "Reserved Parameter Block #5 (Byte 29 Bit 0)"),
    (6, "BEM", 0x2440, 0x0C00, "Модели 14В LIN-генераторов (BEM)", "14V LIN Alternator Models (BEM)"),
)

# UDS 0x34 RequestDownload virtual addresses & payload lengths for ZDC blocks 0..6
ZDC_UDS_UPLOAD_MAP: dict[int, tuple[int, int]] = {
    0: (0x00000A00, 0x0080),
    1: (0x00000A80, 0x0100),
    2: (0x00002880, 0x0800),
    3: (0x00003080, 0x0400),
    4: (0x00000B80, 0x1100),
    5: (0x00003E00, 0x012E),
    6: (0x00001C80, 0x0C00),
}

# Fixed English marker (tests and logs search for it); every user-facing place adds the localized text next to it
UNSUPPORTED_DATASET_WARNING = "Unsupported Dataset: Selected FEC not supported by current dataset"
UNSUPPORTED_DATASET_RU = "Датасет не поддерживает выбранную функцию"

# T20 20-pin J533 bench connector wiring reference
T20_BENCH_PINS: tuple[tuple[int, str, str, str], ...] = (
    (1, "KL30 (+12V)", "Постоянное питание +12 В (аккумулятор / ЛБП)", "Permanent +12V battery / bench PSU"),
    (14, "KL15 (+12V)", "Зажигание +12 В (соединить вместе с Pin 1)", "Ignition +12V (bridge with Pin 1 on bench)"),
    (11, "KL31 (GND)", "Масса (минус блока питания и GND CAN-адаптера)", "Ground (PSU minus & CAN adapter GND)"),
    (19, "Diag CAN-H", "Диагностическая шина CAN High (500 кбит/с)", "Diagnosis CAN High (500 kbit/s)"),
    (9, "Diag CAN-L", "Диагностическая шина CAN Low (500 кбит/с): включён терминатор или резистор 120 Ом к Pin 19!", "Diagnosis CAN Low (500 kbit/s): terminator on or a 120 Ω resistor to Pin 19!"),
)


@dataclasses.dataclass(frozen=True)
class SlotSpec:
    slot: int
    ecu_addr: str
    nvm_id: int
    mask_bit: int | None
    can_suffix: int
    uds_req: str
    uds_resp: str
    off1: int
    off2: int
    rec_size: int
    short_ru: str
    short_en: str
    details_ru: str
    details_en: str
    notes_ru: str
    notes_en: str
    aliases: tuple[str, ...] = ()

    @property
    def short(self) -> str:
        return self.short_en if get_lang() == "en" else self.short_ru

    @property
    def details(self) -> str:
        return self.details_en if get_lang() == "en" else self.details_ru

    @property
    def notes(self) -> str:
        return self.notes_en if get_lang() == "en" else self.notes_ru

    @property
    def cp_tx(self) -> int:
        return 0x17FC0100 | self.can_suffix if self.slot > 0 else 0

    @property
    def cp_rx(self) -> int:
        return 0x17FE0100 | self.can_suffix if self.slot > 0 else 0

    @property
    def crc_off(self) -> int:
        return 0x48 if self.rec_size == 0x42 else 0x44

    @property
    def mask_hex(self) -> str:
        return f"0x{1 << self.mask_bit:04X} (bit {self.mask_bit})" if self.mask_bit is not None else "n/a (+0x0B)"


SLAVE_SLOTS: tuple[SlotSpec, ...] = (
    SlotSpec(
        slot=1,
        ecu_addr="17",
        nvm_id=0x60,
        mask_bit=0,
        can_suffix=0x14,
        uds_req="0x714",
        uds_resp="0x77E",
        off1=0xC000,
        off2=0xC080,
        rec_size=0x42,
        short_ru="Приборная панель / Иммо (J285)",
        short_en="Instrument Cluster / Immo (J285)",
        details_ru="Kombiinstrument / Virtual Cockpit (IKA_WFS, LL_DashBoardUDS)",
        details_en="Instrument Cluster / Virtual Cockpit (IKA_WFS, LL_DashBoardUDS)",
        notes_ru=(
            "Помимо защиты компонентов (CP), приборка 17 на MQB хранит данные "
            "иммобилайзера WFS5 (ключи/CS/MAC). Одной привязки CP для запуска двигателя недостаточно."
        ),
        notes_en=(
            "Besides Component Protection (CP), MQB cluster 17 also stores WFS5 immobilizer data "
            "(keys/CS/MAC). CP binding alone will not authorize engine start."
        ),
        aliases=("kombi", "cluster", "dash", "ipc"),
    ),
    SlotSpec(
        slot=2,
        ecu_addr="09",
        nvm_id=0x61,
        mask_bit=1,
        can_suffix=0x0E,
        uds_req="0x70E",
        uds_resp="0x778",
        off1=0xC100,
        off2=0xC180,
        rec_size=0x42,
        short_ru="Блок бортовой сети BCM (J519)",
        short_en="Central Electrics / BCM (J519)",
        details_ru="Central Electrics / Body Control Module (LL_CentrElectUDS, 5Q0/3Q0 937 08x)",
        details_en="Central Electrics / Body Control Module (LL_CentrElectUDS, 5Q0/3Q0 937 08x)",
        notes_ru=(
            "На платформе MQB блок 09 (BCM) штатно участвует в защите компонентов CP. "
            "Не забудьте также перенести кодировку и адаптации каналов освещения со старого BCM."
        ),
        notes_en=(
            "On MQB vehicles, module 09 (BCM) participates in Component Protection. "
            "Remember to also transfer long coding and lighting adaptation channels from the old BCM."
        ),
        aliases=("bcm", "centr", "0x09"),
    ),
    SlotSpec(
        slot=3,
        ecu_addr="13",
        nvm_id=0x62,
        mask_bit=2,
        can_suffix=0x57,
        uds_req="0x757",
        uds_resp="0x7C1",
        off1=0xC200,
        off2=0xC280,
        rec_size=0x42,
        short_ru="Адаптивный круиз / радар ACC (J428)",
        short_en="Adaptive Cruise / ACC Radar (J428)",
        details_ru="Adaptive Cruise Control / Front Assist (LL_AdaptCruisContrUDS, 5Q0/3Q0/2Q0 907 572)",
        details_en="Adaptive Cruise Control / Front Assist (LL_AdaptCruisContrUDS, 5Q0/3Q0/2Q0 907 572)",
        notes_ru=(
            "Для работы дистанции/ACC в радаре 13 также должны быть активированы "
            "соответствующие коды SWaP/FeC (в самом радаре) и залита параметрия под кузов."
        ),
        notes_en=(
            "For full ACC/Front Assist operation, radar 13 must also have matching SWaP/FeC codes "
            "enabled inside the radar unit and a valid vehicle dataset loaded."
        ),
        aliases=("acc", "radar"),
    ),
    SlotSpec(
        slot=4,
        ecu_addr="15",
        nvm_id=0x63,
        mask_bit=3,
        can_suffix=0x15,
        uds_req="0x715",
        uds_resp="0x77F",
        off1=0xC300,
        off2=0xC380,
        rec_size=0x42,
        short_ru="Подушки безопасности Airbag (J234)",
        short_en="Airbag Control Unit (J234)",
        details_ru="Airbag Control Unit (LL_AirbaUDS, 5Q0/3Q0 959 655)",
        details_en="Airbag Control Unit (LL_AirbaUDS, 5Q0/3Q0 959 655)",
        notes_ru=(
            "Внимание: блок 15 Airbag на MQB жёстко связан с конфигурацией безопасности и WFS/VIN. "
            "Замена б/у блока 15 с другой комплектацией пиропатронов требует точной параметрии."
        ),
        notes_en=(
            "Note: MQB Airbag module 15 is tightly tied to vehicle safety configuration and WFS/VIN. "
            "Installing a used module 15 with different squib/crash config requires exact dataset matching."
        ),
        aliases=("airbag", "srs"),
    ),
    SlotSpec(
        slot=5,
        ecu_addr="47",
        nvm_id=0x64,
        mask_bit=4,
        can_suffix=0x6F,
        uds_req="0x76F",
        uds_resp="0x7D9",
        off1=0xC400,
        off2=0xC480,
        rec_size=0x42,
        short_ru="Акустическая система / усилитель (J525)",
        short_en="Sound System / DSP Amplifier (J525)",
        details_ru="Sound System / DSP Amplifier — Canton / Dynaudio / Fender / B&O (LL_SoundSysteUDS)",
        details_en="Sound System / DSP Amplifier — Canton / Dynaudio / Fender / B&O (LL_SoundSysteUDS)",
        notes_ru=(
            "При дооснащении усилителем 47 (если с завода его не было, банк 5 пуст) "
            "обязательно включайте обход маски 95640 (--bypass-eeprom-mask)."
        ),
        notes_en=(
            "When retrofitting amplifier 47 into a car that had no factory amp (Bank 5 empty), "
            "be sure to enable the 95640 EEPROM mask bypass (--bypass-eeprom-mask)."
        ),
        aliases=("sound", "dsp", "amp", "canton", "dynaudio"),
    ),
    SlotSpec(
        slot=6,
        ecu_addr="57",
        nvm_id=0x65,
        mask_bit=5,
        can_suffix=0x6D,
        uds_req="0x76D",
        uds_resp="0x7D7",
        off1=0xC500,
        off2=0xC580,
        rec_size=0x42,
        short_ru="ТВ-тюнер (R78)",
        short_en="TV Tuner (R78)",
        details_ru="TV Tuner Digital Multimedia (LL_TVTunerUDS)",
        details_en="TV Tuner Digital Multimedia (LL_TVTunerUDS)",
        notes_ru="При дооснащении в ранее пустой банк 6 включайте обход маски 95640.",
        notes_en="When retrofitting into previously empty Bank 6, enable the 95640 EEPROM mask bypass.",
        aliases=("tv", "tvtuner"),
    ),
    SlotSpec(
        slot=7,
        ecu_addr="5F",
        nvm_id=0x66,
        mask_bit=6,
        can_suffix=0x73,
        uds_req="0x773",
        uds_resp="0x7DD",
        off1=0xC600,
        off2=0xC680,
        rec_size=0x42,
        short_ru="Мультимедиа / ГУ MIB1/MIB2/MIB3 (J794)",
        short_en="Infotainment MIB1/MIB2/MIB3 (J794)",
        details_ru="Information Electronics 1 — MIB STD / High (LL_InforElectUDS)",
        details_en="Information Electronics 1 — MIB STD / High (LL_InforElectUDS)",
        notes_ru=(
            "На MIB2 STD TechniSat/Preh рабочий ключ IKA лежит в зашифрованной I2C EEPROM M30 "
            "(запись 0x80000002/3); на Harman/Delphi читается программатором или из IFS/EEPROM."
        ),
        notes_en=(
            "On TechniSat/Preh MIB2 STD, the active IKA key is stored in encrypted M30 I2C EEPROM "
            "(record 0x80000002/3); on Harman/Delphi it can be read via programmer or IFS/EEPROM."
        ),
        aliases=("mib", "mib2", "mib3", "infotainment", "mmi"),
    ),
    SlotSpec(
        slot=8,
        ecu_addr="3C",
        nvm_id=0x67,
        mask_bit=7,
        can_suffix=0x4E,
        uds_req="0x74E",
        uds_resp="0x7B8",
        off1=0xC700,
        off2=0xC780,
        rec_size=0x42,
        short_ru="Ассистент смены полосы 1 Master (J769/J1086)",
        short_en="Lane Change / Side Assist 1 Master (J769)",
        details_ru="Lane Change Assist / Side Assist Master Radar (LL_LaneChangAssisUDS, напр. 2Q0 907 686)",
        details_en="Lane Change Assist / Side Assist Master Radar (LL_LaneChangAssisUDS, e.g. 2Q0 907 686)",
        notes_ru=(
            "Радары слепых зон поколения 2Q0 907 686 имеют защиту компонентов CP. "
            "Второй (ведомый) радар CF при необходимости использует соседний Банк 9."
        ),
        notes_en=(
            "2Q0 907 686 generation Side Assist radars use Component Protection. "
            "If the slave radar CF also participates in CP, it uses adjacent Bank 9."
        ),
        aliases=("swa", "swa1", "sideassist", "bsd"),
    ),
    SlotSpec(
        slot=9,
        ecu_addr="CF",
        nvm_id=0x68,
        mask_bit=8,
        can_suffix=0x8A,
        uds_req="0x17FC008A",
        uds_resp="0x17FE008A",
        off1=0xC800,
        off2=0xC880,
        rec_size=0x42,
        short_ru="Ассистент смены полосы 2 Slave (J770/J1087)",
        short_en="Lane Change / Side Assist 2 Slave (J770)",
        details_ru="Lane Change Assist 2 Slave Radar (29-bit UDS 0x17FC008A / 0x17FE008A)",
        details_en="Lane Change Assist 2 Slave Radar (29-bit UDS 0x17FC008A / 0x17FE008A)",
        notes_ru="Ведомый радар Side Assist 2 (диагностика только по 29-bit Extended CAN).",
        notes_en="Slave Side Assist 2 radar (diagnosed exclusively over 29-bit Extended CAN).",
        aliases=("swa2", "bsd2"),
    ),
    SlotSpec(
        slot=10,
        ecu_addr="3D",
        nvm_id=0x69,
        mask_bit=9,
        can_suffix=0x2C,
        uds_req="0x72C",
        uds_resp="0x796",
        off1=0xC900,
        off2=0xC980,
        rec_size=0x42,
        short_ru="Спецфункции / спецтранспорт (J608)",
        short_en="Special Function Module (J608)",
        details_ru="Special Function Module — Taxi / Police / Driving School (LL_SpeciFunctUDS, 5Q0 907 410)",
        details_en="Special Function Module — Taxi / Police / Driving School (LL_SpeciFunctUDS, 5Q0 907 410)",
        notes_ru="Модуль специальных автомобилей J608 (редкая комплектация).",
        notes_en="Special-purpose vehicle module J608 (rare fleet option).",
        aliases=("specfunc", "j608", "taxi"),
    ),
    SlotSpec(
        slot=11,
        ecu_addr="A5",
        nvm_id=0x6A,
        mask_bit=10,
        can_suffix=0x4F,
        uds_req="0x74F",
        uds_resp="0x7B9",
        off1=0xCA00,
        off2=0xCA80,
        rec_size=0x42,
        short_ru="Передняя камера ассистентов MFK3 (R242)",
        short_en="Front Assist Camera MFK3 (R242)",
        details_ru="Front Sensors Driver Assistance Camera (LL_FrontSensoDriveAssisSysteUDS, напр. 2Q0 980 653)",
        details_en="Front Sensors Driver Assistance Camera (LL_FrontSensoDriveAssisSysteUDS, e.g. 2Q0 980 653)",
        notes_ru=(
            "Камеры 3Q0 980 654 (MFK2) не имели CP, а новые камеры 2Q0 980 653 (Valeo MFK3, ~2020+) "
            "используют Банк 11 (активен с завода на свежих Kodiaq/Octavia/Tiguan)."
        ),
        notes_en=(
            "Older 3Q0 980 654 (MFK2) cameras had no CP, whereas newer 2Q0 980 653 (Valeo MFK3, ~2020+) "
            "cameras use Bank 11 (factory active on late MQB Kodiaq/Octavia/Tiguan)."
        ),
        aliases=("camera", "mfk3", "frontcam", "adas"),
    ),
    SlotSpec(
        slot=12,
        ecu_addr="8C",
        nvm_id=0x6B,
        mask_bit=11,
        can_suffix=0x7B,
        uds_req="0x17FC007B",
        uds_resp="0x17FE007B",
        off1=0xCB00,
        off2=0xCB80,
        rec_size=0x40,
        short_ru="Управление ВВ-батареей гибрида/EV (J840)",
        short_en="Hybrid / EV HV Battery Mgmt BMS (J840)",
        details_ru="HV Battery Management BMS_MQB (KN_Hybrid_01 Hybrid_KompSchutz, 29-bit UDS, sz=0x40)",
        details_en="HV Battery Management BMS_MQB (KN_Hybrid_01 Hybrid_KompSchutz, 29-bit UDS, sz=0x40)",
        notes_ru=(
            "Банк гибридных версий GTE / e-Golf / PHEV (размер записи NvM = 0x40 байт, CRC-32 на +0x44). "
            "Утилита автоматически форматирует 0x40-байтную структуру для этого банка."
        ),
        notes_en=(
            "Used on GTE / e-Golf / PHEV vehicles (NvM record size = 0x40 bytes, CRC-32 at +0x44). "
            "This tool automatically formats the 0x40-byte layout for Bank 12."
        ),
        aliases=("bms", "hybrid", "gte", "hvbattery"),
    ),
)

MASTER_SLOT = SlotSpec(
    slot=0,
    ecu_addr="19",
    nvm_id=0x7B,
    mask_bit=None,
    can_suffix=0x00,
    uds_req="0x710",
    uds_resp="0x77A",
    off1=0xDA00,
    off2=0xDA80,
    rec_size=0x42,
    short_ru="Прикладной мастер-ключ шлюза 19 (Master/GFA)",
    short_en="Gateway 19 App Master Key (Master / GFA)",
    details_ru="Gateway Application Master Key GFA (NvM 0x7B, key_type=3 — НЕ ТРОГАТЬ на рабочей машине!)",
    details_en="Gateway Application Master Key GFA (NvM 0x7B, key_type=3 — DO NOT TOUCH on a live car!)",
    notes_ru=(
        "1) Это прикладной мастер-ключ самого шлюза 19 (GFA, NvM 0x7B, key_type=3): в CAN-обмене CP с\n"
        "ведомыми блоками 1..12 он НИКОГДА не участвует (0x0008C94E грузит только IKA key_type=6),\n"
        "и вычислить из него ключи IKA блоков невозможно.\n"
        "2) Зачем нужен: проверяет AES-CMAC онлайн-команд FAZIT/ODIS (UDS 0x2E 02C5, auth_mode=3 @\n"
        "0x0008AE44) и взводит флаг «шлюз обучен как Master CP» (0xFEDFC988 bit 0 @ 0x0008E184).\n"
        "3) ОПАСНО: если стереть или повредить 0xDA00 на рабочей машине, шлюз 19 упадёт в ошибку CP\n"
        "и принудительно подставит key_type=8 (разовый случайный мусор @ 0x0008C968) во ВСЕ 12 банков —\n"
        "все блоки в машине выпадут в Component Protection Active! Оставляйте 0xDA00 нетронутым\n"
        "(запись через --force-master нужна ТОЛЬКО для офлайн-запуска нового пустого Virgin-шлюза FF..FF)."
    ),
    notes_en=(
        "1) Gateway 19 own Application Master Key (GFA, NvM 0x7B, key_type=3): NEVER used in CAN CP\n"
        "handshakes with slave ECUs 1..12 (0x0008C94E only loads IKA key_type=6), and CANNOT derive IKA.\n"
        "2) Actual roles: verifies AES-CMAC of online FAZIT/ODIS containers (UDS 0x2E 02C5, auth_mode=3 @\n"
        "0x0008AE44) and sets Gateway Master CP status (0xFEDFC988 bit 0 @ 0x0008E184).\n"
        "3) DANGER: erasing or corrupting 0xDA00 on a live car drops Gateway 19 out of Master status and\n"
        "forces key_type=8 (random dummy keys @ 0x0008C968) onto ALL 12 slave banks — putting every ECU\n"
        "in the car into Component Protection Active! Leave 0xDA00 untouched (--force-master is ONLY\n"
        "for offline bench/swap initialization of a brand-new Virgin FF..FF gateway)."
    ),
    aliases=("master", "gw"),
)

ALL_SLOTS: tuple[SlotSpec, ...] = (*SLAVE_SLOTS, MASTER_SLOT)


def clean_user_path(raw: str | Path) -> Path:
    """Normalize user path input (handles quotes & escaped spaces)."""
    if isinstance(raw, Path):
        return raw.expanduser()
    s = raw.strip()
    if len(s) >= 2 and ((s[0] == "'" and s[-1] == "'") or (s[0] == '"' and s[-1] == '"')):
        s = s[1:-1]
    elif sys.platform != "win32" and not re.match(r"[A-Za-z]:[\\/]|\\\\", s):  # a backslash separates Windows paths
        s = re.sub(r"\\([ ()\[\]{}&'!#$~])", r"\1", s)
    return Path(os.path.expanduser(s))
