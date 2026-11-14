"""Synthetic RH850/J533 firmware & DataFlash test fixtures (zero private vehicle data)."""

from __future__ import annotations

import struct
import sys
import zlib

import pytest

from contitool.core.checksums import app_crc
from contitool.core.constants import (
    APP_BASE,
    APP_SIZE,
    CFLASH_SIZE,
    DFLASH_SIZE,
    DFLASH_SWAP_CRC_OFF,
    DFLASH_SWAP_NVM_OFF,
    DFLASH_SWAP_PAY_SIZE,
    FBL_EXP_OFFSET,
    FBL_MOD_OFFSET,
    FBL_PRESENCE_MAGIC,
    STOCK_A167_BE,
    STOCK_CCP_BLACKLIST_CMOV,
    STOCK_ENG_GATE_HEAD,
    STOCK_FBL_MODULUS,
    STOCK_MOVEA_0X40,
    STOCK_SWAP_MODULUS,
    STOCK_UFLASH_RSA_CMOV,
    SWAP_KEY_HDR,
    UFLASH_RSA_CMP_OFFSET,
    UFLASH_SIZE,
)


def make_synthetic_cflash() -> bytes:
    """Construct a valid 1.5 MB synthetic CodeFlash image with all RH850 signature sites & valid CRC-16."""
    prefix = bytearray(b"\xff" * APP_BASE)
    prefix[0xA240:0xA257] = b"TST-SYN01.01.260000001 "
    prefix[0xA257:0xA25A] = b"527"
    prefix[0xA25A:0xA265] = b"3Q0907530AR"
    prefix[0xAB00:0xAB10] = bytes.fromhex("0123456789ABCDEF1032547698BADCFE")
    prefix[FBL_EXP_OFFSET : FBL_EXP_OFFSET + 128] = (b"\x00" * 127) + b"\x03"
    prefix[FBL_MOD_OFFSET : FBL_MOD_OFFSET + 128] = STOCK_FBL_MODULUS
    struct.pack_into("<I", prefix, 0xC000, FBL_PRESENCE_MAGIC)

    app = bytearray(b"\xff" * APP_SIZE)
    app[0x13:0x15] = b"\xff\xff"  # CRC-16/MODBUS init = 0xFFFF
    struct.pack_into("<HH", app, 0x1C, 0, 1)
    struct.pack_into("<II", app, 0x20, APP_BASE + 0x40, CFLASH_SIZE - 1)

    # 1. KSCHUTZ hook site (@ +0x80000 -> vaddr 0x08C200, well within jr disp22 of 0x16FF80)
    k_off = 0x80000
    k_blob = (
        b"\x21\x06\x00\x00\xdf\xfe\x01\x87\x11\x00\x62\x82\xda\x0d\x01\xf0"
        + STOCK_MOVEA_0X40
        + b"\x30\x06\x00\x00\x08\x00\x8c\x7b"
    )
    app[k_off : k_off + len(k_blob)] = k_blob

    # 2. 95640 SPI EEPROM learned-bank bitmask check (@ +0x81000)
    m_off = 0x81000
    m_blob = (
        b"\x83\xf7\x03\x00\x21\x06\x00\x00\xdf\xfe\xc1\xf1\xa3\x0f\x03\x00\x60\x80\x50\x09"
        b"\x82\x3d"
        b"\x40\x36\xe0\xfe"
    )
    app[m_off : m_off + len(m_blob)] = m_blob

    # 3. Engineering Feature 0x80/81/83 gate (@ +0x82000)
    e_off = 0x82000
    e_blob = (
        STOCK_ENG_GATE_HEAD
        + b"\x81\x0f\x00\x00"
        + b"\xe0\x09\xba\x05\x02\x52\x7f\x00\x86\x00\x06\x0e\x80\xff\x01\x06\xf0\xff\xa1\x1d\x01\x82"
    )
    app[e_off : e_off + len(e_blob)] = e_blob

    # 4. CCP_CheckAddr blacklist (@ +0x83000)
    c_off = 0x83000
    c_blob = (
        b"\xc1\xf1\x00\x85\x02\x0d\xf0\xd1\xc1\x05\xe1\xd9"
        + STOCK_CCP_BLACKLIST_CMOV
        + b"\x41\xea\x9d\x00"
    )
    app[c_off : c_off + len(c_blob)] = c_blob

    # 5. OTP 0xA167 RAM-loader branch (@ +0x84000)
    a_off = 0x84000
    a_blob = b"\x40\x0e\x01\x00\x81\x0f\x67\xa1\x01\x06\x01\xff" + STOCK_A167_BE
    app[a_off : a_off + len(a_blob)] = a_blob

    # 6. SWaP RSA-1024 public modulus (@ +0x85000)
    s_off = 0x85000
    s_blob = SWAP_KEY_HDR + STOCK_SWAP_MODULUS
    app[s_off : s_off + len(s_blob)] = s_blob

    _, calc = app_crc(app)
    struct.pack_into("<H", app, 0x1C, calc)
    return bytes(prefix) + bytes(app)


def make_synthetic_dflash() -> bytes:
    """Construct a valid 64 KB synthetic DataFlash image with initialized NvM 0x7C SWaP cache."""
    df = bytearray(b"\xff" * DFLASH_SIZE)
    struct.pack_into("<I", df, DFLASH_SWAP_NVM_OFF, 0x55555555)
    pay = bytearray(DFLASH_SWAP_PAY_SIZE)
    pay[0x000:0x080] = STOCK_SWAP_MODULUS
    pay[0x080:0x100] = (b"\x00" * 127) + b"\x03"
    pay[0x108:0x10D] = bytes.fromhex("1122334455")
    pay[0x10D] = 1
    df[DFLASH_SWAP_NVM_OFF + 4 : DFLASH_SWAP_NVM_OFF + 4 + DFLASH_SWAP_PAY_SIZE] = pay
    crc = zlib.crc32(pay) & 0xFFFFFFFF
    struct.pack_into("<I", df, DFLASH_SWAP_CRC_OFF, crc)
    return bytes(df)


def make_synthetic_uflash() -> bytes:
    """Construct a valid 32 KB synthetic Uflash image with stock RSA verification anchor @ +0x342A."""
    uf = bytearray(b"\xff" * UFLASH_SIZE)
    uf[:0x4000] = b"\x00" * 0x4000
    uf[UFLASH_RSA_CMP_OFFSET - 6 : UFLASH_RSA_CMP_OFFSET] = bytes.fromhex("80ff38158051")
    uf[UFLASH_RSA_CMP_OFFSET : UFLASH_RSA_CMP_OFFSET + 4] = STOCK_UFLASH_RSA_CMOV
    uf[UFLASH_RSA_CMP_OFFSET + 4 : UFLASH_RSA_CMP_OFFSET + 10] = bytes.fromhex("1d504006ff00")
    return bytes(uf)


@pytest.fixture(autouse=True, scope="session")
def _isolated_qsettings(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Keep GUI tests away from real ContiTool settings (recent folders, adapter, history)."""
    from PySide6.QtCore import QSettings

    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path_factory.mktemp("qsettings")))


@pytest.fixture(autouse=True)
def _runs_in_tmp(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Session folders of a test go to a temp folder, never next to pytest (.venv/bin) or into the repository's
    contitool_runs with real bench data: storage.app_dir(), behind runs_root() and the GUI's conn.out_dir, takes the
    folder of the launcher in sys.argv[0]."""
    launcher = tmp_path_factory.mktemp("app") / "conti_cp_tool.py"
    launcher.touch()
    monkeypatch.setattr(sys, "argv", [str(launcher)])


@pytest.fixture(autouse=True)
def _cleanup_qt_top_level_widgets():
    """Destroy top-level Qt widgets after each test to prevent Python 3.15 / Shiboken6 teardown segfaults."""
    yield
    import gc
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QApplication
    from contitool.i18n import _LISTENERS

    app = QApplication.instance()
    if isinstance(app, QApplication):
        for w in list(app.topLevelWidgets()):
            w.close()
            w.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
        _LISTENERS.clear()
        gc.collect()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)


@pytest.fixture
def synth_cflash() -> bytes:
    return make_synthetic_cflash()


@pytest.fixture
def synth_dflash() -> bytes:
    return make_synthetic_dflash()


@pytest.fixture
def synth_uflash() -> bytes:
    return make_synthetic_uflash()
