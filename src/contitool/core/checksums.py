"""Application CRC-16/MODBUS calculation for Continental J533 CodeFlash / FD_0DATA."""

from __future__ import annotations

import struct

from contitool.core.constants import APP_BASE, CFLASH_SIZE
from contitool.i18n import tr


def _make_crc16_reflected_table() -> tuple[int, ...]:
    tbl: list[int] = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = ((c >> 1) ^ 0xA001) if (c & 1) else (c >> 1)
        tbl.append(c & 0xFFFF)
    return tuple(tbl)


_CRC16_TABLE = _make_crc16_reflected_table()


def crc16_reflected(data: bytes | bytearray | memoryview, crc: int) -> int:
    """Reflected CRC-16, poly=0xA001, xorout=0 (with init 0xFFFF: CRC-16/MODBUS)."""
    tbl = _CRC16_TABLE
    c = crc & 0xFFFF
    for b in data:
        c = (c >> 8) ^ tbl[(c ^ b) & 0xFF]
    return c


def app_crc(app: bytes | bytearray) -> tuple[int, int]:
    """Return (stored_crc, calculated_crc) using the Application block header @ 0x0000C200."""
    stored, count = struct.unpack_from("<HH", app, 0x1C)
    crc = (app[0x13] << 8) | app[0x14]
    if not 1 <= count <= 8:
        raise ValueError(
            tr(
                f"Неожиданное число диапазонов CRC ({count}) в заголовке @ 0xC21E",
                f"Unexpected CRC range count ({count}) in block header @ 0xC21E",
            )
        )
    mv = memoryview(app)
    for i in range(count):
        start, end = struct.unpack_from("<II", app, 0x20 + 8 * i)
        if not (APP_BASE + 0x40 <= start <= end < CFLASH_SIZE):
            raise ValueError(
                tr(
                    f"Диапазон CRC #{i} 0x{start:06X}..0x{end:06X} выходит за пределы приложения",
                    f"CRC range #{i} 0x{start:06X}..0x{end:06X} is out of application bounds",
                )
            )
        crc = crc16_reflected(mv[start - APP_BASE : end - APP_BASE + 1], crc)
    return stored, crc
