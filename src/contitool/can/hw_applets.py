"""Firmware-independent RH850/F1L hardware reader applets for OPBT and ST M95640 SPI EEPROM.

Constructed programmatically from documented Renesas RH850/F1L peripheral registers so that
reading Option Bytes (`Extra Area @ 0xFF300070..0xFF300093`) and the external 8 KB SPI EEPROM
(`ST M95640` on `CSIH1` / `Port 10`) does not depend on firmware-specific CodeFlash addresses.
Both applets are strictly read-only and restore all modified MCU registers before returning.
"""

from __future__ import annotations

import hashlib
import struct

RESULT_BASE = 0xFEDE9000
EEPROM_DATA_BASE = 0xFEDEA000

# Renesas RH850/F1L registers (R01UH0390EJ0133)
BFASELR = 0xFFC59008
EXTRA_AREA_BASE = 0xFF300000
FLASH_CFCNT = 0xFFBC0700

WDTA0_BASE = 0xFFED0000
WDTA1_BASE = 0xFFED1000

P10 = 0xFFC10028
PPR10 = 0xFFC10228
PM10 = 0xFFC10328
PMC10 = 0xFFC10428
PFC10 = 0xFFC10528
PFCE10 = 0xFFC10628
PFCAE10 = 0xFFC10A28
PIBC10 = 0xFFC14028
PBDC10 = 0xFFC14128
PIPC10 = 0xFFC14228
PODC10 = 0xFFC14528

PORT10_REGISTERS: tuple[int, ...] = (
    P10,
    PM10,
    PMC10,
    PFC10,
    PFCE10,
    PFCAE10,
    PIBC10,
    PBDC10,
    PIPC10,
    PODC10,
)
PORT10_RESTORE_ORDER: tuple[int, ...] = (
    P10,
    PMC10,
    PFC10,
    PFCE10,
    PFCAE10,
    PIBC10,
    PBDC10,
    PIPC10,
    PODC10,
    PM10,
)

CSIH1CTL0 = 0xFFD82000
CSIH1STR0 = 0xFFD82004
CSIH1STCR0 = 0xFFD82008
CSIH1CTL1 = 0xFFD82010
CSIH1CTL2 = 0xFFD82014
CSIH1MCTL0 = 0xFFD8207F
CSIH1TX0H = 0xFFD8300C
CSIH1RX0H = 0xFFD83014
CSIH1CFG0 = 0xFFD83044
CSIH1BRS0 = 0xFFD83068

CSIH1_SAVED_REGISTERS: tuple[tuple[int, int], ...] = (
    (CSIH1CTL0, 8),
    (CSIH1CFG0, 32),
    (CSIH1CTL1, 16),
    (CSIH1CTL2, 16),
    (CSIH1BRS0, 16),
    (CSIH1MCTL0, 8),
    (CSIH1TX0H, 16),
)

_COND_BE = 0x2
_COND_BNE = 0xA
_COND_BR = 0x5


class _Rh850Builder:
    """Minimal deterministic V850E3v5 instruction emitter with constant-width label branches."""

    def __init__(self) -> None:
        self._items: list[bytes | tuple[str, str, int]] = []
        self._labels: dict[str, int] = {}
        self._pc = 0

    def _emit(self, raw: bytes) -> None:
        self._items.append(raw)
        self._pc += len(raw)

    def label(self, name: str) -> None:
        if name in self._labels:
            raise ValueError(f"Duplicate label: {name}")
        self._labels[name] = self._pc

    def di(self) -> None:
        self._emit(struct.pack("<HH", 0x07E0, 0x0160))

    def ei(self) -> None:
        self._emit(struct.pack("<HH", 0x87E0, 0x0160))

    def synci(self) -> None:
        self._emit(struct.pack("<H", 0x001C))

    def nop(self) -> None:
        self._emit(struct.pack("<H", 0x0000))

    def jmp_lp(self) -> None:
        self._emit(struct.pack("<H", 0x007F))

    def mov_imm(self, imm32: int, reg: int) -> None:
        if not 1 <= reg <= 31:
            raise ValueError(f"Invalid register r{reg}")
        self._emit(struct.pack("<HI", 0x0620 | reg, imm32 & 0xFFFFFFFF))

    def mov_reg(self, src: int, dst: int) -> None:
        self._emit(struct.pack("<H", 0x0000 | (src & 0x1F) | ((dst & 0x1F) << 11)))

    def add_imm5(self, imm5: int, reg: int) -> None:
        if not -16 <= imm5 <= 15:
            raise ValueError(f"imm5 out of range: {imm5}")
        self._emit(struct.pack("<H", 0x0240 | (imm5 & 0x1F) | ((reg & 0x1F) << 11)))

    def addi(self, imm16: int, src: int, dst: int) -> None:
        self._emit(struct.pack("<HH", 0x0600 | (src & 0x1F) | ((dst & 0x1F) << 11), imm16 & 0xFFFF))

    def andi(self, imm16: int, src: int, dst: int) -> None:
        self._emit(struct.pack("<HH", 0x06C0 | (src & 0x1F) | ((dst & 0x1F) << 11), imm16 & 0xFFFF))

    def ori(self, imm16: int, src: int, dst: int) -> None:
        self._emit(struct.pack("<HH", 0x0680 | (src & 0x1F) | ((dst & 0x1F) << 11), imm16 & 0xFFFF))

    def xori(self, imm16: int, src: int, dst: int) -> None:
        self._emit(struct.pack("<HH", 0x06A0 | (src & 0x1F) | ((dst & 0x1F) << 11), imm16 & 0xFFFF))

    def cmp_imm5(self, imm5: int, reg: int) -> None:
        if not -16 <= imm5 <= 15:
            raise ValueError(f"imm5 out of range: {imm5}")
        self._emit(struct.pack("<H", 0x0260 | (imm5 & 0x1F) | ((reg & 0x1F) << 11)))

    def cmp_reg(self, r1: int, r2: int) -> None:
        self._emit(struct.pack("<H", 0x01E0 | (r1 & 0x1F) | ((r2 & 0x1F) << 11)))

    def subr(self, r1: int, r2: int) -> None:
        """`r2 <- r1 - r2` (Format I `001100`)."""
        self._emit(struct.pack("<H", 0x0180 | (r1 & 0x1F) | ((r2 & 0x1F) << 11)))

    def ld_w(self, disp: int, base: int, dst: int) -> None:
        if disp & 3:
            raise ValueError(f"Unaligned ld.w disp: {disp}")
        self._emit(struct.pack("<HH", 0x0720 | (base & 0x1F) | ((dst & 0x1F) << 11), (disp & 0xFFFE) | 1))

    def st_w(self, src: int, disp: int, base: int) -> None:
        if disp & 3:
            raise ValueError(f"Unaligned st.w disp: {disp}")
        self._emit(struct.pack("<HH", 0x0760 | (base & 0x1F) | ((src & 0x1F) << 11), (disp & 0xFFFE) | 1))

    def ld_hu(self, disp: int, base: int, dst: int) -> None:
        if disp & 1:
            raise ValueError(f"Unaligned ld.hu disp: {disp}")
        self._emit(struct.pack("<HH", 0x07E0 | (base & 0x1F) | ((dst & 0x1F) << 11), (disp & 0xFFFE) | 1))

    def st_h(self, src: int, disp: int, base: int) -> None:
        if disp & 1:
            raise ValueError(f"Unaligned st.h disp: {disp}")
        self._emit(struct.pack("<HH", 0x0760 | (base & 0x1F) | ((src & 0x1F) << 11), disp & 0xFFFE))

    def ld_bu_0(self, base: int, dst: int) -> None:
        if not 1 <= dst <= 31:
            raise ValueError("ld.bu destination cannot be r0")
        self._emit(struct.pack("<HH", 0x0780 | (base & 0x1F) | ((dst & 0x1F) << 11), 0x0001))

    def st_b(self, src: int, disp: int, base: int) -> None:
        self._emit(struct.pack("<HH", 0x0740 | (base & 0x1F) | ((src & 0x1F) << 11), disp & 0xFFFF))

    def stsr(self, reg_id: int, dst: int, sel_id: int) -> None:
        hw0 = 0x07E0 | (reg_id & 0x1F) | ((dst & 0x1F) << 11)
        hw1 = 0x0040 | ((sel_id & 0x1F) << 11)
        self._emit(struct.pack("<HH", hw0, hw1))

    def ldsr(self, src: int, reg_id: int, sel_id: int) -> None:
        hw0 = 0x07E0 | (src & 0x1F) | ((reg_id & 0x1F) << 11)
        hw1 = 0x0020 | ((sel_id & 0x1F) << 11)
        self._emit(struct.pack("<HH", hw0, hw1))

    def _bcond9_raw(self, cond: int, disp: int) -> bytes:
        d = disp & 0x1FE
        hw = 0x0580 | (cond & 0xF) | (((d >> 1) & 0x7) << 4) | (((d >> 4) & 0x1F) << 11)
        return struct.pack("<H", hw)

    def jr(self, label: str) -> None:
        self._items.append(("jr", label, self._pc))
        self._pc += 4

    def jarl(self, label: str) -> None:
        self._items.append(("jarl", label, self._pc))
        self._pc += 4

    def be(self, label: str) -> None:
        # Emit `bne +6` (skips the 4-byte `jr label`) followed by `jr label`
        self._emit(self._bcond9_raw(_COND_BNE, 6))
        self.jr(label)

    def bne(self, label: str) -> None:
        # Emit `be +6` (skips the 4-byte `jr label`) followed by `jr label`
        self._emit(self._bcond9_raw(_COND_BE, 6))
        self.jr(label)

    def save_context(self) -> None:
        """Disable interrupts, sync I-cache, and save r20..r29, ep (r30), and lp (r31) on stack."""
        self.di()
        self.synci()
        self.addi(-48, 3, 3)
        for i, reg in enumerate((*range(20, 30), 30, 31)):
            self.st_w(reg, i * 4, 3)

    def restore_context_and_return(self) -> None:
        """Restore r20..r29, ep (r30), lp (r31), re-enable interrupts, and return to RAM-loader."""
        for i, reg in enumerate((*range(20, 30), 30, 31)):
            self.ld_w(i * 4, 3, reg)
        self.addi(48, 3, 3)
        self.ei()
        self.jmp_lp()

    def build(self) -> bytes:
        out = bytearray()
        for item in self._items:
            if isinstance(item, bytes):
                out.extend(item)
                continue
            kind, target_name, pc = item
            if target_name not in self._labels:
                raise KeyError(f"Undefined branch target: {target_name}")
            disp = self._labels[target_name] - pc
            if (disp & 1) != 0 or not (-0x200000 <= disp <= 0x1FFFFE):
                raise ValueError(f"{kind} displacement out of range: {disp}")
            u22 = disp & 0x3FFFFF
            if kind == "jr":
                hw0 = 0x0780 | ((u22 >> 16) & 0x3F)
            else:
                hw0 = 0x0780 | (31 << 11) | ((u22 >> 16) & 0x3F)
            out.extend(struct.pack("<HH", hw0, u22 & 0xFFFE))
        return bytes(out)


def _emit_wdt_subroutine(b: _Rh850Builder, label_name: str = "SUB_WDT") -> None:
    """Refresh both WDTA0 (0xFFED0000) and WDTA1 (0xFFED1000) using RH850/F1L VAC sequence.

    Matches the hardware-verified sequence in `DFLASH_FACI_STUB` / `CFLASH_FACI_STUB`:
      1. `WDTAnWDTE (+0x00) = 0xAC`
      2. `ref = WDTAnREF (+0x08)`
      3. `WDTAnEVAC (+0x04) = (0xAC - ref) & 0xFF`
    Uses caller-saved r11, r12, r13 only so r6..r10 and r20..r29 remain untouched.
    """
    b.label(label_name)
    b.mov_imm(0xAC, 13)
    for wdt_base in (WDTA0_BASE, WDTA1_BASE):
        b.mov_imm(wdt_base, 11)
        b.st_b(13, 0x00, 11)
        b.mov_imm(wdt_base + 0x08, 12)
        b.ld_bu_0(12, 12)
        b.subr(13, 12)
        b.st_b(12, 0x04, 11)
    b.jmp_lp()


def _emit_bfaselr_switch_subroutine(b: _Rh850Builder, label_name: str = "SUB_SWITCH_BFLASH") -> None:
    """Switch BFASELR (`r6` = 0 or 1) and flush RH850 I-cache + flash code buffer (`0xFFBC0700`)."""
    b.label(label_name)
    b.mov_imm(BFASELR, 11)
    b.st_b(6, 0, 11)
    b.ld_bu_0(11, 12)
    b.synci()
    # Flush CPU instruction cache via ICCTRL (SR 24, sel 4, bit 8 = ICHCLR)
    b.stsr(24, 12, 4)
    b.ori(0x0100, 12, 12)
    b.ldsr(12, 24, 4)
    b.label("_ICACHE_WAIT")
    b.stsr(24, 12, 4)
    b.andi(0x0100, 12, 12)
    b.cmp_imm5(0, 12)
    b.bne("_ICACHE_WAIT")
    b.synci()
    # Flush Flash Code Buffer CFCNT (0xFFBC0700): write 1 -> readback -> write 0 -> readback -> synci
    b.mov_imm(FLASH_CFCNT, 11)
    b.mov_imm(1, 12)
    b.st_b(12, 0, 11)
    b.ld_bu_0(11, 12)
    b.st_b(0, 0, 11)
    b.ld_bu_0(11, 12)
    b.synci()
    b.jmp_lp()


def build_opbt_reader_payload() -> bytes:
    """Build RAM-loader applet that reads 256-byte Extra Area (`0xFF300000..0xFF3000FF`) into `0xFEDE9100`.

    Result header at `0xFEDE9000`:
      - `+0x000`: `status` (`1` = success and `BFASELR == 0` verified, `0` = failure)
      - `+0x004`: initial `BFASELR` (`0xFFC59008`)
      - `+0x008`: final `BFASELR` (`0xFFC59008` after restore)
      - `+0x100..+0x1FF`: 256-byte Extra Area (`+0x170..+0x193` = `OPBT0..OPBT8`, 36 bytes)
    """
    b = _Rh850Builder()
    b.save_context()

    b.mov_imm(RESULT_BASE, 20)
    b.st_w(0, 0x00, 20)
    b.st_w(0, 0x04, 20)
    b.st_w(0, 0x08, 20)

    # Record initial BFASELR
    b.mov_imm(BFASELR, 6)
    b.ld_bu_0(6, 7)
    b.st_w(7, 0x04, 20)

    b.jarl("SUB_WDT")

    # Map Extra Area (BFASELR = 1)
    b.mov_imm(1, 6)
    b.jarl("SUB_SWITCH_BFLASH")

    # Copy 64 words (256 bytes) from 0xFF300000 to 0xFEDE9100
    b.mov_imm(EXTRA_AREA_BASE, 23)
    b.mov_imm(RESULT_BASE + 0x100, 24)
    b.mov_imm(64, 25)
    b.label("COPY_EXTRA_LOOP")
    b.ld_w(0, 23, 7)
    b.st_w(7, 0, 24)
    b.add_imm5(4, 23)
    b.add_imm5(4, 24)
    b.add_imm5(-1, 25)
    b.cmp_imm5(0, 25)
    b.bne("COPY_EXTRA_LOOP")

    # Restore Normal CodeFlash view (BFASELR = 0)
    b.mov_imm(0, 6)
    b.jarl("SUB_SWITCH_BFLASH")

    # Verify BFASELR == 0
    b.mov_imm(BFASELR, 6)
    b.ld_bu_0(6, 7)
    b.st_w(7, 0x08, 20)
    b.mov_imm(1, 22)
    b.cmp_imm5(0, 7)
    b.be("OPBT_OK")
    b.mov_imm(0, 22)
    b.label("OPBT_OK")

    b.jarl("SUB_WDT")
    b.st_w(22, 0x00, 20)
    b.restore_context_and_return()

    _emit_bfaselr_switch_subroutine(b, "SUB_SWITCH_BFLASH")
    _emit_wdt_subroutine(b, "SUB_WDT")
    return b.build()


def _mod_port16(b: _Rh850Builder, addr: int, and_mask: int, or_mask: int = 0) -> None:
    b.mov_imm(addr, 6)
    b.ld_hu(0, 6, 7)
    if and_mask != 0xFFFF:
        b.andi(and_mask, 7, 7)
    if or_mask:
        b.ori(or_mask, 7, 7)
    b.st_h(7, 0, 6)


def _read_reg_to_word(b: _Rh850Builder, addr: int, width: int, dst_base_reg: int, dst_disp: int) -> None:
    b.mov_imm(addr, 6)
    if width == 8:
        b.ld_bu_0(6, 7)
    elif width == 16:
        b.ld_hu(0, 6, 7)
    else:
        b.ld_w(0, 6, 7)
    b.st_w(7, dst_disp, dst_base_reg)


def _emit_spi_xfer_subroutine(b: _Rh850Builder, label_name: str = "SUB_SPI_XFER") -> None:
    """Full-duplex 1-byte transfer on CSIH1 Direct Access Mode.

    Input:  `r6` = byte to transmit (`0x00..0xFF`)
    Output: `r7` = received byte (`0x00..0xFF`), `r10` = `1` on success or `0` on timeout.
    """
    b.label(label_name)
    b.mov_imm(CSIH1STR0, 11)
    # 1. Wait until CSIH1STR0.TSF (bit 7) == 0 before writing TX0H
    b.mov_imm(200_000, 12)
    b.label("_SPI_WAIT_IDLE")
    b.ld_bu_0(11, 13)
    b.andi(0x0080, 13, 13)
    b.cmp_imm5(0, 13)
    b.be("_SPI_WRITE_TX")
    b.add_imm5(-1, 12)
    b.cmp_imm5(0, 12)
    b.bne("_SPI_WAIT_IDLE")
    b.mov_imm(0, 10)
    b.jmp_lp()

    # 2. Write byte to CSIH1TX0H (16-bit register @ 0xFFD8300C) and flush peripheral write buffer
    b.label("_SPI_WRITE_TX")
    b.andi(0x00FF, 6, 13)
    b.mov_imm(CSIH1TX0H, 12)
    b.st_h(13, 0, 12)
    b.ld_bu_0(11, 13)  # dummy APB read to synchronize TSF assertion

    # 3. Wait until CSIH1STR0.TSF (bit 7) returns to 0
    b.mov_imm(200_000, 12)
    b.label("_SPI_WAIT_DONE")
    b.ld_bu_0(11, 13)
    b.andi(0x0080, 13, 13)
    b.cmp_imm5(0, 13)
    b.be("_SPI_READ_RX")
    b.add_imm5(-1, 12)
    b.cmp_imm5(0, 12)
    b.bne("_SPI_WAIT_DONE")
    b.mov_imm(0, 10)
    b.jmp_lp()

    # 4. Read received byte from CSIH1RX0H (@ 0xFFD83014)
    b.label("_SPI_READ_RX")
    b.mov_imm(CSIH1RX0H, 12)
    b.ld_hu(0, 12, 7)
    b.andi(0x00FF, 7, 7)
    b.mov_imm(1, 10)
    b.jmp_lp()


def build_m95640_reader_payload(length: int = 0x2000) -> bytes:
    """Build RAM-loader applet that reads ST M95640 SPI EEPROM (`CSIH1`, `P10.11` `CS#`) into `0xFEDEA000`.

    Result header at `0xFEDE9000` (512 bytes):
      - `+0x000`: `status` (`1` = success, `0` = SPI timeout / restore mismatch)
      - `+0x004`: `RDSR (0x05)` status register byte (`0x00..0xFF`)
      - `+0x008`: `bytes_read` (`8192` on full read)
      - `+0x010..+0x01F`: `PPR10` pin snapshots (initial, muxed, CS low, restored)
      - `+0x100..+0x127`: initial `Port 10` registers (`10 x u32`)
      - `+0x130..+0x14B`: initial `CSIH1` registers (`7 x u32`)
      - `+0x180..+0x1A7`: restored `Port 10` registers (`10 x u32`)
      - `+0x1B0..+0x1CB`: restored `CSIH1` registers (`7 x u32`)
    EEPROM data buffer:
      - `0xFEDEA000 .. 0xFEDEA000 + length - 1`
    """
    if not 1 <= length <= 0x2000:
        raise ValueError(f"M95640 read length must be in 1..8192, got {length}")

    b = _Rh850Builder()
    b.save_context()

    b.mov_imm(RESULT_BASE, 20)
    b.mov_imm(RESULT_BASE + 0x100, 21)
    b.st_w(0, 0x00, 20)
    b.st_w(0, 0x04, 20)
    b.st_w(0, 0x08, 20)
    b.mov_imm(0, 23)  # bytes_read = 0

    # 1. Save initial Port 10 & CSIH1 state before touching any hardware pin/register
    _read_reg_to_word(b, PPR10, 16, 20, 0x10)
    for idx, addr in enumerate(PORT10_REGISTERS):
        _read_reg_to_word(b, addr, 16, 21, idx * 4)
    for idx, (addr, width) in enumerate(CSIH1_SAVED_REGISTERS):
        _read_reg_to_word(b, addr, width, 21, 0x30 + idx * 4)

    b.jarl("SUB_WDT")

    # 2. Configure Port 10: P10.11 = GPIO CS# high; P10.0 (SI), P10.1 (SCK), P10.2 (SO) = CSIH1 Alt Mode
    _mod_port16(b, P10, 0xF7FF, 0x0800)
    for addr in (PFC10, PFCE10, PBDC10, PIPC10, PODC10):
        _mod_port16(b, addr, 0xF7F8, 0)
    _mod_port16(b, PMC10, 0xF7F8, 0x0007)
    _mod_port16(b, PFCAE10, 0xF7F8, 0x0007)
    _mod_port16(b, PIBC10, 0xFFFF, 0x0001)
    _mod_port16(b, PM10, 0xF7F8, 0x0001)

    # 3. Configure CSIH1 in Direct Access SPI Mode 0 (8-bit MSB-first, BRS0 = 8)
    b.mov_imm(CSIH1CTL0, 6)
    b.mov_imm(0x01, 7)  # MBS=1, PWR=0 so CFG0/CTL1/CTL2/MCTL0/BRS0 are write-enabled
    b.st_b(7, 0, 6)

    b.mov_imm(CSIH1MCTL0, 6)
    b.st_b(0, 0, 6)  # MMS=00 (Direct Access Mode)

    b.mov_imm(CSIH1STCR0, 6)
    b.mov_imm(0xFFFF, 7)
    b.st_h(7, 0, 6)

    b.mov_imm(CSIH1CFG0, 6)
    b.mov_imm(0x08000000, 7)  # 8-bit frame, SPI Mode 0 (CKP=0, DAP=0), MSB first
    b.st_w(7, 0, 6)

    b.mov_imm(CSIH1CTL1, 6)
    b.st_h(0, 0, 6)

    b.mov_imm(CSIH1CTL2, 6)
    b.st_h(0, 0, 6)

    b.mov_imm(CSIH1BRS0, 6)
    b.mov_imm(8, 7)
    b.st_h(7, 0, 6)

    b.mov_imm(CSIH1CTL0, 6)
    b.mov_imm(0xE1, 7)  # PWR=1, TXE=1, RXE=1, MBS=1
    b.st_b(7, 0, 6)

    _read_reg_to_word(b, PPR10, 16, 20, 0x14)

    # 4. Read Status Register: RDSR (0x05)
    _mod_port16(b, P10, 0xF7FF, 0)  # CS# low
    _read_reg_to_word(b, PPR10, 16, 20, 0x18)

    b.mov_imm(0x05, 6)
    b.jarl("SUB_SPI_XFER")
    b.cmp_imm5(1, 10)
    b.bne("SPI_FAIL")

    b.mov_imm(0x00, 6)
    b.jarl("SUB_SPI_XFER")
    b.cmp_imm5(1, 10)
    b.bne("SPI_FAIL")
    b.st_w(7, 0x04, 20)  # store RDSR byte at +0x004

    _mod_port16(b, P10, 0xF7FF, 0x0800)  # CS# high

    # 5. Sequential READ (0x03) from 0x0000 for `length` bytes into 0xFEDEA000
    b.mov_imm(0, 23)
    b.mov_imm(EEPROM_DATA_BASE, 24)
    b.mov_imm(length, 25)

    _mod_port16(b, P10, 0xF7FF, 0)  # CS# low
    for hdr_byte in (0x03, 0x00, 0x00):
        b.mov_imm(hdr_byte, 6)
        b.jarl("SUB_SPI_XFER")
        b.cmp_imm5(1, 10)
        b.bne("SPI_FAIL")

    b.label("EE_READ_LOOP")
    b.mov_imm(0x00, 6)
    b.jarl("SUB_SPI_XFER")
    b.cmp_imm5(1, 10)
    b.bne("SPI_FAIL")
    b.st_b(7, 0, 24)
    b.add_imm5(1, 23)
    b.add_imm5(1, 24)
    b.add_imm5(-1, 25)

    # Refresh WDTA0/WDTA1 every 128 bytes
    b.mov_reg(23, 6)
    b.andi(0x007F, 6, 6)
    b.cmp_imm5(0, 6)
    b.bne("EE_SKIP_WDT")
    b.jarl("SUB_WDT")
    b.label("EE_SKIP_WDT")

    b.cmp_imm5(0, 25)
    b.bne("EE_READ_LOOP")

    _mod_port16(b, P10, 0xF7FF, 0x0800)  # CS# high
    b.mov_imm(1, 22)
    b.jr("CLEANUP")

    b.label("SPI_FAIL")
    b.mov_imm(0, 22)

    # 6. Cleanup: deassert CS#, restore Port 10 & CSIH1 registers in safe hardware order
    b.label("CLEANUP")
    _mod_port16(b, P10, 0xF7FF, 0x0800)
    for addr in PORT10_RESTORE_ORDER:
        idx = PORT10_REGISTERS.index(addr)
        b.ld_w(idx * 4, 21, 7)
        b.mov_imm(addr, 6)
        b.st_h(7, 0, 6)

    # Clear PWR bit in CSIH1CTL0 before restoring configuration registers, then restore CSIH1CTL0 last
    b.mov_imm(CSIH1CTL0, 6)
    b.mov_imm(0x01, 7)
    b.st_b(7, 0, 6)
    for idx in range(1, len(CSIH1_SAVED_REGISTERS)):
        addr, width = CSIH1_SAVED_REGISTERS[idx]
        b.ld_w(0x30 + idx * 4, 21, 7)
        b.mov_imm(addr, 6)
        if width == 8:
            b.st_b(7, 0, 6)
        elif width == 16:
            b.st_h(7, 0, 6)
        else:
            b.st_w(7, 0, 6)
    b.ld_w(0x30, 21, 7)
    b.mov_imm(CSIH1CTL0, 6)
    b.st_b(7, 0, 6)

    # Snapshot restored registers for host-side verification
    _read_reg_to_word(b, PPR10, 16, 20, 0x1C)
    for idx, addr in enumerate(PORT10_REGISTERS):
        _read_reg_to_word(b, addr, 16, 21, 0x80 + idx * 4)
    for idx, (addr, width) in enumerate(CSIH1_SAVED_REGISTERS):
        _read_reg_to_word(b, addr, width, 21, 0xB0 + idx * 4)

    b.jarl("SUB_WDT")
    b.st_w(23, 0x08, 20)
    b.st_w(22, 0x00, 20)
    b.restore_context_and_return()

    _emit_spi_xfer_subroutine(b, "SUB_SPI_XFER")
    _emit_wdt_subroutine(b, "SUB_WDT")
    return b.build()


OPBT_READER_STUB = build_opbt_reader_payload()
EEPROM_M95640_READER_STUB = build_m95640_reader_payload()
EXPECTED_OPBT_READER_STUB_SHA256 = hashlib.sha256(OPBT_READER_STUB).hexdigest()
EXPECTED_EEPROM_READER_STUB_SHA256 = hashlib.sha256(EEPROM_M95640_READER_STUB).hexdigest()
