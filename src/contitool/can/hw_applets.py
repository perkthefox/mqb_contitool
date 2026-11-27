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

FLMDCNT = 0xFFA00000
FLMDPCMD = 0xFFA00004
FLMDPS = 0xFFA00008
FLID_BASE = 0xFFA08000
FACI_BASE = 0xFFA10000
FACI_CMD = 0xFFA20000

FACI_FPMON_OFF = 0x00
FACI_FASTAT_OFF = 0x10
FACI_FAREASELC_OFF = 0x20
FACI_FSADDR_OFF = 0x30
FACI_FEADDR_OFF = 0x34
FACI_FSTATR_OFF = 0x80
FACI_FENTRYR_OFF = 0x84
FACI_FPROTR_OFF = 0x88
FACI_FPCKAR_OFF = 0xE4

PAYLOAD_ENTRY_ADDR = 0xFEDF8138
SELFID_CODEFLASH_ADDR = 0x0000AB00
UFLASH_BASE_ADDR = 0x01000000
UFLASH_END_ADDR = 0x01007FFF

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
        self._items: list[bytes | tuple[object, ...]] = []
        self._labels: dict[str, int] = {}
        self._pc = 0

    @property
    def pc(self) -> int:
        return self._pc

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

    def syncp(self) -> None:
        self._emit(struct.pack("<H", 0x001F))

    def nop(self) -> None:
        self._emit(struct.pack("<H", 0x0000))

    def align(self, boundary: int = 4) -> None:
        """Pad with 2-byte `nop` instructions until `pc` is a multiple of `boundary`."""
        if boundary <= 0 or boundary % 2 != 0:
            raise ValueError(f"Alignment boundary must be a positive even integer, got {boundary}")
        while self._pc % boundary != 0:
            self.nop()

    def jmp_lp(self) -> None:
        self._emit(struct.pack("<H", 0x007F))

    def mov_imm(self, imm32: int, reg: int) -> None:
        if not 1 <= reg <= 31:
            raise ValueError(f"Invalid register r{reg}")
        self._emit(struct.pack("<HI", 0x0620 | reg, imm32 & 0xFFFFFFFF))

    def mov_imm5(self, imm5: int, reg: int) -> None:
        if not 1 <= reg <= 31 or not -16 <= imm5 <= 15:
            raise ValueError(f"Invalid mov_imm5({imm5}, r{reg})")
        self._emit(struct.pack("<H", 0x0200 | (imm5 & 0x1F) | ((reg & 0x1F) << 11)))

    def mov_u16(self, val16: int, reg: int) -> None:
        if not 1 <= reg <= 31 or not 0 <= val16 <= 0xFFFF:
            raise ValueError(f"Invalid mov_u16(0x{val16:X}, r{reg})")
        if val16 <= 15:
            self.mov_imm5(val16, reg)
        else:
            self.ori(val16, 0, reg)

    def mov_label_addr(self, label: str, reg: int, base_addr: int = PAYLOAD_ENTRY_ADDR) -> None:
        if not 1 <= reg <= 31:
            raise ValueError(f"Invalid register r{reg}")
        self._items.append(("mov_label", label, reg, base_addr))
        self._pc += 6

    def mov_reg(self, src: int, dst: int) -> None:
        self._emit(struct.pack("<H", 0x0000 | (src & 0x1F) | ((dst & 0x1F) << 11)))

    def add_imm5(self, imm5: int, reg: int) -> None:
        if not -16 <= imm5 <= 15:
            raise ValueError(f"imm5 out of range: {imm5}")
        self._emit(struct.pack("<H", 0x0240 | (imm5 & 0x1F) | ((reg & 0x1F) << 11)))

    def addi(self, imm16: int, src: int, dst: int) -> None:
        self._emit(struct.pack("<HH", 0x0600 | (src & 0x1F) | ((dst & 0x1F) << 11), imm16 & 0xFFFF))

    def movhi(self, imm16: int, src: int, dst: int) -> None:
        self._emit(struct.pack("<HH", 0x0640 | (src & 0x1F) | ((dst & 0x1F) << 11), imm16 & 0xFFFF))

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

    def or_reg(self, r1: int, r2: int) -> None:
        """`r2 <- r2 | r1` (Format I `001000`, updates Z/S)."""
        self._emit(struct.pack("<H", 0x0100 | (r1 & 0x1F) | ((r2 & 0x1F) << 11)))

    def and_reg(self, r1: int, r2: int) -> None:
        """`r2 <- r2 & r1` (Format I `001010`, updates Z/S)."""
        self._emit(struct.pack("<H", 0x0140 | (r1 & 0x1F) | ((r2 & 0x1F) << 11)))

    def add_reg(self, r1: int, r2: int) -> None:
        """`r2 <- r2 + r1` (Format I `001110`, updates CY/OV/S/Z)."""
        self._emit(struct.pack("<H", 0x01C0 | (r1 & 0x1F) | ((r2 & 0x1F) << 11)))

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

    def ld_bu(self, disp: int, base: int, dst: int) -> None:
        if not 1 <= dst <= 31:
            raise ValueError("ld.bu destination cannot be r0")
        op_low = (disp & 1) << 5
        self._emit(struct.pack("<HH", 0x0780 | op_low | (base & 0x1F) | ((dst & 0x1F) << 11), (disp & 0xFFFE) | 1))

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

    def be_short(self, label: str) -> None:
        self._items.append(("bcond9", label, self._pc, _COND_BE))
        self._pc += 2

    def bne_short(self, label: str) -> None:
        self._items.append(("bcond9", label, self._pc, _COND_BNE))
        self._pc += 2

    def br_short(self, label: str) -> None:
        self._items.append(("bcond9", label, self._pc, _COND_BR))
        self._pc += 2

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
            kind = item[0]
            if kind == "mov_label":
                _, target_name, reg, base_addr = item
                if target_name not in self._labels:
                    raise KeyError(f"Undefined label: {target_name}")
                addr = (int(base_addr) + self._labels[str(target_name)]) & 0xFFFFFFFF
                out.extend(struct.pack("<HI", 0x0620 | int(reg), addr))
                continue
            if kind == "bcond9":
                _, target_name, pc, cond = item
                if target_name not in self._labels:
                    raise KeyError(f"Undefined branch target: {target_name}")
                disp = self._labels[str(target_name)] - int(pc)
                if (disp & 1) != 0 or not (-256 <= disp <= 254):
                    raise ValueError(f"bcond9 displacement out of range for {target_name}: {disp}")
                out.extend(self._bcond9_raw(int(cond), disp))
                continue
            _, target_name, pc = item
            if target_name not in self._labels:
                raise KeyError(f"Undefined branch target: {target_name}")
            disp = self._labels[str(target_name)] - int(pc)
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


def _emit_faci_wdt_subroutine(b: _Rh850Builder, label_name: str = "SUB_WDT") -> None:
    """Compact WDTA0 + WDTA1 VAC refresh using shared `0xFFED0000` base (`r11..r13` scratch)."""
    b.label(label_name)
    b.movhi(0xFFED, 0, 11)
    b.mov_u16(0x00AC, 13)
    for off in (0x0000, 0x1000):
        b.st_b(13, off, 11)
        b.ld_bu(off + 0x08, 11, 12)
        b.subr(13, 12)
        b.st_b(12, off + 0x04, 11)
    b.jmp_lp()


def _emit_flmd_subroutine(b: _Rh850Builder, label_name: str = "SUB_SET_FLMD") -> None:
    """Set `FLMDCNT` (`0xFFA00000`) to `r6` (`0` or `1`) via `FLMDPCMD = 0xA5`; leaves `FLMDPS & 1` in `r12`."""
    b.label(label_name)
    b.movhi(0xFFA0, 0, 11)
    b.mov_u16(0x00A5, 14)
    b.mov_imm5(-1, 13)
    b.mov_reg(6, 12)
    b.subr(13, 12)  # r12 = ~r6
    b.mov_imm5(15, 13)
    b.label("_FLMD_RETRY")
    b.st_w(14, 0x04, 11)
    b.st_w(6, 0x00, 11)
    b.st_w(12, 0x00, 11)
    b.st_w(6, 0x00, 11)
    b.ld_w(0x08, 11, 12)
    b.andi(0x0001, 12, 12)
    b.be_short("_FLMD_DONE")
    b.add_imm5(-1, 13)
    b.bne_short("_FLMD_RETRY")
    b.label("_FLMD_DONE")
    b.jmp_lp()


def _emit_exit_pe_subroutine(b: _Rh850Builder, label_name: str = "SUB_EXIT_PE") -> None:
    """Clear `FASTAT`/`FSTATR`, reset `FAREASELC = 0x3B00`, write `FENTRYR = 0xAA00`, and poll Read mode."""
    b.label(label_name)
    b.mov_u16(0x0010, 12)
    b.st_b(12, FACI_FASTAT_OFF, 17)
    b.st_b(19, 0x00, 16)
    b.mov_u16(0x3B00, 12)
    b.st_h(12, FACI_FAREASELC_OFF, 17)
    b.mov_u16(0xAA00, 12)
    b.st_h(12, FACI_FENTRYR_OFF, 17)
    b.movhi(0x0001, 0, 13)
    b.label("_EXIT_PE_WAIT")
    b.ld_hu(FACI_FENTRYR_OFF, 17, 12)
    b.cmp_imm5(0, 12)
    b.be_short("_EXIT_PE_DONE")
    b.add_imm5(-1, 13)
    b.bne_short("_EXIT_PE_WAIT")
    b.label("_EXIT_PE_DONE")
    b.synci()
    b.jmp_lp()


def _emit_wait_frdy_subroutine(b: _Rh850Builder, label_name: str = "SUB_WAIT_FRDY") -> None:
    """Poll `FSTATR.FRDY` (`0x8000`) while refreshing `WDTA0`/`WDTA1`; set `r18 = FSTATR` and `Z = (err == 0)`."""
    b.label(label_name)
    b.mov_reg(31, 6)
    b.mov_u16(4096, 14)
    b.label("_FRDY_POLL")
    b.ld_w(FACI_FSTATR_OFF, 17, 18)
    b.andi(0x8000, 18, 11)
    b.bne_short("_FRDY_DONE")
    b.add_imm5(-1, 14)
    b.bne_short("_FRDY_POLL")
    b.jarl("SUB_WDT")
    b.mov_u16(4096, 14)
    b.br_short("_FRDY_POLL")
    b.label("_FRDY_DONE")
    b.andi(0x7000, 18, 11)
    b.mov_reg(6, 31)
    b.jmp_lp()


def _build_faci_code_stub(*, is_uflash: bool) -> tuple[bytes, int]:
    """Build deterministic RH850/F1L FACI CodeFlash / Extended User Area writer applet.

    Result & diagnostic block at `0xFEDE9000` (`5 x u32` = 20 bytes):
      - `+0x00` (`u32`): `marker` (`1`=OK, `2`=`FENTRYR` timeout, `3`=Erase err, `4`=Program err, `5`=`FPMON.FWE` low)
      - `+0x04` (`u32`): `fstatr` (`0xFFA10080`)
      - `+0x08` (`u32`): `last_offset`
      - `+0x0C` (`4x u8`): `fpmon` (`+0x0C`), `flmdps` (`+0x0D`), `fastat` (`+0x0E`), `idst` (`+0x0F`)
      - `+0x10` (`2x u16`): `fentryr` (`+0x10`), `fpckar` (`+0x12`)
    """
    b = _Rh850Builder()
    saved_regs = (22, 31) if is_uflash else (22, 23, 31)
    frame_bytes = len(saved_regs) * 4
    b.di()
    b.synci()
    b.addi(-frame_bytes, 3, 3)
    for idx, reg in enumerate(saved_regs):
        b.st_w(reg, idx * 4, 3)

    # r7 = RESULT_BASE, r15 = 0xD0, r16 = FACI_CMD, r17 = FACI_BASE, r18 = fstatr_snap, r19 = 0x50, r10 = marker
    b.mov_imm(RESULT_BASE, 7)
    b.movhi(0xFFA2, 0, 16)
    b.movhi(0xFFA1, 0, 17)
    b.mov_u16(0x00D0, 15)
    b.mov_u16(0x0050, 19)
    b.mov_imm5(2, 10)
    b.mov_imm5(0, 18)
    b.mov_imm5(-1, 11)
    b.st_w(11, 0x08, 7)
    b.st_w(0, 0x0C, 7)
    b.st_w(0, 0x10, 7)

    b.jarl("SUB_WDT")

    # 1. Ensure FACI starts in Read mode (FENTRYR == 0) before loading SELFID
    b.ld_hu(FACI_FENTRYR_OFF, 17, 12)
    b.cmp_imm5(0, 12)
    b.be_short("PRE_READ_OK")
    b.jarl("SUB_EXIT_PE")
    b.label("PRE_READ_OK")

    # 2. Enable FLMDCNT = 1 and poll FPMON.FWE (bit 7 == 1)
    b.mov_imm5(1, 6)
    b.jarl("SUB_SET_FLMD")
    b.st_b(12, 0x0D, 7)

    b.mov_u16(10000, 13)
    b.label("_WAIT_FPMON")
    b.ld_bu_0(17, 12)
    b.st_b(12, 0x0C, 7)
    b.andi(0x0080, 12, 12)
    b.bne_short("FPMON_OK")
    b.add_imm5(-1, 13)
    b.bne_short("_WAIT_FPMON")
    b.ld_w(FACI_FSTATR_OFF, 17, 18)
    b.mov_imm5(5, 10)
    b.jr("CLEANUP")
    b.label("FPMON_OK")

    # 3. Load 128-bit SELFID into FLID0..FLID3 + mandatory dummy ld.w of FLID3, then verify IDST (0xFFA08010 == 0)
    #    with automatic fallback to 0xFFFFFFFF*4 if Extra Area IDCODE is blank.
    if is_uflash:
        b.mov_u16(SELFID_CODEFLASH_ADDR, 11)
    else:
        b.mov_label_addr("PAYLOAD_DATA", 23, PAYLOAD_ENTRY_ADDR)
        for w_off in (0x00, 0x04, 0x08, 0x0C):
            b.ld_w(w_off, 23, 12)
            b.cmp_imm5(0, 12)
            b.bne_short("USE_HDR_FLID")
        b.mov_u16(SELFID_CODEFLASH_ADDR, 11)
        b.br_short("COPY_FLID")
        b.label("USE_HDR_FLID")
        b.mov_reg(23, 11)
        b.label("COPY_FLID")

    b.mov_imm5(1, 6)
    b.label("_FLID_TRY")
    b.addi(-0x8000, 17, 12)  # 0xFFA10000 - 0x8000 = 0xFFA08000 (FLID_BASE)
    b.mov_imm5(4, 13)
    b.mov_imm5(-1, 14)
    b.label("_FLID_LOOP")
    b.cmp_imm5(0, 6)
    b.be_short("_FLID_STORE")
    b.ld_w(0, 11, 14)
    b.add_imm5(4, 11)
    b.label("_FLID_STORE")
    b.st_w(14, 0, 12)
    b.add_imm5(4, 12)
    b.add_imm5(-1, 13)
    b.bne_short("_FLID_LOOP")
    b.ld_w(-4, 12, 14)       # mandatory dummy read of FLID3 (0xFFA0800C)
    b.ld_w(0, 12, 14)        # read IDST @ 0xFFA08010 (0 = authenticated, 1 = locked)
    b.st_b(14, 0x0F, 7)      # snapshot IDST byte at 0xFEDE900F
    b.andi(0x0001, 14, 14)
    b.be_short("FLID_AUTH_DONE")
    b.add_imm5(-1, 6)
    b.be_short("_FLID_TRY")
    b.label("FLID_AUTH_DONE")

    # 4. Enter CodeFlash / Extended User Area P/E mode (FENTRYR = 0xAA01) and poll FENTRYR == 0x0001
    b.mov_u16(0xAA01, 12)
    b.st_h(12, FACI_FENTRYR_OFF, 17)
    b.mov_u16(1000, 13)
    b.label("_WAIT_PE_ENTRY")
    b.ld_hu(FACI_FENTRYR_OFF, 17, 12)
    b.st_h(12, 0x10, 7)
    b.cmp_imm5(1, 12)
    b.be_short("PE_ENTERED")
    b.add_imm5(-1, 13)
    b.bne_short("_WAIT_PE_ENTRY")
    b.ld_w(FACI_FSTATR_OFF, 17, 18)
    b.mov_imm5(2, 10)
    b.br_short("CLEANUP")

    b.label("PE_ENTERED")
    b.synci()
    b.ld_w(FACI_FSTATR_OFF, 17, 12)
    b.andi(0x4000, 12, 12)
    b.be_short("UNLOCK_FPROTR")
    b.mov_u16(0x0010, 12)
    b.st_b(12, FACI_FASTAT_OFF, 17)
    b.st_b(19, 0x00, 16)

    # 5. Unlock FPROTR = 0x5501 and configure FAREASELC
    b.label("UNLOCK_FPROTR")
    b.mov_u16(0x5501, 12)
    b.st_h(12, FACI_FPROTR_OFF, 17)
    if is_uflash:
        b.mov_u16(0x3B02, 12)
    else:
        b.ld_w(0x10, 23, 12)
    b.st_h(12, FACI_FAREASELC_OFF, 17)

    # 6. Block Erase
    if is_uflash:
        b.movhi(0x0100, 0, 8)
        b.addi(0x7FFF, 8, 12)
    else:
        b.ld_w(0x14, 23, 11)
        b.cmp_imm5(0, 11)
        b.be_short("SKIP_ERASE")
        b.ld_w(0x18, 23, 8)
        b.ld_w(0x1C, 23, 12)

    b.st_w(8, 0x08, 7)
    b.st_w(8, FACI_FSADDR_OFF, 17)
    b.st_w(12, FACI_FEADDR_OFF, 17)
    b.jarl("SUB_WDT")
    b.st_b(19, 0x00, 16)
    b.mov_u16(0x0020, 12)
    b.st_b(12, 0x00, 16)
    b.st_b(15, 0x00, 16)
    b.jarl("SUB_WAIT_FRDY")
    b.be_short("SKIP_ERASE")
    b.mov_imm5(3, 10)
    b.br_short("CLEANUP")

    # 7. 256-byte Page Programming
    b.label("SKIP_ERASE")
    pages_imm_offset = -1
    if is_uflash:
        b.mov_label_addr("PAYLOAD_DATA", 9, PAYLOAD_ENTRY_ADDR)
        pages_imm_offset = b.pc
        b.mov_imm(99, 22)
    else:
        b.ld_w(0x20, 23, 8)
        b.ld_w(0x24, 23, 22)
        b.cmp_imm5(0, 22)
        b.be_short("ALL_OK")
        b.addi(0x28, 23, 9)

    b.label("PAGE_LOOP")
    b.jarl("SUB_WDT")
    b.st_w(8, 0x08, 7)
    b.st_w(8, FACI_FSADDR_OFF, 17)
    b.addi(0x00FF, 8, 12)
    b.st_w(12, FACI_FEADDR_OFF, 17)
    b.st_b(19, 0x00, 16)
    for cmd_byte in (0xE8, 0x80):
        b.mov_u16(cmd_byte, 12)
        b.st_b(12, 0x00, 16)
    b.mov_reg(12, 13)  # 0x80 == 128 halfwords per 256-byte page
    b.label("_HW_LOOP")
    b.ld_hu(0, 9, 12)
    b.st_h(12, 0x00, 16)
    b.label("_WAIT_DBFULL")
    b.ld_w(FACI_FSTATR_OFF, 17, 14)
    b.andi(0x0400, 14, 14)
    b.bne_short("_WAIT_DBFULL")
    b.add_imm5(2, 9)
    b.add_imm5(-1, 13)
    b.bne_short("_HW_LOOP")

    b.st_b(15, 0x00, 16)
    b.jarl("SUB_WAIT_FRDY")
    b.be_short("NEXT_PAGE")
    b.mov_imm5(4, 10)
    b.br_short("CLEANUP")

    b.label("NEXT_PAGE")
    b.addi(0x0100, 8, 8)
    b.add_imm5(-1, 22)
    b.bne_short("PAGE_LOOP")

    b.label("ALL_OK")
    b.mov_imm5(1, 10)

    # 8. Cleanup: snapshot diagnostics, exit P/E mode, flush CFCNT + synci, restore FLMDCNT = 0
    b.label("CLEANUP")
    b.st_w(18, 0x04, 7)
    b.ld_bu(FACI_FASTAT_OFF, 17, 11)
    b.st_b(11, 0x0E, 7)
    b.ld_hu(FACI_FPCKAR_OFF, 17, 11)
    b.st_h(11, 0x12, 7)

    b.ld_hu(FACI_FENTRYR_OFF, 17, 11)
    b.cmp_imm5(0, 11)
    b.be_short("_AFTER_PE_EXIT")
    b.jarl("SUB_EXIT_PE")
    b.label("_AFTER_PE_EXIT")

    b.movhi(0xFFBC, 0, 11)
    b.mov_imm5(1, 12)
    b.st_b(12, 0x0700, 11)
    b.ld_bu(0x0700, 11, 12)
    b.st_b(0, 0x0700, 11)
    b.ld_bu(0x0700, 11, 12)
    b.synci()

    b.mov_imm5(0, 6)
    b.jarl("SUB_SET_FLMD")

    b.jarl("SUB_WDT")
    b.st_w(10, 0x00, 7)
    for idx, reg in enumerate(saved_regs):
        b.ld_w(idx * 4, 3, reg)
    b.addi(frame_bytes, 3, 3)
    b.ei()
    b.jmp_lp()

    _emit_exit_pe_subroutine(b, "SUB_EXIT_PE")
    _emit_flmd_subroutine(b, "SUB_SET_FLMD")
    _emit_wait_frdy_subroutine(b, "SUB_WAIT_FRDY")
    _emit_faci_wdt_subroutine(b, "SUB_WDT")
    # PAYLOAD_ENTRY_ADDR (0xFEDF8138) is 4-byte aligned; RH850/F1L raises MAE (vector 0x00C0) on
    # unaligned ld.w reads from the 40-byte CFLASH_FACI_STUB header placed at PAYLOAD_DATA.
    b.align(4)
    b.label("PAYLOAD_DATA")
    return b.build(), pages_imm_offset


def build_uflash_faci_stub() -> tuple[bytes, int]:
    """Build one-shot RH850/F1L Extended User Area FACI writer stub and its `mov pages, r22` offset."""
    return _build_faci_code_stub(is_uflash=True)


def build_cflash_faci_stub() -> bytes:
    """Build parameterized RH850/F1L CodeFlash / Extended User Area FACI writer stub."""
    stub, _ = _build_faci_code_stub(is_uflash=False)
    return stub


def _emit_fpke_enter(b: _Rh850Builder) -> None:
    b.stsr(5, 18, 0)
    b.ori(0x00A0, 18, 6)
    b.ldsr(6, 5, 0)


def _emit_fpke_leave(b: _Rh850Builder, caller_return: int = 0x0009CF0E) -> None:
    b.mov_imm(caller_return, 31)
    b.mov_imm5(0, 10)
    b.ldsr(18, 5, 0)
    b.jmp_lp()


def _emit_fpke_bfaselr_switch_subroutine(b: _Rh850Builder, label_name: str = "SUB_SWITCH_BFLASH") -> None:
    """Switch `BFASELR` (`r6` = 0 or 1), flush I-cache (`ICCTRL`), and clear code buffer (`CDBCR` on G3M / `0xFFBC0700` on G3K).

    Matches the cluster's own `R_FDL_IFct_InitRAM_Asm` (`0x14AFD2` / `0x14B4C8`) using only caller-saved `r11..r12`.
    """
    b.label(label_name)
    b.movhi(0xFFC6, 0, 11)
    b.st_b(6, -0x6FF8, 11)        # BFASELR = 0xFFC59008 = 0xFFC60000 - 0x6FF8
    b.ld_bu(-0x6FF8, 11, 12)      # dummy read
    b.synci()
    # Flush CPU instruction cache via ICCTRL (SR 24, sel 4, bit 8 = ICHCLR)
    b.stsr(24, 12, 4)
    b.ori(0x0100, 12, 12)
    b.ldsr(12, 24, 4)
    b.label("_D1L_ICACHE_WAIT")
    b.stsr(24, 12, 4)
    b.andi(0x0100, 12, 12)        # sets Z flag directly
    b.bne_short("_D1L_ICACHE_WAIT")
    b.synci()
    # Dispatch by PID (SR 6, sel 1) & 0xE0: 0x20 = G3K (BWCBUFEN 0xFFBC0700), else G3M/D1L (CDBCR SR 24 sel 13 bit 1)
    b.stsr(6, 12, 1)
    b.andi(0x00E0, 12, 12)
    b.addi(-0x0020, 12, 12)       # sets Z=1 iff (PID & 0xE0) == 0x20
    b.be_short("_D1L_G3K_BUF")
    b.stsr(24, 12, 13)
    b.ori(0x0002, 12, 12)
    b.ldsr(12, 24, 13)
    b.stsr(24, 12, 13)
    b.br_short("_D1L_BUF_DONE")
    b.label("_D1L_G3K_BUF")
    b.movhi(0xFFBC, 0, 11)
    b.mov_imm5(1, 12)
    b.st_b(12, 0x0700, 11)
    b.ld_bu(0x0700, 11, 12)
    b.st_b(0, 0x0700, 11)
    b.ld_bu(0x0700, 11, 12)
    b.label("_D1L_BUF_DONE")
    b.synci()
    b.jmp_lp()


def build_fpke_dflash_bc_applet(
    *,
    applet_entry: int = 0xFEDF1800,
    caller_return: int = 0x0009CF0E,
    caller_r29: int = 0xFEDF31C8,
) -> bytes:
    """Build RH850/D1L DataFlash blank-check helper (`<= 256` bytes).

    Parameters at `applet_entry + 0x100` (`0xFEDF1900` on 83A, `0xFEDF4500` on 1703/1711):
      - `+0x00`: `u32` LE `df_offset` (`0x0000..0xFFFF`)
      - `+0x04`: `u32` LE `u32_groups` (`1..16`, where each group blank-checks 32 × 4B words = 128 B)
    Outputs:
      - `applet_entry + 0x200 .. + 4 * u32_groups`: `BCST` bitmask (`1` = programmed, `0` = blank)
      - `applet_entry + 0x300`: `b"SCAN"` on success, or `b"BUSY"` if `FENTRYR != 0`
    Uses only caller-saved registers `r6..r19` (`r20..r28` remain untouched).
    """
    result_addr = (applet_entry + 0x200) & 0xFFFFFFFF
    b = _Rh850Builder()
    _emit_fpke_enter(b)
    b.movhi(0xFFA1, 0, 14)
    b.movhi(0xFFA2, 0, 15)
    b.mov_imm(result_addr, 16)
    b.mov_u16(0x0050, 12)
    b.ld_hu(FACI_FENTRYR_OFF, 14, 6)
    b.cmp_imm5(0, 6)
    b.be_short("IDLE")
    b.mov_imm(0x59535542, 7)
    b.br_short("MARK")
    b.label("IDLE")
    b.mov_u16(0x0080, 7)
    b.jarl("SUB_PE")
    b.jarl("SUB_CLR")
    b.ld_w(-0x100, 16, 8)
    b.ld_w(-0x0FC, 16, 17)
    b.mov_reg(16, 9)
    b.label("OUTER")
    b.mov_imm5(0, 11)
    b.mov_imm5(1, 19)
    b.label("W_BC")
    b.st_w(8, FACI_FSADDR_OFF, 14)
    b.mov_reg(8, 6)
    b.add_imm5(3, 6)
    b.st_w(6, FACI_FEADDR_OFF, 14)
    b.st_b(12, 0, 15)
    b.mov_u16(0x0071, 6)
    b.st_b(6, 0, 15)
    b.mov_u16(0x00D0, 6)
    b.st_b(6, 0, 15)
    b.label("WT_BC")
    b.ld_w(FACI_FSTATR_OFF, 14, 6)
    b.andi(0x8000, 6, 7)
    b.be_short("WT_BC")
    b.andi(0x7000, 6, 7)
    b.be_short("RD_BC")
    b.jarl("SUB_CLR")
    b.or_reg(19, 11)
    b.br_short("NXT")
    b.label("RD_BC")
    b.ld_bu(0xD4, 14, 6)
    b.andi(1, 6, 6)
    b.be_short("NXT")
    b.or_reg(19, 11)
    b.label("NXT")
    b.add_imm5(4, 8)
    b.add_reg(19, 19)
    b.bne_short("W_BC")
    b.st_w(11, 0, 9)
    b.add_imm5(4, 9)
    b.add_imm5(-1, 17)
    b.bne_short("OUTER")
    b.jarl("SUB_CLR")
    b.mov_imm5(0, 7)
    b.jarl("SUB_PE")
    b.mov_imm(0x4E414353, 7)
    b.label("MARK")
    b.st_w(7, 0x0100, 16)
    b.mov_imm(caller_r29, 29)
    _emit_fpke_leave(b, caller_return=caller_return)

    b.label("SUB_PE")
    b.ori(0xAA00, 7, 6)
    b.st_h(6, FACI_FENTRYR_OFF, 14)
    b.mov_reg(6, 13)
    b.label("WT_PE")
    b.ld_hu(FACI_FENTRYR_OFF, 14, 6)
    b.cmp_reg(7, 6)
    b.be_short("WT_PE_OK")
    b.add_imm5(-1, 13)
    b.bne_short("WT_PE")
    b.label("WT_PE_OK")
    b.synci()
    b.jmp_lp()

    b.label("SUB_CLR")
    b.mov_u16(0x0010, 6)
    b.st_b(6, FACI_FASTAT_OFF, 14)
    b.st_b(12, 0, 15)
    b.jmp_lp()
    return b.build()


def build_fpke_dflash_write_applet(
    *,
    applet_entry: int = 0xFEDF1800,
    caller_return: int = 0x0009CF0E,
) -> bytes:
    """Build RH850/D1L DataFlash 64-byte block erase + 4-byte word program helper (`<= 256` bytes).

    Parameters at `applet_entry + 0x100` (`72` bytes):
      - `+0x00`: `u16` LE `blk_off` (`0x0000..0xFFC0`, 64B-aligned zero-based DataFlash offset)
      - `+0x02`: `u16` LE `do_erase` (`1` = erase 64B block before programming, `0` = program into blank cells)
      - `+0x04`: `u32` LE `prog_mask << 16` (bits `31..16`: bit `16 + i` = program word `i`)
      - `+0x08..+0x47`: `64` bytes (`16 × u32`) of target block data
    Outputs at `applet_entry + 0x200`:
      - `+0x00`: `u32` LE `status` (`1` = OK, `3` = `ERSERR`, `4` = `PRGERR`, `6` = `EEL_BUSY`)
      - `+0x04`: `u32` LE `fstatr`
      - `applet_entry + 0x300`: `b"SCAN"`
    Uses only caller-saved registers `r6..r19` (`r20..r28` remain untouched).
    """
    source_data_addr = (applet_entry + 0x108) & 0xFFFFFFFF
    b = _Rh850Builder()
    _emit_fpke_enter(b)
    b.movhi(0xFFA1, 0, 14)
    b.movhi(0xFFA2, 0, 15)
    b.mov_imm(source_data_addr, 16)
    b.mov_u16(0x0050, 12)
    b.mov_imm5(6, 10)
    b.ld_w(FACI_FSTATR_OFF, 14, 17)
    b.ld_hu(FACI_FENTRYR_OFF, 14, 6)
    b.cmp_imm5(0, 6)
    b.bne_short("W_DONE")
    b.mov_u16(0x0080, 7)
    b.br_short("SUB_PE")
    b.label("W_PARAMS")
    b.ld_hu(-8, 16, 8)
    b.ld_hu(-6, 16, 6)
    b.ld_w(-4, 16, 9)
    b.mov_reg(16, 11)
    b.cmp_imm5(0, 6)
    b.be_short("W_INIT")
    b.mov_imm5(3, 10)
    b.st_w(8, FACI_FSADDR_OFF, 14)
    b.addi(0x003F, 8, 6)
    b.st_w(6, FACI_FEADDR_OFF, 14)
    b.mov_u16(0x0020, 6)
    b.jarl("SUB_FIN")
    b.label("W_INIT")
    b.mov_imm5(4, 10)
    b.movhi(1, 0, 19)
    b.label("W_LP")
    b.mov_reg(9, 6)
    b.and_reg(19, 6)
    b.be_short("W_SKP")
    b.st_w(8, FACI_FSADDR_OFF, 14)
    b.mov_u16(0x00E8, 6)
    b.st_b(6, 0, 15)
    b.mov_imm5(2, 6)
    b.st_b(6, 0, 15)
    b.ld_hu(0, 11, 6)
    b.st_h(6, 0, 15)
    b.ld_hu(2, 11, 6)
    b.jarl("SUB_FIN")
    b.label("W_SKP")
    b.add_imm5(4, 8)
    b.add_imm5(4, 11)
    b.add_reg(19, 19)
    b.bne_short("W_LP")
    b.mov_imm5(1, 10)
    b.label("W_EXIT")
    b.mov_imm5(0, 7)
    b.label("SUB_CLR")
    b.mov_u16(0x0010, 6)
    b.st_b(6, FACI_FASTAT_OFF, 14)
    b.st_b(12, 0, 15)
    b.cmp_imm5(0, 7)
    b.bne_short("W_PARAMS")
    b.label("SUB_PE")
    b.ori(0xAA00, 7, 6)
    b.st_h(6, FACI_FENTRYR_OFF, 14)
    b.mov_reg(6, 13)
    b.label("WT_PE")
    b.ld_hu(FACI_FENTRYR_OFF, 14, 6)
    b.cmp_reg(7, 6)
    b.be_short("WT_PE_OK")
    b.add_imm5(-1, 13)
    b.bne_short("WT_PE")
    b.label("WT_PE_OK")
    b.synci()
    b.cmp_imm5(0, 7)
    b.bne_short("SUB_CLR")
    b.label("W_DONE")
    b.st_w(10, 0x00F8, 16)
    b.st_w(17, 0x00FC, 16)
    b.mov_imm(0x4E414353, 7)
    b.st_w(7, 0x01F8, 16)
    _emit_fpke_leave(b, caller_return=caller_return)

    b.label("SUB_FIN")
    b.st_h(6, 0, 15)
    b.mov_u16(0x00D0, 6)
    b.st_b(6, 0, 15)
    b.label("SUB_FRDY")
    b.ld_w(FACI_FSTATR_OFF, 14, 17)
    b.andi(0x8000, 17, 7)
    b.be_short("SUB_FRDY")
    b.andi(0x7000, 17, 7)
    b.bne_short("W_EXIT")
    b.jmp_lp()
    return b.build()


def build_fpke_swresa_reset_applet() -> bytes:
    """Build RH850/D1L immediate hardware software reset helper (`SWRESA = 0xFFF80A04`)."""
    b = _Rh850Builder()
    _emit_fpke_enter(b)
    b.movhi(0xFFF8, 0, 14)
    b.mov_u16(0x00A5, 6)
    b.mov_imm5(1, 7)
    b.mov_imm5(-2, 8)
    b.st_w(6, 0x0000, 14)
    b.st_w(7, 0x0A04, 14)
    b.st_w(8, 0x0A04, 14)
    b.st_w(7, 0x0A04, 14)
    b.label("RST_SPIN")
    b.br_short("RST_SPIN")
    return b.build()


OPBT_READER_STUB = build_opbt_reader_payload()
EEPROM_M95640_READER_STUB = build_m95640_reader_payload()
UFLASH_FACI_STUB, UFLASH_STUB_PAGES_IMM_OFFSET = build_uflash_faci_stub()
CFLASH_FACI_STUB = build_cflash_faci_stub()
EXPECTED_OPBT_READER_STUB_SHA256 = "a5b1a7a12a8547e164ab0f4357257e6d422cec1780240d1c5716f4ac02f74067"
EXPECTED_EEPROM_READER_STUB_SHA256 = "aeda839eeba9d6f307fe06f9278181b9feb11cb361125508f0cff2304ba63830"
EXPECTED_UFLASH_FACI_STUB_SHA256 = "9718f50692f086cf2cea33287c9b9c0e1bb6c70bf0d961c4f3f7c65dc3fa549c"
EXPECTED_CFLASH_FACI_STUB_SHA256 = "0598491f25906507b1b7d21072e1df676e0449a4929735c1b557e101d6646e99"


# ────────────────────────────── J533 Transparent RSCAN0 CAN Bridge Applet ──────────────────────────────

J533_RSCAN0_BASE = 0xFFD00000
J533_BRIDGE_DIAG_CHANNEL = 3

# Verified from Continental 3Q0 907 530 Cflash (0x0D474..0x0D5DC, 0x0DA40, 0x0446BC CanTrcv switch, 0x0C5B4 Port_Config)
J533_BUS_CHANNELS: dict[int, tuple[str, str, str]] = {
    0: ("komfort", "Komfort CAN (панель приборов 17, BCM 09)", "Komfort CAN (cluster 17, BCM 09)"),
    1: ("antrieb", "Antrieb CAN (двигатель 01, КПП 02)", "Drivetrain CAN (engine 01, TCU 02)"),
    2: ("extended", "Extended CAN (ассистенты 13, A5, 3C)", "Extended CAN (ADAS 13, A5, 3C)"),
    4: ("infotainment", "Infotainment CAN (MIB 5F, звук 47)", "Infotainment CAN (MIB 5F, sound 47)"),
    5: ("fahrwerk", "Fahrwerk CAN (ESP 03, руль 44)", "Chassis CAN (ESP 03, steering 44)"),
}

J533_BRIDGE_READY_ID = 0x6F1
J533_BRIDGE_READY_DATA = b"J533BRDG"
J533_BRIDGE_STOP_ID = 0x6F0
J533_BRIDGE_STOP_DATA = b"STOPBRDG"
J533_BRIDGE_END_ID = 0x6F1
J533_BRIDGE_END_DATA = b"BRDG-END"
# Burst variant only: `0x6F0 BURST-GO` makes the gateway itself send its preloaded frame table on the target channel,
# then answer on 0x6F1 (`BURST-OK`, or `BURST-NA` when a frame found no ACK and the rest were dropped).
J533_BRIDGE_BURST_ID = 0x6F0
J533_BRIDGE_BURST_DATA = b"BURST-GO"
J533_BRIDGE_BURST_OK = b"BURST-OK"
J533_BRIDGE_BURST_FAIL = b"BURST-NA"
# Note: a busy loop, not a timer; ~60 us at 80 MHz, more on a slower clock (frames only get further apart).
# Measure the frame spacing on the sub-bus and tune if a target needs an exact pace.
J533_BRIDGE_BURST_GAP_LOOPS = 2400
# The gap loop does not kick the watchdog: 100k loops ~2.5 ms at 80 MHz, still ~25 ms at a tenth of that clock,
# far inside the WDTA window (~0.273 s)
J533_BRIDGE_BURST_GAP_MAX_LOOPS = 100_000

# Port registers for CAN0..CAN5 TX/RX alternate functions and active-low transceiver STB pins (3Q0 907 530 Port_Config)
_P0 = 0xFFC10000
_PM0 = 0xFFC10300
_PMC0 = 0xFFC10400
_PFC0 = 0xFFC10500
_PFCE0 = 0xFFC10600
_PFCAE0 = 0xFFC10A00
_PIBC0 = 0xFFC14000

_P1 = 0xFFC10004
_PM1 = 0xFFC10304
_PMC1 = 0xFFC10404
_PFC1 = 0xFFC10504
_PFCE1 = 0xFFC10604
_PIBC1 = 0xFFC14004

_P8 = 0xFFC10020
_PM8 = 0xFFC10320
_PMC8 = 0xFFC10420

_P11 = 0xFFC1002C
_PM11 = 0xFFC1032C
_PMC11 = 0xFFC1042C


def build_j533_can_bridge_applet(
    target_channel: int = 0,
    *,
    idle_limit: int = 40_000_000,
    burst_frames: list[tuple[int, bytes]] | None = None,
    burst_gap_loops: int = J533_BRIDGE_BURST_GAP_LOOPS,
    target_rx_filter: list[tuple[int, bool]] | tuple[tuple[int, bool], ...] | None = None,
) -> bytes:
    """Build RH850/F1L RAM-loader applet that transparently bridges Diagnosis CAN (`ch3`) <-> `target_channel`.

    Verified against Continental 3Q0 907 530 (`R7F7010543` / `R7F7010563`) `Uflash` + `Cflash`:
      - Configures Port 0/1/8/11 alternate CAN pins identically to `Port_GstConfiguration` (`0x0C5B4`) and drives
        the active-low CAN transceiver `STB` pin LOW only for `ch3` (`P8_10`) and `target_channel`
        (`ch0: P11_12`, `ch1: P11_13`, `ch2: P0_6`, `ch4: P0_8`, `ch5: P8_2`).
      - Copies FBL's live 500 kbit/s bit-timing from `C3CFG` (`0xFFD00030`) to `CtargetCFG` without touching `GCFG`.
      - Sets wildcard `GAFL` receive rules (`GAFLID=0, GAFLM=0`, matching ALL 11-bit and 29-bit frames) into
        32-deep RX FIFO 0 (`ch3 -> target`) and RX FIFO 1 (`target -> ch3`). When `target_rx_filter` is provided
        (1..15 `(can_id, is_extended)` entries), programs exact hardware `GAFL` accept rules on `target_channel`
        so cyclic vehicle bus traffic is filtered in RSCAN0 silicon before entering RX FIFO 1.
      - Uses one TX buffer per direction (`TM48` on `ch3`, `TM[16*target]` on `target`) to preserve strict FIFO order.
      - Sends `J533BRDG` on `0x6F1` once both channels are in Communication Mode.
      - Refreshes `WDTA0` / `WDTA1` every loop iteration; aborts stalled sub-bus TX after a short timeout so an
        unplugged bus never blocks `STOPBRDG`; auto-exits after `idle_limit` idle iterations with no `ch3` traffic.
      - On `0x6F0: STOPBRDG` (or idle timeout), replies `0x6F1: BRDG-END` and triggers `SWRESA` (`0xFFF80A04`)
        with WDTA reset fallback so the gateway boots cleanly back into its normal Application firmware.

    `burst_frames` (opt-in; without it and without `target_rx_filter` the applet is byte-identical to the verified one)
    appends a table of `(29-bit can_id, 8 data bytes)` that `0x6F0: BURST-GO` sends on the target channel back to back
    as extended frames (as the host sends the level-8 stream), each frame waited out and followed by `burst_gap_loops`
    idle loops — the pace a slow host adapter (VAS 6154 RawMode) cannot reach.
    """
    if target_channel not in J533_BUS_CHANNELS:
        raise ValueError(
            f"Unsupported J533 bridge target_channel={target_channel} (expected one of {tuple(J533_BUS_CHANNELS)})"
        )
    if idle_limit <= 0:
        raise ValueError(f"idle_limit must be positive, got {idle_limit}")
    encoded_tgt_rules: list[tuple[int, int]] | None = None
    if target_rx_filter is not None:
        deduped = list(dict.fromkeys((int(cid), bool(ext)) for cid, ext in target_rx_filter))
        if not 1 <= len(deduped) <= 15:
            raise ValueError(f"target_rx_filter must have 1..15 rules (GAFL page 0 limit), got {len(deduped)}")
        encoded_tgt_rules = []
        for cid, is_ext in deduped:
            if is_ext:
                if not 0 <= cid <= 0x1FFFFFFF:
                    raise ValueError(f"Extended filter CAN ID out of range: 0x{cid:X}")
                # GAFLID: IDE=1 (bit 31), RTR=0 (bit 30), LB=0 (bit 29); GAFLM: IDEM=1, RTRM=0, IDM=0x1FFFFFFF (stock 3Q0 907 530)
                encoded_tgt_rules.append((cid | 0x80000000, 0x9FFFFFFF))
            else:
                if not 0 <= cid <= 0x7FF:
                    raise ValueError(f"Standard filter CAN ID out of range: 0x{cid:X}")
                # GAFLID: IDE=0, RTR=0, LB=0; GAFLM: IDEM=1, RTRM=0, IDM=0x7FF (stock 3Q0 907 530)
                encoded_tgt_rules.append((cid, 0x800007FF))
    burst_table = b""
    if burst_frames is not None:
        if not burst_frames:
            raise ValueError("burst_frames must be non-empty")
        if not 0 < burst_gap_loops <= J533_BRIDGE_BURST_GAP_MAX_LOOPS:
            raise ValueError(
                f"burst_gap_loops must be 1..{J533_BRIDGE_BURST_GAP_MAX_LOOPS} (the gap does not kick the watchdog), "
                f"got {burst_gap_loops}"
            )
        for can_id, data in burst_frames:
            if len(data) != 8 or not 0 <= can_id <= 0x1FFFFFFF:
                raise ValueError(f"Burst frame 0x{can_id:X} needs 8 data bytes and a 29-bit id")
            # TMID with IDE (bit 31) always set + TMDF0/TMDF1 exactly as the RX FIFO hands them over
            burst_table += struct.pack("<I", can_id | 0x80000000) + bytes(data)

    diag_ch = J533_BRIDGE_DIAG_CHANNEL
    tgt_ctr_off = 0x0004 + 0x10 * target_channel
    tgt_sts_off = 0x0008 + 0x10 * target_channel
    tgt_cfg_off = 0x0000 + 0x10 * target_channel
    tgt_tmid_addr = J533_RSCAN0_BASE + 0x1000 + 0x100 * target_channel
    tgt_tmc_addr = J533_RSCAN0_BASE + 0x0250 + 0x10 * target_channel
    tgt_tmsts_addr = J533_RSCAN0_BASE + 0x02D0 + 0x10 * target_channel

    diag_tmid_addr = J533_RSCAN0_BASE + 0x1300
    diag_tmc_addr = J533_RSCAN0_BASE + 0x0280
    diag_tmsts_addr = J533_RSCAN0_BASE + 0x0300

    # GAFLCFG0 (ch0..ch3 in bytes 3..0) and GAFLCFG1 (ch4..ch5 in bytes 3..2)
    tgt_rule_count = 1 if encoded_tgt_rules is None else len(encoded_tgt_rules)
    gaflcfg0 = 1 << (8 * (3 - diag_ch))
    gaflcfg1 = 0
    if target_channel < 4:
        gaflcfg0 |= tgt_rule_count << (8 * (3 - target_channel))
    else:
        gaflcfg1 |= tgt_rule_count << (8 * (7 - target_channel))
    # Rule order follows channel number 0..5: FIFO 0 = bit 0 (diag->tgt), FIFO 1 = bit 1 (tgt->diag)
    if target_channel < diag_ch:
        rule0_p1, rule1_p1 = 0x00000002, 0x00000001
    else:
        rule0_p1, rule1_p1 = 0x00000001, 0x00000002

    # Active-low transceiver STB bits: drive LOW (0) for diag ch3 and target_channel, HIGH (1) for inactive buses
    stb_p0 = (0 if target_channel == 2 else 0x0040) | (0 if target_channel == 4 else 0x0100)
    stb_p8 = 0 if target_channel == 5 else 0x0004  # P8_10 stays 0 (Diag CAN active)
    stb_p11 = (0 if target_channel == 0 else 0x1000) | (0 if target_channel == 1 else 0x2000)

    def _wr_h(b_ref: _Rh850Builder, addr: int, val16: int) -> None:
        b_ref.mov_imm(addr, 6)
        b_ref.mov_u16(val16 & 0xFFFF, 7)
        b_ref.st_h(7, 0, 6)

    def _poll_rscan_mode(b_ref: _Rh850Builder, sts_off: int, want: int, tag: str) -> None:
        b_ref.mov_imm(200_000, 10)
        b_ref.label(f"WAIT_{tag}")
        b_ref.jarl("SUB_WDT")
        b_ref.ld_w(sts_off, 14, 6)
        b_ref.andi(0x0007, 6, 6)
        b_ref.cmp_imm5(want, 6)
        b_ref.be(f"DONE_{tag}")
        b_ref.add_imm5(-1, 10)
        b_ref.cmp_imm5(0, 10)
        b_ref.bne(f"WAIT_{tag}")
        b_ref.label(f"DONE_{tag}")

    b = _Rh850Builder()
    b.di()
    b.synci()
    b.jarl("SUB_WDT")

    # 1. Configure Port 0 / Port 1 CAN pins + transceiver STB GPIOs (exact 3Q0 907 530 Port_Config)
    _mod_port16(b, _P0, ~0x0140 & 0xFFFF, stb_p0)
    _wr_h(b, _PIBC0, 0x2236)
    _wr_h(b, _PFC0, 0x009F)
    _wr_h(b, _PFCE0, 0x0000)
    _wr_h(b, _PFCAE0, 0x6600)
    _wr_h(b, _PMC0, 0x66BF)
    _wr_h(b, _PM0, 0xA236)

    _wr_h(b, _PIBC1, 0x0115)
    _wr_h(b, _PFC1, 0x0000)
    _wr_h(b, _PFCE1, 0x0000)
    _wr_h(b, _PMC1, 0x031F)
    _wr_h(b, _PM1, 0xF115)

    _mod_port16(b, _PMC8, ~0x0404 & 0xFFFF, 0)
    _mod_port16(b, _P8, ~0x0404 & 0xFFFF, stb_p8)
    _mod_port16(b, _PM8, ~0x0404 & 0xFFFF, 0)

    _mod_port16(b, _PMC11, ~0x3000 & 0xFFFF, 0)
    _mod_port16(b, _P11, ~0x3000 & 0xFFFF, stb_p11)
    _mod_port16(b, _PM11, ~0x3000 & 0xFFFF, 0)

    # 2. Save live FBL 500 kbit/s bit-timing from C3CFG (0xFFD00030) before entering RSCAN0 Global Reset
    b.mov_imm(J533_RSCAN0_BASE, 14)
    b.ld_w(0x0030, 14, 20)

    # 3. RSCAN0 Global Reset + Channel Reset (ch3 and target_channel)
    b.mov_imm5(1, 7)
    b.st_w(7, 0x0088, 14)  # GCTR = 1 (Global Reset, awake)
    _poll_rscan_mode(b, 0x008C, 1, "GRST")

    b.mov_imm5(1, 7)
    b.st_w(7, 0x0034, 14)  # C3CTR = 1 (Channel Reset, awake)
    _poll_rscan_mode(b, 0x0038, 1, "C3RST")

    b.mov_imm5(1, 7)
    b.st_w(7, tgt_ctr_off, 14)  # CtargetCTR = 1
    _poll_rscan_mode(b, tgt_sts_off, 1, "CTGTRST")

    # 4. Program identical 500 kbit/s bit-timing on ch3 and target_channel
    b.st_w(20, 0x0030, 14)
    b.st_w(20, tgt_cfg_off, 14)

    # 5. Program GAFL receive rules -> RX FIFO 0 (ch3->target) & RX FIFO 1 (target->ch3)
    b.mov_u16(0x0100, 6)
    b.st_w(6, 0x0098, 14)  # GAFLECTR = AFLDAE(1), page 0
    b.mov_imm(gaflcfg0, 6)
    b.st_w(6, 0x009C, 14)  # GAFLCFG0
    b.mov_imm(gaflcfg1, 6)
    b.st_w(6, 0x00A0, 14)  # GAFLCFG1

    if encoded_tgt_rules is None:
        b.st_w(0, 0x0500, 14)  # GAFLID0 = 0
        b.st_w(0, 0x0504, 14)  # GAFLM0  = 0 (wildcard: IDE/RTR/ID ignored)
        b.st_w(0, 0x0508, 14)  # GAFLP0_0 = 0
        b.mov_imm5(rule0_p1, 6)
        b.st_w(6, 0x050C, 14)  # GAFLP1_0

        b.st_w(0, 0x0510, 14)  # GAFLID1 = 0
        b.st_w(0, 0x0514, 14)  # GAFLM1  = 0
        b.st_w(0, 0x0518, 14)  # GAFLP0_1 = 0
        b.mov_imm5(rule1_p1, 6)
        b.st_w(6, 0x051C, 14)  # GAFLP1_1
    else:
        diag_entry = [(0, 0, 0x00000001)]
        tgt_entries = [(gid, gm, 0x00000002) for gid, gm in encoded_tgt_rules]
        ordered_rules = (tgt_entries + diag_entry) if target_channel < diag_ch else (diag_entry + tgt_entries)
        for idx, (gid, gm, gp1) in enumerate(ordered_rules):
            base_off = 0x0500 + idx * 0x10
            if gid == 0:
                b.st_w(0, base_off, 14)
            else:
                b.mov_imm(gid, 6)
                b.st_w(6, base_off, 14)
            if gm == 0:
                b.st_w(0, base_off + 0x04, 14)
            else:
                b.mov_imm(gm, 6)
                b.st_w(6, base_off + 0x04, 14)
            b.st_w(0, base_off + 0x08, 14)
            b.mov_imm5(gp1, 6)
            b.st_w(6, base_off + 0x0C, 14)

    b.st_w(0, 0x0098, 14)  # GAFLECTR = 0 (lock rule table)

    # 6. Configure 32-deep RX FIFO 0 & RX FIFO 1 (RFDC=4 -> 0x0400) and disable unused FIFOs 2..7
    b.st_w(0, 0x00A4, 14)  # RMNB = 0
    b.mov_u16(0x0400, 6)
    b.st_w(6, 0x00B8, 14)  # RFCC0
    b.st_w(6, 0x00BC, 14)  # RFCC1
    for unused_off in range(0x00C0, 0x00D8, 4):
        b.st_w(0, unused_off, 14)

    # 7. Enter Global Operating Mode, enable RX FIFOs 0 & 1, enter Channel Communication Mode
    b.st_w(0, 0x0088, 14)  # GCTR = 0 (Global Operating)
    _poll_rscan_mode(b, 0x008C, 0, "GOP")

    b.mov_u16(0x0401, 6)
    b.st_w(6, 0x00B8, 14)  # RFCC0.RFE = 1
    b.st_w(6, 0x00BC, 14)  # RFCC1.RFE = 1
    b.st_w(0, 0x00D8, 14)  # clear RFSTS0 flags
    b.st_w(0, 0x00DC, 14)  # clear RFSTS1 flags

    b.st_w(0, 0x0034, 14)  # C3CTR = 0 (Communication Mode)
    _poll_rscan_mode(b, 0x0038, 0, "C3COM")
    b.st_w(0, tgt_ctr_off, 14)  # CtargetCTR = 0 (Communication Mode)
    _poll_rscan_mode(b, tgt_sts_off, 0, "CTGTCOM")

    # 8. Load hot-loop constants into callee-saved registers r15..r29
    stop_d0, stop_d1 = struct.unpack("<II", J533_BRIDGE_STOP_DATA)
    ready_d0, ready_d1 = struct.unpack("<II", J533_BRIDGE_READY_DATA)
    end_d0, end_d1 = struct.unpack("<II", J533_BRIDGE_END_DATA)

    b.mov_u16(J533_BRIDGE_STOP_ID, 15)
    b.mov_imm(stop_d0, 16)
    b.mov_imm(stop_d1, 17)
    b.mov_imm(0xF0000000, 18)
    b.mov_u16(0x00FF, 19)
    b.mov_imm(0xDFFFFFFF, 20)  # mask IDE|RTR|ID29, clear THLEN (bit 29)
    b.mov_imm5(0, 21)          # idle counter = 0
    b.mov_imm(idle_limit, 22)
    b.mov_imm(tgt_tmid_addr, 24)
    b.mov_imm(diag_tmid_addr, 25)
    b.mov_imm(tgt_tmc_addr, 26)
    b.mov_imm(tgt_tmsts_addr, 27)
    b.mov_imm(diag_tmc_addr, 28)
    b.mov_imm(diag_tmsts_addr, 29)

    # 9. Emit bridge-ready beacon `J533BRDG` on ch3 0x6F1
    b.st_b(0, 0, 29)
    b.mov_u16(J533_BRIDGE_READY_ID, 6)
    b.st_w(6, 0x00, 25)
    b.mov_imm(0x80000000, 6)  # DLC = 8
    b.st_w(6, 0x04, 25)
    b.mov_imm(ready_d0, 6)
    b.st_w(6, 0x08, 25)
    b.mov_imm(ready_d1, 6)
    b.st_w(6, 0x0C, 25)
    b.mov_imm5(1, 6)
    b.st_b(6, 0, 28)  # TMC48 = 1

    b.mov_imm(100_000, 10)
    b.label("WAIT_READY_TX")
    b.jarl("SUB_WDT")
    b.ld_bu_0(29, 6)
    b.andi(0x0006, 6, 6)
    b.cmp_imm5(0, 6)
    b.bne("READY_TX_DONE")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("WAIT_READY_TX")
    b.label("READY_TX_DONE")
    b.st_b(0, 0, 29)

    # 10. Tight bidirectional transparent bridge loop
    b.label("BRIDGE_LOOP")
    b.jarl("SUB_WDT")

    # ── Direction A: ch3 (Diag CAN) RX FIFO 0 -> target_channel TX buffer 0 ──
    b.ld_w(0x00D8, 14, 6)  # RFSTS0
    b.andi(0x0001, 6, 6)   # RFEMP == 0 means frame waiting
    b.cmp_imm5(0, 6)
    b.bne("CHECK_FIFO1")

    b.ld_w(0x0E00, 14, 6)  # RFID0
    b.ld_w(0x0E04, 14, 7)  # RFPTR0
    b.ld_w(0x0E08, 14, 8)  # RFDF00
    b.ld_w(0x0E0C, 14, 9)  # RFDF10
    b.and_reg(20, 6)       # clear THLEN bit 29; preserve IDE|RTR|ID29

    # Check stop magic BEFORE touching target TX (so unplugged sub-bus can never block STOPBRDG!)
    b.cmp_reg(15, 6)       # id == 0x6F0 (standard, IDE=0)?
    b.bne("FWD_TO_TGT")
    b.cmp_reg(16, 8)       # df0 == "STOP"?
    b.bne("CHECK_BURST" if burst_table else "FWD_TO_TGT")
    b.cmp_reg(17, 9)       # df1 == "BRDG"?
    b.bne("FWD_TO_TGT")
    b.st_w(19, 0x00F8, 14)  # RFPCTR0 = 0xFF
    b.jr("EXIT_BRIDGE")

    if burst_table:
        burst_d0, burst_d1 = struct.unpack("<II", J533_BRIDGE_BURST_DATA)
        b.label("CHECK_BURST")  # id == 0x6F0 already matched; r10 / r23 are free here
        b.mov_imm(burst_d0, 10)
        b.cmp_reg(10, 8)
        b.bne("FWD_TO_TGT")
        b.mov_imm(burst_d1, 10)
        b.cmp_reg(10, 9)
        b.bne("FWD_TO_TGT")
        b.st_w(19, 0x00F8, 14)  # RFPCTR0 = 0xFF (the trigger is consumed, never forwarded)
        b.jr("BURST")

    b.label("FWD_TO_TGT")
    b.mov_imm5(0, 21)      # reset idle counter on live ch3 activity
    # Wait for target TX buffer to become free (bounded ~5-10 ms with WDT refresh; abort if sub-bus has no ACK)
    b.mov_imm(60_000, 10)
    b.label("WAIT_TGT_TX")
    b.jarl("SUB_WDT")
    b.ld_bu_0(27, 23)      # TMSTStgt
    b.andi(0x0001, 23, 23) # TMTSTS
    b.cmp_imm5(0, 23)
    b.be("TGT_TX_FREE")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("WAIT_TGT_TX")
    # Sub-bus TX stalled (no ACK): abort pending TX so bridge stays responsive
    b.mov_imm5(2, 23)
    b.st_b(23, 0, 26)      # TMCtgt = 2 (TMTAR abort)
    b.mov_u16(2000, 10)
    b.label("WAIT_TGT_ABT")
    b.jarl("SUB_WDT")
    b.ld_bu_0(27, 23)
    b.andi(0x0001, 23, 23)
    b.cmp_imm5(0, 23)
    b.be("TGT_TX_FREE")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("WAIT_TGT_ABT")
    b.st_w(19, 0x00F8, 14) # discard frame and move on
    b.jr("CHECK_FIFO1")

    b.label("TGT_TX_FREE")
    b.st_b(0, 0, 27)       # clear TMSTStgt (TMTRF := 00)
    b.and_reg(18, 7)       # keep DLC bits 31:28 only
    b.st_w(6, 0x00, 24)    # TMIDtgt
    b.st_w(7, 0x04, 24)    # TMPTRtgt
    b.st_w(8, 0x08, 24)    # TMDF0tgt
    b.st_w(9, 0x0C, 24)    # TMDF1tgt
    b.mov_imm5(1, 23)
    b.st_b(23, 0, 26)      # TMCtgt = 1 (TMTR)
    b.st_w(19, 0x00F8, 14) # RFPCTR0 = 0xFF

    # ── Direction B: target_channel RX FIFO 1 -> ch3 (Diag CAN) TX buffer 0 (TM48) ──
    b.label("CHECK_FIFO1")
    b.ld_w(0x00DC, 14, 6)  # RFSTS1
    b.andi(0x0001, 6, 6)   # RFEMP == 0?
    b.cmp_imm5(0, 6)
    b.bne("CHECK_IDLE")

    b.ld_bu_0(29, 23)      # TMSTS48
    b.andi(0x0001, 23, 23) # TMTSTS == 0?
    b.cmp_imm5(0, 23)
    b.bne("CHECK_IDLE")    # leave frame queued in 32-deep FIFO 1 until ch3 TX finishes

    b.ld_w(0x0E10, 14, 6)  # RFID1
    b.ld_w(0x0E14, 14, 7)  # RFPTR1
    b.ld_w(0x0E18, 14, 8)  # RFDF01
    b.ld_w(0x0E1C, 14, 9)  # RFDF11
    b.st_w(19, 0x00FC, 14) # RFPCTR1 = 0xFF

    b.and_reg(20, 6)       # preserve IDE|RTR|ID29, clear THLEN
    b.and_reg(18, 7)       # keep DLC bits 31:28
    b.st_b(0, 0, 29)       # clear TMSTS48
    b.st_w(6, 0x00, 25)    # TMID48
    b.st_w(7, 0x04, 25)    # TMPTR48
    b.st_w(8, 0x08, 25)    # TMDF0_48
    b.st_w(9, 0x0C, 25)    # TMDF1_48
    b.mov_imm5(1, 23)
    b.st_b(23, 0, 28)      # TMC48 = 1

    b.label("CHECK_IDLE")
    b.add_imm5(1, 21)
    b.cmp_reg(22, 21)
    b.bne("BRIDGE_LOOP")

    # 11. Clean bridge exit: send `BRDG-END` on ch3 0x6F1, then trigger SWRESA (+ WDTA fallback)
    b.label("EXIT_BRIDGE")
    b.mov_u16(10000, 10)
    b.label("WAIT_END_FREE")
    b.jarl("SUB_WDT")
    b.ld_bu_0(29, 6)
    b.andi(0x0001, 6, 6)
    b.cmp_imm5(0, 6)
    b.be("SEND_END_FRAME")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("WAIT_END_FREE")
    b.mov_imm5(2, 6)
    b.st_b(6, 0, 28)  # abort stuck ch3 TX before sending BRDG-END
    b.mov_u16(1000, 10)
    b.label("WAIT_END_ABT")
    b.ld_bu_0(29, 6)
    b.andi(0x0001, 6, 6)
    b.cmp_imm5(0, 6)
    b.be("SEND_END_FRAME")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("WAIT_END_ABT")

    b.label("SEND_END_FRAME")
    b.st_b(0, 0, 29)
    b.mov_u16(J533_BRIDGE_END_ID, 6)
    b.st_w(6, 0x00, 25)
    b.mov_imm(0x80000000, 6)
    b.st_w(6, 0x04, 25)
    b.mov_imm(end_d0, 6)
    b.st_w(6, 0x08, 25)
    b.mov_imm(end_d1, 6)
    b.st_w(6, 0x0C, 25)
    b.mov_imm5(1, 6)
    b.st_b(6, 0, 28)

    b.mov_imm(40_000, 10)
    b.label("WAIT_END_TX")
    b.jarl("SUB_WDT")
    b.ld_bu_0(29, 6)
    b.andi(0x0006, 6, 6)
    b.cmp_imm5(0, 6)
    b.bne("DO_SWRESA")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("WAIT_END_TX")

    b.label("DO_SWRESA")
    b.movhi(0xFFF8, 0, 14)
    b.mov_u16(0x00A5, 6)
    b.mov_imm5(1, 7)
    b.mov_imm5(-2, 8)
    b.st_w(6, 0x0000, 14)  # PROTCMD0 = 0xA5
    b.st_w(7, 0x0A04, 14)  # SWRESA = 1
    b.st_w(8, 0x0A04, 14)  # SWRESA = ~1
    b.st_w(7, 0x0A04, 14)  # SWRESA = 1
    b.label("BRIDGE_RST_SPIN")
    b.br_short("BRIDGE_RST_SPIN")

    if burst_table:
        _emit_bridge_burst(b, len(burst_frames or ()), burst_gap_loops)

    _emit_wdt_subroutine(b, "SUB_WDT")
    if burst_table:
        b.align(4)
        b.label("BURST_TABLE")
        b._emit(burst_table)
    return b.build()


def _emit_bridge_burst(b: _Rh850Builder, count: int, gap_loops: int) -> None:
    """`BURST`: send the `BURST_TABLE` frames on the target TX buffer, then answer on ch3 and rejoin `BRIDGE_LOOP`.

    Uses only r6..r10 and r23 (the bridge keeps its constants in r14..r29; SUB_WDT clobbers r11..r13).
    r24/r26/r27 = target TMID/TMC/TMSTS, r25/r28/r29 = ch3 TM48 TMID/TMC/TMSTS (set up by the bridge)."""
    ok_d0, ok_d1 = struct.unpack("<II", J533_BRIDGE_BURST_OK)
    na_d0, na_d1 = struct.unpack("<II", J533_BRIDGE_BURST_FAIL)
    b.label("BURST")
    b.mov_label_addr("BURST_TABLE", 8)
    b.mov_imm(count, 9)

    b.label("BURST_NEXT")
    # Previous frame (or the bridge's last forward) must be off the buffer: TMTSTS == 0
    b.mov_imm(60_000, 10)
    b.label("BURST_WAIT_FREE")
    b.jarl("SUB_WDT")
    b.ld_bu_0(27, 23)
    b.andi(0x0001, 23, 23)
    b.cmp_imm5(0, 23)
    b.be("BURST_FREE")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("BURST_WAIT_FREE")
    b.jr("BURST_STALL")

    b.label("BURST_FREE")
    b.st_b(0, 0, 27)       # clear TMSTStgt
    b.ld_w(0, 8, 6)
    b.st_w(6, 0x00, 24)    # TMIDtgt (IDE bit from the table)
    b.mov_imm(0x80000000, 6)
    b.st_w(6, 0x04, 24)    # TMPTRtgt: DLC = 8
    b.ld_w(4, 8, 6)
    b.st_w(6, 0x08, 24)    # TMDF0tgt
    b.ld_w(8, 8, 6)
    b.st_w(6, 0x0C, 24)    # TMDF1tgt
    b.mov_imm5(1, 23)
    b.st_b(23, 0, 26)      # TMCtgt = 1 (TMTR)

    # Wait for this frame to be on the wire and ACKed (TMTRF != 0), so the next one never queues behind it
    b.mov_imm(60_000, 10)
    b.label("BURST_WAIT_DONE")
    b.jarl("SUB_WDT")
    b.ld_bu_0(27, 23)
    b.andi(0x0006, 23, 23)
    b.cmp_imm5(0, 23)
    b.bne("BURST_SENT")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("BURST_WAIT_DONE")
    b.jr("BURST_STALL")

    b.label("BURST_SENT")
    b.mov_imm(gap_loops, 10)
    b.label("BURST_GAP")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne_short("BURST_GAP")
    b.addi(12, 8, 8)
    b.add_imm5(-1, 9)
    b.cmp_imm5(0, 9)
    b.bne("BURST_NEXT")
    b.mov_imm(ok_d0, 7)
    b.mov_imm(ok_d1, 9)
    b.jr("BURST_REPLY")

    # No ACK on the sub-bus: abort the pending frame, drop the rest of the table (a partial stream is never resumed)
    b.label("BURST_STALL")
    b.mov_imm5(2, 23)
    b.st_b(23, 0, 26)      # TMCtgt = 2 (TMTAR abort)
    b.mov_u16(2000, 10)
    b.label("BURST_WAIT_ABT")
    b.jarl("SUB_WDT")
    b.ld_bu_0(27, 23)
    b.andi(0x0001, 23, 23)
    b.cmp_imm5(0, 23)
    b.be("BURST_ABORTED")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("BURST_WAIT_ABT")
    b.label("BURST_ABORTED")
    b.mov_imm(na_d0, 7)
    b.mov_imm(na_d1, 9)

    # Answer on ch3 TM48 (0x6F1), then back to the bridge loop with a fresh idle counter
    b.label("BURST_REPLY")
    b.mov_imm(60_000, 10)
    b.label("BURST_WAIT_TM48")
    b.jarl("SUB_WDT")
    b.ld_bu_0(29, 23)
    b.andi(0x0001, 23, 23)
    b.cmp_imm5(0, 23)
    b.be("BURST_TM48_FREE")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("BURST_WAIT_TM48")
    b.mov_imm5(2, 23)
    b.st_b(23, 0, 28)      # TMC48 = 2: abort the stuck ch3 frame before overwriting it, as EXIT_BRIDGE does
    b.mov_u16(1000, 10)
    b.label("BURST_WAIT_TM48_ABT")
    b.ld_bu_0(29, 23)
    b.andi(0x0001, 23, 23)
    b.cmp_imm5(0, 23)
    b.be("BURST_TM48_FREE")
    b.add_imm5(-1, 10)
    b.cmp_imm5(0, 10)
    b.bne("BURST_WAIT_TM48_ABT")
    b.label("BURST_TM48_FREE")
    b.st_b(0, 0, 29)       # clear TMSTS48
    b.mov_u16(J533_BRIDGE_END_ID, 6)
    b.st_w(6, 0x00, 25)    # TMID48 = 0x6F1
    b.mov_imm(0x80000000, 6)
    b.st_w(6, 0x04, 25)    # DLC = 8
    b.st_w(7, 0x08, 25)
    b.st_w(9, 0x0C, 25)
    b.mov_imm5(1, 23)
    b.st_b(23, 0, 28)      # TMC48 = 1
    b.mov_imm5(0, 21)      # idle counter restarts after the burst
    b.jr("BRIDGE_LOOP")
