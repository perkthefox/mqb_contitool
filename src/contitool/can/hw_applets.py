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
    b.mov_reg(31, 20)
    b.mov_u16(4096, 21)
    b.label("_FRDY_POLL")
    b.ld_w(FACI_FSTATR_OFF, 17, 18)
    b.andi(0x8000, 18, 11)
    b.bne_short("_FRDY_DONE")
    b.add_imm5(-1, 21)
    b.bne_short("_FRDY_POLL")
    b.jarl("SUB_WDT")
    b.mov_u16(4096, 21)
    b.br_short("_FRDY_POLL")
    b.label("_FRDY_DONE")
    b.andi(0x7000, 18, 11)
    b.mov_reg(20, 31)
    b.jmp_lp()


def _build_faci_code_stub(*, is_uflash: bool) -> tuple[bytes, int]:
    """Build deterministic RH850/F1L FACI CodeFlash / Extended User Area writer applet.

    Result & diagnostic block at `0xFEDE9000` (`5 x u32` = 20 bytes):
      - `+0x00` (`u32`): `marker` (`1`=OK, `2`=`FENTRYR` timeout, `3`=Erase err, `4`=Program err, `5`=`FPMON.FWE` low)
      - `+0x04` (`u32`): `fstatr` (`0xFFA10080`)
      - `+0x08` (`u32`): `last_offset`
      - `+0x0C` (`4x u8`): `fpmon` (`+0x0C`), `flmdps` (`+0x0D`), `fastat` (`+0x0E`), reserved (`+0x0F`)
      - `+0x10` (`2x u16`): `fentryr` (`+0x10`), `fpckar` (`+0x12`)
    """
    b = _Rh850Builder()
    saved_regs = (20, 21, 22, 31) if is_uflash else (20, 21, 22, 23, 31)
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
    b.st_w(10, 0x00, 7)
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

    # 3. Load 128-bit SELFID into FLID0..FLID3 + mandatory dummy ld.w of FLID3
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

    b.addi(-0x8000, 17, 12)  # 0xFFA10000 - 0x8000 = 0xFFA08000 (FLID_BASE)
    b.mov_imm5(4, 13)
    b.label("_FLID_LOOP")
    b.ld_w(0, 11, 14)
    b.st_w(14, 0, 12)
    b.add_imm5(4, 11)
    b.add_imm5(4, 12)
    b.add_imm5(-1, 13)
    b.bne_short("_FLID_LOOP")
    b.ld_w(-4, 12, 14)

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
    b.mov_u16(128, 13)
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
    b.di()


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
    b.mov_u16(0xAA80, 6)
    b.jarl("SUB_PE")
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
    b.mov_u16(0xAA00, 6)
    b.jarl("SUB_PE")
    b.mov_imm(0x4E414353, 7)
    b.label("MARK")
    b.st_w(7, 0x0100, 16)
    b.mov_imm(caller_r29, 29)
    _emit_fpke_leave(b, caller_return=caller_return)

    b.label("SUB_PE")
    b.andi(0x00FF, 6, 7)
    b.st_h(6, FACI_FENTRYR_OFF, 14)
    b.label("WT_PE")
    b.ld_hu(FACI_FENTRYR_OFF, 14, 6)
    b.cmp_reg(7, 6)
    b.bne_short("WT_PE")
    b.synci()
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
    b.ld_hu(FACI_FENTRYR_OFF, 14, 6)
    b.cmp_imm5(0, 6)
    b.bne_short("W_DONE")
    b.mov_u16(0xAA80, 6)
    b.jarl("SUB_PE")
    b.ld_hu(-8, 16, 8)
    b.ld_hu(-6, 16, 6)
    b.ld_w(-4, 16, 9)
    b.mov_reg(16, 11)
    b.cmp_imm5(0, 6)
    b.be_short("W_INIT")
    b.mov_imm5(3, 10)
    b.mov_u16(0x003F, 6)
    b.mov_u16(0x0020, 7)
    b.jarl("SUB_CMD")
    b.jarl("SUB_FIN")
    b.label("W_INIT")
    b.mov_imm5(4, 10)
    b.movhi(1, 0, 19)
    b.label("W_LP")
    b.mov_reg(9, 6)
    b.and_reg(19, 6)
    b.be_short("W_SKP")
    b.mov_imm5(3, 6)
    b.mov_u16(0x00E8, 7)
    b.jarl("SUB_CMD")
    b.mov_imm5(2, 6)
    b.st_h(6, 0, 15)
    b.ld_hu(0, 11, 6)
    b.st_h(6, 0, 15)
    b.ld_hu(2, 11, 6)
    b.st_h(6, 0, 15)
    b.jarl("SUB_FIN")
    b.label("W_SKP")
    b.add_imm5(4, 8)
    b.add_imm5(4, 11)
    b.add_reg(19, 19)
    b.bne_short("W_LP")
    b.mov_imm5(1, 10)
    b.label("W_EXIT")
    b.mov_u16(0xAA00, 6)
    b.jarl("SUB_PE")
    b.label("W_DONE")
    b.st_w(10, 0x00F8, 16)
    b.mov_imm(0x4E414353, 7)
    b.st_w(7, 0x01F8, 16)
    _emit_fpke_leave(b, caller_return=caller_return)

    b.label("SUB_PE")
    b.andi(0x00FF, 6, 7)
    b.st_h(6, FACI_FENTRYR_OFF, 14)
    b.label("WT_PE")
    b.ld_hu(FACI_FENTRYR_OFF, 14, 6)
    b.cmp_reg(7, 6)
    b.bne_short("WT_PE")
    b.synci()
    b.mov_u16(0x0010, 6)
    b.st_b(6, FACI_FASTAT_OFF, 14)
    b.st_b(12, 0, 15)
    b.jmp_lp()

    b.label("SUB_CMD")
    b.add_reg(8, 6)
    b.st_w(8, FACI_FSADDR_OFF, 14)
    b.st_w(6, FACI_FEADDR_OFF, 14)
    b.st_b(12, 0, 15)
    b.st_h(7, 0, 15)
    b.jmp_lp()

    b.label("SUB_FIN")
    b.mov_u16(0x00D0, 6)
    b.st_h(6, 0, 15)
    b.label("SUB_FRDY")
    b.ld_w(FACI_FSTATR_OFF, 14, 6)
    b.andi(0x8000, 6, 7)
    b.be_short("SUB_FRDY")
    b.st_w(6, 0x00FC, 16)
    b.andi(0x7000, 6, 7)
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
EXPECTED_UFLASH_FACI_STUB_SHA256 = "a7667b232516aca547885d5069d8e2ee12046bf4da6344396ef376060dcc3f32"
EXPECTED_CFLASH_FACI_STUB_SHA256 = "f7ee469253d89afbfc8bc73f884ec639962f404cd684fea1a20595e5847f9187"
