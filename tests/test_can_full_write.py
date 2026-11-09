"""Comprehensive RH850 CPU/FACI simulation & end-to-end CAN write tests for DataFlash, CodeFlash, and Uflash."""

from __future__ import annotations

from pathlib import Path
import struct
import can
import pytest

from contitool.can import (
    BEACON_ASCII,
    CFLASH_FACI_STUB,
    DFLASH_BLOCK_SIZE,
    DFLASH_FACI_STUB,
    DFLASH_ICUS_RESERVED_OFFSET,
    DFLASH_READER_STUB,
    J533CanLink,
    LOADER_PASSWORD,
    LOADER_RESET_PAYLOAD,
    LOADER_SYNC,
    MAX_LOADER_PACKET_SIZE,
    RSA_PROBE_PAYLOAD,
    UFLASH_FACI_STUB,
    build_cflash_faci_block_payloads,
    build_dflash_faci_payloads,
    build_dflash_reader_payload,
    build_fed_reader_payload,
    build_loader_packet,
    build_reader_payload,
    build_service_loader_uds_steps,
    build_uflash_faci_payloads,
    can_read_memory,
    can_turnkey_read_patch_flash,
    can_write_cflash,
    can_write_dflash,
    can_write_uflash,
    cflash_block_ranges,
    dflash_active_word_count,
    enter_ram_loader,
    fbl_sa2,
    read_memory_area,
    read_memory_bytes,
)
from contitool.core import (
    analyze_cflash,
    analyze_dflash,
    analyze_dflash_swap,
    analyze_uflash,
    apply_cflash_rsa_modulus,
    apply_dflash_swap_rsa_modulus,
    apply_engineering_patch,
    bind_cp_turnkey,
    fbl_app_valid,
    generate_rsa1024_e3_keypair,
    load_rsa1024_key_material,
    parse_hex_key,
    parse_slot_selector,
    save_rsa1024_keypair_bundle,
)
from contitool.core.constants import (
    APP_BASE,
    APP_SIZE,
    CFLASH_SIZE,
    DFLASH_SIZE,
    FBL_MOD_OFFSET,
    FBL_PRESENCE_MAGIC,
    UFLASH_SIZE,
)


def _sext(val: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (val & (sign - 1)) - (val & sign)


class SimulatedRh850FaciMcu:
    """Deterministic RH850 (V850E3v5) CPU + FACI + WDTA hardware emulator for J533 flash stubs."""

    RAM_BASE = 0xFEDE0000
    RAM_SIZE = 0x20000  # 128 KB Local RAM (0xFEDE0000..0xFEDFFFFF)
    PAYLOAD_ENTRY = 0xFEDF8138
    RETURN_PC = 0x01001402

    def __init__(self, cflash: bytes, uflash: bytes, dflash: bytes, selfid: bytes | None = None) -> None:
        assert len(cflash) == CFLASH_SIZE
        assert len(uflash) == UFLASH_SIZE
        assert len(dflash) == DFLASH_SIZE
        self.cflash = bytearray(cflash)
        if selfid is not None:
            assert len(selfid) == 16
            self.cflash[0xAB00:0xAB10] = selfid
        self.uflash = bytearray(uflash)
        self.dflash = bytearray(dflash)
        # Track physical blank vs programmed ECC state per 4-byte DataFlash word
        self.dflash_word_programmed = [
            self.dflash[w * 4 : w * 4 + 4] != b"\xff\xff\xff\xff" for w in range(DFLASH_SIZE // 4)
        ]
        self.ram = bytearray(self.RAM_SIZE)

        # Hardware peripheral state
        self.flid = [0, 0, 0, 0]
        self.flid3_dummy_read = False
        self.fentryr = 0x0000
        self.fprotr = 0x0000
        self.fareaselc = 0x3B00
        self.fsaddr = 0x00000000
        self.feaddr = 0x00000000
        self.fstatr = 0x00008000  # FRDY=1
        self.fcstatr = 0x00
        self.fbcstat = 0x00
        self.fpsaddr = 0x00000000
        self.simulate_rv40f_noise = True
        self._noise_counter = 0
        self.streamed_frames: list[bytes] = []
        self._cmd_seq: list[tuple[int, int]] = []  # (width_bytes, value)

        self.wdta_ref = {0xFFED0000: 0x37, 0xFFED1000: 0x5A}
        self._wdta_armed: dict[int, bool] = {0xFFED0000: False, 0xFFED1000: False}
        self.wdta_kicks = {0xFFED0000: 0, 0xFFED1000: 0}
        self.interrupts_disabled = False

    def read_phys(self, addr: int, length: int) -> bytes:
        addr &= 0xFFFFFFFF
        if 0 <= addr and addr + length <= CFLASH_SIZE:
            assert self.fentryr != 0x0001, "Illegal CPU read from CodeFlash while in CodeFlash P/E mode!"
            return bytes(self.cflash[addr : addr + length])
        if 0x01000000 <= addr and addr + length <= 0x01000000 + UFLASH_SIZE:
            assert self.fentryr != 0x0001, "Illegal CPU read from Uflash while in CodeFlash P/E mode!"
            off = addr - 0x01000000
            return bytes(self.uflash[off : off + length])
        if 0xFF200000 <= addr and addr + length <= 0xFF200000 + DFLASH_SIZE:
            assert self.fentryr != 0x0080, "Illegal CPU read from DataFlash while in DataFlash P/E mode!"
            off = addr - 0xFF200000
            if not self.simulate_rv40f_noise:
                return bytes(self.dflash[off : off + length])
            out = bytearray(self.dflash[off : off + length])
            first_w = off // 4
            last_w = (off + length - 1) // 4
            for w in range(first_w, last_w + 1):
                if w * 4 < DFLASH_ICUS_RESERVED_OFFSET and not self.dflash_word_programmed[w]:
                    self._noise_counter += 1
                    noise = ((w * 0x9E3779B1) ^ (self._noise_counter * 0x85EBCA6B) ^ 0xA55AA55A) & 0xFFFFFFFF
                    if noise == 0xFFFFFFFF:
                        noise = 0xFEFFFFFF
                    noise_bytes = struct.pack("<I", noise)
                    for b_idx in range(4):
                        pos = w * 4 + b_idx - off
                        if 0 <= pos < length:
                            out[pos] = noise_bytes[b_idx]
            return bytes(out)
        if self.RAM_BASE <= addr and addr + length <= self.RAM_BASE + self.RAM_SIZE:
            off = addr - self.RAM_BASE
            return bytes(self.ram[off : off + length])
        if 0xFFA08000 <= addr <= 0xFFA0800C and length == 4:
            idx = (addr - 0xFFA08000) // 4
            if idx == 3:
                self.flid3_dummy_read = True
            return struct.pack("<I", self.flid[idx])
        if addr == 0xFFA10080 and length == 4:
            return struct.pack("<I", self.fstatr)
        if addr == 0xFFA10084 and length == 2:
            return struct.pack("<H", self.fentryr)
        if addr == 0xFFA100D4 and length == 1:
            return bytes([self.fbcstat])
        if addr == 0xFFA100D8 and length == 4:
            return struct.pack("<I", self.fpsaddr)
        if addr in (0xFFED0008, 0xFFED1008) and length == 1:
            base = addr & 0xFFFFF000
            return bytes([self.wdta_ref[base]])
        raise AssertionError(f"Unhandled MMIO/memory read at 0x{addr:08X} ({length} B)")

    def write_phys(self, addr: int, data: bytes) -> None:
        addr &= 0xFFFFFFFF
        ln = len(data)
        if self.RAM_BASE <= addr and addr + ln <= self.RAM_BASE + self.RAM_SIZE:
            off = addr - self.RAM_BASE
            self.ram[off : off + ln] = data
            return
        if 0xFFA08000 <= addr <= 0xFFA0800C and ln == 4:
            assert self.fentryr == 0x0000, "FLID must be loaded in Read mode before P/E entry!"
            idx = (addr - 0xFFA08000) // 4
            self.flid[idx] = int.from_bytes(data, "little")
            return
        if addr == 0xFFA10084 and ln == 2:
            val = int.from_bytes(data, "little")
            assert (val & 0xFF00) == 0xAA00, f"FENTRYR missing 0xAA00 key: 0x{val:04X}"
            mode = val & 0x00FF
            assert mode in (0x00, 0x01, 0x80), f"Invalid FENTRYR mode: 0x{val:04X}"
            if mode in (0x01, 0x80):
                expected_flid = list(struct.unpack("<4I", self.cflash[0xAB00:0xAB10]))
                assert self.flid == expected_flid, f"FLID mismatch on P/E entry: {self.flid} != {expected_flid}"
            self.fentryr = mode
            self._cmd_seq.clear()
            return
        if addr == 0xFFA10088 and ln == 2:
            assert self.fentryr == 0x0001, (
                f"Writing FPROTR while FENTRYR=0x{self.fentryr:04X} raises ILGLERR on RH850/F1L!"
            )
            val = int.from_bytes(data, "little")
            assert val == 0x5501, f"Unexpected FPROTR value: 0x{val:04X}"
            self.fprotr = 1
            return
        if addr == 0xFFA10020 and ln == 2:
            val = int.from_bytes(data, "little")
            assert val in (0x3B00, 0x3B02), f"Unexpected FAREASELC value: 0x{val:04X}"
            self.fareaselc = val
            return
        if addr == 0xFFA10030 and ln == 4:
            self.fsaddr = int.from_bytes(data, "little")
            return
        if addr == 0xFFA10034 and ln == 4:
            self.feaddr = int.from_bytes(data, "little")
            return
        if addr == 0xFFA10010 and ln == 1:
            self.fcstatr = data[0]
            self._cmd_seq.clear()
            return
        if addr == 0xFFA20000 and ln in (1, 2):
            val = int.from_bytes(data, "little")
            self._handle_faci_cmd(ln, val)
            return
        if (addr & 0xFFFFF000) in (0xFFED0000, 0xFFED1000) and ln == 1:
            base = addr & 0xFFFFF000
            reg_off = addr & 0xFFF
            if reg_off == 0x00:
                assert data[0] == 0xAC, f"Bad WDTA WDTE byte: 0x{data[0]:02X}"
                self._wdta_armed[base] = True
                return
            if reg_off == 0x04:
                assert self._wdta_armed[base], "WDTA EVAC written before WDTE=0xAC!"
                expected = (-0x54 - self.wdta_ref[base]) & 0xFF
                assert data[0] == expected, f"Bad WDTA EVAC: 0x{data[0]:02X} != 0x{expected:02X}"
                self._wdta_armed[base] = False
                self.wdta_kicks[base] += 1
                return
        raise AssertionError(f"Unhandled MMIO/memory write at 0x{addr:08X} ({ln} B): {data.hex()}")

    def _handle_faci_cmd(self, width: int, val: int) -> None:
        if width == 1 and val == 0x50:
            # Clear Status command
            self.fstatr = 0x00008000
            self._cmd_seq.clear()
            return
        self._cmd_seq.append((width, val))

        # 1. Block Erase: [0x20, 0xD0]
        if self._cmd_seq == [(1, 0x20), (1, 0xD0)]:
            self._cmd_seq.clear()
            if self.fentryr == 0x0080:
                # DataFlash 64B zero-based erase
                assert 0 <= self.fsaddr < DFLASH_SIZE and self.fsaddr % 64 == 0
                assert self.feaddr == self.fsaddr + 63
                self.dflash[self.fsaddr : self.fsaddr + 64] = b"\xff" * 64
                for w in range(self.fsaddr // 4, (self.fsaddr + 64) // 4):
                    self.dflash_word_programmed[w] = False
            elif self.fentryr == 0x0001:
                assert self.fprotr == 1
                if self.fareaselc == 0x3B02:
                    assert self.fsaddr == 0x01000000 and self.feaddr == 0x01007FFF
                    self.uflash[:] = b"\xff" * UFLASH_SIZE
                else:
                    assert self.fareaselc == 0x3B00
                    valid_blocks = {(s, e - 1) for _, s, e in cflash_block_ranges()}
                    assert (self.fsaddr, self.feaddr) in valid_blocks, (
                        f"Non-hardware CodeFlash erase range 0x{self.fsaddr:X}..0x{self.feaddr:X}"
                    )
                    self.cflash[self.fsaddr : self.feaddr + 1] = b"\xff" * (self.feaddr - self.fsaddr + 1)
            else:
                raise AssertionError("Erase issued outside P/E mode!")
            self.fstatr = 0x00008000
            return

        # 1b. DataFlash Blank Check: [0x71, 0xD0]
        if self._cmd_seq == [(1, 0x71), (1, 0xD0)]:
            self._cmd_seq.clear()
            assert self.fentryr == 0x0080, "Blank Check issued outside DataFlash P/E mode!"
            assert 0 <= self.fsaddr <= self.feaddr < DFLASH_SIZE
            assert self.fsaddr % 4 == 0 and (self.feaddr + 1) % 4 == 0
            assert (self.fsaddr >> 12) == (self.feaddr >> 12), "Blank Check crossed 4 KB boundary!"
            start_w = self.fsaddr // 4
            end_w = (self.feaddr + 1) // 4
            first_prog = next((w for w in range(start_w, end_w) if self.dflash_word_programmed[w]), None)
            if first_prog is not None:
                self.fbcstat = 0x01
                self.fpsaddr = first_prog * 4
            else:
                self.fbcstat = 0x00
                self.fpsaddr = 0x00000000
            self.fstatr = 0x00008000
            return

        # 2. DataFlash 4-byte word program: (2, 0x00E8), (2, 0x0002), hw0, hw1, (2, 0x00D0)
        if (
            self.fentryr == 0x0080
            and len(self._cmd_seq) == 5
            and self._cmd_seq[0] == (2, 0x00E8)
            and self._cmd_seq[1] == (2, 0x0002)
            and self._cmd_seq[4] == (2, 0x00D0)
        ):
            assert self._cmd_seq[2][0] == 2 and self._cmd_seq[3][0] == 2
            assert 0 <= self.fsaddr <= DFLASH_SIZE - 4 and self.fsaddr % 4 == 0
            w_idx = self.fsaddr // 4
            assert not self.dflash_word_programmed[w_idx], (
                f"DataFlash word @ 0x{self.fsaddr:04X} programmed without prior erase (ECC corruption)!"
            )
            word_bytes = struct.pack("<HH", self._cmd_seq[2][1], self._cmd_seq[3][1])
            self.dflash[self.fsaddr : self.fsaddr + 4] = word_bytes
            self.dflash_word_programmed[w_idx] = True
            self._cmd_seq.clear()
            self.fstatr = 0x00008000
            return

        # 3. CodeFlash / Uflash 256-byte page program: (1, 0xE8), (1, 0x80), 128 halfwords, (1, 0xD0)
        if (
            self.fentryr == 0x0001
            and len(self._cmd_seq) == 131
            and self._cmd_seq[0][1] == 0xE8
            and self._cmd_seq[1][1] == 0x80
            and self._cmd_seq[130][1] == 0xD0
        ):
            assert self.fprotr == 1
            page = b"".join(struct.pack("<H", hw) for _, hw in self._cmd_seq[2:130])
            assert len(page) == 256 and self.feaddr == self.fsaddr + 0xFF and self.fsaddr % 256 == 0
            if self.fareaselc == 0x3B02:
                off = self.fsaddr - 0x01000000
                assert 0 <= off <= UFLASH_SIZE - 256
                assert self.uflash[off : off + 256] == b"\xff" * 256, "Uflash page not erased before write!"
                self.uflash[off : off + 256] = page
            else:
                assert 0 <= self.fsaddr <= CFLASH_SIZE - 256
                assert self.cflash[self.fsaddr : self.fsaddr + 256] == b"\xff" * 256, (
                    f"CodeFlash page 0x{self.fsaddr:06X} not erased before write!"
                )
                self.cflash[self.fsaddr : self.fsaddr + 256] = page
            self._cmd_seq.clear()
            self.fstatr = 0x00008000

    def execute_loader_payload(self, payload: bytes, *, check_callee_saved: bool = True) -> dict[str, int]:
        """Load `payload` at 0xFEDF8138 and execute RH850 instructions until returning to `RETURN_PC`."""
        self.streamed_frames = []
        off = self.PAYLOAD_ENTRY - self.RAM_BASE
        self.ram[off : off + len(payload)] = payload

        regs = [0] * 32
        regs[3] = 0xFEDFFFE0  # sp
        regs[28] = 0xFEDF8130  # loader r28 pointer
        regs[29] = 0xFEDF8000  # loader r29 pointer
        regs[30] = 0xFEDE1234  # ep sentinel
        regs[31] = self.RETURN_PC  # lp
        for r_idx in range(20, 28):
            regs[r_idx] = 0xA5000000 | r_idx
        saved_snapshot = {r_idx: regs[r_idx] for r_idx in [3, *range(20, 30), 31]}

        z_flag = False
        pc = self.PAYLOAD_ENTRY
        steps = 0
        max_steps = 5_000_000

        while pc != self.RETURN_PC:
            steps += 1
            assert steps <= max_steps, f"Stub execution exceeded {max_steps} instructions @ PC=0x{pc:08X}"
            regs[0] = 0

            # Native FBL service traps in Uflash (valid whenever CodeFlash/Uflash is in Read mode)
            if pc == 0x01000EF0:
                assert self.fentryr != 0x0001, "Cannot call Uflash 0x01000EF0 while FENTRYR == 0x0001!"
                self.wdta_kicks[0xFFED0000] += 1
                self.wdta_kicks[0xFFED1000] += 1
                regs[1] = 0xDEADBEEF
                regs[2] = 0xCAFEBABE
                regs[30] = 0xFFED1000
                pc = regs[31] & 0xFFFFFFFF
                continue
            if pc == 0x010010F0:
                assert self.fentryr != 0x0001, "Cannot call Uflash 0x010010F0 while FENTRYR == 0x0001!"
                src_addr = regs[6] & 0xFFFFFFFF
                stream_len = regs[7] & 0xFFFF
                blob = self.read_phys(src_addr, stream_len)
                for f_off in range(0, stream_len, 8):
                    self.streamed_frames.append(blob[f_off : f_off + 8])
                for clob in (1, 2, *range(6, 20), 30):
                    regs[clob] = 0x55AA0000 | clob
                pc = regs[31] & 0xFFFFFFFF
                continue

            ram_off = pc - self.RAM_BASE
            assert 0 <= ram_off <= self.RAM_SIZE - 2, f"PC out of Local RAM: 0x{pc:08X}"
            hw0 = struct.unpack_from("<H", self.ram, ram_off)[0]

            # 32-bit indirect jarl [reg1], lp: hw0 = 0xC7E0 | reg1, hw1 = 0xF960
            if (hw0 & 0xFFE0) == 0xC7E0:
                hw1 = struct.unpack_from("<H", self.ram, ram_off + 2)[0]
                if hw1 == 0xF960:
                    target = regs[hw0 & 0x1F] & 0xFFFFFFFF
                    regs[31] = (pc + 4) & 0xFFFFFFFF
                    pc = target
                    continue

            # Special 32-bit system instructions: di (e007 6001) / ei (e087 6001)
            if hw0 in (0x07E0, 0x87E0):
                hw1 = struct.unpack_from("<H", self.ram, ram_off + 2)[0]
                if hw0 == 0x07E0 and hw1 == 0x0160:
                    self.interrupts_disabled = True
                    pc += 4
                    continue
                if hw0 == 0x87E0 and hw1 == 0x0160:
                    self.interrupts_disabled = False
                    pc += 4
                    continue

            # nop (0x0000)
            if hw0 == 0x0000:
                pc += 2
                continue

            # Format III short conditional branch: ddddd 1011 ddd cccc
            if ((hw0 >> 7) & 0xF) == 0b1011:
                cond = hw0 & 0xF
                disp9 = (((hw0 >> 11) & 0x1F) << 4) | (((hw0 >> 4) & 0x7) << 1)
                disp = _sext(disp9, 9)
                take = (
                    True
                    if cond == 0x5
                    else (z_flag if cond == 0x2 else ((not z_flag) if cond == 0xA else None))
                )
                assert take is not None, f"Unsupported bcond condition 0x{cond:X} @ 0x{pc:08X}"
                pc = (pc + disp) if take else (pc + 2)
                continue

            # Format IV sld.bu disp4[ep], reg2 (reg2 != r0; reg2 == r0 is Format I jmp [reg1]): RRRRR 0000110 dddd
            if ((hw0 >> 4) & 0x7F) == 0b0000110 and ((hw0 >> 11) & 0x1F) != 0:
                reg2 = (hw0 >> 11) & 0x1F
                disp4 = hw0 & 0xF
                regs[reg2] = self.read_phys((regs[30] + disp4) & 0xFFFFFFFF, 1)[0]
                pc += 2
                continue

            # Format IV sst.b reg2, disp7[ep]: RRRRR 0111 ddddddd
            if ((hw0 >> 7) & 0xF) == 0b0111:
                reg2 = (hw0 >> 11) & 0x1F
                disp7 = hw0 & 0x7F
                self.write_phys((regs[30] + disp7) & 0xFFFFFFFF, bytes([regs[reg2] & 0xFF]))
                pc += 2
                continue

            # Format V jr / jarl disp22: RRRRR 11110 dddddd + ddddddddddddddd0 (hw1 bit 0 == 0)
            if ((hw0 >> 6) & 0x1F) == 0b11110:
                hw1 = struct.unpack_from("<H", self.ram, ram_off + 2)[0]
                if (hw1 & 1) == 0:
                    reg2 = (hw0 >> 11) & 0x1F
                    disp22 = ((hw0 & 0x3F) << 16) | (hw1 & 0xFFFE)
                    disp = _sext(disp22, 22)
                    if reg2 != 0:
                        regs[reg2] = (pc + 4) & 0xFFFFFFFF
                    pc = (pc + disp) & 0xFFFFFFFF
                    continue

            op6 = (hw0 >> 5) & 0x3F
            reg1 = hw0 & 0x1F
            reg2 = (hw0 >> 11) & 0x1F

            # Format I / II (16-bit)
            if op6 == 0b000011 and reg2 == 0:  # jmp [reg1]
                pc = regs[reg1] & 0xFFFFFFFF
                continue
            if op6 == 0b000000:  # mov reg1, reg2
                if reg2 != 0:
                    regs[reg2] = regs[reg1]
                pc += 2
                continue
            if op6 == 0b001110:  # add reg1, reg2
                res = (regs[reg2] + regs[reg1]) & 0xFFFFFFFF
                z_flag = res == 0
                if reg2 != 0:
                    regs[reg2] = res
                pc += 2
                continue
            if op6 == 0b001100:  # subr reg1, reg2 (reg2 <- reg1 - reg2)
                res = (regs[reg1] - regs[reg2]) & 0xFFFFFFFF
                z_flag = res == 0
                if reg2 != 0:
                    regs[reg2] = res
                pc += 2
                continue
            if op6 == 0b001111:  # cmp reg1, reg2
                z_flag = ((regs[reg2] - regs[reg1]) & 0xFFFFFFFF) == 0
                pc += 2
                continue
            if op6 == 0b010000:  # mov imm5, reg2
                if reg2 != 0:
                    regs[reg2] = _sext(reg1, 5) & 0xFFFFFFFF
                pc += 2
                continue
            if op6 == 0b010010:  # add imm5, reg2
                res = (regs[reg2] + _sext(reg1, 5)) & 0xFFFFFFFF
                z_flag = res == 0
                if reg2 != 0:
                    regs[reg2] = res
                pc += 2
                continue
            if op6 == 0b010011:  # cmp imm5, reg2
                z_flag = ((regs[reg2] - (_sext(reg1, 5) & 0xFFFFFFFF)) & 0xFFFFFFFF) == 0
                pc += 2
                continue

            # Format VI (32-bit / 48-bit)
            if op6 == 0b110001 and reg2 == 0 and reg1 != 0:  # 48-bit mov imm32, reg1
                imm32 = struct.unpack_from("<I", self.ram, ram_off + 2)[0]
                regs[reg1] = imm32
                pc += 6
                continue
            if op6 == 0b110000:  # addi imm16, reg1, reg2
                imm16 = _sext(struct.unpack_from("<H", self.ram, ram_off + 2)[0], 16)
                res = (regs[reg1] + imm16) & 0xFFFFFFFF
                z_flag = res == 0
                if reg2 != 0:
                    regs[reg2] = res
                pc += 4
                continue
            if op6 == 0b110001:  # movea imm16, reg1, reg2
                imm16 = _sext(struct.unpack_from("<H", self.ram, ram_off + 2)[0], 16)
                if reg2 != 0:
                    regs[reg2] = (regs[reg1] + imm16) & 0xFFFFFFFF
                pc += 4
                continue
            if op6 == 0b110010:  # movhi imm16, reg1, reg2
                imm16 = struct.unpack_from("<H", self.ram, ram_off + 2)[0]
                if reg2 != 0:
                    regs[reg2] = (regs[reg1] + (imm16 << 16)) & 0xFFFFFFFF
                pc += 4
                continue
            if op6 == 0b110110:  # andi imm16_u, reg1, reg2
                imm16 = struct.unpack_from("<H", self.ram, ram_off + 2)[0]
                res = regs[reg1] & imm16
                z_flag = res == 0
                if reg2 != 0:
                    regs[reg2] = res
                pc += 4
                continue

            # Format VII loads/stores (32-bit)
            hw1 = struct.unpack_from("<H", self.ram, ram_off + 2)[0]
            if op6 == 0b111001:  # ld.h / ld.w disp16[reg1], reg2
                disp = _sext(hw1 & 0xFFFE, 16)
                addr = (regs[reg1] + disp) & 0xFFFFFFFF
                if hw1 & 1:
                    val = int.from_bytes(self.read_phys(addr, 4), "little")
                else:
                    val = _sext(int.from_bytes(self.read_phys(addr, 2), "little"), 16) & 0xFFFFFFFF
                if reg2 != 0:
                    regs[reg2] = val
                pc += 4
                continue
            if op6 == 0b111111 and (hw1 & 1):  # ld.hu disp16[reg1], reg2
                disp = _sext(hw1 & 0xFFFE, 16)
                addr = (regs[reg1] + disp) & 0xFFFFFFFF
                val = int.from_bytes(self.read_phys(addr, 2), "little")
                if reg2 != 0:
                    regs[reg2] = val
                pc += 4
                continue
            if op6 in (0b111100, 0b111101) and (hw1 & 1):  # ld.bu disp16[reg1], reg2
                disp = _sext((hw1 & 0xFFFE) | (op6 & 1), 16)
                addr = (regs[reg1] + disp) & 0xFFFFFFFF
                val = self.read_phys(addr, 1)[0]
                if reg2 != 0:
                    regs[reg2] = val
                pc += 4
                continue
            if op6 == 0b111011:  # st.h / st.w reg2, disp16[reg1]
                disp = _sext(hw1 & 0xFFFE, 16)
                addr = (regs[reg1] + disp) & 0xFFFFFFFF
                if hw1 & 1:
                    self.write_phys(addr, struct.pack("<I", regs[reg2] & 0xFFFFFFFF))
                else:
                    self.write_phys(addr, struct.pack("<H", regs[reg2] & 0xFFFF))
                pc += 4
                continue
            if op6 == 0b111010:  # st.b reg2, disp16[reg1]
                disp = _sext(hw1, 16)
                addr = (regs[reg1] + disp) & 0xFFFFFFFF
                self.write_phys(addr, bytes([regs[reg2] & 0xFF]))
                pc += 4
                continue

            raise AssertionError(f"Unsupported opcode 0x{hw0:04X} @ PC=0x{pc:08X}")

        assert self.fentryr == 0x0000, f"Stub returned without exiting P/E mode (FENTRYR=0x{self.fentryr:04X})!"
        assert not self.interrupts_disabled, "Stub returned with interrupts still disabled (di without ei)!"
        if check_callee_saved:
            for r_idx, exp in saved_snapshot.items():
                if r_idx == 27 and regs[27] == self.RETURN_PC:
                    continue  # reader payloads (stock and fed) return with r27 = lp, as on the hardware
                assert regs[r_idx] == exp, (
                    f"Callee-saved register r{r_idx} corrupted: 0x{regs[r_idx]:08X} != 0x{exp:08X}"
                )

        st_off = 0xFEDE9000 - self.RAM_BASE
        marker, fstatr, last_off = struct.unpack_from("<3I", self.ram, st_off)
        return {"marker": marker, "fstatr": fstatr, "last_offset": last_off, "steps": steps}


class SimulatedJ533CanBus:
    """Full in-memory J533 ECU CAN bus connecting UDS + 0x6F0 RAM-Loader to `SimulatedRh850FaciMcu`."""

    def __init__(self, mcu: SimulatedRh850FaciMcu) -> None:
        self.mcu = mcu
        self.rx_queue: list[can.Message] = []
        self._loader_expected = 0
        self._loader_buf = bytearray()
        self._uds_multi_expected = 0
        self._uds_multi_buf = bytearray()
        self._dl_offset = 0
        self._dl_buf = bytearray()
        self._seed = 0x2468ACE1

    def recv(self, timeout: float = 0.0):
        return self.rx_queue.pop(0) if self.rx_queue else None

    def shutdown(self) -> None:
        return None

    def _reply(self, arb_id: int, data: bytes) -> None:
        self.rx_queue.append(can.Message(arbitration_id=arb_id, data=data, is_extended_id=False))

    def _reply_uds(self, payload: bytes) -> None:
        if len(payload) <= 7:
            self._reply(0x77A, (bytes([len(payload)]) + payload).ljust(8, b"\xaa"))
            return
        self._reply(0x77A, bytes([0x10 | (len(payload) >> 8), len(payload) & 0xFF]) + payload[:6])
        seq = 1
        for off in range(6, len(payload), 7):
            self._reply(0x77A, bytes([0x20 | seq]) + payload[off : off + 7].ljust(7, b"\xaa"))
            seq = (seq + 1) & 0x0F

    def send(self, message: can.Message, timeout: float = 1.0) -> None:
        arb = message.arbitration_id
        raw = bytes(message.data)
        if arb == 0x710:
            pci = raw[0] >> 4
            if pci == 0:
                self._handle_uds(raw[1 : 1 + (raw[0] & 0x0F)])
            elif pci == 1:
                self._uds_multi_expected = ((raw[0] & 0x0F) << 8) | raw[1]
                self._uds_multi_buf = bytearray(raw[2:])
                self._reply(0x77A, b"\x30\x00\x00\xaa\xaa\xaa\xaa\xaa")
            elif pci == 2:
                self._uds_multi_buf.extend(raw[1:])
                if len(self._uds_multi_buf) >= self._uds_multi_expected:
                    self._handle_uds(bytes(self._uds_multi_buf[: self._uds_multi_expected]))
        elif arb == 0x6F0:
            if raw == LOADER_SYNC:
                self._loader_buf.clear()
                self._loader_expected = 0
                self._reply(0x6F1, LOADER_SYNC)
                return
            if not self._loader_buf:
                sz = raw[0] | ((raw[1] & 0x7F) << 8)
                assert sz <= MAX_LOADER_PACKET_SIZE
                self._loader_expected = sz + 3
            self._loader_buf.extend(raw)
            if len(self._loader_buf) >= self._loader_expected:
                pkt = bytes(self._loader_buf[: self._loader_expected])
                self._loader_buf.clear()
                assert pkt[0x110:0x118] == LOADER_PASSWORD
                self._dispatch_loader_code(pkt[0x118:-1])

    def _dispatch_loader_code(self, code: bytes) -> None:
        if code.startswith(LOADER_RESET_PAYLOAD):
            self._reply(0x6F1, b"\x00\x00")
            return
        if BEACON_ASCII in code:
            self._reply(0x6F1, BEACON_ASCII[:8])
            self._reply(0x6F1, BEACON_ASCII[8:].ljust(8, b"\x00"))
            self._reply(0x6F1, b"\x00\x00")
            return
        if code.startswith(b"\x26\x06") and len(code) <= 48 and b"\xf0\x10\x00\x01" in code:
            addr = int.from_bytes(code[2:6], "little")
            ln = int.from_bytes(code[8:12], "little")
            blob = self.mcu.read_phys(addr, ln)
            for off in range(0, ln, 8):
                self._reply(0x6F1, blob[off : off + 8])
            self._reply(0x6F1, b"\x00\x00")
            return
        if code.startswith(RSA_PROBE_PAYLOAD):
            eng = analyze_uflash(bytes(self.mcu.uflash)).rsa_bypassed
            rsa_status = 0 if eng else 2
            self.mcu.write_phys(0xFEDE9000, struct.pack("<I", rsa_status))
            self._reply(0x6F1, b"\x00\x00")
            return

        # Execute real RH850 FACI machine code stub (`DFLASH_READER_STUB`, `DFLASH_FACI_STUB`, `CFLASH_FACI_STUB`, or `UFLASH_FACI_STUB`)!
        is_uflash_legacy = code.startswith(UFLASH_FACI_STUB[:32])
        self.mcu.execute_loader_payload(code, check_callee_saved=not is_uflash_legacy)
        for frame_data in self.mcu.streamed_frames:
            self._reply(0x6F1, frame_data)
        self._reply(0x6F1, b"\x00\x00")

    def _handle_uds(self, req: bytes) -> None:
        stage1, stage2, trigger = build_service_loader_uds_steps()
        if req == b"\x10\x03":
            self._reply_uds(b"\x50\x03\x00\x32\x01\xf4")
        elif req == b"\x3e\x00":
            self._reply_uds(b"\x7e\x00")
        elif req == b"\x11\x01":
            self._reply_uds(b"\x51\x01")
        elif req == bytes.fromhex("14ffffff"):
            self._reply_uds(b"\x54")
        elif req == bytes.fromhex("1902ff"):
            self._reply_uds(b"\x59\x02\x09")
        elif req == b"\x27\x03":
            self._reply_uds(b"\x67\x03\x11\x22\x33\x44")
        elif req.startswith(b"\x27\x04"):
            self._reply_uds(b"\x67\x04")
        elif req == bytes.fromhex("31010203"):
            self._reply_uds(b"\x71\x01\x02\x03\x00")
        elif req == b"\x10\x02":
            self._reply_uds(b"\x50\x02\x00\x32\x01\xf4")
        elif req == b"\x27\x11":
            self._reply_uds(b"\x67\x11" + struct.pack(">I", self._seed))
        elif req == trigger:
            pass  # Enters 0x0100120E RAM-loader
        elif req.startswith(b"\x27\x12") and len(req) == 6:
            key = int.from_bytes(req[2:6], "big")
            assert key == fbl_sa2(self._seed), "Invalid FBL SA2 key in UDS session!"
            self._reply_uds(b"\x67\x12")
        elif req.startswith(b"\x2e\x04\x10"):
            self._reply_uds(b"\x6e\x04\x10")
        elif req == stage1:
            self._reply_uds(b"\x62" + (b"\x00" * 334) + bytes.fromhex("041005"))
        elif req == stage2:
            pass
        elif req.startswith(b"\x2e\xf1\x5a"):
            self._reply_uds(b"\x6e\xf1\x5a")
        elif req == bytes.fromhex("3101ff000101"):
            self.mcu.cflash[0xC000:CFLASH_SIZE] = b"\xff" * (CFLASH_SIZE - 0xC000)
            self._reply_uds(b"\x71\x01\xff\x00\x00")
        elif req.startswith(b"\x34\x00\x44"):
            self._dl_offset = int.from_bytes(req[3:7], "big")
            dl_size = int.from_bytes(req[7:11], "big")
            assert self._dl_offset == APP_BASE and dl_size == APP_SIZE
            self._dl_buf = bytearray()
            self._reply_uds(b"\x74\x20\x02\x02")
        elif req.startswith(b"\x36"):
            self._dl_buf.extend(req[2:])
            self._reply_uds(bytes([0x76, req[1]]))
        elif req == b"\x37":
            assert len(self._dl_buf) == APP_SIZE
            self.mcu.cflash[self._dl_offset : self._dl_offset + APP_SIZE] = self._dl_buf
            self._reply_uds(b"\x77")
        elif req.startswith(bytes.fromhex("3101020244")):
            # Verify Engineering RSA-Free FBL is active if signature is all-zero
            sig = req[-128:]
            if sig == b"\x00" * 128:
                assert analyze_uflash(bytes(self.mcu.uflash)).rsa_bypassed, (
                    "Stock Uflash rejected unsigned FD_0DATA in CheckMemory!"
                )
            self._reply_uds(b"\x71\x01\x02\x02\x00")
        elif req == bytes.fromhex("3101ff01"):
            assert analyze_cflash(bytes(self.mcu.cflash)).crc_ok, "FD_0DATA CRC-16 invalid!"
            struct.pack_into("<I", self.mcu.cflash, 0xC000, FBL_PRESENCE_MAGIC)
            self._reply_uds(b"\x71\x01\xff\x01\x00")
        elif req == b"\x22\xf1\xdf":
            valid = fbl_app_valid(bytes(self.mcu.cflash))
            self._reply_uds(bytes([0x62, 0xF1, 0xDF, 0x40 if valid else 0x44]))
        elif req in (b"\x22\xf1\x97", b"\x22\x06\x00"):
            # F197 and 0600 live in the application's DID tables only — the bootloader's read table has no entry
            # for either, so an ECU sitting in FBL refuses them. That tells a running application from a cold FBL.
            if fbl_app_valid(bytes(self.mcu.cflash)):
                self._reply_uds(b"\x62\xf1\x97GW MQB High" if req[1] == 0xF1 else bytes.fromhex("620600030100347f08"))
            else:
                self._reply_uds(b"\x7f\x22\x31")
        else:
            raise AssertionError(f"Unhandled UDS request in SimulatedJ533CanBus: {req.hex()}")


def test_dflash_faci_stub_executes_cleanly_on_rh850_simulator(
    synth_cflash: bytes, synth_uflash: bytes, synth_dflash: bytes
) -> None:
    selfid = bytes.fromhex("0123456789ABCDEF1032547698BADCFE")
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, synth_dflash, selfid=selfid)

    # Modify two CP banks + clear one previously populated block to 0xFF (testing 0-word blank preservation!)
    spec_5f = parse_slot_selector("5F")
    ika = parse_hex_key("112233445566778899AABBCCDDEEFF00")
    _, target_df_raw, _ = bind_cp_turnkey(synth_cflash, synth_dflash, [(spec_5f, ika)])
    target_df = bytearray(target_df_raw)
    # Also write a partial block at 0x0100 with 3 active words + 13 trailing 0xFFFFFFFF words
    target_df[0x0100:0x010C] = b"CONTITOOL123"
    # And populate block 0x0200 in initial MCU Dflash, then erase it back to all 0xFF in target_df
    mcu.dflash[0x0200:0x0240] = b"\x5a" * 64
    for w in range(0x0200 // 4, 0x0240 // 4):
        mcu.dflash_word_programmed[w] = True

    assert dflash_active_word_count(bytes(target_df[0x0100:0x0140])) == 3
    assert dflash_active_word_count(b"\xff" * 64) == 0

    changed_blocks = [
        (off, bytes(target_df[off : off + 64]))
        for off in range(0, DFLASH_ICUS_RESERVED_OFFSET, 64)
        if target_df[off : off + 64] != mcu.dflash[off : off + 64]
    ]
    assert len(changed_blocks) == 6  # 4 blocks for 5F primary+mirror + 1 block @ 0x0100 + 1 erased block @ 0x0200
    payloads = build_dflash_faci_payloads(changed_blocks)
    assert len(payloads) == 1
    assert payloads[0].startswith(DFLASH_FACI_STUB)

    res = mcu.execute_loader_payload(payloads[0])
    assert res["marker"] == 1
    assert res["fstatr"] == 0x8000
    assert mcu.flid3_dummy_read is True
    assert mcu.wdta_kicks[0xFFED0000] == 8  # 1 entry + 6 blocks + 1 exit
    assert mcu.wdta_kicks[0xFFED1000] == 8
    assert bytes(mcu.dflash) == bytes(target_df)

    # Trailing 0xFFFFFFFF words in block 0x0100 and all 16 words in erased block 0x0200 MUST remain blank!
    assert all(mcu.dflash_word_programmed[w] for w in range(0x0100 // 4, 0x010C // 4))
    assert not any(mcu.dflash_word_programmed[w] for w in range(0x010C // 4, 0x0140 // 4))
    assert not any(mcu.dflash_word_programmed[w] for w in range(0x0200 // 4, 0x0240 // 4))


def test_cflash_and_uflash_faci_stubs_execute_cleanly_on_rh850_simulator(
    synth_cflash: bytes, synth_uflash: bytes, synth_dflash: bytes
) -> None:
    selfid = bytes.fromhex("CAFEBABE01020304DEADBEEF05060708")
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, synth_dflash, selfid=selfid)

    # 1. Verify 54 physical blocks cover 0..1.5 MB with zero gaps
    ranges = cflash_block_ranges()
    assert len(ranges) == 54
    assert ranges[0] == (0, 0x000000, 0x002000)
    assert ranges[5] == (5, 0x00A000, 0x00C000)
    assert ranges[8] == (8, 0x010000, 0x018000)
    assert ranges[-1] == (53, 0x178000, 0x180000)
    for idx in range(len(ranges) - 1):
        assert ranges[idx][2] == ranges[idx + 1][1]

    # 2. Program 8 KB Boot Block 5 (0x00A000..0x00BFFF) with custom FBL RSA modulus
    custom_mod = b"\x99" + (b"\x42" * 126) + b"\x01"
    cf_mod = bytearray(mcu.cflash)
    cf_mod[FBL_MOD_OFFSET : FBL_MOD_OFFSET + 128] = custom_mod
    pkts_8k = build_cflash_faci_block_payloads(0x00A000, bytes(cf_mod[0x00A000:0x00C000]))
    assert len(pkts_8k) == 1
    assert pkts_8k[0].startswith(CFLASH_FACI_STUB)
    st_8k = mcu.execute_loader_payload(pkts_8k[0])
    assert st_8k["marker"] == 1 and st_8k["fstatr"] == 0x8000
    assert bytes(mcu.cflash[0x00A000:0x00C000]) == bytes(cf_mod[0x00A000:0x00C000])

    # 3. Program a dense 32 KB block (all 128 pages non-0xFF -> split across 2 packets)
    dense_32k = bytes(((i * 7 + 3) & 0xFF) for i in range(0x8000))
    pkts_32k = build_cflash_faci_block_payloads(0x010000, dense_32k)
    assert len(pkts_32k) == 2
    for p in pkts_32k:
        assert len(build_loader_packet(p)) <= MAX_LOADER_PACKET_SIZE + 3
        st = mcu.execute_loader_payload(p)
        assert st["marker"] == 1 and st["fstatr"] == 0x8000
    assert bytes(mcu.cflash[0x010000:0x018000]) == dense_32k

    # 4. A Uflash that needs two packets is refused: between them the loader would run from a half-erased Uflash
    dense_uf = bytearray(synth_uflash)
    dense_uf[0x4000:] = b"\x55" * 0x4000
    with pytest.raises(ValueError, match="122"):
        build_uflash_faci_payloads(bytes(dense_uf))
    real_size = bytearray(synth_uflash)
    real_size[0x4000:0x622C] = b"\x55" * 0x222C  # 99 pages, as every 3Q0907530 Uflash seen
    uf_pkts, uf_pages = build_uflash_faci_payloads(bytes(real_size))
    assert len(uf_pkts) == 1 and uf_pages == 99
    st = mcu.execute_loader_payload(uf_pkts[0], check_callee_saved=False)  # legacy stub, verified on hardware (99 pages)
    assert st["marker"] == 1 and st["fstatr"] == 0x8000
    assert bytes(mcu.uflash) == bytes(real_size)


def test_loader_packet_cap_and_dflash_icus_guardrail(synth_dflash: bytes) -> None:
    with pytest.raises(ValueError, match="0x7DB8"):
        build_loader_packet(b"\x00" * MAX_LOADER_PACKET_SIZE)

    with pytest.raises(ValueError, match="ICUS|0xF800"):
        build_dflash_faci_payloads([(DFLASH_ICUS_RESERVED_OFFSET, b"\x00" * 64)])

    pkts = build_dflash_faci_payloads(
        [(DFLASH_ICUS_RESERVED_OFFSET, b"\x00" * 64)], allow_icus_tail=True
    )
    assert len(pkts) == 1

    all_blocks = [
        (off, synth_dflash[off : off + DFLASH_BLOCK_SIZE])
        for off in range(0, DFLASH_ICUS_RESERVED_OFFSET, DFLASH_BLOCK_SIZE)
    ]
    assert len(all_blocks) == 992
    full_pkts = build_dflash_faci_payloads(all_blocks)
    assert len(full_pkts) == 3
    for p in full_pkts:
        assert len(build_loader_packet(p)) <= MAX_LOADER_PACKET_SIZE + 3


def test_end_to_end_can_workflows_replace_bench_programmer(
    synth_cflash: bytes,
    synth_dflash: bytes,
    synth_uflash: bytes,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    live_selfid = bytes.fromhex("AABBCCDDEEFF00112233445566778899")
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, synth_dflash, selfid=live_selfid)
    sim_bus = SimulatedJ533CanBus(mcu)
    monkeypatch.setattr(can.interface, "Bus", lambda **kwargs: sim_bus)

    # 1. Arbitrary physical memory read (`can_read_memory`)
    mem_out = tmp_path / "selfid_read.bin"
    mem_rep = can_read_memory(
        "mock0",
        0x0000AB00,
        16,
        output_file=mem_out,
        session_dir=tmp_path / "s_read_mem",
    )
    assert mem_rep["complete"] is True
    assert mem_out.read_bytes() == live_selfid

    # 2. Direct CAN DataFlash write (`can_write_dflash`) with CP key + custom SWaP RSA modulus
    kp = generate_rsa1024_e3_keypair()
    kp_json, _, _ = save_rsa1024_keypair_bundle(tmp_path / "swap_fbl_key.json", kp)
    kp_mod, _ = load_rsa1024_key_material(kp_json)
    spec_5f = parse_slot_selector("5F")
    ika_5f = parse_hex_key("A1B2C3D4E5F60718293A4B5C6D7E8F90")
    _, df_cp, _ = bind_cp_turnkey(synth_cflash, synth_dflash, [(spec_5f, ika_5f)])
    df_target, _, _ = apply_dflash_swap_rsa_modulus(df_cp, kp_mod)
    df_path = tmp_path / "Dflash_target.bin"
    df_path.write_bytes(df_target)

    df_rep = can_write_dflash("mock0", df_path, session_dir=tmp_path / "s_df")
    assert df_rep["complete"] is True
    assert df_rep["write_performed"] is True
    assert df_rep["readback"]["reference_match"] is True
    assert bytes(mcu.dflash) == df_target
    assert analyze_dflash_swap(bytes(mcu.dflash)).swap_rsa_mod == kp_mod

    # Second write of identical DataFlash skips erase/write cleanly
    df_rep2 = can_write_dflash("mock0", df_path, session_dir=tmp_path / "s_df_noop")
    assert df_rep2["complete"] is True
    assert df_rep2["already_matching"] is True
    assert df_rep2["write_performed"] is False

    # 3. Boot-block CodeFlash write (`Sector 5` custom FBL RSA key @ 0xA2F7 + automatic SELFID preservation)
    cf_fbl_raw, _, _ = apply_cflash_rsa_modulus(synth_cflash, kp_mod, patch_swap=False, patch_fbl=True)
    cf_donor = bytearray(cf_fbl_raw)
    cf_donor[0xAB00:0xAB10] = b"\xde\xad\xbe\xef" * 4  # Donor SELFID that MUST NOT overwrite live MCU SELFID!
    cf_boot_path = tmp_path / "Cflash_fbl_donor.bin"
    cf_boot_path.write_bytes(bytes(cf_donor))

    cf_boot_rep = can_write_cflash("mock0", cf_boot_path, session_dir=tmp_path / "s_cf_boot")
    assert cf_boot_rep["complete"] is True
    assert cf_boot_rep["selfid_preserved"] is True
    assert cf_boot_rep["changed_boot_blocks"] == [5]
    assert cf_boot_rep["changed_app_blocks"] == []
    assert len(cf_boot_rep["boot_faci_blocks"]) == 1
    assert "uds_programming" not in cf_boot_rep
    assert bytes(mcu.cflash[0xAB00:0xAB10]) == live_selfid
    assert analyze_cflash(bytes(mcu.cflash)).fbl_rsa_mod == kp_mod

    # 4. Pure `--raw-faci` differential CodeFlash write (no UDS needed even on stock Uflash!)
    assert not analyze_uflash(bytes(mcu.uflash)).rsa_bypassed
    cf_eng, _, _ = apply_engineering_patch(bytes(mcu.cflash))
    cf_eng_path = tmp_path / "Cflash_eng.bin"
    cf_eng_path.write_bytes(cf_eng)
    cf_raw_rep = can_write_cflash(
        "mock0", cf_eng_path, raw_faci=True, session_dir=tmp_path / "s_cf_raw_faci"
    )
    assert cf_raw_rep["complete"] is True
    assert len(cf_raw_rep["faci_blocks"]) >= 1
    assert analyze_cflash(bytes(mcu.cflash)).eng_gate_unlocked

    # 5. Turnkey 1-command pipeline with live CP bank DataFlash binding (`cp_updates`)
    ika_47 = parse_hex_key("00112233445566778899AABBCCDDEEFF")
    tk_rep = can_turnkey_read_patch_flash(
        "mock0",
        session_dir=tmp_path / "s_turnkey",
        cp_updates=[(parse_slot_selector("47"), ika_47)],
        clear_dtc_after=True,
    )
    assert tk_rep["complete"] is True
    assert analyze_uflash(bytes(mcu.uflash)).rsa_bypassed
    assert analyze_cflash(bytes(mcu.cflash)).hook_mode == "HYBRID"
    slots = {s.spec.ecu_addr: s for s in analyze_dflash(bytes(mcu.dflash))}
    assert slots["47"].kind == "PLAIN" and slots["47"].first16_hex == ika_47.hex()

    # 6. CLI `can write-dflash` and `can read-mem` subcommands
    from contitool.cli.main import main

    cli_mem = tmp_path / "cli_mem.bin"
    assert (
        main(
            [
                "can",
                "read-mem",
                "--port",
                "mock0",
                "--address",
                "0xFF20C400",
                "--length",
                "20",
                "--out-file",
                str(cli_mem),
                "--output-dir",
                str(tmp_path / "s_cli_mem"),
            ]
        )
        == 0
    )
    assert cli_mem.read_bytes() == b"\x55\x55\x55\x55" + ika_47

    # Missing --yes must abort destructive write-dflash with exit code 1
    assert main(["can", "write-dflash", "--port", "mock0", "--dflash", str(df_path)]) == 1
    assert (
        main(
            [
                "can",
                "write-dflash",
                "--port",
                "mock0",
                "--dflash",
                str(df_path),
                "--output-dir",
                str(tmp_path / "s_cli_df"),
                "--yes",
            ]
        )
        == 0
    )
    assert bytes(mcu.dflash) == df_target

    # Restore stock Uflash via `can_write_uflash(restore_stock=True)`
    uf_rst = can_write_uflash("mock0", restore_stock=True, session_dir=tmp_path / "s_uf_rst")
    assert uf_rst["complete"] is True
    assert not analyze_uflash(bytes(mcu.uflash)).rsa_bypassed


def test_dflash_blankcheck_reader_eliminates_rv40f_noise_and_feeds_wdta(
    synth_cflash: bytes,
    synth_uflash: bytes,
    synth_dflash: bytes,
    tmp_path: Path,
) -> None:
    selfid = bytes.fromhex("102030405060708090A0B0C0D0E0F001")
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, synth_dflash, selfid=selfid)

    # Exercise both physical blank words (flag=0 -> synthesized 0xFFFFFFFF without CPU read)
    # and an explicitly programmed 0xFFFFFFFF interior word (flag=1 -> read via ECC CPU ld.w).
    mcu.dflash[0x0100:0x0104] = b"\xde\xad\xbe\xef"
    mcu.dflash_word_programmed[0x0100 // 4] = True
    mcu.dflash[0x0104:0x0108] = b"\xff\xff\xff\xff"
    mcu.dflash_word_programmed[0x0104 // 4] = True
    mcu.dflash[0x0108:0x0140] = b"\xff" * (0x40 - 8)
    for w in range(0x0108 // 4, 0x0140 // 4):
        mcu.dflash_word_programmed[w] = False

    # 1. Raw CPU bus reads (`build_reader_payload`) diverge on erased RV40F cells
    raw_read_1 = mcu.read_phys(0xFF200000, 4096)
    raw_read_2 = mcu.read_phys(0xFF200000, 4096)
    assert raw_read_1 != raw_read_2
    assert raw_read_1 != bytes(mcu.dflash[:4096])

    # 2. Single 4 KB `DFLASH_READER_STUB` execution kicks WDTA0/1 >= 20 times (every 256 B + stream)
    p_4k = build_dflash_reader_payload(0xFF200000, 4096, calls=1, feed=True)
    assert p_4k.startswith(DFLASH_READER_STUB)
    mcu.wdta_kicks = {0xFFED0000: 0, 0xFFED1000: 0}
    mcu.execute_loader_payload(p_4k)
    assert mcu.wdta_kicks[0xFFED0000] == 20
    assert mcu.wdta_kicks[0xFFED1000] == 20
    assert b"".join(mcu.streamed_frames) == bytes(mcu.dflash[:4096])

    # 3. Two consecutive full 64 KB reads over CAN (`read_memory_area`) match byte-for-byte + consume 00 00
    sim_bus = SimulatedJ533CanBus(mcu)
    with J533CanLink("mock0", bus=sim_bus) as link:
        enter_ram_loader(link)
        dump1_path = tmp_path / "dflash_run1.bin"
        dump2_path = tmp_path / "dflash_run2.bin"
        rep1 = read_memory_area(link, 0xFF200000, 0xFF210000, dump1_path, label="Dflash #1")
        rep2 = read_memory_area(link, 0xFF200000, 0xFF210000, dump2_path, label="Dflash #2")
        assert rep1["sha256"] == rep2["sha256"]
        assert dump1_path.read_bytes() == bytes(mcu.dflash)
        assert dump2_path.read_bytes() == bytes(mcu.dflash)

        # Unaligned sub-word DataFlash read slices cleanly from Blank-Checked words
        sub = read_memory_bytes(link, 0xFF200101, 11)
        assert sub == bytes(mcu.dflash[0x0101:0x010C])
        assert sim_bus.rx_queue == []

        # Multi-call (`calls=16`) single-applet 64 KB batch also matches 100%
        batch_payload = build_dflash_reader_payload(0xFF200000, 4096, calls=16, feed=True)
        link.send_loader_payload(batch_payload)
        streamed = bytearray()
        while len(streamed) < DFLASH_SIZE:
            streamed.extend(bytes(link.receive_frame(link.LOADER_RX_ID, timeout=1.0).data))
        end_frame = bytes(link.receive_frame(link.LOADER_RX_ID, timeout=1.0).data)
        assert end_frame == b"\x00\x00"
        assert bytes(streamed) == bytes(mcu.dflash)


def test_can_write_dflash_rejects_noisy_legacy_dump(
    synth_cflash: bytes,
    synth_uflash: bytes,
    synth_dflash: bytes,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, synth_dflash)
    noisy_dump = mcu.read_phys(0xFF200000, DFLASH_SIZE)
    noisy_path = tmp_path / "noisy_dflash.bin"
    noisy_path.write_bytes(noisy_dump)

    sim_bus = SimulatedJ533CanBus(mcu)
    monkeypatch.setattr(can.interface, "Bus", lambda **kwargs: sim_bus)
    with pytest.raises(ValueError, match="Blank Check"):
        can_write_dflash("mock0", noisy_path, session_dir=tmp_path / "s_noisy_reject")


def test_fed_reader_reads_codeflash_in_64k_payloads_and_kicks_before_every_read(
    synth_cflash: bytes,
    synth_uflash: bytes,
    synth_dflash: bytes,
    tmp_path: Path,
) -> None:
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, synth_dflash)

    # One payload: 3 reads of 4 KB, the FBL watchdog service before each read and once before returning
    mcu.wdta_kicks = {0xFFED0000: 0, 0xFFED1000: 0}
    mcu.execute_loader_payload(build_fed_reader_payload(0x00010000, 4096, 3))
    assert b"".join(mcu.streamed_frames) == bytes(mcu.cflash[0x10000:0x13000])
    assert mcu.wdta_kicks == {0xFFED0000: 4, 0xFFED1000: 4}

    # The whole CodeFlash through read_memory_area: 24 payloads of 16 x 4 KB, byte-exact, nothing left on the bus
    sim_bus = SimulatedJ533CanBus(mcu)
    payloads: list[bytes] = []
    dispatch = sim_bus._dispatch_loader_code

    def counting(code: bytes) -> None:
        payloads.append(code)
        dispatch(code)

    sim_bus._dispatch_loader_code = counting
    with J533CanLink("mock0", bus=sim_bus) as link:
        enter_ram_loader(link)
        payloads.clear()
        out = tmp_path / "Cflash.bin"
        rep = read_memory_area(link, 0x00000000, CFLASH_SIZE, out, label="Cflash")
        assert rep["complete"] and out.read_bytes() == bytes(mcu.cflash)
        assert len(payloads) == CFLASH_SIZE // (16 * 4096)
        assert all(p.startswith(build_fed_reader_payload(i * 0x10000, 4096, 16)) for i, p in enumerate(payloads))  # + packet padding
        assert sim_bus.rx_queue == []


def test_can_write_dflash_stops_before_erasing_when_the_protected_tail_holds_data(
    synth_cflash: bytes,
    synth_uflash: bytes,
    synth_dflash: bytes,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    from contitool.i18n import set_lang

    set_lang("en")
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    ecu_df = bytearray(synth_dflash)
    ecu_df[0xF800:0xF810] = bytes(range(16))  # an ECU with ICU-S data in the guarded tail
    mcu = SimulatedRh850FaciMcu(synth_cflash, synth_uflash, bytes(ecu_df))
    sim_bus = SimulatedJ533CanBus(mcu)
    monkeypatch.setattr(can.interface, "Bus", lambda **kwargs: sim_bus)
    cand = bytearray(synth_dflash)
    cand[0xDB00] ^= 0x0F  # a programmed word (SWaP NvM magic), so it reads back reliably
    (tmp_path / "cand.bin").write_bytes(cand)
    with pytest.raises(RuntimeError, match="protected DataFlash area"):
        can_write_dflash("mock0", tmp_path / "cand.bin", session_dir=tmp_path / "s_tail", skip_full_backup=True)
    assert mcu.read_phys(0xFF20DB00, 4) == synth_dflash[0xDB00:0xDB04]  # nothing was erased or programmed


def test_writing_an_edited_backup_keeps_the_records_the_ecu_updated_itself(synth_dflash: bytes) -> None:
    """Only the blocks the user edited are written: the gateway keeps some DataFlash records up to date itself,
    and writing the whole edited copy rolled those back to how they were when the backup was taken."""
    from contitool.can.workflows import merge_dflash_edits

    base = synth_dflash
    edited = bytearray(base)
    edited[0x1000] ^= 0x0F  # what the user changed
    current = bytearray(base)
    current[0x2000] ^= 0xF0  # what the gateway changed by itself since the backup
    merged, kept, conflicts = merge_dflash_edits(bytes(current), base, bytes(edited))

    assert not conflicts and kept == [0x2000]
    assert merged[0x1000:0x1040] == bytes(edited[0x1000:0x1040])  # the edit goes in
    assert merged[0x2000:0x2040] == bytes(current[0x2000:0x2040])  # the ECU's own record stays
    assert merged[:0x1000] == base[:0x1000] and merged[0x2040:] == base[0x2040:]  # nothing else moves

    both = bytearray(edited)
    both[0x2000] ^= 0x33  # user and ECU changed the same block differently
    _, _, conflicts = merge_dflash_edits(bytes(current), base, bytes(both))
    assert conflicts == [0x2000]

    same = bytearray(edited)
    same[0x2000] ^= 0xF0  # both changed it the same way: nothing to refuse
    _, _, conflicts = merge_dflash_edits(bytes(current), base, bytes(same))
    assert not conflicts
