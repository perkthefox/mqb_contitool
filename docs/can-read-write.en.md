# Live Diagnosis CAN (`500 kbit/s`) Read & Write Mechanism on J533

[![Читать на русском](https://img.shields.io/badge/lang-%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-blue)](can-read-write.md) • [Back to `docs/` Index](README.md)

This document explains concretely — with exact RAM/Flash addresses, `FACI` hardware registers, RH850 opcodes, and CAN frames — how **ContiTool** 100% replaces an external bench programmer over the 20-pin `T20` Diagnosis CAN connector on an unmodified, factory-locked **Continental VAG MQB J533 Gateway (`3Q0 907 530 xx`, Renesas `RH850/F1L`)**: reading all memory regions (`Cflash`, `Uflash`, `Dflash`, plus arbitrary `read-mem` ranges), unlocking and programming `Uflash` (`32 KB`), differentially programming `DataFlash` (`64 KB`), and flashing all of `CodeFlash` (`1.5 MB`, including boot blocks `0x00000000..0x0000BFFF` and `FD_0DATA`) without opening the ECU housing.

---

## 1. Physical Layer & `RH850/F1L` Memory Map

### Bench Harness Wiring (`J533 T20`, `500 kbit/s`)

| `T20` Pin | Signal | Function |
| :---: | :--- | :--- |
| **Pin 1** | `KL30 (+12V)` | Permanent `+12V` bench supply (`12.5–13.8 V`, `>= 1 A`) |
| **Pin 14** | `KL15 (+12V)` | Ignition `+12V` (bridge together with `Pin 1` on bench) |
| **Pin 11** | `KL31 (GND)` | Common ground (power supply minus & CAN adapter `GND`) |
| **Pin 19** | `Diag CAN-H` | Diagnosis `CAN High` (`500 kbit/s`) |
| **Pin 9** | `Diag CAN-L` | Diagnosis `CAN Low` (`500 kbit/s`) |

A **`120 Ω` termination resistor** across **`Pin 19`** and **`Pin 9`** is mandatory (`J533` has no internal termination on its diagnostic CAN pair).

### CAN Identifier Pairs on Diagnosis CAN

1. **Standard `ISO 14229 UDS` over `ISO 15765-2 (ISO-TP)`**:
   - **`0x710`** (11-bit, Tester TX → Gateway, SingleFrame padded with `0xAA`, ConsecutiveFrame with `0x00`);
   - **`0x77A`** (11-bit, Gateway RX → Tester).
2. **Continental Factory Stream Loader (`CAN RAM-Loader`)**:
   - **`0x6F0`** (11-bit, raw 8-byte stream frames without `ISO-TP` headers);
   - **`0x6F1`** (11-bit, sync replies, status frames, and raw memory dump stream).

### `R7F7010543AFP / R7F7010563AFP` Address Space

| Region | Address Range | Size | Contents |
| :--- | :---: | :---: | :--- |
| **`Cflash` (Boot + OTP)** | `0x00000000 .. 0x0000BFFF` | `49,152` B | Reset vector, `Sector 5` (`OTP` byte at `0x0000A167`, `FBL RSA-1024` modulus at `0x0000A2F7`, `SA2` bytecode at `0x0000A377`, chip 128-bit `SELFID` at `0x0000AB00`) |
| **`Cflash` (Presence)** | `0x0000C000 .. 0x0000C1FF` | `512` B | Application presence header (`0x90482442` LE at `0x0000C000`, `0xFFFFFFFF` at `0x0000C100`) |
| **`Cflash` (`FD_0DATA`)** | `0x0000C200 .. 0x0017FFFF` | `1,523,200` B | Main Gateway Application (`App CRC-16/MODBUS` at `0x0000C21C`, range count `1` at `0x0000C21E`, `[start, end]` bounds at `0x0000C220..0x0000C227`) |
| **`Uflash` (`Ext. User Area`)** | `0x01000000 .. 0x01007FFF` | `32,768` B | Flash Bootloader (`FBL`) + embedded Continental `CAN RAM-Loader` (`Stage 1 @ 0x01000BCC`, `Stage 2 @ 0x0100120E`, `RSA` verifier @ `0x010033FC / +0x342A`) |
| **`Dflash` (`Data Flash`)** | `0xFF200000 .. 0xFF20FFFF` | `65,536` B | `ZDC` datasets (`0x0000..0x303F`), 12 `CP` banks (`0xC000..0xCBFF`), Master Key `GFA` (`0xDA00`), `SWaP RSA` cache + `VCRN` (`0xDB00`), 15 `FSC` slots (`0xDD00..0xE83F`) |
| **`Local RAM`** | `0xFEDE0000 .. 0xFEDFFFFF` | `131,072` B | `FBL` working variables (`0xFEDE0000..`), `RAM-Loader` staging window (`0xFEDF8020..0xFEDFFEFF`), and reset-retention word (`0xFEDFFFF0`) |

---

## 2. End-to-End CAN Pipeline Overview

```mermaid
flowchart TD
    APP["Stock J533 Application (0x710 / 0x77A)"] -->|"10 03 -> 27 03/04 CAFFE012 -> 31 01 02 03 -> 10 02"| FBL["Uflash FBL (ProgrammingSession)"]
    FBL -->|"27 11 + two multi-DID 0x22 passes (338 B & 337 B)"| DESC["Redirect FCL pointer @ 0xFEDE0C68 -> 0xFEDE0548"]
    DESC -->|"27 12 ... 0E 12 00 01 (attempt-counter save path)"| LOADER["Stage-2 CAN RAM-Loader @ 0x0100120E (0x6F0 / 0x6F1)"]
    LOADER -->|"28-byte reader stub -> 0x010010F0"| DUMP["Read-only dump of Cflash (1.5 MB) + Uflash (32 KB) + Dflash (64 KB) + read-mem"]
    LOADER -->|"RAM FACI drivers (SELFID + WDTA0/WDTA1)"| FACI["Direct Write: Uflash (32 KB), DataFlash (64 KB) & CodeFlash Boot Blocks (0x0000..0xBFFF)"]
    FACI -->|"Reset FE FF -> 10 02 -> SA2 -> 31 01 FF00 -> 34/36/37 -> 0202 -> FF01"| UDS["Standard UDS FD_0DATA programming (or --raw-faci) + full 1.5 MB readback check"]
```

On a factory-sealed production gateway, three protections are active:
1. The MCU serial programming interface is locked (`Security Lock`).
2. The application-level `CAN RAM-Loader` trigger (`0x07FC80FE`) is blocked by `Feature 0x81` and `OTP [0x0000A167] != 0x00`.
3. Standard UDS flashing in `Uflash` requires a factory `RSA-1024` signature during `CheckMemory (31 01 02 02)`.

To operate without opening the unit, **ContiTool** enters the standard `Uflash` `ProgrammingSession (10 02)` and transfers execution directly to **`0x0100120E`** — Stage 2 of Continental's own `CAN RAM-Loader` already compiled into every stock `Uflash.bin`.

---

## 3. Entering the Factory `CAN RAM-Loader` (`0x0100120E`) on Stock Firmware

### Phase 1 — Entering `Uflash` Programming Session (`10 02`)

Starting from the normal Gateway Application, the tester unlocks programming preconditions using the stock static Level 2 key (`CA FF E0 12`) and switches into `Uflash`:

```text
TX 0x710: 02 10 03 AA AA AA AA AA          -> RX 0x77A: 06 50 03 00 32 01 F4 AA
TX 0x710: 02 27 03 AA AA AA AA AA          -> RX 0x77A: 06 67 03 <S0 S1 S2 S3> AA
TX 0x710: 06 27 04 CA FF E0 12 AA          -> RX 0x77A: 02 67 04 AA AA AA AA AA
TX 0x710: 04 31 01 02 03 AA AA AA          -> RX 0x77A: 05 71 01 02 03 00 AA AA
TX 0x710: 02 10 02 AA AA AA AA AA          -> RX 0x77A: 03 7F 10 78 AA -> 06 50 02 00 19 01 F4 AA
```

Upon receiving `10 02`, the application writes magic `0xA5430911` to `0xFEDFFFF0` and performs a software reset into `Uflash.bin` (`0x01000000`).

### Phase 2 — Two-Pass Aligned `Renesas FCL` Descriptor Staging in RAM

Inside `Uflash`, key buffers occupy deterministic `Local RAM` addresses:

| `Local RAM` Address | Role in `Uflash.bin` |
| :---: | :--- |
| `0xFEDE0052` | 1-byte RAM scratch cell: `2E 04 10 <XX>` writes `<XX>`, and `22 04 10` echoes `04 10 <XX>` (`3` bytes) |
| `0xFEDE0536` | Incoming multi-frame UDS request buffer (`ISO-TP RX`): request offset `+0x12` maps to **`0xFEDE0548`**, and offset `+0x12` of a 22-byte frame maps `0xFEDE0558` (`0xFEDE0548 + 0x10`) |
| `0xFEDE0B18` | Outgoing `ReadDataByIdentifier (0x22)` response assembly buffer (`330`-byte nominal capacity) |
| **`0xFEDE0C68`** | Active `Renesas FCL` flash library descriptor pointer (located **exactly `+336` bytes** past `0xFEDE0B18`! Initial boot value: `0xFEDE0014` = `14 00 DE FE` LE) |

The `Uflash` multi-DID `0x22` dispatcher (`0x01003DC2`) accepts up to **19 DIDs** per request and appends their values into `0xFEDE0B18` without checking total output length against `330` bytes. Unknown DIDs (`0x000E`, `0x1200`, `0x0100`) emit zero bytes into `0xFEDE0B18` while remaining intact inside the `ISO-TP` request buffer.

First, `27 11` (`RequestSeed`) places the `SecurityAccess` state machine into seed-issued state (computing the valid SA2 key is not needed here). Then two calibrated 19-DID `0x22` requests rewrite the low two bytes of `0xFEDE0C68`:

1. **Pass 1 (`338`-byte response — writes `0x05` to `0xFEDE0C69`)**:
   - `2E 04 10 05` stores `0x05` at `0xFEDE0052`.
   - `0x22` request with 19 DIDs: `6 × F17C` + `F1A2` + `F15B` + `[000E, 1200, 0100]` + `7 × F15B` + `0410`.
   - The `338`-byte response (`62 ... 04 10 05`) writes `0x10` at `+336` (`0xFEDE0C68`) and `0x05` at `+337` (`0xFEDE0C69`), leaving upper bytes `DE FE` untouched (`0xFEDE0C68` becomes `0xFEDE0510`).
2. **Pass 2 (`337`-byte response — writes `0x48` to `0xFEDE0C68`)**:
   - `2E 04 10 48` stores `0x48` at `0xFEDE0052`.
   - `0x22` request with 19 DIDs: `8 × F15B` + `[000E, 1200, 0100]` + `6 × F15B` + `F17C` + `0410`.
   - The `337`-byte response (`62 ... 04 10 48`) overwrites only offset `+336` (`0xFEDE0C68`) with `0x48` while preserving `0x05` at `0xFEDE0C69`.
   - The `FCL` descriptor pointer at `0xFEDE0C68` is now **`0xFEDE0548`** (`48 05 DE FE`), 4-byte aligned inside the `ISO-TP` RX buffer.

### Phase 3 — Dispatch to `0x0100120E` via `27 12` Key-Mismatch Handler

Next, the tester sends a 22-byte `SendKey` frame:

```text
27 12 DE AD BE EF 00 00 00 00 00 00 00 00 00 00 00 00 0E 12 00 01
```

1. Stored at `0xFEDE0536` in the `ISO-TP` RX buffer, its trailing 4 bytes `0E 12 00 01` (`0x0100120E` in Little-Endian) land at `0xFEDE0558`, which is **`0xFEDE0548 + 0x10`**.
2. `SendKey` (`0x01002F92`) detects that `DE AD BE EF` mismatches, increments the attempt counter (`0xFEDE0AEE`), and invokes the NvM persistence helper (`0x01001002` → `FCL` wrapper `0x01001AA8` → dispatcher `0x01004B66`).
3. `0x01004B66` dereferences `0xFEDE0C68` (`0xFEDE0548`), reads the handler pointer at `*(uint32_t *)(0xFEDE0548 + 0x10) == 0x0100120E`, and jumps straight into **`0x0100120E`** — Stage 2 of the factory **`CAN RAM-Loader`**.

Zero flash erase or write commands have been issued, and both `OTP [0x0000A167]` and Stage-1 `Seed/Key` are bypassed cleanly in RAM.

---

## 4. `0x6F0 / 0x6F1` Stream Framing & Read-Only Memory Dumping

Inside `0x0100120E`, the RH850 CPU runs in `Supervisor Mode` and listens for raw 8-byte frames on **`0x6F0`**.

### `build_loader_packet` Framing

Before each packet, the link synchronizes:
- Tester sends on `0x6F0`: `84 00 00 00 00` (`DLC = 5`).
- Gateway echoes on `0x6F1`: `84 00 00 00 00`.

A packet of total length `size + 3` bytes (where `size = max(0x120, align16(0x118 + len(payload)))`, enforced up to the `0x0100120E` hardware buffer cap of **`0x7DB8` = `32,184` bytes**) is then streamed in sequential 8-byte frames on `0x6F0`:

| Packet Offset | `Local RAM` Address | Field |
| :---: | :---: | :--- |
| `0x000 .. 0x001` | Length header | `[size & 0xFF, 0x80 \| (size >> 8)]` (15-bit LE length with bit 15 `0x8000` set) |
| `0x002 .. 0x10F` | `0xFEDF8022 .. 0xFEDF812F` | Zero padding up to base pointer `r28` (`0xFEDF8130`) |
| **`0x110 .. 0x117`** | **`0xFEDF8130 .. 0xFEDF8137`** | Mandatory 8-byte Continental password: **`DE 42 56 5E E5 65 24 ED`** |
| **`0x118 ..`** | **`0xFEDF8138 ..`** | Native `RH850` machine code invoked via `jarl [r28 + 8], lp` (returns to loader loop via `7F 00` = `jmp [lp]`) |
| `size + 2` | Checksum | Bytewise `XOR` over packet bytes `0 .. size + 1` |

Sending the 2-byte payload `FE FF` at `0x118` triggers the factory loader's clean MCU reset back into normal Application mode.

Whenever **any** RAM applet returns via `jmp [lp]`, the `0x0100120E` dispatcher (`0x01001410 -> 0x010011C2`) sends a closing 2-byte **`00 00`** status frame on `0x6F1`. **ContiTool** explicitly consumes this `00 00` frame after every applet (beacon, memory read, RSA probe, and FACI write) so it can never collide with the next `84 00 00 00 00` loader sync.

### Readiness Beacon, 28-Byte `Cflash`/`Uflash` Reader & 652-Byte `FACI Blank-Check` `Dflash` Reader

1. **Readiness Beacon (`35` bytes)**: transmits literal ASCII `J533-RCE-OK` on `0x6F1` via FBL's internal CAN TX helper `0x010010F0` (followed by the closing `00 00` frame) to confirm RAM code execution before any other operation.
2. **Direct `Cflash`, `Uflash` & `RAM` Reader (`28` bytes)**: reads CodeFlash, Extended User Area, or SRAM directly over the CPU bus:
   ```text
   26 06 <addr_le32>        ; mov  imm32(address), r6
   27 06 <len_le32>         ; mov  imm32(length),  r7
   1F D8                    ; mov  lp, r27              (save return address)
   21 06 F0 10 00 01        ; mov  0x010010F0, r1       (FBL internal CAN frame sender)
   E1 C7 60 F9              ; jarl [r1], lp             (streams r7 bytes from [r6] over 0x6F1)
   1B F8                    ; mov  r27, lp
   7F 00                    ; jmp  [lp]                 (return to 0x0100120E -> 00 00 frame)
   ```
3. **Deterministic `DataFlash` Reader with Hardware `FACI Blank Check` (`652` + `16` bytes, `DFLASH_READER_STUB`)**:
   on `Renesas RV40F` silicon (`R7F7010543AFP`), physically erased 4-byte `DataFlash` words (`0xFF200000 .. 0xFF20FFFF`) carry no programmed ECC syndrome, so raw CPU bus reads (`ld.w`) return random floating-gate analog noise (causing consecutive dumps to diverge by thousands of bytes and latching `DFERSTR` ECC flags).
   **ContiTool** eliminates this completely using the two-pass `DFLASH_READER_STUB` staged through `0xFEDFA000`:
   - **Pass 1 (`DataFlash P/E Mode`, `FENTRYR = 0xAA80`)**: loads the MCU's `SELFID` from `0x0000AB00` into `0xFFA08000..0xFFA0800C` (leaving `FPROTR = 0xFFA10088` untouched, since it is valid only in CodeFlash P/E mode) and issues the hardware **Blank Check (`0x71` → `0xD0`)** command to `0xFFA20000` for each 4-byte word (`FSADDR = off`, `FEADDR = off + 3`), recording `FBCSTAT.BCSTAT` (`0xFFA100D4` bit `0`).
   - **Pass 2 (`Read Mode`, `FENTRYR = 0xAA00`)**: physically blank words (`BCSTAT == 0`) are written as deterministic `FF FF FF FF` into `0xFEDFA000` without ever executing a CPU `ld.w` on `0xFF20xxxx`; ECC-checked `ld.w` reads are performed **only** on genuinely programmed words (`BCSTAT == 1`), and the clean chunk is streamed out via `0x010010F0`.
   - **`273 ms` Hardware Watchdog Budget (`WDTA0/1` @ `240 kHz`)**: the stub calls the FBL's native watchdog service **`0x01000EF0`** at chunk entry, **every `256` bytes (`64` words ≈ `0.7 ms`)** inside the Blank Check loop, on `P/E` exit, and immediately before/after `0x010010F0` (`4 KB` stream ≈ `115 ms`), staying well inside the `273 ms` hardware window.

   **ContiTool** streams memory in **`4096`-byte chunks**:
   - `Cflash.bin`: `0x00000000 .. 0x0017FFFF` (`384` chunks = `1,572,864` B, `28`-byte stub);
   - `Uflash.bin`: `0x01000000 .. 0x01007FFF` (`8` chunks = `32,768` B, `28`-byte stub);
   - `Dflash.bin`: `0xFF200000 .. 0xFF20FFFF` (`16` chunks = `65,536` B, Blank-Checked `DFLASH_READER_STUB` guaranteeing byte-exact repeatability and `can write-dflash` readback verification);
   - any custom physical address range (`can read-mem --address <ADDR> --length <LEN>`), automatically routing `0xFF200000..0xFF20FFFF` through `DFLASH_READER_STUB` and other regions through the 28-byte stub.

   Because `FACI Blank Check (0x71)` is strictly non-destructive, `can backup` never alters flash contents.

---

## 5. Atomic One-Shot `FACI` Programming of Engineering `Uflash`

### What the 4-Byte `Engineering RSA-Free` Patch Changes (`+0x342A`)

Inside `Uflash.bin`, the `RSA-1024 PKCS#1 v1.5` verifier `0x010033FC` sets its return code at offset **`+0x342A`** (`0x0100342A`):

- **Factory Stock (`rsa_status = 2` on signature mismatch):**
  `E2 57 14 EB` — `cmov ne, 2, r10, r29`
- **Engineering `RSA-Free` FBL (`rsa_status = 0` unconditionally):**
  `00 EA 00 00` — `mov 0, r29; nop`

All structural safety checks — sector range limits, `TransferData` sequence checks, and **`App CRC-16/MODBUS` @ `0x0000C21C`** verification in `CheckProgrammingDependencies (31 01 FF 01)` — remain completely intact. Before programming, **ContiTool** verifies that the candidate `Uflash` differs from the gateway's physical `Uflash_before.bin` **nowhere outside `+0x342A .. +0x342D`**.

### Why `Uflash` Must Be Written in One Self-Contained RAM Packet

The entire `Extended User Area` (`0x01000000 .. 0x01007FFF`, `32 KB`) is a **single hardware erase block** that holds the active `CAN RAM-Loader` (`0x0100120E`) itself. Erasing `Uflash` destroys the loader until reprogramming completes, so fetching a second chunk over CAN is impossible.

**ContiTool** therefore packs the entire operation into a single RAM packet (~`26 KB`):
- **`436` bytes** of self-contained RH850 `FACI` driver code (`0xFEDF8138 .. 0xFEDF82EB`);
- **`N × 256` bytes** of non-`0xFF` `Uflash` pages placed immediately at `0xFEDF82EC` (typically `99` pages = `25,344` bytes).

### Step-by-Step Execution Inside the 436-Byte `FACI` RAM Stub

1. **Disable interrupts (`di`)** so the CPU never vectors into flash while Code Flash is in `P/E` mode.
2. **Load 128-bit `SELFID` from `Cflash + 0xAB00`**: copies the MCU's own 4-word `SELFID` from `0x0000AB00` into `FACI` authentication registers `0xFFA08000 .. 0xFFA0800C` (no external programmer `IDCODE` is required).
3. **Enter Extended User Area `P/E` Mode**:
   - `FENTRYR` (`0xFFA10084`) `= 0xAA01` (Code Flash P/E mode);
   - `FPROTR` (`0xFFA10088`) `= 0x5501` (unlock protection);
   - `FAREASELC` (`0xFFA10020`) `= 0x3B02` (select Extended User Area `0x01000000`).
4. **Block Erase (`0x01000000 .. 0x01007FFF`)**:
   - sets `FSADDR = 0x01000000` (`0xFFA10030`) and `FEADDR = 0x01007FFF` (`0xFFA10034`);
   - writes `0x50` (`Clear Status`), `0x20`, `0xD0` (`Block Erase`) to the `FACI` command window (`0xFFA20000`);
   - polls `FSTATR.FRDY == 1` (`bit 15` at `0xFFA10080`) and checks error mask `0x7000 == 0`.
5. **256-Byte Page Programming (`99 × 256` B)**:
   - for each page, sets `FSADDR` / `FEADDR` and issues `0x50`, `0xE8`, `0x80` (`128` 16-bit halfwords);
   - writes `128` halfwords from `0xFEDF82EC+`, polling `FSTATR.DBFULL == 0` (`bit 10`) on every halfword;
   - writes `0xD0`, waits for `FSTATR.FRDY == 1`, and checks `FSTATR & 0x7000 == 0`.
6. **Exit `P/E` Mode & Report**:
   - writes `FENTRYR = 0xAA00` and `FAREASELC = 0x3B00`;
   - stores completion marker `1` and final `FSTATR` at `0xFEDE9000..0xFEDE9007`;
   - re-enables interrupts (`ei`), transmits `00 00` on `0x6F1`, and returns via `jmp [lp]` into the newly written `Uflash`.

**ContiTool** immediately reads back all `32,768` bytes over CAN to verify a 100% byte-for-byte match and runs a **92-byte live `RSA` probe** (calling `0x010033FC` on 128 `0xFF` bytes to confirm `rsa_status == 0`).

---

## 6. Standard UDS Programming of `CodeFlash` (`FD_0DATA`)

Once Engineering `Uflash` is active (`rsa_status == 0`), programming the main Gateway Application (`0x0000C200 .. 0x0017FFFF`, `1,523,200` bytes) uses **standard `ISO 14229 UDS` services** (`0x710` → `0x77A`):

1. **Enter `ProgrammingSession`**: `10 03` → `27 03 / 27 04 CA FF E0 12` → `31 01 02 03` → `10 02`.
2. **Unlock `FBL SecurityAccess` (`27 11` → `27 12`)**: computes the exact 4-byte key from the `27 11` seed using the `VAG SA2` bytecode algorithm (`fbl_sa2`: 8 shift/XOR rounds with `0x1EDC6F41` + 11 borrow-subtractions of `0x80361423` with `0x04000200`).
3. **Write Workshop `Fingerprint`**: `2E F1 5A <BCD YY MM DD + 6-byte tester serial>` (`9` bytes).
4. **Erase Application Flash (`EraseMemory`)**: `31 01 FF 00 01 01` — erases `0x0000C000 .. 0x0017FFFF` (`7F 31 78` pending responses until `71 01 FF 00 00`).
5. **`RequestDownload`**:
   ```text
   34 00 44 00 00 C2 00 00 17 3E 00
   ```
   (`address = 0x0000C200`, `size = 0x00173E00 = 1,523,200` bytes).
6. **`TransferData (0x36)` in `512`-Byte Blocks**:
   - The FBL's internal ISO-TP receive buffer is capped at `0x202 = 514` bytes (`2`-byte `36 <seq>` header + **`512` payload bytes**, aligned to two 256-byte `FACI` pages).
   - Streams `2,975` blocks (`2,975 × 512 = 1,523,200` B) with rolling `seq = 0x01 .. 0xFF`, followed by `RequestTransferExit` (`37` → `77`).
7. **Memory & Dependency Verification**:
   - `CheckMemory`: `31 01 02 02 44 00 00 C2 00 00 17 3E 00 00 80 <128 signature or zero bytes>` → `71 01 02 02 00`.
   - `CheckProgrammingDependencies`: `31 01 FF 01` — FBL recomputes **`App CRC-16/MODBUS`** across `FD_0DATA`, verifies it against `0x0000C21C`, and writes the 4-byte application presence magic **`0x90482442`** (`42 24 48 90` LE) to `0x0000C000`.
8. **Reset & Full 1.5 MB Readback Verification**: after `ECUReset (11 01)`, **ContiTool** re-enters the `RAM-Loader`, reads back all `1,572,864` bytes of `Cflash`, verifies 100% byte identity, returns to Application mode, and checks `10 03` / `3E 00` / `19 02 FF` DTCs.

---

## 7. Native CAN Programming of `DataFlash` (`64 KB`, `0xFF200000..0xFF20FFFF`) (`DFLASH_FACI_STUB`)

On `R7F7010543AFP / R7F7010563AFP`, internal `64 KB` `Data Flash` consists of **`1,024` erasable `64`-byte blocks** and is programmed in **`4`-byte words** (two 16-bit halfwords with hardware `ECC`). **ContiTool** writes `DataFlash.bin` directly over **Diagnosis CAN** (`can write-dflash` / **"Write to ECU"** in GUI / `can turnkey --set ...`), eliminating any need for a bench programmer.

### Inside the 784-Byte `DFLASH_FACI_STUB` RAM Driver (`0xFEDF8138 .. 0xFEDF8447`)

1. **Full EABI Register Preservation & `WDTA0 + WDTA1` Servicing**:
   - saves `r20..r29, ep, lp` (`48` bytes on `sp = 0xFEDFFFE0`) so `0x0100120E` loop pointers (`r28 = 0xFEDF8130`, `r29 = 0xFEDF8000`) remain intact across unlimited back-to-back `0x6F0` packets;
   - invokes an embedded 30-byte RAM watchdog helper before starting, after every 64-byte block erase, and after every 4-byte word write to kick both `WDTA0` (`0xFFED0000`) and `WDTA1` (`0xFFED1000`) (`0xAC` + `-0x54 - WDTAnREF`).
2. **`SELFID` Load & `Data Flash P/E` Entry**:
   - copies the 128-bit `SELFID` from `0x0000AB00..0x0000AB0F` to `FLID` (`0xFFA08000..0xFFA0800C`) with a dummy read of `0xFFA0800C` prior to entering `P/E`;
   - writes **`FENTRYR` (`0xFFA10084`) `= 0xAA80`** and polls `(FENTRYR & 0x00FF) == 0x0080`. Unlike `Code Flash`, `FPROTR` does not apply to `Data Flash` on `RH850/F1L` and is intentionally left untouched to avoid raising `FSTATR.ILGLERR`.
3. **Zero-Based `FSADDR / FEADDR` & `64`-Byte Block Erase**:
   - `Data Flash` `FACI` registers `FSADDR` (`0xFFA10030`) and `FEADDR` (`0xFFA10034`) take **zero-based byte offsets (`0x00000000 .. 0x0000F7FF`)** rather than CPU read-window addresses (`0xFF200000+`);
   - for each modified block `b`, sets `FSADDR = b * 64` and `FEADDR = b * 64 + 63`, writes bytes `0x50` (`Clear Status`), `0x20`, `0xD0` to `0xFFA20000`, waits for `FSTATR.FRDY == 1` (`bit 15`), and verifies `(FSTATR & 0x7000) == 0`.
4. **Active `4`-Byte Word Programming Preserving `R_FDL` Blank Check & `ECC`**:
   - in Renesas `FDL / EEL`, an erased word (`0xFFFFFFFF`) has a distinct blank physical `ECC` state from an explicitly programmed `0xFFFFFFFF` word. `dflash_active_word_count()` strips trailing `0xFFFFFFFF` words in each 64-byte block (`words_to_write = 0..16`), leaving erased tails genuinely blank (`words_to_write = 0` for all-`0xFF` blocks);
   - for each active 4-byte word, sets `FSADDR = word_offset`, writes byte `0x50` and halfwords `0x00E8`, `0x0002`, two data halfwords (polling `FSTATR.DBFULL == 0` bit 10), and `0x00D0` to `0xFFA20000`, then checks `FRDY == 1` and `(FSTATR & 0x7000) == 0`.
5. **Hardware `ICUSB` Tail Guard (`0xF800 .. 0xFFFF`)**:
   - the top `2,048` bytes (`blocks 992..1023`, `0xF800..0xFFFF`) are hardware-guarded (`OPBT8` + `Flash Guard`) for `ICUSB` secure storage, while all gateway structures (`ZDC`, 12 `CP` banks, `GFA`, `SWaP RSA`, `VCRN`, 15 `FSC` slots) reside within `0x0000..0xF0BF`. Modifying `0xF800..0xFFFF` is blocked by `DFLASH_ICUS_RESERVED_OFFSET` unless `--allow-icus-tail` is passed explicitly.
6. **Differential Execution & Full Readback Verification**:
   - **ContiTool** saves `Dflash_before.bin` (`64 KB`), packs only modified 64-byte blocks (up to `360` blocks per `0x6F0` packet, or automatic multi-packet batching under `--full-rewrite`), executes `DFLASH_FACI_STUB`, and reads back all `65,536` bytes to verify 100% byte identity.

---

## 8. Direct `CodeFlash` Boot-Block Programming (`0x00000000..0x0000BFFF`) & `--raw-faci` Mode (`CFLASH_FACI_STUB`)

Standard UDS `EraseMemory (31 01 FF 00)` only erases `0x0000C000 .. 0x0017FFFF`, leaving the first `48 KB` (`blocks 0..5`, including `Sector 5` `0x0000A000..0x0000BFFF` holding `OTP @ 0x0000A167` and the `FBL RSA-1024` modulus `@ 0x0000A2F7`) untouched. To write **any** `CodeFlash.bin` change over CAN — including custom `FBL RSA` keys (`--target fbl`) or pure UDS-free flashing (`--raw-faci`) — **ContiTool** includes the 696-byte **`CFLASH_FACI_STUB`** RAM driver.

### Physical `CodeFlash` Block Geometry (`54` Erase Blocks = `1.5 MB`)

- **Blocks `0 .. 7`** (`0x00000000 .. 0x0000FFFF`): **`8 × 8 KB` blocks** (`32 × 256` B pages per block; `Block 5` = `0x0000A000 .. 0x0000BFFF`, `Block 6` = `0x0000C000 .. 0x0000DFFF` spans the presence header and start of `FD_0DATA`).
- **Blocks `8 .. 53`** (`0x00010000 .. 0x0017FFFF`): **`46 × 32 KB` blocks** (`128 × 256` B pages per block).

### How `CFLASH_FACI_STUB` (`0xFEDF8138 .. 0xFEDF83EF`) Operates

1. **Packet Splitting Within the `0x7DB8` Loader Cap**:
   - any `8 KB` block (`<= 32` pages) fits into a single `0x6F0` packet (`erase_flag = 1`);
   - a dense `32 KB` block (`128` pages) automatically splits into two packets: packet 1 (`erase_flag = 1`) erases `[block_start .. block_end]` and programs the first page batch, and packet 2 (`erase_flag = 0`) programs the remaining pages without re-erasing.
2. **`Code Flash` `FACI` Sequence**:
   - loads `SELFID` from `0x0000AB00` → `FENTRYR = 0xAA01` → `FPROTR = 0x5501` → **`FAREASELC = 0x3B00`** (`User Area`, or `0x3B02` when writing full 128-page `Extended User Area` images);
   - when `erase_flag == 1`, issues `0x50`, `0x20`, `0xD0` over `[block_start .. block_end]`;
   - programs each non-`0xFF` 256-byte page via `0x50`, `0x00E8`, `0x0080`, `128` halfwords (`DBFULL == 0`), and `0x00D0`, kicking `WDTA0 + WDTA1` throughout.
3. **Automatic `SELFID` Preservation (`0x0000AB00 .. 0x0000AB0F`)**:
   - before writing `CodeFlash.bin` (especially donor dumps), **ContiTool** automatically splices the target MCU's live 128-bit `SELFID` (`0x0000AB00..0x0000AB0F`) into the outgoing image so the gateway's own `FACI` authentication ID is never clobbered (override only with `--overwrite-selfid`).
   - if only boot blocks `0x00000000..0x0000BFFF` changed (e.g. a custom `FBL RSA` modulus), **ContiTool** writes just the affected `8 KB` block via `CFLASH_FACI_STUB` and verifies `Cflash` without re-flashing `1.5 MB` of `FD_0DATA`.
