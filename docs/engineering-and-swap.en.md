# Engineering Mode, Service CAN/UDS Protocols & `RSA-1024` / `SWaP` / `ODX` Cryptography

[![Читать на русском](https://img.shields.io/badge/lang-%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-blue)](engineering-and-swap.md) • [Back to `docs/` Index](README.md)

This document specifies the exact machine-code modifications behind **Engineering Mode**, the diagnostic and calibration protocols of **Continental VAG MQB Gateway J533 (`3Q0 907 530 xx`, `RH850/F1L`)**, stock `CRC-32` `ZDC` dataset flashing, and **`RSA-1024 (e = 3)`** signing for **`SWaP FSC v2`** certificates and **`ODX`** firmware updates.

---

## 1. Exact Binary Modifications of Engineering Mode (`patch-engineering`)

`patch-engineering` (and the GUI Engineering toggle) applies four reversible patches located by unique `RH850` instruction signatures (restorable byte-for-byte with `--restore-stock`):

| # | Firmware Target | Stock Bytes (`RH850`) | Engineering Patch (`RH850`) | Technical Effect |
| :---: | :--- | :--- | :--- | :--- |
| **1** | `Feature 0x80 / 0x81 / 0x83` Gate (`CodeFlash`) | `40 0E E0 FE` (`movhi 0xfee0, r0, r1`) | `00 52 7F 00` (`mov 0, r10; jmp [lp]`) | System engineering gate immediately returns `0` (enabled) without `31 01 03 06` authentication |
| **2** | `CCP_CheckAddr` Filter (`CodeFlash`) | `E0 E7 06 E3` (`cmov nh, 0, r28, r28`) | `00 00 00 00` (`nop; nop`) | Removes the `ASAM CCP` address blacklist: unlocks live reading of `CodeFlash` / `DataFlash` / `Uflash` / `RAM` and live `RAM` writes |
| **3** | `0x07FC80FE` `CAN RAM-Loader` Check (`CodeFlash`) | `D2 0D` (`be +26`) + `OTP [0x0000A167] = 0xFF` | `00 00` (`nop`) + `OTP [0x0000A167] = 0x00` | Permits entering the `0x6F0 / 0x6F1` loader directly from Application via `0x07FC80FE` |
| **4** | `FBL CheckMemory` Verifier (`Uflash + 0x342A`) | `E2 57 14 EB` (`cmov ne, 2, r10, r29`) | `00 EA 00 00` (`mov 0, r29; nop`) | `31 01 02 02` accepts any firmware / `.odx` with a valid `App CRC-16` without requiring a factory `RSA-1024` signature |

`Application CRC-16/MODBUS` (`poly = 0xA001`) at `0x0000C21C` is updated automatically whenever `CodeFlash` is modified.

---

## 2. Diagnostic UDS Sessions & `SecurityAccess` Algorithms

On Diagnosis CAN (`500 kbit/s`, Tester **`0x710`** → Gateway **`0x77A`**), four UDS sessions exist even on unmodified factory firmware:

| Request (`0x710`) | Reply (`0x77A`) | Session | Capabilities |
| :---: | :---: | :--- | :--- |
| `10 03` | `50 03 ...` | `ExtendedDiagnosticSession` | Long Coding (`0x0600`), installation list (`0x04A3`), `LIN` / `BEM` / `Wake-up` tests |
| **`10 40`** | `50 40 ...` | **`EOLSession` (VW End-Of-Line)** | `ZDC` dataset upload (`0x34 / 0x36`), `SWaP FSC` activation (`0x3C01` + `0xC001`), `KSCHUTZ` sync (`0x0567`) |
| **`10 4F`** | `50 4F ...` | **`DevelopmentSession`** | Continental developer session & `27 03 / 27 04` `SecurityAccess` |
| `10 02` | `50 02 ...` | `ProgrammingSession` | Software reset into `Uflash.bin` FBL (`0xFEDFFFF0 = 0xA5430911`) |

### Application `SecurityAccess` (`CodeFlash`) — `Level 3` (`27 03 / 27 04`)

Subfunction `27 01 / 27 02` **does not exist** on the Continental `J533` gateway (it returns `7F 27 12` `subFunctionNotSupported`). All application-level authentication — including `ODIS` itself — runs on **`Level 3` (`27 03` → `27 04`)**, which accepts two key derivations:

1. **Open VAG Login `20103` (`0x00004E87`)** — used by `ODIS` and `ContiTool` for `ZDC` dataset upload, `SWaP FSC` activation, and EOL routines in `10 40`:
   - Formula: `Key = (uint32_be(Seed) + 0x00004E87) & 0xFFFFFFFF`
   - Example (`Seed = 12 34 56 78`): `27 04 12 34 A4 FF` → `67 04` (if `Seed == 00 00 00 00`, access is already unlocked and `27 04` is skipped).
2. **Continental Engineering Access (`0xCAFFE012`)** — unlocks programming preconditions (`31 01 02 03`) and developer services:
   - Accepts either dynamic `Key = (uint32_be(Seed) + 0xCAFFE012) & 0xFFFFFFFF` or the **seed-independent static master key `CA FF E0 12`** (`27 04 CA FF E0 12` → `67 04`).

### `Uflash` FBL `VAG SA2` Algorithm (`10 02` → `27 11 / 27 12`)

In `ProgrammingSession (10 02)`, `Uflash` computes `27 11 / 27 12` keys via its `SA2` bytecode VM (`0x010023D8`, script at `0x0000A377`):

```python
def conti_j533_fbl_sa2(seed: int) -> int:
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
```

Reference vectors:
- `0x00000001` → `0x7DAD27A0`
- `0x12345678` → `0x7CA16271`
- `0xDEADBEEF` → `0x3AEE8BB5`
- `0xFFFFFFFF` → `0xEAE26413`

---

## 3. `ASAM CCP v2.1` (`29-bit CAN 0x1BFC8600 / 0x1BFC8601`) & `0x07FC80FE` Trigger

Gateway firmware includes a complete **ASAM CCP v2.1** calibration server (`500 kbit/s`, 29-bit Extended CAN IDs, Station Address **`0x0055`** Big-Endian):
- **Request (`CRO`, `0x1BFC8600`):** `[CMD, CTR, Byte2, Byte3, Byte4, Byte5, Byte6, Byte7]`
- **Reply (`DTO`, `0x1BFC8601`):** `[0xFF, ERR, CTR, D0, D1, D2, D3, D4]` (`ERR = 0x00` OK, `0x33` locked on stock without `patch-engineering`).

| `CMD` | Mnemonic | `0x1BFC8600` Frame | Description |
| :---: | :--- | :--- | :--- |
| `0x01` | `CONNECT` | `01 <CTR> 00 55 00 00 00 00` | Open CCP session with station `0x0055` |
| `0x1B` | `GET_CCP_VERSION` | `1B <CTR> 02 01 00 00 00 00` | Confirm `CCP v2.1` |
| `0x02` | `SET_MTA` | `02 <CTR> <00\|01> 00 <Addr_BE32>` | Set 32-bit Big-Endian pointer `MTA0` (`00`) or `MTA1` (`01`) |
| `0x04` | `UPLOAD` | `04 <CTR> <Size:01..05> 00 00 00 00 00` | Read `1..5` bytes from `[MTA0]` and advance `MTA0 += Size` |
| `0x0F` | `SHORT_UP` | `0F <CTR> <Size:01..05> 00 <Addr_BE32>` | Single-frame `1..5`-byte read via `MTA1` |
| `0x03` | `DNLOAD` | `03 <CTR> <Size:01..05> <D0..D4>` | Write `1..5` bytes to RAM at `[MTA0]`, `MTA0 += Size` |
| `0x23` | `DNLOAD_6` | `23 <CTR> <D0..D5>` | Write `6` bytes to RAM at `[MTA0]`, `MTA0 += 6` |
| `0x07` | `DISCONNECT` | `07 <CTR> <00\|01> 00 00 00 00 00` | Close CCP session |

### Practical `ASAM CCP` Operations (with `patch-engineering`)

1. **Live read of CP Bank `#7` (`5F` @ `0xFF20C600`):**
   `CONNECT` → `SET_MTA(0xFF20C600)` → sequential `UPLOAD(5)` reads `55 55 55 55` and key bytes live.
2. **Instant in-RAM activation of all 13 `SWaP / FeC` features until reboot:**
   The `SWaP` manager (`0x0007E05A`) stores active feature flags in `*(uint16_t *)0xFEDE1394` (`0x0002` `MKE`, `0x0008` `FPA Base`, `0xFFE0` 11 `FPA` profiles). Writing **`0xFFFA`** (`FA FF` LE) enables all 13 features immediately:
   ```text
   TX 0x1BFC8600: 01 01 00 55 00 00 00 00   -> RX 0x1BFC8601: FF 00 01 ...
   TX 0x1BFC8600: 02 02 00 00 FE DE 13 94   -> RX 0x1BFC8601: FF 00 02 ...
   TX 0x1BFC8600: 03 03 02 FA FF 00 00 00   -> RX 0x1BFC8601: FF 00 03 00 FE DE 13 96
   ```
3. **Timerless jump to `CAN RAM-Loader`:** write `0xA4420810` (`10 08 42 A4` LE) to `0xFEDFFFF0` via `SET_MTA` + `DNLOAD` and send `UDS 11 01`.

### Application Trigger `0x07FC80FE` & `Stage 1 Seed/Key` (`0x6F0 / 0x6F1`)

On an engineering-patched unit, sending 29-bit `TX 0x07FC80FE: 84 00 00 00 00 00 00 00` at startup resets into Stage 1 of the factory `CAN RAM-Loader` (`0x01000BCC`) on `0x6F0 / 0x6F1`:
1. Request `Seed`: `30 00 00 00 00 00 00 00` → reply `30 <S0 S1 S2 S3>`.
2. Compute the 4-byte `Key` (`poly = 0xA001` reflected, **`init = 0x0000`**):
   ```python
   def crc16_reflected_zero(data: bytes) -> int:
       crc = 0x0000
       for b in data:
           crc ^= b
           for _ in range(8):
               crc = ((crc >> 1) ^ 0xA001) if (crc & 1) else (crc >> 1)
       return crc & 0xFFFF

   def conti_ramloader_key(seed4: bytes) -> bytes:
       s0, s1, s2, s3 = seed4
       buf = bytes([0x65, 0x96, s2, s1, 0xAC, s3, 0x53, s0])
       c1, c2 = crc16_reflected_zero(buf[0:8]), crc16_reflected_zero(buf[2:8])
       b0, b1, b2, b3 = c1 & 0xFF, (c1 >> 8) & 0xFF, c2 & 0xFF, (c2 >> 8) & 0xFF
       rem = s3 % 3
       return bytes([b1, b2, b3, b0] if rem == 0 else ([b2, b0, b1, b3] if rem == 1 else [b3, b2, b0, b1]))
   ```
   Test vectors: `12 34 56 78` → `58 A0 46 90`; `A1 B2 C3 01` → `A4 94 EF F1`; `11 22 33 44` → `7D 60 50 63`.
3. Send `20 <K0 K1 K2 K3> 00 00 00`, then `50 00 00 00 00 00 00 00` to enter Stage 2 (`0x0100120E`).

---

## 4. Stock `ZDC` Dataset Upload (No `RSA`) & Service `DID` / `RID` Reference

The application's `ZDC` upload handler (`0x0003E552` / `0x0003D558`) performs **zero `RSA` checks**, validating only a trailing 4-byte Little-Endian **`IEEE 802.3 CRC-32` (`zlib.crc32`)** (`payload = body + struct.pack("<I", zlib.crc32(body))`). Custom datasets therefore flash over OBD onto 100% stock gateways:

| `idx` | UDS Address (`0x34`) | Size (`UDS_Len`) | Offset in `Dflash.bin` | Dataset Purpose |
| :---: | :---: | :---: | :---: | :--- |
| `0` | `0x00000A00` | `0x0080` (`128` B) | `0x0080 .. 0x00FF` | Base `ZDC` configuration block |
| `1` | `0x00000A80` | `0x0100` (`256` B) | `0x0100 .. 0x01FF` | **`MKE`** — Driver Alert / Fatigue Detection (`'ZM3'`) |
| **`2`** | **`0x00002880`** | **`0x0800` (`2048` B)** | `0x0200 .. 0x09FF` | **`FPA` (`Driving Profile Selection`)** — mode & `Mode` button matrix |
| `3` | `0x00003080` | `0x0400` (`1024` B) | `0x0A00 .. 0x0DFF` | Auxiliary / Hybrid energy management |
| `4` | `0x00000B80` | `0x1100` (`4352` B) | `0x1340 .. 0x243F` | **Main Gateway network routing table** (`'NC00'`) |
| `5` | `0x00003E00` | `0x012E` (`302` B) | `0x1200 .. 0x132D` | Subsystem calibration table |
| `6` | `0x00001C80` | `0x0C00` (`3072` B) | `0x2440 .. 0x303F` | **`BEM`** — battery, LIN alternator & `Start-Stop` curves |

Standard UDS upload sequence (`0x710` → `0x77A`, `can_upload_zdc_datasets`):

1. **Authentication & Workshop Fingerprint**: `10 40` → `27 03` / `27 04 <Seed + 0x00004E87>` (login `20103`) → `2E F1 98 <6-byte tester ID>` → `2E F1 99 <UTC BCD YY MM DD>`.
2. **Indivisible Per-Block Transfer & `CheckMemory` (`uninterruptible`)**:
   - `RequestDownload`: `34 00 44 <Addr_BE32> <Len_BE32>` → reply `74 20 04 00` (`maxNumberOfBlockLength = 1,024` B).
   - `TransferData`: `36 <seq> <data>` **strictly in full-size `maxNumberOfBlockLength - 2` (`1,022`-byte) blocks** up to the final chunk (matching `ODIS-E`: `1022 + 1022 + ...`). Sending artificially short `240`-byte chunks after `74 10 FE` is rejected by the gateway with **`7F 36 31` (`requestOutOfRange`)** and leaves the dataset half-erased!
   - `RequestTransferExit`: `37` → `77`.
   - **Immediate Per-Block `CheckMemory` right after `37`**: start `31 01 02 EF 03 10 00` and poll **`31 03 02 EF`** until completion (`71 03 02 EF 02 FF FF` = **`CRC PASS`**, `00 00` = `CRC-32` failure). This clears the gateway's transfer-complete latch (omitting it makes the next `34` fail with `7F 34 22`).
3. **Sealing Dataset Passport & Automatic `0x0600` Coding Sync**:
   - writes `2E F1 A0` (`11` B ASCII dataset part number), `2E F1 A1` (`4` B ASCII version), and `2E F1 A4` (`12` B equipment mask);
   - automatically reads `22 06 00` (`30` bytes), sets the enable bits for every uploaded dataset in `2E 06 00` (without which gateway firmware ignores the uploaded dataset on boot!), and restarts the gateway via `11 02`.

> [!IMPORTANT]
> When editing **`FPA` (`#2`)** presets, the dataset's header tag and year bytes must stay untouched (modifying only shared profile sections and recalculating the trailing `CRC-32`), otherwise the gateway raises **`DTC 000601` (`Dataset implausible`)**.

### Guided `SWaP` & Coding Preparation When Writing Datasets Over CAN (`v2.0.2`)

Uploading a `ZDC` table alone is not enough when the underlying feature is gated by `SWaP`: `MKE` requires `0x10000300`, and `FPA` hides any driving profile whose `0x10000100..0x1000010B` code is inactive. In the **"Write datasets over CAN"** dialog, `ContiTool` guides the whole sequence step by step:
1. Reads the gateway's live accepted `SWaP` features (`22 3C 00`) and Long Coding (`22 06 00`), showing which `SWaP` codes the dataset relies on and which `0x0600` bytes change.
2. When required `SWaP` codes are inactive and the user chooses to enable them, runs **`can_activate_swap`**: reads the gateway's own `DataFlash` via `RAM-Loader`, patches only the `Multi-FSC` records while preserving the unit's `VIN` and existing datasets (`apply_dflash_swap_fecs`), and writes the modified blocks back via `DFLASH_FACI_STUB`.
3. Uploads `ZDC` blocks over UDS (`can_upload_zdc_datasets`), aligns `0x0600`, re-verifies `22 3C 00`, and offers to clear `DTC`s.

### Key Service `DIDs (0x2E)` & `RoutineControl (0x31)` RIDs

| Service + ID | Session / Security | Function |
| :---: | :---: | :--- |
| `2E 04 FC` / `2E 04 FE` | `10 40` + `27 03/04 (20103)` | `Production Mode` — factory power-check bitmasks with auto-decrement counter |
| `2E 09 28` | `10 03` / `10 40` | `Transport Mode` — shipping power-saving mode |
| `2E 06 00` / `2E 04 A3` | `10 03` / `10 40` | `Long Coding` (`30` B, preceded by `F198`/`F199`) & Gateway installation list (`Verbauliste` in `95640`) |
| `22 1F 07` / `22 1F 19` | `10 03` | Live `LIN` frame monitor for steering-wheel `MFL_01` and cruise-control `GRA_Neu` buttons (`can_learn_mfl_button`) |
| `31 01 02 03` | `10 03` / `10 40` | `CheckProgrammingPreconditions` prior to `10 02` |
| `31 01 03 06` | `10 40` / `10 4F` | Native `ICUS0` challenge-response unlock for `Feature 0x80/0x81/0x83` |
| `31 01 03 B0` / `05 C7` | `10 03` / `10 40` | Reset `BEM` battery statistics & communication fault counters |
| `31 01 04 B5` / `04 B6` | `10 03` / `10 40` | Start & poll `LIN` slave bus diagnostic test |
| `31 01 04 75` | `10 03` / `10 40` | Hold CAN subnetworks awake (`Partial Networking`) |
| `31 01 05 67` | `10 40` + `27 03/04 (20103)` | `KSCHUTZ` (`CP`) service status synchronization |
| `31 01 06 65` / `06 91` | `10 03` / `10 40` | Physical `Wake-up` line test / forced bus sleep |
| `31 01 10 27` | `10 40` + `27 03/04 (20103)` | Factory EOL CAN/LIN transceiver self-test |

---

## 5. `RSA-1024 (e = 3)` Cryptography, `SWaP FSC v2` Certificates & `ODX` Signing

### 1. `RSA-1024` Key Parameters on `J533`

Both signature verifiers on the gateway (`SWaP` in Application and `.odx` in `Uflash`) use **1024-bit RSA with hardcoded public exponent `e = 3`**:
- **ContiTool** generates 512-bit primes `p` and `q` (40-round Miller–Rabin) with top bits `11` and `p % 3 == 2`, `q % 3 == 2` so `gcd((p - 1)(q - 1), 3) == 1` and `N = p * q` is strictly 1024 bits (`MSB = 1`);
- exports `.json` alongside OpenSSL-compatible `.private.pem` (`PKCS#1`) and `.public.pem` (`SPKI`) files.

### 2. Public Modulus `N` (`128`-Byte Big-Endian) Locations

1. **`SWaP / FeC` Key (`--target swap`) — synchronized in two places:**
   - in `CodeFlash.bin`: 128 bytes immediately following the unique 38-byte header `00 1B 00 FF FF FF` + `(31 × 0x00)` + `03`;
   - in `DataFlash.bin` (`NvM 0x7C @ 0xDB00`): **ContiTool** writes the 128-byte modulus at **`0xDB04`**, **preserves the gateway's original 5-byte hardware `VCRN` at `0xDC0C`** (`DID 0x3C03`), and recomputes the `IEEE CRC-32` (`480` bytes `0xDB04..0xDCE3`) at **`0xDCE4`**.
2. **`FBL / ODX` Key (`--target fbl`):**
   - resides in `Sector 5` of the full `1.5 MB` `CodeFlash.bin`: 128-byte exponent (`127 × 0x00 + 0x03`) at **`0x0000A277`** and 128-byte modulus `N` at **`0x0000A2F7`**.

### 3. Byte Layout of the 171-Byte (`0xAB`) `VAG SWaP FSC v2` Certificate (`sign-fsc`)

Each certificate comprises a **43-byte signed body (`0x00..0x2A`)** and a **128-byte signature (`0x2B..0xAA`)**:

| Offset | Length | Value | Field Description |
| :---: | :---: | :--- | :--- |
| `+0x00` | `2` B | `11 02` | `VAG FSC v2` container header |
| `+0x02` | `4` B | `FeC_BE32` | Feature Enablement Code Big-Endian (e.g., `10 00 01 00` `FPA`, `10 00 03 00` `MKE`) |
| `+0x06` | `1` B | `03` | Individualization ID type (`VCRN`) |
| `+0x07` | `5` B | `VCRN[0..4]` | Gateway 5-byte hardware `VCRN` from `DataFlash @ 0xDC0C` (`DID 0x3C03`) |
| `+0x0C` | `18` B | `VIN_17B + 0x00` | 17 ASCII `VIN` characters + `0x00` terminator (or `18` zero bytes) |
| `+0x1E` | `4` B | `Timestamp_BE32` | Certificate issue timestamp (`Unix UTC`, Big-Endian) |
| `+0x22` | `9` B | `00 × 9` | Validity restriction block (`00..00` = permanent license) |
| `+0x2B` | `128` B | `Signature_128B` | `RSASSA-PKCS1-v1_5` signature over **`TeleTrusT RIPEMD-160`** of bytes `0..42` (`DigestInfo = 30 21 30 09 06 05 2B 24 03 02 01 05 00 04 14` + `20`-byte digest) |

#### Five-Step OBD `FSC` Activation Sequence (`0x710` → `0x77A`)

1. `10 40` — enter `EOLSession` (`31 01 C0 01` is rejected in `10 03`).
2. `27 03` → `27 04 <Seed + 0x00004E87>` — unlock `SecurityAccess Level 3` (open login `20103`).
3. *(Optional)* read `VCRN` via `22 3C 03`.
4. `2E 3C 01 <171-byte FSC>` — stage certificate into RAM buffer `0xFEDF590D`.
5. **`31 01 C0 01`** *(strictly 4 bytes with zero inline parameters — appending `FSC` bytes to `31 01` returns `7F 31 13`!)* → poll **`31 03 C0 01`** (delete an installed `FeC`: `31 01 C0 02 <4B FeC>`).

### 4. `ODX` Application Firmware Signature (`sign-odx`)

During `CheckMemory (31 01 02 02)`, `Uflash` hashes an 8-byte Big-Endian `[start_addr, length]` prefix concatenated with `FD_0DATA` using **`SHA-1`**:

$$\text{Msg} = \mathtt{00\,00\,C2\,00} \;\|\; \mathtt{00\,17\,3E\,00} \;\|\; \text{FD\_0DATA}_{1,523,200\text{ B}}$$

`sign-odx` verifies `App CRC-16` at `0x0000C21C` and non-zero range count at `0x0000C21E`, then produces the 128-byte `RSASSA-PKCS1-v1_5 (SHA-1)` signature (`DigestInfo = 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14`) for `<FW-SIGNATURE>` in `.odx`.
