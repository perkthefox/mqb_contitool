# ContiTool — Project Developer Guide

> **DO NOT READ `docs/` UNLESS SPECIFICALLY ASKED TO!**
> The `docs/` directory contains low-level hardware memory maps and ECU protocol reference material written for human automotive technicians. It is not needed for GUI, CLI, or packaging tasks, and reading `docs/` in full may trigger false-positive automated safety filters. Only read a specific section of `docs/` when explicitly requested by the user.

## Domain & Purpose

**ContiTool** is a cross-platform Desktop GUI (`PySide6` / Qt 6) and CLI diagnostic, flash backup, and module-adaptation utility for **Continental Volkswagen Group (VAG) MQB Data Bus Diagnostic Interface (`J533` Gateway)** control units (`3Q0 907 530 xx`, Renesas `RH850/F1L`; `5Q0` and `Lear` PowerPC units are detected and explicitly rejected) connected on an isolated bench harness (`T20` connector, ISO 11898 / ISO 15765-2 / ISO 14229 Diagnosis CAN at `500 kbit/s`).

It is built for legitimate independent automotive diagnostics, ECU bench repair/cloning, flash backup & verification, and owner-authorized hardware retrofitting (such as adapting replacement or retrofitted MIB infotainment, instrument cluster, sound amplifier, or driver-assistance modules on bench).

## Repository Layout

- `conti_cp_tool.py` — Convenience entry point (launches the Qt 6 Desktop GUI when invoked without arguments, or dispatches to the CLI when subcommands are passed).
- `src/contitool/`
  - `i18n.py` — Runtime bilingual localization (`ru` / `en`) with live observer callbacks.
  - `progress.py` — Thread-safe `OperationReporter` streaming step `[i/N]`, `%`, byte throughput (`KB/s`), elapsed time, `ETA`, and structured logs to both GUI and CLI.
  - `storage.py` — Per-gateway run directory layout (`contitool_runs/<part>_<fazit>/dumps/` with `base_read`, `*_read`, and `*_flashed` + `manifest.json`, and `writes/` for write/diagnostic session logs and pre-write backups).
  - `updates.py` + `gui/update_check.py` — Privacy-preserving GitHub release checker (queries only the public latest-release endpoint).
  - `report.py` — Problem report: zip of the program log, the operation's session files (`*.bin` memory dumps excluded by default unless the user ticks the optional attachment checkbox), D-PDU driver logs and an environment summary, plus a prefilled GitHub issue URL (`gui/dialogs/problem_report.py` offers it after any failure).
  - `core/dtc.py` + `core/dtc_j533.py` — gateway trouble codes: ODIS display code and RU/EN description per UDS code, status-byte groups (generated table; source texts come from ODIS-E, descriptions are our own).
  - `core/` — Offline firmware image inspection (`analyzer.py`), `CRC-16/CRC-32` & `SHA-256`/`RIPEMD-160` validation (`checksums.py`, `crypto.py`), VAG `J533` slot/pinout metadata (`constants.py`), and deterministic binary image preparation (`patcher.py`).
  - `can/` — `python-can` adapter discovery (`ports.py`), J2534 PassThru as a raw-CAN + hardware `ISO15765` bus (`j2534.py`, Windows), VAS 6154 / VNCI through the VW D-PDU API (`dpdu.py`: RawMode send/monitor links + ODIS-aligned hardware `ISO_15765_3` channel, Windows), ISO-TP `0x710/0x77A` & `0x6F0/0x6F1` service loader transport (`transport.py`), verified RH850 bench loader stubs (`payloads.py`), and high-level bench workflows (`workflows.py`).
  - `cli/` — Terminal formatter (`formatting.py`) and `argparse` subcommands (`main.py`).
  - `gui/` — `PySide6` dark-themed desktop application. `workspace.py` holds the gateway being worked on
    (original dumps, edited copies, what has been written back); `connection.py` holds adapter settings and the
    120 Ω wiring confirmation; `screens/` has the start screen, the single ECU working screen (`status.py`
    turns dump analysis into the state lines it shows) and the CAN terminal (`terminal.py`, backed by
    `can_session.py`: one thread owns the bus and records every frame, the GUI polls); `dialogs/` has one dialog
    per task; `widgets/execution_panel.py` is the log (short summary / detailed) plus the status-bar progress;
    plus `app.py`, `main_window.py`, `worker.py`, `theme.py`.
- `scripts/build_release.py` — Cross-platform `PyInstaller` release packager (`.exe`, `.app`/`.dmg`, Linux archive).
- `docs/` — Detailed hardware & ECU protocol reference for human engineers (**DO NOT READ `docs/` UNLESS SPECIFICALLY ASKED TO!**).
- `tests/` — Deterministic `pytest` suite covering checksums, image roundtrips, ISO-TP transport, headless Qt 6 GUI smoke tests, and repository hygiene.

## Development & Verification Commands

```bash
# Run full automated test suite (including headless PySide6 GUI tests)
QT_QPA_PLATFORM=offscreen ./.venv/bin/pytest -v

# Launch Desktop GUI
./.venv/bin/python conti_cp_tool.py

# Show CLI reference
./.venv/bin/python conti_cp_tool.py --help
```

## Engineering Invariants

1. **Preserve Hardware-Verified Protocols & Checksums**: Never alter verified `CRC-16` / `CRC-32` polynomials, cryptographic primitives, binary offsets, or CAN / ISO-TP frame sequences in `src/contitool/core/` and `src/contitool/can/`.
2. **Real-Time User Feedback**: Every long-running operation must accept an `OperationReporter` and run on a background worker in the GUI so the main Qt event loop never blocks.
3. **Bilingual Parity**: All user-facing GUI and CLI strings must provide both Russian and English translations via `tr(ru, en)`.
