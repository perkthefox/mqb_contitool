"""Where ContiTool keeps its files.

    contitool_runs/                       next to the program
      3Q0907530C_TST-SYN01.01.260000001/ one folder per gateway: hardware part number + FAZIT
        dumps/
          base_read/                      the first complete read of this gateway — what it came with
          2026-11-09_15-20-05_read/       later complete reads
          2026-11-09_15-34-12_flashed/    what it holds after a write, manifest.json: what changed vs base_read
        writes/
          2026-11-09_15-31-40_write/      every operation that changes the gateway (and the diagnostics):
                                          logs, results and the backups taken before writing
      unknown/                            a gateway whose identity could not be read
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import time
from typing import Any

RUNS = "contitool_runs"
DUMPS, WRITES, BASE_READ = "dumps", "writes", "base_read"
AREA_FILES = ("Cflash.bin", "Dflash.bin", "Uflash.bin")
FAZIT_OFFSET, HW_PN_OFFSET = 0xA240, 0xA25A  # in CodeFlash: 23 ASCII, 11 ASCII


def app_dir() -> Path:
    """The folder ContiTool is run from: next to the .exe (the .app bundle on macOS), or next to conti_cp_tool.py."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        bundle = next((p for p in exe.parents if p.suffix == ".app"), None)
        return bundle.parent if bundle is not None else exe.parent
    main = Path(sys.argv[0]).resolve() if sys.argv and sys.argv[0] else None
    return main.parent if main is not None and main.is_file() else Path.cwd()


def runs_root() -> Path:
    """contitool_runs next to the program. Where that cannot be written (Program Files, a quarantined .app the system
    runs from a random read-only place) it is Documents/ContiTool/contitool_runs instead."""
    for root in (app_dir() / RUNS, Path.home() / "Documents" / "ContiTool" / RUNS):
        try:
            root.mkdir(parents=True, exist_ok=True)
            probe = root / ".write_test"
            probe.write_bytes(b"")
            probe.unlink()
            return root
        except OSError:
            continue
    return Path.cwd() / RUNS


def unit_name(part: str, fazit: str) -> str:
    """`3Q0907530C_TST-SYN01.01.260000001`; what a file system may refuse becomes '-'. 'unknown' without both."""
    def clean(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9.\-]+", "-", (s or "").strip()).strip("-.")

    part, fazit = clean(part), clean(fazit)
    return f"{part}_{fazit}" if part and fazit else "unknown"


def unit_of_cflash(cflash: bytes | None) -> str:
    """The gateway a CodeFlash image belongs to (its boot area carries both numbers)."""
    if not cflash or len(cflash) < HW_PN_OFFSET + 11:
        return "unknown"
    ascii_at = lambda off, n: cflash[off : off + n].decode("ascii", "replace")  # noqa: E731
    return unit_name(ascii_at(HW_PN_OFFSET, 11), ascii_at(FAZIT_OFFSET, 23))


def unit_of_ident(ident: list[dict[str, str]]) -> str:
    """The gateway as `can_identify` read it: hardware number (F191) and FAZIT (F17C)."""
    vals = {i.get("did"): i.get("value", "") for i in ident or []}
    return unit_name(vals.get("F191", ""), vals.get("F17C", ""))


def new_session(root: Path, unit: str, kind: str, *, dumps: bool = False) -> Path:
    """A fresh `<date>_<time>_<kind>` folder under the gateway's dumps/ or writes/."""
    base = root / (unit or "unknown") / (DUMPS if dumps else WRITES)
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    cand, n = base / f"{stamp}_{kind}", 2
    while cand.exists():
        cand, n = base / f"{stamp}_{kind}_{n}", n + 1
    cand.mkdir(parents=True)
    return cand


def _repath(obj: Any, old: str, new: str) -> Any:
    if isinstance(obj, str):
        return obj.replace(old, new)
    if isinstance(obj, list):
        return [_repath(v, old, new) for v in obj]
    if isinstance(obj, dict):
        return {k: _repath(v, old, new) for k, v in obj.items()}
    return obj


def keep_as_base(read_dir: Path) -> Path:
    """A complete read becomes the gateway's base_read if it has none yet; returns where the read now is."""
    base = read_dir.parent / BASE_READ
    if base.exists() or not all((read_dir / name).is_file() for name in AREA_FILES):
        return read_dir
    read_dir.rename(base)
    manifest = base / "manifest.json"
    if manifest.is_file():  # it names its own files by absolute path
        data = _repath(json.loads(manifest.read_text(encoding="utf-8")), str(read_dir), str(base))
        manifest.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return base


def changed_ranges(a: bytes, b: bytes, *, merge_gap: int = 16) -> list[tuple[int, int]]:
    """[start, end) byte ranges where `a` and `b` differ (equal lengths); ranges closer than `merge_gap` merge."""
    out: list[tuple[int, int]] = []
    step, n = 256, min(len(a), len(b))
    for blk in range(0, n, step):
        if a[blk : blk + step] == b[blk : blk + step]:
            continue
        for i in range(blk, min(blk + step, n)):
            if a[i] != b[i]:
                if out and i - out[-1][1] <= merge_gap:
                    out[-1] = (out[-1][0], i + 1)
                else:
                    out.append((i, i + 1))
    return out


def record_flashed(unit_dir: Path, files: dict[str, Path], session: Path, base_fallback: dict[str, Path]) -> Path:
    """What the gateway holds after a write, as dumps/<date>_flashed with a manifest of what changed against
    base_read. `files`: area file name -> the file now true for the ECU. Without a base_read yet, the backups the
    write took first (`*_before.bin` in `session`) become it, else `base_fallback` (the files the write started from)."""
    dumps = unit_dir / DUMPS
    base = dumps / BASE_READ
    if not base.exists():
        before = {p.name.replace("_before", ""): p for p in session.rglob("*_before.bin")}
        src = {name: before.get(name) or base_fallback.get(name) for name in AREA_FILES}
        src = {k: v for k, v in src.items() if v is not None and v.is_file()}
        if src:
            base.mkdir(parents=True)
            for name, p in src.items():
                shutil.copy2(p, base / name)
            (base / "manifest.json").write_text(json.dumps(
                {"source": "backup before the first write", "session": str(session)}, indent=2), encoding="utf-8")
    out = new_session(unit_dir.parent, unit_dir.name, "flashed", dumps=True)
    areas: dict[str, Any] = {}
    for name, p in files.items():
        shutil.copy2(p, out / name)
        now = p.read_bytes()
        entry: dict[str, Any] = {"sha256": hashlib.sha256(now).hexdigest()}
        ref = base / name
        if ref.is_file():
            old = ref.read_bytes()
            rng = changed_ranges(old, now)
            entry.update(
                base_sha256=hashlib.sha256(old).hexdigest(),
                changed_bytes=sum(e - s for s, e in rng),
                changed_ranges=[f"0x{s:06X}..0x{e - 1:06X}" for s, e in rng[:500]],
                changed_ranges_total=len(rng),
            )
        areas[name] = entry
    (out / "manifest.json").write_text(json.dumps(
        {"created": time.strftime("%Y-%m-%d %H:%M:%S"), "base": BASE_READ if base.exists() else None,
         "write_session": str(session), "areas": areas}, indent=2, ensure_ascii=False), encoding="utf-8")
    return out
