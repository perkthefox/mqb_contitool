"""The gateway being worked on: original dump files, edited copies, and what has been written back."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, Signal

from contitool.core import (
    DetectedDumpFile,
    detect_dump_file,
    discover_hw_identity,
)

KINDS = ("cflash", "dflash", "uflash")
OPTIONAL_KINDS = ("eeprom", "opbt")
ALL_KINDS = KINDS + OPTIONAL_KINDS
NAMES = {
    "cflash": "CodeFlash",
    "dflash": "DataFlash",
    "uflash": "Uflash",
    "eeprom": "EEPROM",
    "opbt": "OPBT",
}
ACCEPTS = {
    "cflash": ("cflash", "fd_0data"),
    "dflash": ("dflash",),
    "uflash": ("uflash",),
    "eeprom": ("eeprom",),
    "opbt": ("opbt",),
}
CANDIDATES = {
    "cflash": ("Cflash.bin", "CodeFlash.bin", "Cflash_before.bin", "FD_0DATA.raw.bin"),
    "dflash": ("Dflash.bin", "DataFlash.bin", "Dflash_before.bin"),
    "uflash": ("Uflash.bin", "Uflash_before.bin", "UserBootCode.bin"),
    "eeprom": ("Eeprom.bin", "EEPROM.bin", "m95640.bin", "M95640.bin"),
    "opbt": ("Opbt.bin", "OPBT.bin", "opbt.bin", "ExtraArea.bin"),
}
EDIT_DIR = "ContiTool_edited"
_RECENT_KEY = "workspace/recent"


def kind_of(det: DetectedDumpFile) -> str | None:
    """Workspace slot for a detected file, or None if it is not a usable gateway dump."""
    if not det.valid:
        return None
    return next((k for k, accepted in ACCEPTS.items() if det.kind in accepted), None)


class Workspace(QObject):
    """Edits never touch the originals: every change is written to <folder>/ContiTool_edited/."""

    changed = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.folder: Path | None = None
        self.source = "files"  # "can" when created from a CAN backup in this session
        self.original: dict[str, Path] = {}
        self.current: dict[str, Path] = {}
        self.written: dict[str, bytes] = {}  # kind -> SHA-256 of the file written to the ECU
        self.read_warnings: dict[str, str] = {}  # optional kind -> non-fatal CAN read warning
        self.extra_idcode: bytes = b""  # 16-byte RH850 IDCODE from Extra Area (0xFF300050)
        self.chip_id: bytes = b""  # 32-byte RH850 SCDS Chip ID (0xFFCD00E0)
        self._info: dict[str, DetectedDumpFile] = {}

    # ── state ──
    @property
    def is_open(self) -> bool:
        return bool(self.current)

    def info(self, kind: str) -> DetectedDumpFile | None:
        return self._info.get(kind)

    def path(self, kind: str) -> Path | None:
        return self.current.get(kind)

    def modified(self, kind: str) -> bool:
        return kind in self.current and self.current[kind] != self.original.get(kind)

    def pending(self, kind: str) -> bool:
        """Modified and not yet written to the ECU."""
        return self.modified(kind) and kind not in self.written

    def edit_path(self, kind: str) -> Path:
        assert self.folder is not None
        name = self.original[kind].name if kind in self.original else CANDIDATES[kind][0]
        return self.folder / EDIT_DIR / name

    @property
    def part_number(self) -> str:
        inf = self.info("cflash")
        einf = self.info("eeprom")
        e = einf.eeprom_info if einf else None
        if inf and inf.cflash_info:
            c = inf.cflash_info
            if c.sw_pn:
                return c.sw_pn
            if e and e.part_number and c.sw_ver and e.sw_version == c.sw_ver:
                return e.part_number
            if c.hw_pn:
                return c.hw_pn
        return e.part_number if e else ""

    @property
    def idcode(self) -> bytes:
        inf = self.info("cflash")
        if inf and inf.cflash_info and inf.cflash_info.idcode:
            return inf.cflash_info.idcode
        op = self.info("opbt")
        if op and op.opbt_info and op.opbt_info.idcode:
            return op.opbt_info.idcode
        return self.extra_idcode

    # ── loading ──
    def open_folder(self, folder: Path, source: str = "files") -> list[str]:
        """Load the first matching dump of each kind. Returns names of kinds that were not found."""
        files = {}
        for kind, names in CANDIDATES.items():
            hit = next((folder / n for n in names if (folder / n).is_file()), None)
            if hit is not None:
                files[kind] = hit
        return self._open(folder, files, source)

    def open_files(self, paths: list[Path]) -> list[str]:
        """Classify loose files by content. Returns names of files that are not gateway dumps."""
        files: dict[str, Path] = {}
        rejected = []
        for p in paths:
            kind = kind_of(detect_dump_file(p))
            if kind is None:
                rejected.append(p.name)
            else:
                files[kind] = p
        if files:
            self._open(next(iter(files.values())).parent, files, "files")
        return rejected

    def _open(self, folder: Path, files: dict[str, Path], source: str) -> list[str]:
        self.folder, self.source = folder, source
        self.original, self.current, self.written, self.read_warnings, self._info = {}, {}, {}, {}, {}
        self.extra_idcode, self.chip_id = b"", b""
        missing = []
        for kind in KINDS:
            p = files.get(kind)
            det = detect_dump_file(p) if p else None
            if det is not None and kind_of(det) == kind:
                self.original[kind] = self.current[kind] = p
                self._info[kind] = det
            else:
                missing.append(kind)
        for kind in OPTIONAL_KINDS:
            p = files.get(kind)
            det = detect_dump_file(p) if p else None
            if det is not None and kind_of(det) == kind:
                self.original[kind] = self.current[kind] = p
                self._info[kind] = det
        manifest_path = folder / "manifest.json"
        if manifest_path.is_file():
            try:
                mdata = json.loads(manifest_path.read_text(encoding="utf-8"))
                area_warns = mdata.get("area_warnings")
                if isinstance(area_warns, dict):
                    for kind in OPTIONAL_KINDS:
                        if kind not in self.current and isinstance(area_warns.get(kind), str) and area_warns[kind]:
                            self.read_warnings[kind] = area_warns[kind]
            except (OSError, ValueError):
                pass
        self._load_hw_identity(folder)
        if self.is_open:
            _remember_recent(folder)
        self.changed.emit()
        return missing

    def _load_hw_identity(self, *search_dirs: Path) -> None:
        op = self._info.get("opbt")
        if op and op.opbt_info:
            if op.opbt_info.idcode and not self.extra_idcode:
                self.extra_idcode = op.opbt_info.idcode
            if op.opbt_info.chip_id and not self.chip_id:
                self.chip_id = op.opbt_info.chip_id

        found_idcode, found_chip_id = discover_hw_identity(
            *search_dirs,
            has_opbt_file="opbt" in self.current,
        )
        if not self.extra_idcode and found_idcode:
            self.extra_idcode = found_idcode
        if not self.chip_id and found_chip_id:
            self.chip_id = found_chip_id

        if op and op.opbt_info:
            if self.extra_idcode and not op.opbt_info.idcode:
                op.opbt_info.idcode = self.extra_idcode
            if self.chip_id and not op.opbt_info.chip_id:
                op.opbt_info.chip_id = self.chip_id

    def replace(self, kind: str, path: Path) -> str | None:
        """Use another file for one slot (as a new original). Returns an error text or None."""
        det = detect_dump_file(path)
        if kind_of(det) != kind:
            return det.summary_text
        self.original[kind] = self.current[kind] = path
        self.written.pop(kind, None)
        self.read_warnings.pop(kind, None)
        self._info[kind] = det
        if kind == "opbt":
            self.extra_idcode, self.chip_id = b"", b""
            same_dir = self.folder is not None and path.parent.resolve() == self.folder.resolve()
            self._load_hw_identity(path.parent, *([self.folder] if same_dir and self.folder else []))
        self.changed.emit()
        return None

    # ── edits ──
    def commit(self, kind: str, path: Path) -> None:
        """Adopt an edited file produced by a background task (call on the GUI thread)."""
        self.current[kind] = path
        if kind in self.written and self.written[kind] != _sha256(path):
            del self.written[kind]  # new content: not in the ECU yet, even under the same file name
        self._info[kind] = detect_dump_file(path)
        self.changed.emit()

    def mark_written(self, kinds: list[str]) -> None:
        for k in kinds:
            if k in self.current:
                self.written[k] = _sha256(self.current[k])
        self.changed.emit()

    def revert(self) -> None:
        for kind, p in self.original.items():
            self.current[kind] = p
            self._info[kind] = detect_dump_file(p)
        self.extra_idcode, self.chip_id = b"", b""
        op_orig = self.original.get("opbt")
        if op_orig is not None:
            same_dir = self.folder is not None and op_orig.parent.resolve() == self.folder.resolve()
            self._load_hw_identity(op_orig.parent, *([self.folder] if same_dir and self.folder else []))
        elif self.folder:
            self._load_hw_identity(self.folder)
        self.changed.emit()

    def close(self) -> None:
        self.folder = None
        self.original, self.current, self.written, self.read_warnings, self._info = {}, {}, {}, {}, {}
        self.extra_idcode, self.chip_id = b"", b""
        self.changed.emit()


def _sha256(path: Path) -> bytes:
    return hashlib.sha256(path.read_bytes()).digest()


def recent_folders() -> list[Path]:
    raw = QSettings().value(_RECENT_KEY, []) or []
    items = [raw] if isinstance(raw, str) else list(raw)
    return [Path(p) for p in items if Path(p).is_dir()]


def _remember_recent(folder: Path) -> None:
    items = [str(folder)] + [str(p) for p in recent_folders() if p != folder]
    QSettings().setValue(_RECENT_KEY, items[:5])
