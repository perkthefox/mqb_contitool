"""The gateway being worked on: original dump files, edited copies, and what has been written back."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, Signal

from contitool.core import DetectedDumpFile, detect_dump_file

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
        if inf and inf.cflash_info and inf.cflash_info.hw_pn:
            return inf.cflash_info.hw_pn
        einf = self.info("eeprom")
        return einf.eeprom_info.part_number if einf and einf.eeprom_info else ""

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
        if self.is_open:
            _remember_recent(folder)
        self.changed.emit()
        return missing

    def replace(self, kind: str, path: Path) -> str | None:
        """Use another file for one slot (as a new original). Returns an error text or None."""
        det = detect_dump_file(path)
        if kind_of(det) != kind:
            return det.summary_text
        self.original[kind] = self.current[kind] = path
        self.written.pop(kind, None)
        self.read_warnings.pop(kind, None)
        self._info[kind] = det
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
        self.changed.emit()

    def close(self) -> None:
        self.folder = None
        self.original, self.current, self.written, self.read_warnings, self._info = {}, {}, {}, {}, {}
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
