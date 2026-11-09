"""Folder layout: contitool_runs/<part>_<FAZIT>/{dumps,writes}, base_read and flashed sets with their manifest."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys

from contitool import storage


def test_gateway_folder_names(synth_cflash: bytes) -> None:
    assert storage.unit_name("3Q0907530C ", "TST-SYN01.01.260000001") == "3Q0907530C_TST-SYN01.01.260000001"
    assert storage.unit_name("3Q0907530C", "") == "unknown" and storage.unit_name("a/b:c", "x*y") == "a-b-c_x-y"
    ident = [{"did": "F191", "value": "3Q0907530C"}, {"did": "F17C", "value": "TST-SYN01.01.260000001"}]
    assert storage.unit_of_ident(ident) == "3Q0907530C_TST-SYN01.01.260000001"
    assert storage.unit_of_cflash(synth_cflash).endswith("_TST-SYN01.01.260000001") and storage.unit_of_cflash(None) == "unknown"


def test_first_complete_read_becomes_base_read_and_writes_record_what_changed(tmp_path: Path) -> None:
    root = tmp_path / "contitool_runs"
    read = storage.new_session(root, "PN_FZ", "read", dumps=True)
    images = {"Cflash.bin": bytes(4096), "Dflash.bin": bytes(1024), "Uflash.bin": bytes(512)}
    for name, raw in images.items():
        (read / name).write_bytes(raw)
    (read / "manifest.json").write_text(json.dumps({"areas": {"cflash": {"output_file": str(read / "Cflash.bin")}}}))
    base = storage.keep_as_base(read)
    assert base == root / "PN_FZ" / "dumps" / "base_read" and not read.exists()
    assert json.loads((base / "manifest.json").read_text())["areas"]["cflash"]["output_file"] == str(base / "Cflash.bin")
    again = storage.new_session(root, "PN_FZ", "read", dumps=True)
    for name, raw in images.items():
        (again / name).write_bytes(raw)
    assert storage.keep_as_base(again) == again  # the base stays the first read

    write = storage.new_session(root, "PN_FZ", "write")
    assert write.parent == root / "PN_FZ" / "writes" and write.name.endswith("_write")
    now = bytearray(images["Dflash.bin"])
    now[0x10:0x14] = b"\x01\x02\x03\x04"
    now[0x300] = 0xFF
    (write / "Dflash_readback.bin").write_bytes(now)
    flashed = storage.record_flashed(root / "PN_FZ", {"Dflash.bin": write / "Dflash_readback.bin"}, write, {})
    m = json.loads((flashed / "manifest.json").read_text())
    assert flashed.parent == root / "PN_FZ" / "dumps" and flashed.name.endswith("_flashed") and m["base"] == "base_read"
    assert m["areas"]["Dflash.bin"]["changed_ranges"] == ["0x000010..0x000013", "0x000300..0x000300"]
    assert (flashed / "Dflash.bin").read_bytes() == bytes(now)


def test_without_a_base_read_the_backups_before_the_write_become_it(tmp_path: Path) -> None:
    root, unit = tmp_path / "runs", "PN_FZ"
    write = storage.new_session(root, unit, "write")
    (write / "dflash" / "backup").mkdir(parents=True)
    (write / "dflash" / "backup" / "Dflash_before.bin").write_bytes(bytes(64))
    (write / "Dflash_readback.bin").write_bytes(b"\x05" + bytes(63))
    flashed = storage.record_flashed(root / unit, {"Dflash.bin": write / "Dflash_readback.bin"}, write, {})
    assert (root / unit / "dumps" / "base_read" / "Dflash.bin").read_bytes() == bytes(64)
    assert json.loads((flashed / "manifest.json").read_text())["areas"]["Dflash.bin"]["changed_bytes"] == 1


def test_runs_folder_sits_next_to_the_program(tmp_path: Path, monkeypatch) -> None:
    app = tmp_path / "ContiTool.app" / "Contents" / "MacOS"
    app.mkdir(parents=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(app / "ContiTool"))
    assert storage.app_dir() == tmp_path  # beside the .app, never inside the bundle
    assert storage.runs_root() == tmp_path / "contitool_runs"
    monkeypatch.setattr(sys, "executable", str(tmp_path / "win" / "ContiTool.exe"))
    assert storage.app_dir() == tmp_path / "win"


def test_a_full_read_on_file_is_recognised(tmp_path: Path) -> None:
    unit = tmp_path / "3Q0907530C_TST-SYN01.01.260000001"
    assert not storage.has_full_read(unit)
    flashed = unit / "dumps" / "2026-11-09_15-34-12_flashed"  # only what was written: not a full read
    flashed.mkdir(parents=True)
    (flashed / "Dflash.bin").write_bytes(b"\0")
    read = unit / "dumps" / "2026-11-09_15-20-05_read"
    read.mkdir()
    for name in storage.AREA_FILES[:2]:
        (read / name).write_bytes(b"\0")
    assert not storage.has_full_read(unit)  # Uflash missing
    (read / "Uflash.bin").write_bytes(b"\0")
    assert not storage.has_full_read(unit)  # a read that broke off: short files
    for name, size in storage.AREA_SIZES.items():
        (read / name).write_bytes(bytes(size))
    assert storage.has_full_read(unit)
    other = tmp_path / "unknown"
    shutil.copytree(unit / "dumps", other / "dumps")
    assert not storage.has_full_read(other)  # another gateway's read cannot vouch for an unidentified one
