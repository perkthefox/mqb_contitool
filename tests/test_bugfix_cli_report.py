"""Problem report privacy, CLI option checks, update version parsing, storage read detection."""

from __future__ import annotations

import sys
import time
import urllib.parse
import zipfile
from pathlib import Path

import pytest

from contitool import report, storage
from contitool.cli.main import main
from contitool.core import generate_rsa1024_e3_keypair, save_rsa1024_keypair_bundle
from contitool.i18n import set_lang
from contitool.updates import newer_release, version_key

FAZIT, VIN = "TST-SYN01.01.2400000001", "WVWZZZAUZNW000001"  # test values the hygiene check allows
UNIT = f"3Q0907530AR_{FAZIT}"


# 1. key material never goes into a report


def test_report_never_carries_key_material(tmp_path: Path) -> None:
    """The GUI saves a new key pair to <workspace>/ContiTool_keys; after a CAN read the workspace is base_read, inside
    the folder the report sweeps. A key operation that fails after saving must not publish the private key."""
    runs = tmp_path / "contitool_runs"
    base = runs / UNIT / "dumps" / "base_read"
    base.mkdir(parents=True)
    for n in storage.AREA_FILES:
        (base / n).write_bytes(b"\xff" * 16)
    (base / "manifest.json").write_text("{}")
    started = time.time()
    saved = save_rsa1024_keypair_bundle(base / "ContiTool_keys" / "j533_swap_20261110_010203.json",
                                        generate_rsa1024_e3_keypair())
    odd = runs / UNIT / "writes" / "2026-11-10_01-02-03_write" / "contitool_KEYS"  # any depth, any case
    odd.mkdir(parents=True)
    (odd / "j533_fbl.json").write_text('{"d_hex": "00"}')
    (runs / "loose.PRIVATE.PEM").write_text("-----BEGIN RSA PRIVATE KEY-----\n")
    failure = report.Failure("Your SWaP key", "CodeFlash CRC-16 mismatch", started=started)

    for dumps in (None, {"loaded/Cflash.bin": base / "Cflash.bin"}):
        z = report.build_report_zip(tmp_path / "r.zip", failure, {"Adapter": "-"}, "log\n", runs, driver_dirs=[],
                                    dumps=dumps)
        with zipfile.ZipFile(z) as zf:
            names = zf.namelist()
            assert f"sessions/{UNIT}/dumps/base_read/manifest.json" in names  # the rest of the folder still goes in
            assert not any("contitool_keys" in n.lower() or n.lower().endswith(".pem") for n in names), names
            assert not any(b"d_hex" in zf.read(n) or b"PRIVATE KEY" in zf.read(n) for n in names)
    assert all(p.is_file() for p in saved)


# 2. FAZIT / VIN masked next to "_", home folder hidden


def test_ids_next_to_an_underscore_are_masked(monkeypatch) -> None:
    home = "/srv/ivan.petrov"
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("USERPROFILE", home)
    text = f"saved to {home}/contitool_runs/{UNIT}/dumps"
    masked = report.mask_ids(text)
    assert FAZIT not in masked and "ivan.petrov" not in masked
    assert masked == "saved to ~/contitool_runs/3Q0907530AR_TST-SYN01.01.24********/dumps"
    assert report.mask_ids(f"backup_{VIN}_read") == "backup_WVWZZZAUZNW******_read"
    assert report.mask_ids(f"{FAZIT}_x VIN:{VIN}") == "TST-SYN01.01.24********_x VIN:WVWZZZAUZNW******"
    # not IDs: stay as they are
    plain = ("HW 3Q0907530AR, NRC 0x31 at 0x01000EF0, CRC 1A2B3C4D, frame 0x6F1, block_12 of 384, "
             "2026-11-09_15-31-40_write, /srv/ivan.petrovich/x, dump_0123456789abcdef0")
    assert report.mask_ids(plain) == plain


def test_issue_text_and_zip_logs_hide_the_run_folder_fazit(tmp_path: Path, monkeypatch) -> None:
    set_lang("en")
    home = str(tmp_path / "home" / "ivan.petrov")
    monkeypatch.setenv("HOME", home)
    monkeypatch.setenv("USERPROFILE", home)
    where = f"{home}/ContiTool/contitool_runs/{UNIT}/dumps/2026-11-09_15-20-05_read"
    failure = report.Failure(f"Reading {where}", f"No CAN frame; see {where}/can.jsonl", f"Traceback {where}", time.time())
    log = f"INFO Folder: {where}\n"
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(report.issue_url(failure, {"OS": "x"}, log)).query)
    for field in ("title", "error", "log"):
        assert FAZIT not in query[field][0] and "ivan.petrov" not in query[field][0], field
    z = report.build_report_zip(tmp_path / "r.zip", failure, {"Adapter": "-"}, log, tmp_path / "runs", driver_dirs=[])
    with zipfile.ZipFile(z) as zf:
        for name in ("issue.md", "contitool_log.txt", "traceback.txt"):
            text = zf.read(name).decode()
            assert FAZIT not in text and "ivan.petrov" not in text and "~/ContiTool" in text, name


# 3. set-rsa-key --target fbl leaves DataFlash alone


def _key(tmp_path: Path) -> Path:
    path = tmp_path / "k.json"
    save_rsa1024_keypair_bundle(path, generate_rsa1024_e3_keypair())
    return path


@pytest.mark.parametrize("source", (["--key", "KEY"], ["--restore-stock"]))
def test_set_rsa_key_fbl_does_not_touch_dataflash(source: list[str], tmp_path: Path, synth_cflash: bytes,
                                                  synth_dflash: bytes) -> None:
    cf, df = tmp_path / "cf.bin", tmp_path / "df.bin"
    cf.write_bytes(synth_cflash)
    df.write_bytes(synth_dflash)
    key = str(_key(tmp_path))
    source = [key if a == "KEY" else a for a in source]
    rc = main(["-l", "en", "set-rsa-key", *source, "--target", "fbl", "--cflash-in", str(cf), "--cflash-out",
               str(tmp_path / "a.bin"), "--dflash-in", str(df), "--dflash-out", str(tmp_path / "b.bin")])
    assert rc == 1 and not (tmp_path / "b.bin").exists()
    # without DataFlash the FBL key goes in as before
    assert main(["-l", "en", "set-rsa-key", *source, "--target", "fbl", "--cflash-in", str(cf), "--cflash-out",
                 str(tmp_path / "a.bin")]) == 0


# 4. sign-fsc: FeC and timestamp are 32-bit


@pytest.mark.parametrize("bad", (["--fec", "1FFFFFFFF"], ["--fec", "-5"], ["--fec", "0"],
                                 ["--fec", "10000100", "--timestamp", "-1"],
                                 ["--fec", "10000100", "--timestamp", "0x100000000"]))
def test_sign_fsc_rejects_values_it_cannot_sign(bad: list[str], tmp_path: Path) -> None:
    out = tmp_path / "x.fsc"
    rc = main(["-l", "en", "sign-fsc", "-k", str(_key(tmp_path)), *bad, "--vcrn", "1122334455", "--no-vin",
               "-o", str(out)])
    assert rc == 1 and not out.exists()


def test_sign_fsc_still_signs_a_valid_fec(tmp_path: Path) -> None:
    out = tmp_path / "x.fsc"
    assert main(["-l", "en", "sign-fsc", "-k", str(_key(tmp_path)), "--fec", "0x10000100", "--timestamp", "0xFFFFFFFF",
                 "--vcrn", "1122334455", "--no-vin", "-o", str(out)]) == 0
    assert out.read_bytes()[2:6] == bytes.fromhex("10000100")


# 5. options that only work together with another one


@pytest.mark.parametrize("extra", (["--kl15-profiles", "keep", "--mfl-key", "0x20"],
                                   ["--kl15-profiles", "keep", "--mfl-long-press"],
                                   ["--kl15-profiles", "keep", "--console-ring", "1,2"],
                                   ["--kl15-profiles", "keep", "--mfl-ring", "1,2"],
                                   ["--mke-speed-on", "999"], ["--mke-speed-on", "-5"],
                                   ["--mke-speed-off-high", "256"]))
def test_parameterize_refuses_options_it_would_ignore(extra: list[str], tmp_path: Path, synth_dflash: bytes) -> None:
    df, out = tmp_path / "df.bin", tmp_path / "out.bin"
    df.write_bytes(synth_dflash)
    rc = main(["-l", "en", "parameterize", "-i", str(df), "-o", str(out), *extra])
    assert rc != 0 and not out.exists()


def test_parameterize_mke_speed_in_range_still_works(tmp_path: Path, synth_dflash: bytes) -> None:
    df, out = tmp_path / "df.bin", tmp_path / "out.bin"
    df.write_bytes(synth_dflash)
    assert main(["-l", "en", "parameterize", "-i", str(df), "-o", str(out), "--mke-speed-on", "70",
                 "--mke-speed-off-high", "255"]) == 0


@pytest.mark.parametrize("extra", (["--fpa-preset", "fwd"], ["--button-mode", "console"], ["--mfl-key", "0x20"],
                                   ["--kl15-memory"], ["--timestamp", "-1"]))
def test_activate_swap_refuses_options_it_would_ignore_or_cut(extra: list[str], tmp_path: Path,
                                                                              synth_dflash: bytes) -> None:
    df, out = tmp_path / "df.bin", tmp_path / "out.bin"
    df.write_bytes(synth_dflash)
    rc = main(["-l", "en", "activate-swap", "-i", str(df), "-o", str(out), "--fec", "10000100", "--no-vin", *extra])
    assert rc != 0 and not out.exists()


# 6. a windowed build has no console streams


def test_cli_runs_without_console_streams(tmp_path: Path, monkeypatch) -> None:
    for name in ("stdin", "stdout", "stderr"):
        monkeypatch.setattr(sys, name, None)
    assert main(["-l", "en", "banks"]) == 0
    assert main(["-l", "en", "gen-rsa-key", "-o", str(tmp_path / "k.json")]) == 0
    assert (tmp_path / "k.json").is_file()


# 7. two-component release tags


def test_two_component_release_tags_are_versions() -> None:
    assert version_key("v2.1") == version_key("2.1.0") and version_key("v3.0") == version_key("3.0.0")
    assert newer_release({"tag_name": "v2.1"}, "2.0.2b") is not None
    assert newer_release({"tag_name": "v2.0"}, "2.0.2b") is None
    assert version_key("v2.0.2b") < version_key("v2.0.10")
    assert version_key("2.0.1") < version_key("2.0.1a") < version_key("2.0.1e") < version_key("2.0.2") < version_key("2.1")
    assert version_key("2") == () and version_key("2.0.2.1") == ()


# 8. a second read in the same second


def test_a_full_read_named_read_2_counts(tmp_path: Path) -> None:
    unit = tmp_path / UNIT
    read = unit / "dumps" / "2026-11-09_15-20-05_read_2"
    read.mkdir(parents=True)
    for name, size in storage.AREA_SIZES.items():
        (read / name).write_bytes(bytes(size))
    assert storage.has_full_read(unit)
    assert storage.latest_area(unit, "Dflash.bin") == read / "Dflash.bin"
