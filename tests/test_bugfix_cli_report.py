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
            assert f"sessions/{report.mask_ids(UNIT)}/dumps/base_read/manifest.json" in names  # the rest of the folder still goes in
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


# 9. CLI & formatting code-review fixes


def test_visible_len_annotation_and_parser_flags() -> None:
    import importlib
    from typing import get_type_hints

    from contitool.cli import formatting

    cli_mod = importlib.import_module("contitool.cli.main")

    assert get_type_hints(formatting.visible_len)["return"] is int
    assert not hasattr(cli_mod, "normalize_kombi_dflash_input")

    ap = cli_mod.build_arg_parser()
    # --vin and --no-vin are mutually exclusive on activate-swap and sign-fsc
    with pytest.raises(SystemExit):
        ap.parse_args(["activate-swap", "-i", "a.bin", "-o", "b.bin", "--vin", VIN, "--no-vin"])
    with pytest.raises(SystemExit):
        ap.parse_args(["sign-fsc", "-k", "k.json", "--fec", "10000100", "--vin", VIN, "--no-vin"])

    # --allow-dpdu-driver exists on all ECU subcommands
    for cmd_argv in (
        ["fpke", "read", "--interface", "dpdu", "--via-gateway", "--allow-dpdu-driver"],
        ["kombi", "read", "--interface", "dpdu", "--allow-dpdu-driver"],
        ["bcm", "status", "--interface", "dpdu", "--allow-dpdu-driver"],
        ["mrr", "status", "--interface", "dpdu", "--allow-dpdu-driver"],
        ["elv", "status", "--interface", "dpdu", "--allow-dpdu-driver"],
    ):
        ns = ap.parse_args(cmd_argv)
        assert ns.allow_dpdu_driver is True

    # elv --enter-programming help mentions 11 01, not 11 02
    sub_actions = next(a for a in ap._actions if a.dest == "cmd").choices
    elv_help = sub_actions["elv"].format_help()
    assert "11 01" in elv_help and "11 02" not in elv_help


def test_cli_sign_fsc_vcrn_separators_and_parameterize_rejects_fpa_schema(
    tmp_path: Path, synth_dflash: bytes
) -> None:
    out = tmp_path / "x.fsc"
    assert main(["-l", "en", "sign-fsc", "-k", str(_key(tmp_path)), "--fec", "10000100",
                 "--vcrn", "0x11-22-33-44-55", "--no-vin", "-o", str(out)]) == 0
    assert out.read_bytes()[7:12] == bytes.fromhex("1122334455")

    df = tmp_path / "df.bin"
    df_out = tmp_path / "df_out.bin"
    df.write_bytes(synth_dflash)
    rc = main(["-l", "en", "parameterize", "-i", str(df), "-o", str(df_out), "--fpa-preset", "fwd", "--fpa-schema", "JC00"])
    assert rc == 1 and not df_out.exists()


def test_cli_kombi_and_fpke_read_out_file_use_session_dir_and_copy_primary(
    tmp_path: Path, monkeypatch
) -> None:
    import importlib
    import json

    cli_mod = importlib.import_module("contitool.cli.main")

    sessions_seen: list[Path] = []

    def fake_kombi_read(port, *, session_dir, **kw):
        sessions_seen.append(session_dir)
        session_dir.mkdir(parents=True, exist_ok=True)
        rep_p = session_dir / "kombi_read_report.json"
        df_p = session_dir / "Dflash.bin"
        rep_p.write_text(json.dumps({"ok": "kombi"}), encoding="utf-8")
        df_p.write_bytes(b"KOMBI_DF")
        return {"session_dir": str(session_dir), "report_path": str(rep_p), "dflash": {"output": str(df_p)}}

    def fake_fpke_read(port, *, session_dir, **kw):
        sessions_seen.append(session_dir)
        session_dir.mkdir(parents=True, exist_ok=True)
        rep_p = session_dir / "fpke_read_report.json"
        df_p = session_dir / "Dflash.bin"
        rep_p.write_text(json.dumps({"ok": "fpke"}), encoding="utf-8")
        df_p.write_bytes(b"FPKE_DF")
        return {"session_dir": str(session_dir), "report_path": str(rep_p), "dflash": {"output": str(df_p)}}

    monkeypatch.setattr(cli_mod, "can_kombi_full_read", fake_kombi_read)
    monkeypatch.setattr(cli_mod, "can_fpke_full_read", fake_fpke_read)
    monkeypatch.setattr(cli_mod, "format_kombi_report", lambda **_k: "ok")
    monkeypatch.setattr(cli_mod, "format_fpke_report", lambda **_k: "ok")

    out_dir = tmp_path / "runs"
    work = tmp_path / "work"
    work.mkdir()
    kombi_json = work / "foo.json"
    fpke_bin = work / "bar.bin"

    assert main(["-l", "en", "kombi", "read", "--port", "fake", "--output-dir", str(out_dir), "-o", str(kombi_json)]) == 0
    assert main(["-l", "en", "fpke", "read", "--mode", "report", "--port", "fake", "--output-dir", str(out_dir), "-o", str(fpke_bin)]) == 0
    assert len(sessions_seen) == 2
    assert all(s.parent == out_dir for s in sessions_seen)
    assert sorted(p.name for p in work.iterdir()) == ["bar.bin", "foo.json"]  # work dir NOT polluted!
    assert json.loads(kombi_json.read_text(encoding="utf-8")) == {"ok": "kombi"}
    assert fpke_bin.read_bytes() == b"FPKE_DF"


def test_cli_elv_in_place_guard_and_adapt_cluster_overrides_and_validation(
    tmp_path: Path, monkeypatch
) -> None:
    import importlib

    cli_mod = importlib.import_module("contitool.cli.main")

    same_file = tmp_path / "elv.bin"
    same_file.write_bytes(b"\xff" * 64)
    assert main(["-l", "en", "elv", "virginize-dflash", "--dflash", str(same_file), "-o", str(same_file)]) == 1
    assert main(["-l", "en", "elv", "adapt-dflash", "--dflash", str(same_file), "-o", str(same_file),
                 "--vin", VIN, "--k5", "11" * 16, "--power-class", "6F"]) == 1

    # Cluster dump with missing/invalid VIN overridden by --vin, merged before session dir creation
    cl_file = tmp_path / "cluster.bin"
    cl_file.write_bytes(b"\x00" * 64)
    monkeypatch.setattr(
        cli_mod,
        "elv_extract_cluster_material",
        lambda _df, _cf=None: {"vin": "", "slot_a_hex": "22" * 16, "slot_a_crc_ok": True, "power_class": 0x6F},
    )
    out_dir = tmp_path / "elv_runs"
    # Without --vin override, cluster has empty VIN -> must fail BEFORE creating session dir!
    rc_bad = main(["-l", "en", "elv", "adapt", "--port", "fake", "--yes", "--output-dir", str(out_dir),
                   "--cluster-dflash", str(cl_file)])
    assert rc_bad == 1 and not out_dir.exists()

    captured: list[dict] = []
    monkeypatch.setattr(cli_mod, "can_elv_adapt", lambda port, **kw: captured.append(kw) or {"ok": True})
    rc_ok = main(["-l", "en", "elv", "adapt", "--port", "fake", "--yes", "--output-dir", str(out_dir),
                  "--cluster-dflash", str(cl_file), "--vin", VIN, "--power-class", "76"])
    assert rc_ok == 0 and len(captured) == 1
    assert captured[0]["new_vin"] == VIN
    assert captured[0]["new_k5"] == "22" * 16
    assert captured[0]["new_power_class"] == 0x76


def test_cli_plan_transfer_json_and_cross_family(tmp_path: Path) -> None:
    import json

    passport_a = {
        "schema": "contitool.immo_passport.v1",
        "platform": "kombi_v850e2",
        "dflash_sha256": "aa" * 32,
        "cluster_metadata": {"part_number": "5NA920740B", "odometer_km": 12345},
        "component_protection_separate": {"ika_cp3": "11" * 16},
        "immo": {
            "personalized": True,
            "vin": VIN,
            "vin_state": "present",
            "cs": "33" * 16,
            "k_ffb": "44" * 16,
            "vdo_cs_plus": "",
            "crc32_a_le": "01020304",
            "crc32_b_le": "05060708",
            "power_class": 0x6F,
            "power_class_hex": "0x6F",
            "mac_fields": {"dash": "1122", "ecu": "3344", "tcu": "5566", "elv": "7788"},
            "mac4": "11223344",
            "keys": ["AABBCCDD"],
            "counts": {"learned_keys": 1, "allowed_keys": 2, "session_xor_flags": 0},
            "mode_and_flags": {"partners_mask_hex": "0x07", "adapted_partner_codes": ["ECU"], "immo_mode": 6,
                               "key_over_can": False, "lf_reader_config": 1},
            "s0_s1": {"state": "present"},
            "key_queue_0x6a": {"usable_key_data": True},
        },
    }
    passport_b = {**passport_a, "platform": "fpke_rh850", "dflash_sha256": "bb" * 32,
                  "cluster_metadata": {"part_number": "5E0920790A", "odometer_km": 99999}}
    pa = tmp_path / "donor.json"
    pb = tmp_path / "recip.json"
    pa.write_text(json.dumps(passport_a), encoding="utf-8")
    pb.write_text(json.dumps(passport_b), encoding="utf-8")

    out_k = tmp_path / "plan_kombi.json"
    out_f = tmp_path / "plan_fpke.json"
    assert main(["-l", "en", "kombi", "plan-transfer", "--dflash", str(pa), "--dflash-b", str(pb), "-o", str(out_k)]) == 0
    assert json.loads(out_k.read_text(encoding="utf-8"))["transfer_from_a"]["vin"] == VIN
    assert main(["-l", "en", "fpke", "plan-transfer", "--dflash", str(pa), "--dflash-b", str(pb), "-o", str(out_f)]) == 0
    plan_f = json.loads(out_f.read_text(encoding="utf-8"))
    assert plan_f["transfer_from_a"]["vin"] == VIN and plan_f["donor_a"]["platform"] == "kombi_v850e2"


def test_cli_mrr_bootloader_inspect_force_and_lazy_sessions_and_bcm_adapt_ffb(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    import importlib
    import json

    from contitool.can import dpdu
    from contitool.core.mrr import mrr_compute_ecu_boot_sum

    cli_mod = importlib.import_module("contitool.cli.main")

    # 1. mrr inspect --cflash Bootloader.bin without --dflash prints bootloader_size + ecu_boot_sum_hex
    boot = tmp_path / "Bootloader.bin"
    boot_bytes = bytes((i & 0xFF) for i in range(0x10000))
    boot.write_bytes(boot_bytes)
    assert main(["-l", "en", "mrr", "inspect", "--cflash", str(boot)]) == 0
    rep_boot = json.loads(capsys.readouterr().out)
    assert rep_boot["bootloader_size"] == 0x10000
    assert rep_boot["ecu_boot_sum_hex"] == mrr_compute_ecu_boot_sum(boot_bytes).hex()

    # 2. mrr write-keys & reset-cp-counter forward force=True + honor --allow-dpdu-driver
    monkeypatch.setattr(dpdu, "accepted_drivers", set())
    monkeypatch.setattr(dpdu, "discover_dpdu", lambda: [{"name": "VW", "version": "30.3.0"}])
    wk_calls: list[dict] = []
    rc_calls: list[dict] = []
    monkeypatch.setattr(cli_mod, "can_mrr_write_keys", lambda port, **kw: wk_calls.append(kw) or {"ok": True})
    monkeypatch.setattr(cli_mod, "can_mrr_reset_cp_counter", lambda port, **kw: rc_calls.append(kw) or {"ok": True})
    assert main(["-l", "en", "mrr", "write-keys", "--interface", "dpdu", "--allow-dpdu-driver", "--yes", "--force"]) == 0
    assert main(["-l", "en", "mrr", "reset-cp-counter", "--interface", "dpdu", "--yes", "--force"]) == 0
    assert wk_calls[0]["force"] is True and rc_calls[0]["force"] is True
    assert "30.3.0" in dpdu.accepted_drivers

    # 3. Lazy session directories: invalid mrr swap-on --swap-groups and invalid can read-mem leave NO folder
    mrr_out = tmp_path / "mrr_runs"
    can_out = tmp_path / "can_runs"
    assert main(["-l", "en", "mrr", "swap-on", "--port", "fake", "--yes", "--output-dir", str(mrr_out),
                 "--swap-groups", "1,2"]) == 1
    assert not mrr_out.exists()
    assert main(["-l", "en", "can", "read-mem", "--port", "fake", "--output-dir", str(can_out)]) == 1
    assert not can_out.exists()
    monkeypatch.setattr(cli_mod, "can_learn_mfl_button", lambda port, **kw: {"captured": False})
    assert main(["-l", "en", "can", "learn-mfl", "--port", "fake", "--output-dir", str(can_out)]) == 0
    assert not can_out.exists()

    # 4. bcm adapt-ffb: validates manual inputs before touching CAN, parses leading-zero counter "0012", handles --freq
    bcm_calls: list[dict] = []
    monkeypatch.setattr(cli_mod, "can_bcm_adapt_ffb", lambda port, **kw: bcm_calls.append(kw) or {"ok": True})
    assert main(["-l", "en", "bcm", "adapt-ffb", "--port", "fake", "--yes"]) == 1
    assert bcm_calls == []
    assert main(["-l", "en", "bcm", "adapt-ffb", "--port", "fake", "--yes", "--kc", "11" * 16]) == 1
    assert bcm_calls == []
    assert main(["-l", "en", "bcm", "adapt-ffb", "--port", "fake", "--yes",
                 "--kc", "11" * 16, "--key", "AABBCCDD:0012", "--key", "11223344:0x20"]) == 0
    assert len(bcm_calls) == 1
    assert bcm_calls[0]["keys"][0]["rolling_counter"] == 12
    assert bcm_calls[0]["keys"][1]["rolling_counter"] == 0x20

    # Cluster adapt-ffb with --freq warns cleanly when helper doesn't take freq_code
    cl_calls: list[dict] = []
    monkeypatch.setattr(cli_mod, "can_bcm_adapt_ffb_from_cluster", lambda port, **kw: cl_calls.append(kw) or {"ok": True})
    capsys.readouterr()
    assert main(["-l", "en", "bcm", "adapt-ffb", "--port", "fake", "--yes", "--from-live-cluster", "--freq", "2"]) == 0
    err_txt = capsys.readouterr().err
    assert "--freq" in err_txt and len(cl_calls) == 1
