""""Write to ECU": the engineering bootloader is installed only when the application itself is reprogrammed."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer  # noqa: E402

from contitool.core.constants import APP_BASE, FBL_MOD_OFFSET  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402


@pytest.mark.parametrize(("offset", "engineering"), [(FBL_MOD_OFFSET, False), (APP_BASE + 0x100, True)])
def test_engineering_bootloader_only_for_application_changes(
    offset: int, engineering: bool, synth_cflash, synth_dflash, synth_uflash, tmp_path: Path, monkeypatch
) -> None:
    from PySide6.QtWidgets import QMessageBox

    from contitool.gui.app import create_window
    from contitool.gui.screens import ecu

    set_lang("en")
    app, win = create_window()
    folder = tmp_path / "dumps"
    folder.mkdir()
    for name, raw in (("Cflash.bin", synth_cflash), ("Dflash.bin", synth_dflash), ("Uflash.bin", synth_uflash)):
        (folder / name).write_bytes(raw)
    win.open_folder(str(folder))
    edited = bytearray(synth_cflash)
    edited[offset] ^= 0xFF  # a boot-block byte (own FBL key) or an application byte
    (tmp_path / "Cflash_edit.bin").write_bytes(edited)
    win.ws.commit("cflash", tmp_path / "Cflash_edit.bin")
    app.processEvents()

    calls: list[str] = []
    win.conn.out_dir = tmp_path / "runs"
    monkeypatch.setattr(ecu, "ensure_ready", lambda *_a: True)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(ecu, "can_write_uflash", lambda *a, **k: calls.append("uflash_eng") or {})
    monkeypatch.setattr(ecu, "can_write_cflash", lambda *a, **k: calls.append("cflash") or {})
    win.ecu_screen._write_to_ecu()
    loop = QEventLoop()
    win.runner.operation_finished.connect(lambda *_: loop.quit())
    QTimer.singleShot(8000, loop.quit)
    loop.exec()
    assert calls == (["uflash_eng", "cflash"] if engineering else ["cflash"])
    win.close()


@pytest.mark.parametrize(
    ("at", "value", "ok"),
    [
        (0xC100, bytes.fromhex("42244890"), True),  # the FBL marks the app valid in its second word: FBL @ 0x1C32 rule
        (0xC100, bytes.fromhex("00000000"), False),  # ... or invalid: a real failure
        (0xC010, b"\x5a", False),  # anything else in the FBL block is not ours to ignore
        (APP_BASE + 0x200, b"\x5a", False),
        (0xA000, b"\x5a", False),
    ],
)
def test_codeflash_readback_follows_the_fbl_validity_rule(
    at: int, value: bytes, ok: bool, synth_cflash: bytes, tmp_path: Path, monkeypatch
) -> None:
    """After UDS programming only the FBL's validity words may differ, and only if the FBL then calls the app valid."""
    import contextlib

    from contitool.can import workflows
    from contitool.core.constants import CFLASH_ADDR_START

    ecu_img = bytearray(synth_cflash)
    candidate = bytearray(synth_cflash)
    candidate[APP_BASE + 0x100] ^= 0xFF

    def read_area(_link, start, end, path, reference=None, **_kw):
        data = bytes(ecu_img[start:end]) if start == CFLASH_ADDR_START else b"\xff" * (end - start)
        path.write_bytes(data)
        return {"reference_match": reference is None or data == reference, "first_mismatch_address": None}

    def program_app(_link, app, **_kw):
        ecu_img[APP_BASE:] = app
        ecu_img[at : at + len(value)] = value  # what the bootloader (or a fault) changed on its own

    monkeypatch.setattr(workflows, "J533CanLink", lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(workflows, "enter_ram_loader", lambda *a, **k: {})
    monkeypatch.setattr(workflows, "run_rsa_probe", lambda *a, **k: {"rsa_status": 0})
    monkeypatch.setattr(workflows, "_reset_to_application", lambda *a, **k: {})
    monkeypatch.setattr(workflows, "_program_application_uds", program_app)
    monkeypatch.setattr(workflows, "read_memory_area", read_area)
    run = lambda: workflows.can_write_cflash(  # noqa: E731
        "fake", bytes(candidate), ignore_input_crc=True, session_dir=tmp_path / "cf", return_to_app=False
    )
    if ok:
        assert "fbl_validity_words" in run()
    else:
        with pytest.raises(RuntimeError, match="readback mismatch"):
            run()


def test_fbl_validity_words_do_not_force_an_application_reflash(synth_cflash: bytes) -> None:
    """A boot-block-only edit on an ECU whose FBL used its second validity word must not count block 6 as changed."""
    from contitool.can.workflows import _cflash_block_differs

    ecu = bytearray(synth_cflash)
    ecu[0xC100:0xC104] = bytes.fromhex("42244890")  # valid through the second word
    expected = bytes(synth_cflash)  # what can_write_cflash builds: magic @ 0xC000, FF @ 0xC100
    assert not _cflash_block_differs(bytes(ecu), expected, 0xC000, 0xE000)
    ecu[0xC100:0xC104] = b"\x00" * 4  # application invalidated by the FBL: it must be programmed again
    assert _cflash_block_differs(bytes(ecu), expected, 0xC000, 0xE000)


def test_a_driver_error_is_retried_like_a_timeout(tmp_path: Path, monkeypatch) -> None:
    """D-PDU / J2534 raise can.CanOperationError (not a RuntimeError); one hiccup must not abort a 1.5 MB read."""
    import can

    from contitool.can import workflows

    calls: list[int] = []

    def flaky(_link, _payload, addr, size):
        calls.append(addr)
        if len(calls) == 1:
            raise can.CanOperationError("The VCI could not send a frame")
        return b"\xab" * size

    link = type("L", (), {"drain_rx": lambda self, max_frames=0: 0})()
    monkeypatch.setattr(workflows, "_stream_loader_read_payload", flaky)
    monkeypatch.setattr(workflows.time, "sleep", lambda _s: None)
    res = workflows.read_memory_area(link, 0x10000, 0x20000, tmp_path / "r.bin")
    assert len(calls) == 2 and (tmp_path / "r.bin").read_bytes() == b"\xab" * 0x10000 and res is not None


def test_reads_are_cut_at_dataflash_limits_and_into_4kb_requests(monkeypatch) -> None:
    from contitool.can import workflows

    calls: list[tuple[str, int, int]] = []
    monkeypatch.setattr(workflows, "build_reader_payload", lambda a, n: ("stock", a, n))
    monkeypatch.setattr(workflows, "build_dflash_reader_payload", lambda a, n, **k: ("blank", a, n))
    monkeypatch.setattr(workflows, "_stream_loader_read_payload", lambda _l, p, a, n, **k: calls.append(p) or b"\x11" * n)

    assert workflows.read_memory_bytes(None, 0xFF1FF800, 0x1000) == b"\x11" * 0x1000  # used to raise "straddles"
    assert calls == [("stock", 0xFF1FF800, 0x800), ("blank", 0xFF200000, 0x800)]
    calls.clear()
    workflows.read_memory_bytes(None, 0x0, 0x4000)  # one 16 KB stream resets the ECU (0.273 s watchdog)
    assert calls == [("stock", off, 0x1000) for off in range(0, 0x4000, 0x1000)]


def test_zdc_transfer_blocks_follow_the_ecus_limit() -> None:
    from contitool.can.workflows import ZDC_UPLOAD_CHUNK_SIZE, _transfer_chunk

    assert _transfer_chunk(bytes.fromhex("742000fc"), ZDC_UPLOAD_CHUNK_SIZE) == 0xF0  # the simulator's answer
    assert _transfer_chunk(bytes.fromhex("74200082"), ZDC_UPLOAD_CHUNK_SIZE) == 0x80  # a variant that caps at 130 B
    with pytest.raises(RuntimeError, match="Malformed"):
        _transfer_chunk(b"\x74", ZDC_UPLOAD_CHUNK_SIZE)


def test_faci_block_packets_respect_the_page_cap() -> None:
    from contitool.can.payloads import build_cflash_faci_block_payloads

    block = bytes(range(256)) * 40 + b"\xff" * (0x8000 - 40 * 256)  # 40 used pages in a 32 KB block
    pkts = build_cflash_faci_block_payloads(0x10000, block, max_pages_per_packet=32)
    assert [len(p) for p in pkts] == sorted([len(p) for p in pkts], reverse=True) and len(pkts) == 2  # 32 + 8 pages
