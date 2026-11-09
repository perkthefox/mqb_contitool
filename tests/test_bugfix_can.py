"""Regressions in the CAN layer: readback after a boot-block write, cancel bookkeeping, D-PDU link state, restore
owner check, stale UDS answers."""

from __future__ import annotations

import json
import struct
import time

import can
import pytest

from contitool.can import J533CanLink, can_write_cflash, can_write_dflash, can_write_uflash, dpdu, workflows
from contitool.can.dpdu import COPT_STOPCOMM, DPduBus
from contitool.can.workflows import can_restore_backup, read_memory_area
from contitool.core.constants import FBL_MOD_OFFSET, FBL_PRESENCE_MAGIC
from contitool.i18n import set_lang
from contitool.progress import OperationCancelledError, OperationReporter
from test_can_full_write import SimulatedJ533CanBus, SimulatedRh850FaciMcu
from test_dpdu import FakePduApi
from test_restore_backup import _backup, fake_ecu  # noqa: F401 - fake_ecu is a fixture


@pytest.fixture(autouse=True)
def _no_kept_link():
    dpdu.close_session()
    yield
    dpdu.close_session()


def _sim(monkeypatch, cflash: bytes, uflash: bytes, dflash: bytes) -> SimulatedRh850FaciMcu:
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)
    mcu = SimulatedRh850FaciMcu(cflash, uflash, dflash)
    bus = SimulatedJ533CanBus(mcu)
    monkeypatch.setattr(can.interface, "Bus", lambda **_k: bus)
    return mcu


@pytest.mark.parametrize("raw_faci", [False, True])
def test_a_boot_block_write_does_not_fail_on_validity_words_it_never_wrote(
    monkeypatch, synth_cflash, synth_uflash, synth_dflash, tmp_path, raw_faci
) -> None:
    """The FBL had already written its valid-flag at 0xC100; only block 5 changes, so 0xC100 is never written."""
    ecu = bytearray(synth_cflash)
    struct.pack_into("<I", ecu, 0xC100, FBL_PRESENCE_MAGIC)  # 42 24 48 90
    mcu = _sim(monkeypatch, bytes(ecu), synth_uflash, synth_dflash)
    cand = bytearray(ecu)
    cand[FBL_MOD_OFFSET : FBL_MOD_OFFSET + 128] = b"\x99" + b"\x42" * 126 + b"\x01"  # another FBL key: block 5
    path = tmp_path / "cand.bin"
    path.write_bytes(cand)

    rep = can_write_cflash("mock0", path, raw_faci=raw_faci, session_dir=tmp_path / "s")
    assert rep["complete"] is True and rep["changed_blocks"] == [5]
    assert bytes(mcu.cflash[0xA000:0xC000]) == cand[0xA000:0xC000]
    assert bytes(mcu.cflash[0xC100:0xC104]) == bytes.fromhex("42244890")


def _cancel_at_step(index: int) -> OperationReporter:
    rep = OperationReporter()
    rep._on_step = lambda s: rep.cancel() if s.index == index else None
    return rep


def test_a_cancel_held_back_by_the_uflash_write_leaves_the_write_on_record(
    monkeypatch, synth_cflash, synth_uflash, synth_dflash, tmp_path
) -> None:
    mcu = _sim(monkeypatch, synth_cflash, synth_uflash, synth_dflash)
    with pytest.raises(OperationCancelledError):  # step 4 is the FACI write: the cancel waits for it
        can_write_uflash("mock0", session_dir=tmp_path / "s", reporter=_cancel_at_step(4))
    res = json.loads((tmp_path / "s" / "uflash_write_result.json").read_text())
    assert bytes(mcu.uflash) != synth_uflash  # the engineering bootloader is in the ECU…
    assert res["write_performed"] is True and res["packets"]  # …and the record says so


def test_a_cancel_held_back_by_the_dflash_write_leaves_the_write_on_record(
    monkeypatch, synth_cflash, synth_uflash, synth_dflash, tmp_path
) -> None:
    mcu = _sim(monkeypatch, synth_cflash, synth_uflash, synth_dflash)
    target = bytearray(synth_dflash)
    target[0x0200:0x0240] = b"\x5a" * 64
    with pytest.raises(OperationCancelledError):
        can_write_dflash("mock0", bytes(target), session_dir=tmp_path / "s", reporter=_cancel_at_step(4))
    res = json.loads((tmp_path / "s" / "dflash_write_result.json").read_text())
    assert bytes(mcu.dflash[0x0200:0x0240]) == b"\x5a" * 64
    assert res["write_performed"] is True and res["packets"]


def test_a_restore_cancelled_after_the_engineering_bootloader_says_it_stays(
    fake_ecu, synth_cflash, synth_dflash, synth_uflash, tmp_path, monkeypatch  # noqa: F811
) -> None:
    set_lang("en")
    ecu, calls = fake_ecu
    ecu.update(cflash=synth_cflash, dflash=synth_dflash)

    def cancelled(*_a, **_k):
        calls.append("cflash")
        raise OperationCancelledError("cancelled")

    monkeypatch.setattr(workflows, "can_write_cflash", cancelled)
    logs: list[str] = []
    files = _backup(tmp_path, synth_cflash, synth_dflash, synth_uflash)
    with pytest.raises(OperationCancelledError):
        can_restore_backup("fake", files, ["cflash"], session_dir=tmp_path / "run",
                           reporter=OperationReporter(on_log=lambda e: logs.append(e.message)))
    assert calls == ["uflash_eng", "cflash"]
    assert any("engineering bootloader stays" in m for m in logs)
    owner = json.loads((tmp_path / "run" / "owner" / "owner.json").read_text())
    assert owner["uflash_engineering"]["write_performed"] is True


def test_restoring_dataflash_alone_compares_the_vcrn(fake_ecu, synth_cflash, synth_dflash, tmp_path) -> None:  # noqa: F811
    """FAZIT answers over UDS, but a DataFlash backup carries only the VCRN: that one has to be read."""
    ecu, calls = fake_ecu
    ecu.update(cflash=synth_cflash, dflash=synth_dflash)
    df = tmp_path / "Dflash.bin"
    df.write_bytes(synth_dflash)
    res = can_restore_backup("fake", {"dflash": df}, ["dflash"], session_dir=tmp_path / "run")
    assert res["ecu"]["vcrn"] == "1122334455"
    assert calls == ["dflash"]


def test_a_failed_stopcomm_on_the_old_tx_link_does_not_condemn_the_new_one(monkeypatch) -> None:
    monkeypatch.setattr(dpdu, "MAX_RAW_TX_COPS_BEFORE_RECYCLE", 1)
    api = FakePduApi()
    bus = DPduBus(dll=api)
    msg = can.Message(arbitration_id=0x6F0, data=bytes(8), is_extended_id=False)
    bus.send(msg)
    real = api.PDUStartComPrimitive
    api.PDUStartComPrimitive = lambda *a: 0x01 if a[2] == COPT_STOPCOMM else real(*a)  # the VCI refuses STOPCOMM
    before = bus.h_tx
    bus.maybe_recycle_tx()
    api.PDUStartComPrimitive = real
    assert bus.h_tx != before  # a fresh TX link…
    bus.send(msg)  # …that works
    assert not bus.spent
    bus.shutdown()


def test_a_second_frame_error_of_the_broken_stream_does_not_abort_the_retry(monkeypatch, tmp_path) -> None:
    api = FakePduApi()
    bus = DPduBus(dll=api)
    packed = (0x6F1).to_bytes(4, "big") + bytes(5) + (0x6F1).to_bytes(4, "big") + b"\x00\x00"
    real_sleep = time.sleep

    def break_stream() -> None:
        api._result(packed, b"\x00\x00\x00\x00")
        end = time.monotonic() + 2.0
        while bus._rx_error is None and time.monotonic() < end:
            real_sleep(0.001)

    attempts: list[int] = []

    def stream(link, _payload, _addr, size, **_kw):
        attempts.append(1)
        if len(attempts) == 1:
            break_stream()
            link.receive_frame(link.LOADER_RX_ID, timeout=1.0)  # raises the first FrameError
        return bytes(size)

    def sleep(sec: float) -> None:
        if sec == 2.5:  # the read waits out the broken stream, whose rest arrives meanwhile
            break_stream()
        else:
            real_sleep(sec)

    monkeypatch.setattr(workflows, "_stream_loader_read_payload", stream)
    monkeypatch.setattr(time, "sleep", sleep)
    with J533CanLink("", bus=bus) as link:
        res = read_memory_area(link, 0, 0x10000, tmp_path / "cf.bin")
    assert res["complete"] and len(attempts) == 2
    bus.shutdown()


class _LateEcu:
    """Answers each UDS request at once, except the first `10 03`: that answer turns up only after the wait."""

    ANSWERS = {b"\x10\x03": b"\x50\x03\x00\x32\x01\xf4", b"\x22\xf1\x97": b"\x62\xf1\x97GW", b"\x22\x06\x00": b"\x62\x06\x00\x03"}

    def __init__(self) -> None:
        self.rx: list[can.Message] = []
        self.late: list[can.Message] = []
        self.first = True

    def send(self, msg: can.Message, timeout: float | None = None) -> None:
        raw = bytes(msg.data)
        req = raw[1 : 1 + (raw[0] & 0x0F)]
        ans = self.ANSWERS[req]
        (self.late if self.first else self.rx).append(
            can.Message(arbitration_id=0x77A, data=(bytes([len(ans)]) + ans).ljust(8, b"\xaa"), is_extended_id=False))
        self.first = False

    def recv(self, timeout: float | None = None) -> can.Message | None:
        return self.rx.pop(0) if self.rx else None

    def shutdown(self) -> None:
        pass


def test_a_late_uds_answer_is_not_taken_for_the_answer_to_the_next_request() -> None:
    bus = _LateEcu()
    link = J533CanLink("", bus=bus)
    with pytest.raises(TimeoutError):
        link.request_uds(b"\x10\x03", 0x50, timeout=0.05)
    bus.rx += bus.late  # the ECU answers after all, while the tester waits before trying again
    assert link.request_uds(b"\x10\x03", 0x50, timeout=0.5)[:2] == b"\x50\x03"
    assert link.request_uds(b"\x22\xf1\x97", 0x62, timeout=0.5) == b"\x62\xf1\x97GW"
    assert link.request_uds(b"\x22\x06\x00", 0x62, timeout=0.5) == b"\x62\x06\x00\x03"


def test_a_kept_link_that_dies_while_being_claimed_is_closed_not_left_claimed(monkeypatch) -> None:
    api = FakePduApi()
    monkeypatch.setattr(dpdu, "CLOSE_WAIT", 0.5)
    monkeypatch.setattr(dpdu, "DPduBus", lambda channel, bitrate: DPduBus(channel, bitrate, dll=api))
    first = dpdu.open_session("")
    dpdu.release_session(first)
    real_claim = first.claim

    def claim_as_the_receive_thread_dies() -> None:
        real_claim()
        first.spent = True  # what claim() finds when the receive thread died a moment ago

    monkeypatch.setattr(first, "claim", claim_as_the_receive_thread_dies)
    second = dpdu.open_session("")
    assert second is not first
    assert first._is_shutdown and not first.claimed
