"""OpenPDU end to end against a stand-in VCI: the byte stream must be the reference driver's."""

from __future__ import annotations

import socket
import struct
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import Future

import can
import pytest
from fake_vci import SYNC, VW, FakeVci, ack, result, retarget, wait_for

from openpdu import ConnectionLost, ProtocolError, Refused, Vci, VciTimeout
from openpdu import comparams as cp
from openpdu import session as openpdu_session
from openpdu.can_bus import OpenPduBus, _parse_channel


@pytest.fixture
def fake_vci() -> Iterator[FakeVci]:
    fake = FakeVci()
    yield fake
    fake.close()


def connect(fake: FakeVci) -> Vci:
    return Vci.connect("127.0.0.1", fake.port, timeout=2.0)


def is_primitive(payload: bytes, cop_type: int) -> bool:
    return payload[0] == 0x02 and payload[20] == cop_type


def in_thread(call: Callable[[], object]) -> Future:
    """`call` run in a daemon thread; the future gets what it returned or raised."""
    future: Future = Future()

    def run() -> None:
        try:
            future.set_result(call())
        except BaseException as exc:
            future.set_exception(exc)

    threading.Thread(target=run, daemon=True).start()
    return future


def test_the_session_opens_with_clock_sync_and_firmware_configuration(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        assert vci.greet.version == (27, 2, 0)
    sync_time, configure = fake_vci.received[:2]
    seconds, micros = struct.unpack_from(">II", sync_time, 4)
    assert sync_time[:4] == bytes.fromhex("06ffff83")
    assert abs(seconds - time.time()) < 5 and micros < 1_000_000
    assert configure == VW["ioctl_configure_firmware"]


def test_monitor_and_raw_links_send_exactly_what_the_reference_driver_sends(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        monitor = vci.monitor()
        raw = vci.raw_link()
        raw.send(0x710, bytes.fromhex("0210030000000000"))
        raw.send(0x1BFCA2ED, bytes(range(8)))
        echoes = [monitor.recv(1.0), monitor.recv(1.0)]
        raw.close()
        monitor.close()
    cancel_monitor = struct.pack(">BHBII", 0x06, 0x017E, 0x81, 0, 0)
    assert fake_vci.received[2:] == [
        *[VW[name] for name in (
            "create_monitor", "connect_monitor", "start_monitor", "create_raw", "connect_raw", "start_raw",
            "send_raw_11bit", "send_raw_29bit", "stop_raw", "disconnect_raw", "destroy_raw",
        )],
        cancel_monitor,
        *[VW[name] for name in ("stop_monitor", "disconnect_monitor", "destroy_monitor")],
    ]
    assert [(e.can_id, e.extended, e.echo) for e in echoes] == [(0x710, False, True), (0x1BFCA2ED, True, True)]
    assert echoes[1].data == bytes(range(8))


def test_an_isotp_link_sends_exactly_what_the_reference_driver_sends(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci, vci.isotp_link(0x710, 0x77A) as uds:
        assert uds.request(bytes.fromhex("3e00")) == bytes.fromhex("7e00")
        assert uds.request(bytes.fromhex("22f187"), expect=bytes.fromhex("62f187")) == bytes.fromhex("62f187")
    assert fake_vci.received[2:] == [
        VW["create_isotp"], VW["connect_isotp"], retarget(VW["start_isotp"], hcop=0),
        retarget(VW["request_3e00"], hcop=1), retarget(VW["request_22f187"], hcop=2),
        retarget(VW["stop_isotp"], hcop=3), VW["disconnect_isotp"], VW["destroy_isotp"],
    ]


def test_a_full_vci_queue_gets_the_same_primitive_again(fake_vci: FakeVci) -> None:
    refused_once: list[bytes] = []

    def queue_full_once(p: bytes) -> list[bytes] | None:
        if is_primitive(p, 4) and not refused_once:
            refused_once.append(p)
            return [ack(0x142, struct.unpack_from(">I", p, 3)[0], 0x1E)]
        return None

    fake_vci.answer = queue_full_once
    with connect(fake_vci) as vci, vci.raw_link() as raw:
        raw.send(0x710, b"\x02\x3e\x00")
    sends = [p for p in fake_vci.received if is_primitive(p, 4)]
    assert len(sends) == 2
    first_hcop = struct.unpack_from(">I", sends[0], 3)[0]
    retry_hcop = struct.unpack_from(">I", sends[1], 3)[0]
    assert retry_hcop != first_hcop
    assert sends[1] == retarget(sends[0], hcop=retry_hcop)


@pytest.mark.parametrize("code,error", [(0x1CE8, Refused), (0x0133, VciTimeout), (0x0134, VciTimeout),
                                        (0x0135, VciTimeout)])
def test_a_failed_primitive_raises_with_the_vcis_code(fake_vci: FakeVci, code: int, error: type) -> None:
    def fail(p: bytes) -> list[bytes] | None:
        if is_primitive(p, 4):
            hcop = struct.unpack_from(">I", p, 3)[0]
            return [ack(1, hcop, 0xC9), ack(1, hcop, code), ack(1, hcop, 0)]
        return None

    fake_vci.answer = fail
    with connect(fake_vci) as vci, vci.isotp_link(0x710, 0x77A) as uds:
        with pytest.raises(error) as caught:
            uds.request(b"\x22\xf1\x87")
    assert caught.value.code == code


def test_a_uds_request_skips_response_pending_and_returns_negative_answers(fake_vci: FakeVci) -> None:
    answers = iter([[b"\x7f\x22\x78", b"\x62\xf1\x87\x01"], [b"\x7f\x2e\x31"]])

    def pending_then_answer(p: bytes) -> list[bytes] | None:
        if is_primitive(p, 4):
            hcop = struct.unpack_from(">I", p, 3)[0]
            return [ack(1, hcop, 0xC9), *(result(1, hcop, d) for d in next(answers)), ack(1, hcop)]
        return None

    fake_vci.answer = pending_then_answer
    with connect(fake_vci) as vci, vci.isotp_link(0x710, 0x77A) as uds:
        assert uds.request(b"\x22\xf1\x87") == b"\x62\xf1\x87\x01"
        assert uds.request(b"\x2e\xf1\x98\x00") == b"\x7f\x2e\x31"


def test_a_refused_connect_still_frees_the_link(fake_vci: FakeVci) -> None:
    fake_vci.answer = lambda p: [ack(0x142, SYNC, 0x50)] if p[0] == 0x12 else None
    with connect(fake_vci) as vci:
        with pytest.raises(Refused) as caught:
            vci.raw_link()
    assert caught.value.code == 0x50
    assert fake_vci.received[-2:] == [VW["disconnect_raw"], VW["destroy_raw"]]


def test_the_vci_ping_is_answered(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        fake_vci.push(bytes.fromhex("0a0102"))
        vci.ioctl(0x05)  # a round trip: the pong went out before its reply came back
        assert wait_for(lambda: bytes.fromhex("0b0102") in fake_vci.received)


def test_a_dropped_session_wakes_a_waiting_receiver(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        monitor = vci.monitor()
        threading.Timer(0.2, fake_vci.drop).start()
        with pytest.raises(ConnectionLost):
            monitor.recv(5.0)
        with pytest.raises(ConnectionLost):
            vci.raw_link()


def test_a_refused_or_foreign_greet_ends_the_connect(fake_vci: FakeVci) -> None:
    fake_vci.greet = b"\x0fanother client holds this VCI"
    with pytest.raises(Refused, match="another client"):
        connect(fake_vci)

    other = FakeVci()
    other.greet = bytes.fromhex("07ffff850000000000000000")
    try:
        with pytest.raises(ProtocolError):
            connect(other)
    finally:
        other.close()


def test_the_python_can_bus_sends_any_id_and_hears_the_bus(fake_vci: FakeVci) -> None:
    bus = OpenPduBus(f"127.0.0.1:{fake_vci.port}")
    try:
        bus.send(can.Message(arbitration_id=0x1BFCA2ED, data=bytes(8), is_extended_id=True))
        fake_vci.bus_frame(0x77A, b"\x02\x7e\x00")
        msg = bus.recv(1.0)  # the echo of our own frame is skipped
        assert (msg.arbitration_id, bytes(msg.data), msg.is_extended_id) == (0x77A, b"\x02\x7e\x00", False)
        assert bus.recv(0.1) is None
        with pytest.raises(can.CanOperationError):
            bus.send(can.Message(arbitration_id=0x710, is_remote_frame=True))
    finally:
        bus.shutdown()


def test_closing_a_link_whose_stop_fails_still_disconnects_and_destroys_it(fake_vci: FakeVci) -> None:
    def refuse_stop(p: bytes) -> list[bytes] | None:
        if is_primitive(p, 2):
            hcop = struct.unpack_from(">I", p, 3)[0]
            return [ack(0x142, hcop, 0x40), ack(0x142, hcop)]
        return None

    with connect(fake_vci) as vci:
        raw = vci.raw_link()
        fake_vci.answer = refuse_stop
        with pytest.raises(Refused):
            raw.close()
        raw.close()  # idempotent
    assert fake_vci.received[-2:] == [VW["disconnect_raw"], VW["destroy_raw"]]


def test_the_session_uses_tcp_keepalive(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        sock = vci._sock
        assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
        if hasattr(socket, "TCP_KEEPINTVL"):
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL) == 5


def test_a_vci_that_never_greets_times_out() -> None:
    with socket.create_server(("127.0.0.1", 0)) as silent, pytest.raises(VciTimeout):
        Vci.connect("127.0.0.1", silent.getsockname()[1], timeout=0.2)


def test_a_malformed_message_is_dropped_and_the_session_goes_on(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        fake_vci.push(ack(1, 2) + b"\0")  # an ack must be 13 bytes
        vci.ioctl(0x05)
        assert vci.alive


def test_a_link_event_is_logged_as_a_warning(fake_vci: FakeVci, caplog: pytest.LogCaptureFixture) -> None:
    with connect(fake_vci) as vci:
        fake_vci.push(ack(0x17E, 0xFFFFFFFE, 0x0131))
        vci.ioctl(0x05)
    assert "link 0x17e: code 0x0131" in caplog.text


def test_an_unanswered_request_ends_the_session(fake_vci: FakeVci) -> None:
    fake_vci.answer = lambda p: [] if p[:4] == bytes.fromhex("06ffff05") else None
    with connect(fake_vci) as vci:
        with pytest.raises(VciTimeout):
            vci.ioctl(0x05, timeout=0.2)
        assert not vci.alive
        with pytest.raises(VciTimeout):  # its late reply can no longer be taken for another request's
            vci.raw_link()


def test_a_reply_for_another_link_ends_the_session(fake_vci: FakeVci) -> None:
    fake_vci.answer = lambda p: [ack(0x99, SYNC)] if p[0] == 0x12 else None
    with connect(fake_vci) as vci:
        with pytest.raises(ProtocolError):
            vci.raw_link()
        assert not vci.alive


def test_a_failing_cleanup_does_not_hide_why_the_link_failed(fake_vci: FakeVci) -> None:
    codes = {0x12: 0x50, 0x13: 0x40}  # CONNECT refused, then DISCONNECT refused too
    fake_vci.answer = lambda p: [ack(0x142, SYNC, codes[p[0]])] if p[0] in codes else None
    with connect(fake_vci) as vci:
        with pytest.raises(Refused) as caught:
            vci.raw_link()
    assert caught.value.code == 0x50


def test_a_primitive_the_host_gives_up_on_is_cancelled_on_the_vci(fake_vci: FakeVci) -> None:
    def never_finish(p: bytes) -> list[bytes] | None:
        return [ack(1, struct.unpack_from(">I", p, 3)[0], 0xC9)] if is_primitive(p, 4) else None

    fake_vci.answer = never_finish
    with connect(fake_vci) as vci, vci.isotp_link(0x710, 0x77A) as uds:
        with pytest.raises(VciTimeout):
            uds.request(b"\x22\xf1\x87", timeout=0.2)
        assert vci.alive
    (request,) = [p for p in fake_vci.received if is_primitive(p, 4)]
    assert struct.pack(">BHBII", 6, 1, 0x81, struct.unpack_from(">I", request, 3)[0], 0) in fake_vci.received


def test_the_uds_host_timeout_outlasts_the_vcis_own_wait(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        with vci.isotp_link(0x710, 0x77A) as uds:
            assert uds.response_timeout == pytest.approx(100 + 5.15 + 2)  # RC78 completion + P2* + margin
        with vci.isotp_link(0x710, 0x77A, app={"RC78CompletionTimeout": 0, "P2Star": 10_000}) as uds:
            assert uds.response_timeout == pytest.approx(1 + 2)


@pytest.mark.parametrize("answer,response", [
    (lambda h: [ack(1, h, 0xC9), ack(1, h)], b""),
    (lambda h: [ack(1, h, 0xC9), ack(1, h, 0x0133), ack(1, h)], b""),
    (lambda h: [ack(1, h, 0xC9), result(1, h, b"\x7f\x3e\x12"), ack(1, h)], b"\x7f\x3e\x12"),
], ids=["no-response", "ecu-silent", "negative"])
def test_a_request_with_suppressed_positive_response(fake_vci: FakeVci, answer: Callable[[int], list[bytes]],
                                                     response: bytes) -> None:
    fake_vci.answer = lambda p: answer(struct.unpack_from(">I", p, 3)[0]) if is_primitive(p, 4) else None
    with connect(fake_vci) as vci, vci.isotp_link(0x710, 0x77A) as uds:
        assert uds.request(b"\x3e\x80", suppress_positive=True) == response
    (request,) = [p for p in fake_vci.received if is_primitive(p, 4)]
    assert request[19] & 0x02  # the CoP's suppress-positive-response flag


def test_an_isotp_link_takes_29_bit_ids_only_with_their_formats(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        with pytest.raises(ValueError, match="needs 29 bits"):
            vci.isotp_link(0x18DA10F1, 0x18DAF110)
        assert not any(p[0] == 0x10 for p in fake_vci.received)  # refused before CREATE
        formats = {"CanPhysReqFormat": 6, "CanRespUSDTFormat": 6}  # placeholders: the real values are not verified
        vci.isotp_link(0x18DA10F1, 0x18DAF110, urid=formats).close()
    (connect_isotp,) = [p for p in fake_vci.received if p[0] == 0x12]
    entry = cp.unpack(cp.ISOTP_URID, connect_isotp[-cp.size(cp.ISOTP_URID):])
    assert (entry["CanPhysReqId"], entry["CanPhysReqFormat"], entry["CanRespUSDTId"],
            entry["CanRespUSDTFormat"]) == (0x18DA10F1, 6, 0x18DAF110, 6)


@pytest.mark.parametrize("code,error", [(0x0131, Refused), (0x0000, ConnectionLost)])
def test_an_ack_on_the_monitor_feed_ends_it(fake_vci: FakeVci, code: int, error: type) -> None:
    with connect(fake_vci) as vci, vci.monitor() as monitor:
        ((link, hcop),) = fake_vci.monitor_feed.items()
        fake_vci.push(ack(link, hcop, code))
        with pytest.raises(error) as caught:
            monitor.recv(1.0)
        with pytest.raises(ConnectionLost, match="not running"):
            monitor.recv(0)
    assert caught.value.code == (code if error is Refused else None)


@pytest.mark.parametrize("end,message", [("link", "monitor link"), ("session", "VCI session closed")])
def test_ending_a_monitor_wakes_a_receiver_waiting_forever(fake_vci: FakeVci, end: str, message: str) -> None:
    with connect(fake_vci) as vci:
        monitor = vci.monitor()
        pending = in_thread(monitor.recv)
        time.sleep(0.1)  # let it block
        (monitor if end == "link" else vci).close()
        error = pending.exception(timeout=2.0)
    assert isinstance(error, ConnectionLost) and message in str(error)


def test_shutting_down_the_bus_wakes_a_receiver_waiting_forever(fake_vci: FakeVci) -> None:
    bus = OpenPduBus(f"127.0.0.1:{fake_vci.port}")
    pending = in_thread(bus.recv)
    time.sleep(0.1)  # let it block
    bus.shutdown()
    assert isinstance(pending.exception(timeout=2.0), can.CanOperationError)


def test_a_non_blocking_bus_send_still_waits_for_its_frame(fake_vci: FakeVci) -> None:
    bus = OpenPduBus(f"127.0.0.1:{fake_vci.port}")
    try:
        bus.send(can.Message(arbitration_id=0x710, data=b"\x02\x3e\x00", is_extended_id=False), timeout=0)
    finally:
        bus.shutdown()
    assert len([p for p in fake_vci.received if is_primitive(p, 4)]) == 1


def test_queue_full_trailing_done_does_not_satisfy_the_retry(fake_vci: FakeVci) -> None:
    rejected: list[int] = []

    def queue_full_with_trailing_done(p: bytes) -> list[bytes] | None:
        if is_primitive(p, 4) and not rejected:
            hcop = struct.unpack_from(">I", p, 3)[0]
            rejected.append(hcop)
            return [ack(1, hcop, 0x1E), ack(1, hcop, 0)]  # trailing DONE for the rejected attempt
        return None

    fake_vci.answer = queue_full_with_trailing_done
    with connect(fake_vci) as vci, vci.isotp_link(0x710, 0x77A) as uds:
        assert uds.request(b"\x22\xf1\x87") == b"\x62\xf1\x87"
    assert len(rejected) == 1
    sends = [p for p in fake_vci.received if is_primitive(p, 4)]
    assert len(sends) == 2
    assert struct.unpack_from(">I", sends[1], 3)[0] != rejected[0]


def test_queue_full_respects_deadline_and_raises_timeout(fake_vci: FakeVci) -> None:
    def always_full(p: bytes) -> list[bytes] | None:
        if is_primitive(p, 4):
            hcop = struct.unpack_from(">I", p, 3)[0]
            return [ack(0x142, hcop, 0x1E)]
        return None

    fake_vci.answer = always_full
    with connect(fake_vci) as vci, vci.raw_link() as raw:
        t0 = time.monotonic()
        with pytest.raises(VciTimeout):
            raw.send(0x710, b"\x02\x3e\x00", timeout=0.05)
        elapsed = time.monotonic() - t0
    assert elapsed < 0.25
    assert len([p for p in fake_vci.received if is_primitive(p, 4)]) == 1


def test_timeout_cancels_before_unsubscribing_and_drains_done(fake_vci: FakeVci) -> None:
    subscribed_at_cancel: list[bool] = []
    vci_ref: list[Vci] = []

    def hang_then_finish_on_cancel(p: bytes) -> list[bytes] | None:
        if is_primitive(p, 4):
            return [ack(1, struct.unpack_from(">I", p, 3)[0], 0xC9)]
        if p[0] == 0x06 and p[3] == 0x81:
            link = struct.unpack_from(">H", p, 1)[0]
            hcop = struct.unpack_from(">I", p, 4)[0]
            subscribed_at_cancel.append((link, hcop) in vci_ref[0]._subscribers)
            return [b"\x07" + p[1:4] + bytes(8), ack(link, hcop, 0)]
        return None

    fake_vci.answer = hang_then_finish_on_cancel
    with connect(fake_vci) as vci:
        vci_ref.append(vci)
        with vci.isotp_link(0x710, 0x77A) as uds:
            t0 = time.monotonic()
            with pytest.raises(VciTimeout):
                uds.request(b"\x22\xf1\x87", timeout=0.1)
            elapsed = time.monotonic() - t0
            assert not vci._subscribers
    assert subscribed_at_cancel == [True]
    # Returned promptly once terminal DONE arrived instead of waiting the full drain window
    assert elapsed < 0.28


def test_monitor_stop_cancels_feed_before_stopcomm(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        monitor = vci.monitor()
        feed_hcop = monitor._feed_hcop
        monitor.stop()
        monitor.close()
    cancel_msg = struct.pack(">BHBII", 0x06, 0x017E, 0x81, feed_hcop, 0)
    stop_idx = next(i for i, p in enumerate(fake_vci.received) if is_primitive(p, 2))
    cancel_idx = fake_vci.received.index(cancel_msg)
    assert cancel_idx < stop_idx


def test_oversized_frame_is_rejected_with_protocol_error(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci:
        # Push only a bogus 4-byte length header exceeding MAX_FRAME_BYTES without sending the payload
        with fake_vci._lock:
            assert fake_vci._client is not None
            fake_vci._client.sendall(struct.pack(">I", openpdu_session.MAX_FRAME_BYTES + 1))
        assert wait_for(lambda: not vci.alive)
        with pytest.raises(ProtocolError, match="too large"):
            vci.ioctl(0x05)


def test_trickling_greet_respects_overall_deadline() -> None:
    """A peer sending 1 byte per 60 ms must still hit the 150 ms overall greet deadline."""
    stop = threading.Event()
    with socket.create_server(("127.0.0.1", 0)) as server:
        port = server.getsockname()[1]

        def trickle() -> None:
            try:
                client, _ = server.accept()
            except OSError:
                return
            with client:
                data = struct.pack(">I", 20) + b"\x0e" + bytes(19)
                for i in range(len(data)):
                    if stop.wait(0.06):
                        break
                    try:
                        client.sendall(data[i:i + 1])
                    except OSError:
                        break

        t = threading.Thread(target=trickle, daemon=True)
        t.start()
        try:
            t0 = time.monotonic()
            with pytest.raises(VciTimeout):
                Vci.connect("127.0.0.1", port, timeout=0.15)
            elapsed = time.monotonic() - t0
            assert elapsed < 0.5
        finally:
            stop.set()
            t.join(timeout=1.0)


def test_stalled_pong_does_not_block_reader_thread(fake_vci: FakeVci) -> None:
    with connect(fake_vci) as vci, vci.monitor() as monitor:
        # Hold _send_lock to simulate a stalled TCP send buffer
        with vci._send_lock:
            fake_vci.push(bytes.fromhex("0a1234"))
            fake_vci.bus_frame(0x77A, b"\x02\x7e\x00")
            # Reader must keep dispatching bus frames even though pong cannot send yet
            rec = monitor.recv(1.0)
            assert rec is not None and rec.can_id == 0x77A and rec.data == b"\x02\x7e\x00"
        # Once send unblocks, the queued pong goes out
        assert wait_for(lambda: bytes.fromhex("0b1234") in fake_vci.received)


def test_openpdu_bus_channel_parsing_and_every_id_raw(fake_vci: FakeVci) -> None:
    assert OpenPduBus.every_id_raw is True
    assert _parse_channel("192.168.0.10") == ("192.168.0.10", 4500)
    assert _parse_channel("192.168.0.10:4501") == ("192.168.0.10", 4501)
    assert _parse_channel("[::1]:4501") == ("::1", 4501)
    assert _parse_channel("[::1]") == ("::1", 4500)
    assert _parse_channel("::1") == ("::1", 4500)
    for bad in ("", "   ", ":4500", "[]:4500", "[]", "[::1", "[::1]extra",
                "127.0.0.1:", "[::1]:", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:abc"):
        with pytest.raises(ValueError):
            _parse_channel(bad)
    with pytest.raises(ValueError):
        OpenPduBus("")

    bus = OpenPduBus(f"127.0.0.1:{fake_vci.port}")
    try:
        assert bus.every_id_raw is True
    finally:
        bus.shutdown()
        bus.shutdown()  # guarded by _is_shutdown


def test_openpdu_bus_cleans_up_if_super_init_fails(fake_vci: FakeVci, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("super init failed")

    monkeypatch.setattr(can.BusABC, "__init__", boom)
    with pytest.raises(RuntimeError, match="super init failed"):
        OpenPduBus(f"127.0.0.1:{fake_vci.port}")
    # Both raw and monitor links were disconnected and destroyed before VCI closed
    assert VW["disconnect_raw"] in fake_vci.received
    assert VW["destroy_raw"] in fake_vci.received
    assert VW["disconnect_monitor"] in fake_vci.received
    assert VW["destroy_monitor"] in fake_vci.received
