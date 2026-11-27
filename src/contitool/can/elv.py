"""VAG MQB 2B ELV / ESCL / J764 (Marquardt 3Q0 905 861) live CAN transport and UDS/WFS5 workflows.

Supports both direct Komfort CAN (`500 kbit/s`) and operation behind a `19 J533` gateway
(11-bit UDS `0x731 -> 0x79B` or 29-bit fallback `0x17FC0231 -> 0x17FE0231`, plus transparent
J533 Komfort CAN `ch0` bridge for 29-bit `0x1BFD8A0B -> 0x1BFD8A0A` Data Flash backup).
"""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import struct
import time
from typing import Any

import can

from contitool.can.transport import (
    FRAME_SEND_TIMEOUT,
    TRANSPORT_ERRORS,
    J533CanLink,
    UdsNegativeResponse,
    UnexpectedUdsResponse,
)
from contitool.core.dtc import describe_elv, group as dtc_group, status_text as dtc_status_text
from contitool.core.elv import (
    ELV_CMD_RESET_IDAC,
    ELV_DEV_MEM_RX_ID,
    ELV_DEV_MEM_TX_ID,
    ELV_DFLASH_BASE_ADDR,
    ELV_DFLASH_COMPACT_SIZE,
    ELV_GATEWAY_71_CAN_ID,
    ELV_GATEWAY_71_ENGINE_STOPPED,
    ELV_KL_STATUS_CAN_ID,
    ELV_NM_WAKE_ID,
    ELV_NM_WAKE_PAYLOAD,
    ELV_UDS_EXT_RX_ID,
    ELV_UDS_EXT_TX_ID,
    ELV_UDS_RX_ID,
    ELV_UDS_TX_ID,
    ELV_WFS_ELV_CAN_ID,
    ELV_WFS_KOMBI_CAN_ID,
    _norm_vin17,
    _validate_u8,
    elv_bootloader_seed_to_key,
    elv_build_02e1_payload,
    elv_build_02e2_adapt_payload,
    elv_build_02e2_virgin_payload,
    elv_build_3c0_frame,
    elv_build_dev_mem_read_frame,
    elv_build_wfs5_01b_response,
    elv_decode_status_dids,
    elv_detect_profile,
    elv_extract_cluster_material,
    elv_parse_dflash,
    elv_verify_02f9,
    elv_verify_wfs5_01a_reply,
)
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter

# Exact RX IDs from 2B ELV on Komfort CAN (ch0) for J533 gateway bridge GAFL filter
ELV_BRIDGE_RX_FILTER: tuple[tuple[int, bool], ...] = (
    (ELV_UDS_RX_ID, False),
    (ELV_UDS_EXT_RX_ID, True),
    (ELV_DEV_MEM_RX_ID, True),
    (ELV_WFS_ELV_CAN_ID, False),
)

ELV_PASSPORT_DIDS: tuple[tuple[str, int], ...] = (
    ("part_number", 0xF187),
    ("sw_version", 0xF189),
    ("hw_part_number", 0xF191),
    ("hw_version", 0xF1A3),
    ("fazit", 0xF17C),
    ("serial", 0xF18C),
    ("system_name", 0xF197),
    ("asam_odx", 0xF19E),
    ("asam_version", 0xF1A2),
    ("vin", 0xF190),
    ("coding", 0x0600),
    ("f1df", 0xF1DF),
)

ELV_STATUS_DIDS: tuple[int, ...] = (
    0x1105,  # WFS5 Mode (0x01 Virgin, 0x02 Adapted, 0xFF Plant)
    0x02ED,  # WFS5 mode/brand/version/PowerClass (10 B)
    0x02EE,  # WFS5 config/IDac locked flags (10 B)
    0x02EF,  # WFS5 lockout timers for 02E2/02E1 (6 B)
    0x02E0,  # Diagnostic random challenge C_diag (4 B)
    0x02F9,  # Diagnostic status + verification MAC (5 B)
    0x2C8B,  # Lock cycle counter (2 B)
    0x1109,  # Bolt unlock/lock travel times in 5 ms ticks (4 B)
)


def _clean_ascii(raw: bytes) -> str:
    return "".join(chr(b) for b in raw if 0x20 <= b < 0x7F).strip()


def _norm_key_16b(val: bytes | str, label: str) -> bytes:
    if isinstance(val, (bytes, bytearray, memoryview)):
        raw = bytes(val)
    else:
        cleaned = "".join(str(val).split()).replace("0x", "").replace("0X", "")
        try:
            raw = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"{label} must be 32 hex digits (16 bytes), got {val!r}") from exc
    if len(raw) != 16:
        raise ValueError(f"{label} must be 16 bytes (32 hex digits), got {len(raw)} bytes")
    return raw


def _is_in_memory_bus(link: J533CanLink) -> bool:
    return hasattr(link.bus, "rx_queue") and not hasattr(link.bus, "serialPortOrig")


class ElvCanLink(J533CanLink):
    """CAN link for 2B ELV / J764: 11-bit UDS `0x731/0x79B` (29-bit fallback `0x17FC0231/0x17FE0231`) and 29-bit memory read."""

    UDS_TX_ID = ELV_UDS_TX_ID
    UDS_RX_ID = ELV_UDS_RX_ID
    UDS_FC_PAD = 0x55

    def __init__(
        self,
        port: str,
        *,
        interface: str = "slcan",
        bitrate: int = 500_000,
        tty_baudrate: int = 115_200,
        listen_only: bool = False,
        log_path: Path | None = None,
        bus: Any | None = None,
        via_gateway: bool = False,
        use_extended_uds: bool = False,
    ) -> None:
        super().__init__(
            port,
            interface=interface,
            bitrate=bitrate,
            tty_baudrate=tty_baudrate,
            listen_only=listen_only,
            log_path=log_path,
            bus=bus,
        )
        self.via_gateway = bool(via_gateway)
        if use_extended_uds:
            self.UDS_TX_ID = ELV_UDS_EXT_TX_ID
            self.UDS_RX_ID = ELV_UDS_EXT_RX_ID
        else:
            self.UDS_TX_ID = ELV_UDS_TX_ID
            self.UDS_RX_ID = ELV_UDS_RX_ID

    def _should_use_hw_uds(self) -> bool:
        """Return True when the underlying bus requires hardware ISO-TP (`uds_only` / `nonraw` D-PDU)."""
        if self._hw_uds:
            return False
        bus_ctx = getattr(self.bus, "uds_session", None)
        if not callable(bus_ctx):
            return False
        return bool(getattr(self.bus, "uds_only", False)) or bool(getattr(self.bus, "nonraw", None))

    def request_uds(
        self,
        uds_payload: bytes,
        expected_sid: int | None = None,
        *,
        timeout: float = 2.0,
        allow_pending: bool = True,
        resend: bool = True,
    ) -> bytes:
        """Send UDS request on `0x731/0x79B`, routing via `uds_session` on `uds_only`/`nonraw` D-PDU buses."""
        if self._should_use_hw_uds():
            with self.uds_session() as active:
                if not active and getattr(self.bus, "uds_only", False):
                    refusal = str(getattr(self.bus, "uds_refusal", "") or "").strip()
                    detail = f" ({refusal})" if refusal else ""
                    raise TimeoutError(
                        tr(
                            f"Адаптер D-PDU не смог открыть аппаратный канал UDS ISO-TP для 2B ELV "
                            f"(0x{self.UDS_TX_ID:03X} → 0x{self.UDS_RX_ID:03X}){detail}.",
                            f"D-PDU adapter could not open a hardware UDS ISO-TP link for 2B ELV "
                            f"(0x{self.UDS_TX_ID:03X} → 0x{self.UDS_RX_ID:03X}){detail}.",
                        )
                    )
                return super().request_uds(
                    uds_payload,
                    expected_sid,
                    timeout=timeout,
                    allow_pending=allow_pending,
                    resend=resend,
                )
        return super().request_uds(
            uds_payload,
            expected_sid,
            timeout=timeout,
            allow_pending=allow_pending,
            resend=resend,
        )

    def send_frame(self, identifier: int, data: bytes | bytearray, pad: int | None = None) -> None:
        raw = bytes(data)
        if pad is not None and len(raw) < 8:
            raw += bytes([pad & 0xFF]) * (8 - len(raw))
        msg = can.Message(arbitration_id=identifier, data=raw, is_extended_id=bool(identifier > 0x7FF))
        self._write_trace("tx", identifier, msg.dlc, raw)
        self.bus.send(msg, timeout=FRAME_SEND_TIMEOUT)
        self.tx_frames += 1

    def send_raw_frame(self, identifier: int, data: bytes | bytearray, *, pad: int | None = None) -> None:
        self.send_frame(identifier, data, pad=pad)

    def send_elv_wake_burst(self, count: int = 3) -> None:
        """Broadcast Komfort CAN OSEK-NM wakeup (`0x1B000010`) so a sleeping bench ELV wakes up."""
        in_mem = _is_in_memory_bus(self)
        for _ in range(max(1, count)):
            with contextlib.suppress(*TRANSPORT_ERRORS):
                self.send_raw_frame(ELV_NM_WAKE_ID, ELV_NM_WAKE_PAYLOAD)
            if not in_mem:
                time.sleep(0.02)
        if not in_mem:
            time.sleep(0.06)

    def send_engine_stopped_burst(self, count: int = 4) -> None:
        """Send `0x3DC Gateway_71` (`01 00 00 00 00 00`) engine-stopped frames required before `2E 02E2`."""
        for _ in range(max(1, count)):
            with contextlib.suppress(*TRANSPORT_ERRORS):
                self.send_raw_frame(ELV_GATEWAY_71_CAN_ID, ELV_GATEWAY_71_ENGINE_STOPPED)
            if not _is_in_memory_bus(self):
                time.sleep(0.025)

    def send_kl_status(
        self,
        bz: int,
        *,
        kl_s: bool = False,
        kl_15: bool = False,
        kl_50: bool = False,
    ) -> None:
        """Send one E2E-valid `0x3C0 Klemmen_Status_01` frame."""
        frame = elv_build_3c0_frame(bz=bz, kl_s=kl_s, kl_15=kl_15, kl_50=kl_50)
        self.send_raw_frame(ELV_KL_STATUS_CAN_ID, frame)

    def probe_uds_channel(self, *, timeout: float = 0.8) -> tuple[bool, bool]:
        """Try 11-bit UDS (`0x731/0x79B`), falling back to 29-bit UDS (`0x17FC0231/0x17FE0231`).

        Returns `(responding, in_bootloader)`.
        """
        orig_tx, orig_rx = self.UDS_TX_ID, self.UDS_RX_ID
        if self._hw_uds:
            candidates: tuple[tuple[int, int], ...] = ((orig_tx, orig_rx),)
        else:
            candidates = (
                (ELV_UDS_TX_ID, ELV_UDS_RX_ID),
                (ELV_UDS_EXT_TX_ID, ELV_UDS_EXT_RX_ID),
            )
        for tx_id, rx_id in candidates:
            self.UDS_TX_ID = tx_id
            self.UDS_RX_ID = rx_id
            try:
                self.request_uds(b"\x10\x03", 0x50, timeout=timeout)
                return True, False
            except UdsNegativeResponse as exc:
                if exc.nrc in (0x12, 0x7E, 0x7F):
                    # Bootloader refuses 10 03 or stays in default/programming session
                    with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                        self.request_uds(b"\x10\x01", 0x50, timeout=min(0.5, timeout))
                    return True, True
                with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    self.request_uds(b"\x10\x01", 0x50, timeout=min(0.5, timeout))
                return True, False
            except (*TRANSPORT_ERRORS, UnexpectedUdsResponse):
                continue
        self.UDS_TX_ID = orig_tx if self._hw_uds else ELV_UDS_TX_ID
        self.UDS_RX_ID = orig_rx if self._hw_uds else ELV_UDS_RX_ID
        return False, False

    def dev_read_memory(
        self,
        addr: int,
        length: int = 8,
        *,
        timeout: float = 0.35,
        retries: int = 4,
    ) -> bytes:
        """Read 1..8 bytes via `0x1BFD8A0B -> 0x1BFD8A0A` (`FUN_ram_00025a62`)."""
        req = elv_build_dev_mem_read_frame(addr, length)
        last_exc: Exception | None = None
        for attempt in range(max(1, retries)):
            try:
                if attempt > 0:
                    self.drain_rx(quick=True)
                self.send_raw_frame(ELV_DEV_MEM_TX_ID, req)
                msg = self.receive_frame(ELV_DEV_MEM_RX_ID, timeout=timeout)
                data = bytes(msg.data)
                if len(data) < length:
                    raise TimeoutError(
                        tr(
                            f"Короткий ответ чтения памяти ELV по адресу 0x{addr:08X}: получено {len(data)} из {length} Б",
                            f"Short ELV memory read reply at 0x{addr:08X}: got {len(data)} of {length} bytes",
                        )
                    )
                return data[:length]
            except (*TRANSPORT_ERRORS, TimeoutError) as exc:
                last_exc = exc
                if not _is_in_memory_bus(self):
                    time.sleep(0.01)
        raise TimeoutError(
            tr(
                f"Нет ответа от ELV на чтение памяти 0x{addr:08X} (0x1BFD8A0B → 0x1BFD8A0A): {last_exc}",
                f"No reply from ELV for memory read at 0x{addr:08X} (0x1BFD8A0B → 0x1BFD8A0A): {last_exc}",
            )
        )

    def read_dflash_32k(
        self,
        *,
        reporter: OperationReporter = NULL_REPORTER,
        timeout: float = 0.4,
    ) -> bytes:
        """Read the full 32 KiB Data Flash (`0xFCFF8000..0xFCFFFFFF`) in 4096 x 8-byte frames."""
        out = bytearray(ELV_DFLASH_COMPACT_SIZE)
        total_chunks = ELV_DFLASH_COMPACT_SIZE // 8
        self.drain_rx(quick=True)
        in_mem = _is_in_memory_bus(self)
        for idx in range(total_chunks):
            if idx % 32 == 0:
                reporter.check_cancelled()
            if not in_mem and idx > 0 and (idx % 512) == 0:
                with contextlib.suppress(*TRANSPORT_ERRORS):
                    self.send_raw_frame(ELV_NM_WAKE_ID, ELV_NM_WAKE_PAYLOAD)
            off = idx * 8
            addr = ELV_DFLASH_BASE_ADDR + off
            chunk = self.dev_read_memory(addr, 8, timeout=timeout)
            out[off : off + 8] = chunk
            if (idx + 1) % 256 == 0 or (idx + 1) == total_chunks:
                reporter.progress(
                    (idx + 1) * 8,
                    ELV_DFLASH_COMPACT_SIZE,
                    unit="B",
                    detail=tr("Чтение Data Flash ELV", "Reading ELV Data Flash"),
                )
        if not in_mem:
            with contextlib.suppress(*TRANSPORT_ERRORS):
                self.send_raw_frame(ELV_NM_WAKE_ID, ELV_NM_WAKE_PAYLOAD)
        return bytes(out)


def _warn_dpdu_29bit_elv(reporter: OperationReporter) -> None:
    reporter.warning(
        tr(
            "29-битный режим D-PDU RawMode для чтения Data Flash / WFS5 блока 2B ELV не проверен на реальном "
            "оборудовании; рекомендуется нативный CAN-адаптер (CANable / gs_usb / PCAN / SocketCAN).",
            "29-bit D-PDU RawMode for 2B ELV Data Flash / WFS5 operations is unverified on hardware; "
            "a native CAN adapter (CANable / gs_usb / PCAN / SocketCAN) is recommended.",
        )
    )


@contextlib.contextmanager
def _managed_elv_session(
    port: str,
    *,
    interface: str = "slcan",
    log_path: Path | None = None,
    bus: Any | None = None,
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    needs_raw_komfort: bool = False,
    bridge_error_msg: str | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> Iterator[tuple[ElvCanLink, bool]]:
    """Open an `ElvCanLink` over direct Komfort CAN or behind J533 gateway (with optional ch0 bridge for 29-bit frames)."""
    if not via_gateway or not needs_raw_komfort:
        if needs_raw_komfort and interface == "dpdu":
            _warn_dpdu_29bit_elv(reporter)
        with ElvCanLink(
            port,
            interface=interface,
            log_path=log_path,
            bus=bus,
            via_gateway=via_gateway,
        ) as link:
            if needs_raw_komfort and (
                bool(getattr(link.bus, "uds_only", False)) or bool(getattr(link.bus, "nonraw", None))
            ):
                raise RuntimeError(
                    tr(
                        "Для прямого подключения к 2B ELV на столе (кадр 0x3DC Gateway_71 / 29-битное чтение Data Flash / "
                        "WFS5 0x01A/0x01B) требуется адаптер с raw CAN — текущий адаптер D-PDU работает только в режиме "
                        "UDS ISO-TP / фиксированных ID.",
                        "Direct bench operations on 2B ELV (raw 0x3DC Gateway_71 / 29-bit Data Flash read / "
                        "WFS5 0x01A/0x01B) require a raw-CAN adapter — the current D-PDU adapter only supports "
                        "UDS ISO-TP / fixed-ID mode.",
                    )
                )
            if not needs_raw_komfort and link._should_use_hw_uds():
                with link.uds_session() as active:
                    if not active:
                        refusal = str(getattr(link.bus, "uds_refusal", "") or "").strip()
                        detail = f" ({refusal})" if refusal else ""
                        raise RuntimeError(
                            tr(
                                f"Адаптер D-PDU не смог открыть аппаратный канал UDS ISO-TP для 2B ELV "
                                f"(0x{link.UDS_TX_ID:03X} → 0x{link.UDS_RX_ID:03X}){detail}. "
                                "Проверьте питание ELV и шлюза или используйте адаптер с raw CAN.",
                                f"D-PDU adapter could not open a hardware UDS ISO-TP link for 2B ELV "
                                f"(0x{link.UDS_TX_ID:03X} → 0x{link.UDS_RX_ID:03X}){detail}. "
                                "Check ELV and gateway power or use a raw-CAN adapter.",
                            )
                        )
                    yield link, False
                return
            if not via_gateway:
                link.send_elv_wake_burst()
            yield link, False
        return

    if not gateway_bridge:
        raise RuntimeError(
            bridge_error_msg
            or tr(
                "Чтение 32 КБ Data Flash ELV (29-бит 0x1BFD8A0B → 0x1BFD8A0A) через шлюз требует шлюз "
                "Continental 3Q0 907 530 и адаптер с raw CAN для прозрачного RAM-моста ch3 ↔ ch0 — "
                "либо прямое подключение к шине CAN Komfort ELV (T4: Pin 1 CAN-H / Pin 2 CAN-L).",
                "Reading 32 KB ELV Data Flash (29-bit 0x1BFD8A0B → 0x1BFD8A0A) behind a gateway requires a "
                "Continental 3Q0 907 530 gateway and a raw-CAN adapter for the transparent ch3 ↔ ch0 bridge — "
                "or direct connection to ELV Komfort CAN (T4: Pin 1 CAN-H / Pin 2 CAN-L).",
            )
        )

    if interface == "dpdu":
        _warn_dpdu_29bit_elv(reporter)

    from contitool.can.bridge import j533_can_bridge

    with j533_can_bridge(
        port,
        interface=interface,
        target_channel=gateway_channel,
        log_path=None,
        bus=bus,
        target_rx_filter=ELV_BRIDGE_RX_FILTER,
        reporter=reporter,
    ) as bridge:
        with ElvCanLink(
            port,
            interface=interface,
            log_path=log_path,
            bus=bridge.bus,
            via_gateway=False,
        ) as br_link:
            br_link.send_elv_wake_burst()
            yield br_link, True


def _read_elv_passport_and_status(
    link: ElvCanLink,
    *,
    read_dtcs: bool = True,
) -> tuple[dict[str, Any], dict[str, Any], dict[int, bytes], list[dict[str, Any]] | None]:
    ok, in_bl = link.probe_uds_channel(timeout=0.9)
    if not ok:
        if not link.via_gateway:
            link.send_elv_wake_burst(count=4)
            ok, in_bl = link.probe_uds_channel(timeout=1.1)
        if not ok:
            raise RuntimeError(
                tr(
                    "Блокиратор руля ELV (2B, 0x731 → 0x79B) не отвечает по CAN. Проверьте питание +12 В (Pin 3), "
                    "массу (Pin 4), CAN-H / CAN-L (Pin 1 / Pin 2) и терминатор 120 Ом.",
                    "Steering column lock ELV (2B, 0x731 → 0x79B) did not answer on CAN. Check +12 V (Pin 3), "
                    "GND (Pin 4), CAN-H / CAN-L (Pin 1 / Pin 2), and 120 Ω termination.",
                )
            )

    passport: dict[str, Any] = {
        "in_bootloader": in_bl,
        "uds_tx_id": f"0x{link.UDS_TX_ID:X}",
        "uds_rx_id": f"0x{link.UDS_RX_ID:X}",
    }
    raw_dids: dict[int, bytes] = {}

    for key, did in ELV_PASSPORT_DIDS:
        try:
            raw = link.request_uds(bytes([0x22, (did >> 8) & 0xFF, did & 0xFF]), 0x62, timeout=1.2)[3:]
        except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            continue
        raw_dids[did] = raw
        if key == "coding":
            passport["coding_hex"] = raw.hex().upper()
        elif key == "f1df":
            passport["f1df_hex"] = raw.hex().upper()
            if raw:
                passport["in_bootloader"] = bool(raw[0] & 0x04)
        else:
            val = _clean_ascii(raw)
            if val:
                passport[key] = val

    for did in ELV_STATUS_DIDS:
        try:
            raw = link.request_uds(bytes([0x22, (did >> 8) & 0xFF, did & 0xFF]), 0x62, timeout=1.2)[3:]
        except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            continue
        raw_dids[did] = raw

    status = elv_decode_status_dids(raw_dids)

    dtcs: list[dict[str, Any]] | None = None
    if read_dtcs:
        dtcs = _read_elv_dtcs_in_session(link)

    return passport, status, raw_dids, dtcs


def _read_elv_dtcs_in_session(link: ElvCanLink) -> list[dict[str, Any]]:
    raw_resp: bytes | None = None
    used_mask: int | None = None
    for mask in (0x09, 0xFF):
        try:
            raw_resp = link.request_uds(bytes([0x19, 0x02, mask]), 0x59, timeout=1.5)
            used_mask = mask
            break
        except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            continue
    if raw_resp is None or len(raw_resp) < 3:
        return []
    body = raw_resp[3:]
    out: list[dict[str, Any]] = []
    for off in range(0, len(body) - 3, 4):
        code = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2]
        st = body[off + 3]
        grp = dtc_group(st)
        if used_mask == 0xFF and grp == "untested":
            continue
        disp, desc = describe_elv(code)
        out.append(
            {
                "code": code,
                "code_hex": f"{code:06X}",
                "display": disp,
                "description": desc,
                "status": st,
                "status_hex": f"0x{st:02X}",
                "group": grp,
                "status_text": dtc_status_text(st),
            }
        )
    return out


def _verify_live_02f9(
    link: ElvCanLink,
    k5: bytes,
    passport: dict[str, Any],
    raw_dids: dict[int, bytes],
) -> dict[str, Any]:
    """Perform a read-only `22 02E0 -> 22 02F9` cryptographic verification against the live ELV."""
    fazit_val: bytes | str = raw_dids.get(0xF17C, b"")
    vin_val: bytes | str = raw_dids.get(0xF190, b"")
    did_02ed = raw_dids.get(0x02ED, b"")
    did_02ee = raw_dids.get(0x02EE, b"")

    # Re-read fresh raw F17C/F190/02ED/02EE if any piece was absent or stale
    if not fazit_val:
        with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            got = link.request_uds(b"\x22\xf1\x7c", 0x62, timeout=1.2)[3:]
            if got:
                raw_dids[0xF17C] = got
                fazit_val = got
    if not fazit_val:
        fazit_val = passport.get("fazit", "")

    if not vin_val:
        with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            got = link.request_uds(b"\x22\xf1\x90", 0x62, timeout=1.2)[3:]
            if got:
                raw_dids[0xF190] = got
                vin_val = got
    if not vin_val:
        vin_val = passport.get("vin", "") or ("-" * 17)

    if len(did_02ed) != 10:
        with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            did_02ed = link.request_uds(b"\x22\x02\xed", 0x62, timeout=1.2)[3:]
            if len(did_02ed) == 10:
                raw_dids[0x02ED] = did_02ed
    if len(did_02ee) != 10:
        with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            did_02ee = link.request_uds(b"\x22\x02\xee", 0x62, timeout=1.2)[3:]
            if len(did_02ee) == 10:
                raw_dids[0x02EE] = did_02ee

    if not (fazit_val and len(did_02ed) == 10 and len(did_02ee) == 10):
        return {
            "verified": False,
            "match": False,
            "reason": tr(
                "Отсутствуют данные FAZIT / 02ED / 02EE для проверки 02F9",
                "Missing FAZIT / 02ED / 02EE for 02F9 check",
            ),
        }

    try:
        c_diag = link.request_uds(b"\x22\x02\xe0", 0x62, timeout=1.2)[3:]
        resp_02f9 = link.request_uds(b"\x22\x02\xf9", 0x62, timeout=1.5)[3:]
    except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse) as exc:
        return {"verified": False, "match": False, "reason": str(exc)}

    if len(c_diag) < 4 or len(resp_02f9) < 5:
        return {
            "verified": False,
            "match": False,
            "reason": tr(
                f"Короткий ответ 02E0 ({len(c_diag)} Б) или 02F9 ({len(resp_02f9)} Б)",
                f"Short 02E0 ({len(c_diag)}B) or 02F9 ({len(resp_02f9)}B) response",
            ),
        }

    check = elv_verify_02f9(
        k5,
        resp_02f9[:5],
        fazit=fazit_val,
        vin=vin_val,
        did_02ed=did_02ed,
        did_02ee=did_02ee,
        c_diag=c_diag[:4],
    )
    check["verified"] = True
    check["c_diag_hex"] = c_diag[:4].hex().upper()
    return check


# ────────────────────────────── Public High-Level Workflows ──────────────────────────────


def can_elv_status(
    port: str,
    *,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    read_dtcs: bool = True,
    log_path: Path | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read live UDS passport, WFS5/actuator status DIDs, and optionally DTCs from `2B ELV`."""
    reporter.step(1, 1, tr("Чтение паспорта и статуса ELV (2B)", "Reading ELV (2B) passport & status"))
    with _managed_elv_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=False,
        reporter=reporter,
    ) as (link, _used_bridge):
        passport, status, _raw, dtcs = _read_elv_passport_and_status(link, read_dtcs=read_dtcs)
    prof = elv_detect_profile(passport)
    if prof["warning"]:
        reporter.warning(prof["warning"])
    return {
        "ecu_kind": "elv",
        "diag_addr": "2B",
        "via_gateway": via_gateway,
        "gateway_bridge": gateway_bridge,
        "passport": passport,
        "status": status,
        "dtcs": dtcs if dtcs is not None else [],
        "profile": prof,
        "officially_supported": bool(prof["verified"]),
        "support_warning": prof["warning"],
    }


def can_elv_clear_dtc(
    port: str,
    *,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    log_path: Path | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Clear all fault codes (`UDS 14 FF FF FF`) on `2B ELV` and re-read active DTCs."""
    reporter.step(1, 2, tr("Очистка ошибок ELV (14 FF FF FF)", "Clearing ELV fault codes (14 FF FF FF)"))
    with _managed_elv_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=False,
        reporter=reporter,
    ) as (link, _used_bridge):
        ok, _ = link.probe_uds_channel(timeout=0.9)
        if not ok and not link.via_gateway and not link._hw_uds:
            link.send_elv_wake_burst(count=4)
            ok, _ = link.probe_uds_channel(timeout=1.1)
        if not ok:
            raise RuntimeError(tr("ELV (2B) не отвечает по UDS", "ELV (2B) is not responding to UDS"))
        link.request_uds(b"\x14\xff\xff\xff", 0x54, timeout=2.0)
        reporter.step(2, 2, tr("Проверка оставшихся ошибок", "Checking remaining DTCs"))
        remaining = _read_elv_dtcs_in_session(link)
    return {
        "cleared": True,
        "remaining_count": len(remaining),
        "dtcs": remaining,
    }


def can_elv_read_dflash(
    port: str,
    *,
    out_dir: Path | str | None = None,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    verify_02f9: bool = True,
    read_dtcs: bool = True,
    log_path: Path | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read full 32 KiB Data Flash (`0xFCFF8000..0xFCFFFFFF`) over CAN, verify 47/47 CRCs and live `22 02F9` MAC."""
    t0 = time.monotonic()
    with _managed_elv_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=True,
        reporter=reporter,
    ) as (link, used_bridge):
        reporter.step(1, 3, tr("Чтение паспорта и статуса ELV", "Reading ELV passport & status"))
        passport, status, raw_dids, dtcs = _read_elv_passport_and_status(link, read_dtcs=read_dtcs)
        prof = elv_detect_profile(passport)
        if prof["warning"]:
            reporter.warning(prof["warning"])

        reporter.step(2, 3, tr("Чтение Data Flash ELV (32 КБ по CAN)", "Reading ELV Data Flash (32 KB over CAN)"))
        dflash_bytes = link.read_dflash_32k(reporter=reporter)
        parsed = elv_parse_dflash(dflash_bytes)

        reporter.step(3, 3, tr("Проверка CRC-32 (47/47) и криптоподписи 02F9", "Verifying CRC-32 (47/47) and live 02F9 MAC"))
        check_02f9: dict[str, Any] = {"verified": False, "match": False}
        slot_a_hex = parsed["block34"]["slot_a_hex"]
        if verify_02f9 and len(slot_a_hex) == 32:
            check_02f9 = _verify_live_02f9(link, bytes.fromhex(slot_a_hex), passport, raw_dids)
            if check_02f9.get("match"):
                reporter.info(
                    tr(
                        f"Криптоподпись 22 02F9 подтверждена ({check_02f9['actual_mac_hex']}) — ключ Slot A / K_5 верен",
                        f"Live 22 02F9 MAC verified ({check_02f9['actual_mac_hex']}) — Slot A / K_5 key confirmed",
                    )
                )
            elif check_02f9.get("verified"):
                reporter.warning(
                    tr(
                        f"Несовпадение 22 02F9 MAC: ожидалось {check_02f9['expected_mac_hex']}, получено {check_02f9['actual_mac_hex']}",
                        f"22 02F9 MAC mismatch: expected {check_02f9['expected_mac_hex']}, got {check_02f9['actual_mac_hex']}",
                    )
                )

    elapsed = round(time.monotonic() - t0, 2)
    saved_files: dict[str, str] = {}
    if out_dir is not None:
        target_dir = Path(out_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        bin_path = target_dir / "elv_dflash_32k.bin"
        bin_path.write_bytes(dflash_bytes)
        saved_files["dflash"] = str(bin_path)

        rep_obj = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_sec": elapsed,
            "via_gateway": via_gateway,
            "used_bridge": used_bridge,
            "passport": passport,
            "profile": prof,
            "officially_supported": bool(prof["verified"]),
            "support_warning": prof["warning"],
            "status": status,
            "dflash_sha256": parsed["sha256"],
            "dflash_size": len(dflash_bytes),
            "active_pool": parsed["active_pool"],
            "pool0_counter": parsed["pool0_counter"],
            "pool1_counter": parsed["pool1_counter"],
            "crc_valid_count": parsed["crc_valid_count"],
            "crc_total_count": parsed["crc_total_count"],
            "all_crc_ok": parsed["all_crc_ok"],
            "triple_copy_ok": parsed["triple_copy_ok"],
            "identity": parsed["identity"],
            "block34": parsed["block34"],
            "block04": parsed["block04"],
            "block02": parsed["block02"],
            "block31": parsed["block31"],
            "block32": parsed["block32"],
            "verify_02f9": check_02f9,
            "dtcs": dtcs if dtcs is not None else [],
        }
        rep_path = target_dir / "elv_report.json"
        rep_path.write_text(json.dumps(rep_obj, indent=2, ensure_ascii=False), encoding="utf-8")
        saved_files["report"] = str(rep_path)

    return {
        "ecu_kind": "elv",
        "diag_addr": "2B",
        "via_gateway": via_gateway,
        "used_bridge": used_bridge,
        "elapsed_sec": elapsed,
        "passport": passport,
        "profile": prof,
        "officially_supported": bool(prof["verified"]),
        "support_warning": prof["warning"],
        "status": status,
        "dflash_bytes": dflash_bytes,
        "dflash_parsed": parsed,
        "verify_02f9": check_02f9,
        "dtcs": dtcs if dtcs is not None else [],
        "saved_files": saved_files,
    }


def _backup_and_resolve_current_k5(
    link: ElvCanLink,
    *,
    current_k5: bytes | str | None,
    backup_dir: Path | str | None,
    passport: dict[str, Any],
    status: dict[str, Any],
    raw_dids: dict[int, bytes],
    reporter: OperationReporter,
) -> tuple[bytes, dict[str, Any] | None, dict[str, str]]:
    """Resolve current `K_5` (reading DFLASH if omitted) and optionally write a pre-write backup."""
    saved_files: dict[str, str] = {}
    parsed: dict[str, Any] | None = None
    dflash_bytes: bytes | None = None

    need_dflash = current_k5 is None or (backup_dir is not None and not link.via_gateway and not link._hw_uds)
    if need_dflash:
        try:
            dflash_bytes = link.read_dflash_32k(reporter=reporter)
        except TRANSPORT_ERRORS:
            if current_k5 is None:
                raise
            # If user explicitly passed current_k5 (e.g., UDS-only without 29-bit channel), backup is best-effort
            reporter.warning(
                tr(
                    "Не удалось выполнить 29-битный бэкап Data Flash перед записью — продолжаем с явно указанным ключом K_5.",
                    "Could not complete 29-bit Data Flash backup before write — continuing with explicitly supplied K_5.",
                )
            )
            dflash_bytes = None
        if dflash_bytes is not None:
            parsed = elv_parse_dflash(dflash_bytes)
            if not parsed["all_crc_ok"]:
                raise RuntimeError(
                    tr(
                        f"Ошибка целостности считанного Data Flash ({parsed['crc_valid_count']}/{parsed['crc_total_count']} CRC) — запись отменена",
                        f"DFLASH integrity check failed ({parsed['crc_valid_count']}/{parsed['crc_total_count']} CRCs) — write aborted",
                    )
                )

    if dflash_bytes is not None and parsed is not None and backup_dir is not None:
        bdir = Path(backup_dir)
        bdir.mkdir(parents=True, exist_ok=True)
        bin_p = bdir / "elv_dflash_32k_backup.bin"
        bin_p.write_bytes(dflash_bytes)
        rep_p = bdir / "elv_backup_report.json"
        rep_p.write_text(
            json.dumps(
                {
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "dflash_sha256": parsed["sha256"],
                    "passport": passport,
                    "status": status,
                    "block34": parsed["block34"],
                    "block04": parsed["block04"],
                    "block02": parsed["block02"],
                    "block31": parsed["block31"],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        saved_files["backup_dflash"] = str(bin_p)
        saved_files["backup_report"] = str(rep_p)
        reporter.info(tr(f"Резервная копия Data Flash сохранена: {bin_p}", f"Data Flash backup saved: {bin_p}"))

    if current_k5 is not None:
        cur_k5 = _norm_key_16b(current_k5, "current_k5")
    else:
        assert parsed is not None
        slot_a_hex = parsed["block34"]["slot_a_hex"]
        if len(slot_a_hex) != 32:
            raise RuntimeError(tr("Не удалось извлечь текущий ключ K_5 из Data Flash", "Failed to extract current K_5 from Data Flash"))
        cur_k5 = bytes.fromhex(slot_a_hex)

    # Confirm key matches live ECU before sending a mutating 02E2/02E1 write (fail-closed to avoid 02EF lockouts)
    pre_check = _verify_live_02f9(link, cur_k5, passport, raw_dids)
    if not (pre_check.get("verified") is True and pre_check.get("match") is True):
        if pre_check.get("verified") is True:
            raise RuntimeError(
                tr(
                    f"Текущий ключ K_5 не прошёл проверку 22 02F9 (ожидалось {pre_check['expected_mac_hex']}, "
                    f"блок вернул {pre_check['actual_mac_hex']}) — запись отменена во избежание блокировки.",
                    f"Current K_5 failed live 22 02F9 check (expected {pre_check['expected_mac_hex']}, "
                    f"ECU returned {pre_check['actual_mac_hex']}) — write aborted to prevent lockout.",
                )
            )
        reason = pre_check.get("reason") or tr("неизвестная причина", "unknown reason")
        raise RuntimeError(
            tr(
                f"Не удалось проверить текущий ключ K_5 через 22 02F9 ({reason}) — "
                "запись отменена во избежание запуска таймера блокировки 02EF.",
                f"Could not verify current K_5 via live 22 02F9 ({reason}) — "
                "write aborted to prevent triggering 02EF lockout timers.",
            )
        )

    return cur_k5, parsed, saved_files


def can_elv_adapt(
    port: str,
    *,
    new_vin: str,
    new_k5: bytes | str,
    new_power_class: int,
    current_k5: bytes | str | None = None,
    cfg_byte: int = 0x80,
    brand_byte: int = 0x01,
    backup_dir: Path | str | None = None,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    log_path: Path | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Adapt ELV to a target vehicle over CAN via `UDS 2E 02E2` (`VIN`, `K_5`, `PowerClass`, `IDac -> 0x00`)."""
    norm_vin = _norm_vin17(new_vin).decode("ascii")
    target_k5 = _norm_key_16b(new_k5, "new_k5")
    pc_u8 = _validate_u8(new_power_class, "new_power_class")
    cfg_u8 = _validate_u8(cfg_byte, "cfg_byte")
    brand_u8 = _validate_u8(brand_byte, "brand_byte")
    if current_k5 is not None:
        _norm_key_16b(current_k5, "current_k5")
    needs_raw = (
        current_k5 is None
        or (not via_gateway)
        or (backup_dir is not None and via_gateway and gateway_bridge)
    )

    with _managed_elv_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=needs_raw,
        bridge_error_msg=tr(
            "Адаптация ELV через шлюз без указания текущего ключа K_5 требует чтения 32 КБ Data Flash "
            "(29-бит 0x1BFD8A0B → 0x1BFD8A0A) через RAM-мост Continental 3Q0 907 530 — укажите известный "
            "текущий ключ K_5 (--current-k5) либо подключитесь к шине CAN Komfort напрямую.",
            "Adapting ELV behind a gateway without current K_5 requires reading 32 KB Data Flash "
            "(29-bit 0x1BFD8A0B → 0x1BFD8A0A) via a Continental 3Q0 907 530 RAM bridge — supply known "
            "current K_5 (--current-k5) or connect directly to ELV Komfort CAN.",
        ),
        reporter=reporter,
    ) as (link, used_bridge):
        reporter.step(1, 4, tr("Чтение паспорта, бэкап и проверка текущего ключа K_5", "Reading passport, backup & verifying current K_5"))
        passport, status, raw_dids, _ = _read_elv_passport_and_status(link, read_dtcs=False)
        prof = elv_detect_profile(passport)
        if prof["warning"]:
            reporter.warning(prof["warning"])
        if status.get("mode") == 0xFF:
            raise RuntimeError(
                tr(
                    "ELV находится в заводском режиме Plant (0xFF); сначала переведите в Virgin (2E 1105 01).",
                    "ELV is in Plant mode (0xFF); switch to Virgin (2E 1105 01) before 2E 02E2 adaptation.",
                )
            )
        if status.get("lockout_02e2_timer", 0):
            raise RuntimeError(
                tr(
                    f"Активен таймер блокировки WFS5 02E2 ({status['lockout_02e2_timer']}) — подождите истечения таймера.",
                    f"WFS5 02E2 lockout timer is active ({status['lockout_02e2_timer']}) — wait for it to expire.",
                )
            )

        cur_k5, pre_parsed, saved_files = _backup_and_resolve_current_k5(
            link,
            current_k5=current_k5,
            backup_dir=backup_dir,
            passport=passport,
            status=status,
            raw_dids=raw_dids,
            reporter=reporter,
        )

        reporter.step(2, 4, tr("Отправка условия ДВС заглушен (0x3DC Gateway_71)", "Sending engine-stopped precondition (0x3DC Gateway_71)"))
        if not link.via_gateway:
            link.send_engine_stopped_burst()

        reporter.step(3, 4, tr("Запись адаптации WFS5 (UDS 2E 02E2, 52 Б)", "Writing WFS5 adaptation (UDS 2E 02E2, 52 B)"))
        payload_52 = elv_build_02e2_adapt_payload(
            cur_k5,
            new_vin=norm_vin,
            new_k5=target_k5,
            new_power_class=pc_u8,
            cfg_byte=cfg_u8,
            brand_byte=brand_u8,
        )
        link.request_uds(b"\x2e\x02\xe2" + payload_52, 0x6E, timeout=5.0)
        if not _is_in_memory_bus(link):
            time.sleep(0.15)

        reporter.step(4, 4, tr("Проверка результата адаптации и криптоподписи 02F9", "Verifying post-adaptation state & 02F9 MAC"))
        post_passport, post_status, post_raw, _ = _read_elv_passport_and_status(link, read_dtcs=False)
        post_02f9 = _verify_live_02f9(link, target_k5, post_passport, post_raw)

    return {
        "ok": bool(
            post_status.get("mode") == 0x02
            and post_passport.get("vin") == norm_vin
            and post_status.get("power_class") == pc_u8
            and post_02f9.get("verified") is True
            and post_02f9.get("match") is True
        ),
        "operation": "adapt",
        "used_bridge": used_bridge,
        "profile": prof,
        "officially_supported": bool(prof["verified"]),
        "support_warning": prof["warning"],
        "new_vin": norm_vin,
        "new_k5_hex": target_k5.hex().upper(),
        "new_power_class": pc_u8,
        "idp_hex": pre_parsed["block04"]["idp_hex"] if pre_parsed else "",
        "post_passport": post_passport,
        "post_status": post_status,
        "verify_02f9": post_02f9,
        "saved_files": saved_files,
    }


def can_elv_adapt_from_cluster(
    port: str,
    fpke_dflash: bytes,
    *,
    fpke_cflash: bytes | None = None,
    current_k5: bytes | str | None = None,
    cfg_byte: int = 0x80,
    brand_byte: int = 0x01,
    backup_dir: Path | str | None = None,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    log_path: Path | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Extract target vehicle `VIN`, `Slot A / K_5`, and `PowerClass` from an FPK_E dump and adapt ELV over CAN."""
    mat = elv_extract_cluster_material(fpke_dflash, fpke_cflash)
    if mat.get("slot_a_crc_ok") is False:
        raise RuntimeError(
            tr(
                "Контрольная сумма CRC-32 ключа Slot A (K_5) в дампе приборной панели FPK_E не совпадает с EEL 0x68 — "
                "адаптация ELV отменена во избежание записи повреждённого ключа.",
                "Slot A (K_5) key in the FPK_E cluster dump failed CRC-32 verification against EEL 0x68 — "
                "ELV adaptation aborted to avoid writing a corrupted key.",
            )
        )
    if not mat["vin"] or len(mat["vin"]) != 17:
        raise ValueError(tr("В дампе приборной панели FPK_E отсутствует корректный 17-значный VIN", "FPK_E dump has no valid 17-char VIN"))
    if not mat["slot_a_hex"] or len(mat["slot_a_hex"]) != 32:
        raise ValueError(tr("В дампе приборной панели FPK_E отсутствует ключ Slot A (K_5)", "FPK_E dump has no Slot A (K_5) key"))
    if mat["power_class"] is None:
        raise ValueError(tr("В дампе приборной панели FPK_E отсутствует PowerClass", "FPK_E dump has no PowerClass"))

    res = can_elv_adapt(
        port,
        new_vin=mat["vin"],
        new_k5=mat["slot_a_hex"],
        new_power_class=int(mat["power_class"]),
        current_k5=current_k5,
        cfg_byte=cfg_byte,
        brand_byte=brand_byte,
        backup_dir=backup_dir,
        interface=interface,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        log_path=log_path,
        bus=bus,
        reporter=reporter,
    )
    res["cluster_material"] = mat
    return res


def can_elv_virginize(
    port: str,
    *,
    current_k5: bytes | str | None = None,
    virgin_k5: bytes | str | None = None,
    backup_dir: Path | str | None = None,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    log_path: Path | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Reset an adapted ELV (`Mode 2`) back to `Virgin` (`Mode 1`) over CAN via `UDS 2E 02E2` (`FUN_ram_00027ad0`)."""
    if current_k5 is not None:
        _norm_key_16b(current_k5, "current_k5")
    if virgin_k5 is not None:
        _norm_key_16b(virgin_k5, "virgin_k5")
    needs_raw = (
        current_k5 is None
        or (not via_gateway)
        or (backup_dir is not None and via_gateway and gateway_bridge)
    )

    with _managed_elv_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=needs_raw,
        bridge_error_msg=tr(
            "Сброс ELV в Virgin через шлюз без указания текущего ключа K_5 требует чтения 32 КБ Data Flash "
            "(29-бит 0x1BFD8A0B → 0x1BFD8A0A) через RAM-мост Continental 3Q0 907 530 — укажите известный "
            "текущий ключ K_5 (--current-k5) либо подключитесь к шине CAN Komfort напрямую.",
            "Resetting ELV to Virgin behind a gateway without current K_5 requires reading 32 KB Data Flash "
            "(29-bit 0x1BFD8A0B → 0x1BFD8A0A) via a Continental 3Q0 907 530 RAM bridge — supply known "
            "current K_5 (--current-k5) or connect directly to ELV Komfort CAN.",
        ),
        reporter=reporter,
    ) as (link, used_bridge):
        reporter.step(1, 4, tr("Чтение паспорта, бэкап и проверка текущего ключа K_5", "Reading passport, backup & verifying current K_5"))
        passport, status, raw_dids, _ = _read_elv_passport_and_status(link, read_dtcs=False)
        prof = elv_detect_profile(passport)
        if prof["warning"]:
            reporter.warning(prof["warning"])
        if status.get("mode") == 0xFF:
            raise RuntimeError(
                tr(
                    "ELV уже в заводском режиме Plant (0xFF) — для перевода в Virgin используйте 2E 1105 01.",
                    "ELV is in Plant mode (0xFF) — use 2E 1105 01 to switch to Virgin.",
                )
            )
        if status.get("lockout_02e2_timer", 0):
            raise RuntimeError(
                tr(
                    f"Активен таймер блокировки WFS5 02E2 ({status['lockout_02e2_timer']}).",
                    f"WFS5 02E2 lockout timer is active ({status['lockout_02e2_timer']}).",
                )
            )

        cur_k5, pre_parsed, saved_files = _backup_and_resolve_current_k5(
            link,
            current_k5=current_k5,
            backup_dir=backup_dir,
            passport=passport,
            status=status,
            raw_dids=raw_dids,
            reporter=reporter,
        )
        vk5 = _norm_key_16b(virgin_k5, "virgin_k5") if virgin_k5 is not None else cur_k5

        reporter.step(2, 4, tr("Отправка условия ДВС заглушен (0x3DC Gateway_71)", "Sending engine-stopped precondition (0x3DC Gateway_71)"))
        if not link.via_gateway:
            link.send_engine_stopped_burst()

        reporter.step(3, 4, tr("Сброс ELV в Virgin Mode 1 (UDS 2E 02E2)", "Resetting ELV to Virgin Mode 1 (UDS 2E 02E2)"))
        payload_52 = elv_build_02e2_virgin_payload(cur_k5, virgin_k5=vk5)
        link.request_uds(b"\x2e\x02\xe2" + payload_52, 0x6E, timeout=5.0)
        if not _is_in_memory_bus(link):
            time.sleep(0.15)

        reporter.step(4, 4, tr("Проверка Virgin-состояния (Mode 1, VIN = '---')", "Verifying Virgin state (Mode 1, VIN = '---')"))
        post_passport, post_status, post_raw, _ = _read_elv_passport_and_status(link, read_dtcs=False)
        post_02f9 = _verify_live_02f9(link, vk5, post_passport, post_raw)

    return {
        "ok": bool(post_status.get("mode") == 0x01 and post_02f9.get("verified") is True and post_02f9.get("match") is True),
        "operation": "virginize",
        "used_bridge": used_bridge,
        "profile": prof,
        "officially_supported": bool(prof["verified"]),
        "support_warning": prof["warning"],
        "virgin_k5_hex": vk5.hex().upper(),
        "idp_hex": pre_parsed["block04"]["idp_hex"] if pre_parsed else "",
        "post_passport": post_passport,
        "post_status": post_status,
        "verify_02f9": post_02f9,
        "saved_files": saved_files,
    }


def can_elv_reset_idac(
    port: str,
    *,
    current_k5: bytes | str | None = None,
    backup_dir: Path | str | None = None,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    log_path: Path | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Reset learned cluster `IDac` (`0xAA -> 0x00`) in Mode 2 via `22 02E0 -> 2E 02E1` (`cmd=0x04, arg=0x80`)."""
    if current_k5 is not None:
        _norm_key_16b(current_k5, "current_k5")
    needs_raw = current_k5 is None or (backup_dir is not None and via_gateway and gateway_bridge)

    with _managed_elv_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=needs_raw,
        bridge_error_msg=tr(
            "Сброс IDac через шлюз без указания текущего ключа K_5 требует чтения 32 КБ Data Flash "
            "(29-бит 0x1BFD8A0B → 0x1BFD8A0A) через RAM-мост Continental 3Q0 907 530 — укажите известный "
            "текущий ключ K_5 (--current-k5) либо подключитесь к шине CAN Komfort напрямую.",
            "Resetting IDac behind a gateway without current K_5 requires reading 32 KB Data Flash "
            "(29-bit 0x1BFD8A0B → 0x1BFD8A0A) via a Continental 3Q0 907 530 RAM bridge — supply known "
            "current K_5 (--current-k5) or connect directly to ELV Komfort CAN.",
        ),
        reporter=reporter,
    ) as (link, used_bridge):
        reporter.step(1, 3, tr("Чтение статуса и проверка текущего ключа K_5", "Reading status & verifying current K_5"))
        passport, status, raw_dids, _ = _read_elv_passport_and_status(link, read_dtcs=False)
        prof = elv_detect_profile(passport)
        if prof["warning"]:
            reporter.warning(prof["warning"])
        if status.get("mode") != 0x02:
            raise RuntimeError(
                tr(
                    f"Команда сброса IDac (2E 02E1 cmd=04 arg=80) работает только в режиме Adapted (Mode 2), текущий режим: {status.get('mode_label')}.",
                    f"Reset IDac (2E 02E1 cmd=04 arg=80) requires Adapted mode (Mode 2); current mode: {status.get('mode_label')}.",
                )
            )
        if status.get("lockout_02e1_timer", 0):
            raise RuntimeError(
                tr(
                    f"Активен таймер блокировки WFS5 02E1 ({status['lockout_02e1_timer']}).",
                    f"WFS5 02E1 lockout timer is active ({status['lockout_02e1_timer']}).",
                )
            )

        cur_k5, _pre_parsed, saved_files = _backup_and_resolve_current_k5(
            link,
            current_k5=current_k5,
            backup_dir=backup_dir,
            passport=passport,
            status=status,
            raw_dids=raw_dids,
            reporter=reporter,
        )

        reporter.step(2, 3, tr("Запрос челленджа 22 02E0 и сброс IDac (2E 02E1)", "Requesting 22 02E0 challenge & sending 2E 02E1 reset IDac"))
        c_diag = link.request_uds(b"\x22\x02\xe0", 0x62, timeout=1.5)[3:7]
        cmd, arg = ELV_CMD_RESET_IDAC
        payload_4 = elv_build_02e1_payload(cur_k5, c_diag, cmd=cmd, arg=arg)
        link.request_uds(b"\x2e\x02\xe1" + payload_4, 0x6E, timeout=4.0)
        if not _is_in_memory_bus(link):
            time.sleep(0.1)

        reporter.step(3, 3, tr("Проверка статуса IDac (DID 0x02EE)", "Verifying cleared IDac status (DID 0x02EE)"))
        post_passport, post_status, _post_raw, _ = _read_elv_passport_and_status(link, read_dtcs=False)

    return {
        "ok": not bool(post_status.get("idac_locked", True)),
        "operation": "reset_idac",
        "used_bridge": used_bridge,
        "profile": prof,
        "officially_supported": bool(prof["verified"]),
        "support_warning": prof["warning"],
        "c_diag_hex": c_diag.hex().upper(),
        "payload_02e1_hex": payload_4.hex().upper(),
        "post_passport": post_passport,
        "post_status": post_status,
        "saved_files": saved_files,
    }


_ELV_PRECONDITION_LABELS: dict[int, tuple[str, str]] = {
    0x01: ("двигатель запущен (RPM > 0)", "engine running (RPM > 0)"),
    0x02: ("нет авторизации WFS5 / KL15 (0x3C0 + 0x01A/0x01B)", "WFS5 / KL15 authorization not active (0x3C0 + 0x01A/0x01B)"),
    0x05: ("автомобиль движется (скорость > 0)", "vehicle moving (speed > 0)"),
    0x81: ("активна 10-минутная блокировка загрузчика (0xA7)", "10-minute bootloader security lockout active (0xA7)"),
}


def _decode_precondition_codes(body: bytes) -> list[str]:
    out: list[str] = []
    for code in body:
        if code == 0x00:
            continue
        pair = _ELV_PRECONDITION_LABELS.get(code)
        if pair is not None:
            out.append(f"0x{code:02X}: {tr(pair[0], pair[1])}")
        else:
            out.append(f"0x{code:02X}")
    return out


def _read_elv_mode(link: ElvCanLink) -> int | None:
    """Best-effort read of WFS5 mode (`0x01` Virgin, `0x02` Adapted, `0xFF` Plant) from DID `0x1105` / `0x02ED`."""
    for did in (0x1105, 0x02ED):
        try:
            resp = link.request_uds(bytes([0x22, (did >> 8) & 0xFF, did & 0xFF]), 0x62, timeout=0.9)
            if len(resp) >= 4:
                return resp[3]
        except (*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
            continue
    return None


def _request_31_01_02_03_with_wfs5(
    link: ElvCanLink,
    *,
    k5: bytes | None,
    power_class: int | None,
    idac: bytes | None,
    expected_idp: bytes | None = None,
    send_kl15: bool = False,
    bz: int = 0,
    timeout: float = 2.8,
) -> tuple[bytes, int, bool | None, dict[str, Any] | None]:
    """Run `10 03` -> `31 01 02 03` while maintaining `0x3C0 KL15=1` and answering ELV `0x01A` Type 1 with `0x01B`.

    Matches `FUN_ram_0002052e` / `FUN_ram_000205b4` / `FUN_ram_000274de` / `FUN_ram_00026f94`:
    in Adapted Mode 2, `31 01 02 03` returns `7F 31 78` (ResponsePending) and triggers ELV to transmit
    `0x01A` Type 1 (`01 P0 P1 P2 P3 00 00 00`) ONLY while `KL15 == 1` (`0x3C0`) is active with valid CRC-8 + BZ.
    Answering with `0x01B` (`elv_build_wfs5_01b_response`) sets `DAT_ram_ffffbfdc |= 0x11` -> `DAT_ram_ffffb4ed = 1`
    so ELV returns empty `71 01 02 03` and permits `10 02` (as long as `KL15` stays ON).
    """
    in_mem = _is_in_memory_bus(link)
    do_wfs5 = (
        not link.via_gateway
        and k5 is not None
        and power_class is not None
        and idac is not None
    )

    if not link.via_gateway and (do_wfs5 or send_kl15):
        if not in_mem:
            with contextlib.suppress(*TRANSPORT_ERRORS):
                link.send_raw_frame(ELV_NM_WAKE_ID, ELV_NM_WAKE_PAYLOAD)
        # Establish valid KL15=1 (clears E2E/timeout flag DAT_ram_ffffb36f -> 0, sets DAT_ram_ffffb36e -> 1)
        burst = 3 if in_mem else 10
        for _ in range(burst):
            link.send_kl_status(bz & 0x0F, kl_s=True, kl_15=True)
            bz = (bz + 1) & 0x0F
            if not in_mem:
                time.sleep(0.035)

    link.request_uds(b"\x10\x03", 0x50, timeout=1.5)

    if not do_wfs5:
        resp_pre = link.request_uds(b"\x31\x01\x02\x03", 0x71, timeout=12.0)
        return bytes(resp_pre[4:]), bz, None, None

    assert k5 is not None and power_class is not None and idac is not None
    link.drain_rx(quick=True)
    link.send_raw_frame(link.UDS_TX_ID, b"\x04\x31\x01\x02\x03", pad=link.UDS_FC_PAD)

    r_chal: bytes | None = None
    p_chal: bytes | None = None
    type1_replies = 0
    type2_ver: dict[str, Any] | None = None
    final_uds: bytes | None = None

    # ISO-TP multi-frame reassembly state for UDS_RX_ID
    mf_buf = bytearray()
    mf_expected = 0
    mf_next_sn = 1

    t0 = time.monotonic()
    last_3c0 = t0
    while time.monotonic() - t0 < timeout:
        now = time.monotonic()
        if not in_mem and (now - last_3c0) >= 0.035:
            link.send_kl_status(bz & 0x0F, kl_s=True, kl_15=True)
            bz = (bz + 1) & 0x0F
            last_3c0 = now

        msg = link.bus.recv(timeout=0.01 if not in_mem else 0.05)
        if msg is None:
            if in_mem:
                # Advance BZ once if mock bus didn't respond immediately
                link.send_kl_status(bz & 0x0F, kl_s=True, kl_15=True)
                bz = (bz + 1) & 0x0F
            continue

        raw = bytes(msg.data)
        link.rx_frames += 1
        link._write_trace("rx", msg.arbitration_id, msg.dlc, raw)

        if msg.arbitration_id == ELV_WFS_ELV_CAN_ID and len(raw) >= 8:
            mtype = raw[0]
            if mtype == 0x01 and type1_replies < 2:
                p_chal = raw[1:5]
                r_chal = secrets.token_bytes(4)
                resp_01b = elv_build_wfs5_01b_response(k5, power_class, p_chal, r_chal, idac)
                link.send_raw_frame(ELV_WFS_KOMBI_CAN_ID, resp_01b)
                type1_replies += 1
            elif mtype == 0x02 and p_chal is not None and r_chal is not None:
                type2_ver = elv_verify_wfs5_01a_reply(
                    k5,
                    power_class,
                    raw,
                    r_challenge=r_chal,
                    p_challenge=p_chal,
                    expected_idp=expected_idp,
                )
            continue

        if msg.arbitration_id != link.UDS_RX_ID or not raw:
            continue

        pci_type = (raw[0] >> 4) & 0x0F
        uds_pdu: bytes | None = None
        if pci_type == 0:
            sf_len = raw[0] & 0x0F
            if not (1 <= sf_len <= 7) or len(raw) < 1 + sf_len:
                continue
            uds_pdu = raw[1 : 1 + sf_len]
        elif pci_type == 1:
            if len(raw) != 8:
                continue
            cand_expected = ((raw[0] & 0x0F) << 8) | raw[1]
            if cand_expected <= 6:
                continue
            mf_expected = cand_expected
            mf_buf = bytearray(raw[2:])
            mf_next_sn = 1
            link.send_raw_frame(link.UDS_TX_ID, b"\x30\x00\x00", pad=link.UDS_FC_PAD)
            continue
        elif pci_type == 2 and mf_expected > 0:
            if (raw[0] & 0x0F) == (mf_next_sn & 0x0F):
                need = min(7, mf_expected - len(mf_buf))
                if len(raw) < 1 + need:
                    continue
                mf_buf.extend(raw[1 : 1 + need])
                mf_next_sn = (mf_next_sn + 1) & 0x0F
                if len(mf_buf) >= mf_expected:
                    uds_pdu = bytes(mf_buf[:mf_expected])
                    mf_expected = 0
            if uds_pdu is None:
                continue
        else:
            continue

        if not uds_pdu:
            continue
        if len(uds_pdu) >= 3 and uds_pdu[0] == 0x7F and uds_pdu[1] == 0x31 and uds_pdu[2] == 0x78:
            continue  # ResponsePending while ELV runs WFS5 0x01A/0x01B challenge
        if len(uds_pdu) >= 3 and uds_pdu[0] == 0x7F and uds_pdu[1] == 0x31:
            raise UdsNegativeResponse(0x31, uds_pdu[2], uds_pdu)
        if uds_pdu[0] == 0x71:
            final_uds = uds_pdu
            break
        raise UnexpectedUdsResponse(f"Unexpected UDS response to 31 01 02 03: {uds_pdu.hex()}")

    if final_uds is None:
        raise TimeoutError(
            tr(
                "Таймаут ответа ELV на 31 01 02 03 (проверка условий программирования)",
                "Timed out waiting for ELV response to 31 01 02 03 (programming preconditions)",
            )
        )

    body = final_uds[4:]
    precond_ok = len(body) == 0 or body == b"\x00"
    wfs5_info: dict[str, Any] = {
        "p_challenge_hex": p_chal.hex().upper() if p_chal is not None else "",
        "r_challenge_hex": r_chal.hex().upper() if r_chal is not None else "",
        "type1_replies": type1_replies,
    }
    if type2_ver is not None:
        wfs5_info.update(type2_ver)
        wfs5_ok: bool | None = bool(type2_ver.get("ok"))
    elif p_chal is not None:
        # When steering bolt is unlocked (`DAT_ram_ffffb2d3 == 0`), FUN_ram_00026f94 accepts 0x01B,
        # sets `bfdc |= 0x11` -> `DAT_ram_ffffb4ed = 1` and finishes `31 01 02 03` with empty body
        # without emitting a Type 2 frame.
        wfs5_info["type"] = 1
        wfs5_info["auth_granted"] = precond_ok
        wfs5_ok = precond_ok
    else:
        # Already authorized or Virgin/Plant mode where ELV did not need to issue 0x01A Type 1
        wfs5_info["auth_granted"] = precond_ok
        wfs5_ok = True if precond_ok else False

    return body, bz, wfs5_ok, wfs5_info


def can_elv_check_bootloader(
    port: str,
    *,
    current_k5: bytes | str | None = None,
    power_class: int | None = None,
    idac: bytes | str | None = None,
    enter_programming: bool = False,
    interface: str = "slcan",
    via_gateway: bool = False,
    gateway_bridge: bool = False,
    gateway_channel: int = 0,
    log_path: Path | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Check programming preconditions (`31 01 02 03`), and optionally verify WFS5 `0x01A/0x01B` + `10 02` + `27 11/12` + `11 01`."""
    has_wfs5_creds = current_k5 is not None and power_class is not None and idac is not None
    needs_raw = bool(has_wfs5_creds or (enter_programming and (not via_gateway or gateway_bridge)))
    result: dict[str, Any] = {
        "preconditions_ok": False,
        "preconditions_raw_hex": "",
        "preconditions_reasons": [],
        "wfs5_handshake_ok": None,
        "programming_session_ok": None,
        "security_access_ok": None,
        "returned_to_app": None,
    }

    with _managed_elv_session(
        port,
        interface=interface,
        log_path=log_path,
        bus=bus,
        via_gateway=via_gateway,
        gateway_bridge=gateway_bridge,
        gateway_channel=gateway_channel,
        needs_raw_komfort=needs_raw,
        bridge_error_msg=tr(
            "Авторизация WFS5 на шине CAN (0x3C0 + 0x01A/0x01B) через шлюз требует шлюз Continental 3Q0 907 530 "
            "и адаптер с raw CAN для прозрачного RAM-моста ch3 ↔ ch0 — либо прямое подключение к шине CAN Komfort "
            "ELV (T4: Pin 1 CAN-H / Pin 2 CAN-L), либо запуск check-bootloader без WFS5-данных.",
            "WFS5 CAN authorization (0x3C0 + 0x01A/0x01B) behind a gateway requires a Continental 3Q0 907 530 "
            "gateway and a raw-CAN adapter for the transparent ch3 ↔ ch0 bridge — or direct connection to ELV "
            "Komfort CAN (T4: Pin 1 CAN-H / Pin 2 CAN-L), or omitting WFS5 credentials to test UDS 10 02 / 27 11-12 only.",
        ),
        reporter=reporter,
    ) as (link, used_bridge):
        result["used_bridge"] = used_bridge
        total_steps = 3 if enter_programming else 1
        reporter.step(1, total_steps, tr("Проверка связи с ELV и определение режима WFS5", "Connecting to ELV & checking WFS5 mode"))
        ok, in_bl = link.probe_uds_channel(timeout=0.9)
        if not ok and not link.via_gateway and not link._hw_uds:
            link.send_elv_wake_burst(count=4)
            ok, in_bl = link.probe_uds_channel(timeout=1.1)
        if not ok:
            raise RuntimeError(tr("ELV (2B) не отвечает по UDS", "ELV (2B) is not responding to UDS"))
        result["initially_in_bootloader"] = in_bl

        k5_b: bytes | None = _norm_key_16b(current_k5, "current_k5") if current_k5 is not None else None
        pc_val: int | None = _validate_u8(power_class, "power_class") if power_class is not None else None
        idac_b: bytes | None = None
        if idac is not None:
            idac_b = bytes(idac) if isinstance(idac, (bytes, bytearray, memoryview)) else bytes.fromhex("".join(str(idac).split()))
            if len(idac_b) != 2:
                raise ValueError(f"idac must be 2 bytes (4 hex digits), got {len(idac_b)} bytes")
        idp_b: bytes | None = None

        mode = None if in_bl else _read_elv_mode(link)
        result["mode"] = mode

        if not in_bl:
            bl_passport: dict[str, str] = {}
            for k_key, did in (("part_number", 0xF187), ("sw_version", 0xF189), ("system_name", 0xF197)):
                with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    raw_d = link.request_uds(bytes([0x22, (did >> 8) & 0xFF, did & 0xFF]), 0x62, timeout=0.9)[3:]
                    txt_d = _clean_ascii(raw_d)
                    if txt_d:
                        bl_passport[k_key] = txt_d
            if bl_passport:
                bl_prof = elv_detect_profile(bl_passport)
                result["officially_supported"] = bool(bl_prof["verified"])
                result["support_warning"] = bl_prof["warning"]
                if bl_prof["warning"]:
                    reporter.warning(bl_prof["warning"])

        pre_idac_state: int | None = None
        pre_idac_locked: bool | None = None
        if not in_bl and mode == 2:
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                raw_02ee = link.request_uds(b"\x22\x02\xee", 0x62, timeout=0.9)[3:]
                if len(raw_02ee) >= 2:
                    pre_idac_locked = bool(raw_02ee[1] & 0x40)

        # In Adapted Mode 2, `10 02` strictly requires WFS5 `0x01A` Type 1 <-> `0x01B` with `KL15=1`.
        # If credentials were not passed (e.g. GUI before reading DFLASH, or CLI), auto-read DFLASH on raw Komfort CAN.
        if (
            enter_programming
            and not in_bl
            and mode == 2
            and (k5_b is None or pc_val is None or idac_b is None)
        ):
            if link.via_gateway:
                raise RuntimeError(
                    tr(
                        "Вход в бутлодер адаптированного ELV (Mode 2) требует авторизации WFS5 (0x3C0 + 0x01A/0x01B) "
                        "по прямому Komfort CAN или через мост J533 (ch0).",
                        "Entering bootloader on an adapted ELV (Mode 2) requires WFS5 authorization (0x3C0 + 0x01A/0x01B) "
                        "over direct Komfort CAN or J533 Komfort bridge (ch0).",
                    )
                )
            reporter.info(
                tr(
                    "Адаптированный ELV (Mode 2): автоматическое чтение K_5 / PowerClass / IDac из Data Flash…",
                    "Adapted ELV (Mode 2): auto-reading K_5 / PowerClass / IDac from Data Flash…",
                )
            )
            dflash_bytes = link.read_dflash_32k(reporter=reporter)
            parsed = elv_parse_dflash(dflash_bytes)
            if not parsed["all_crc_ok"]:
                raise RuntimeError(
                    tr(
                        f"Ошибка целостности считанного Data Flash ({parsed['crc_valid_count']}/{parsed['crc_total_count']} CRC) — "
                        "авторизация WFS5 отменена.",
                        f"DFLASH integrity check failed ({parsed['crc_valid_count']}/{parsed['crc_total_count']} CRCs) — "
                        "WFS5 authorization aborted.",
                    )
                )
            pre_idac_state = parsed["block04"]["idac_state"]
            slot_a_hex = parsed["block34"]["slot_a_hex"]
            if k5_b is None and len(slot_a_hex) == 32:
                k5_b = bytes.fromhex(slot_a_hex)
            if pc_val is None and parsed["block34"]["power_class"] is not None:
                pc_val = _validate_u8(int(parsed["block34"]["power_class"]), "power_class")
            if idac_b is None and len(parsed["block04"]["idac_hex"]) == 4:
                idac_b = bytes.fromhex(parsed["block04"]["idac_hex"])
            if len(parsed["block04"]["idp_hex"]) == 4:
                idp_b = bytes.fromhex(parsed["block04"]["idp_hex"])

        # Bench WFS5 0x01A/0x01B handshake with IDac=0000 on an unlearned Mode 2 ELV would auto-lock IDac=0x0000 (0xAA).
        # Track this so we automatically reset IDac state back to 0x00 via 22 02E0 -> 2E 02E1 (04 80) after returning to App.
        idac_was_unlearned = pre_idac_state == 0x00 or (pre_idac_state is None and pre_idac_locked is False)
        should_restore_unlearned_idac = bool(
            not in_bl
            and mode == 2
            and idac_was_unlearned
            and idac_b == b"\x00\x00"
            and k5_b is not None
        )

        def _restore_idac_unlearned() -> bool:
            assert k5_b is not None
            try:
                with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    link.request_uds(b"\x10\x03", 0x50, timeout=1.2)
                c_diag = link.request_uds(b"\x22\x02\xe0", 0x62, timeout=1.5)[3:7]
                if len(c_diag) != 4 or c_diag == b"\x00\x00\x00\x00":
                    raise RuntimeError(f"Invalid DID 0x02E0 challenge: {c_diag.hex()}")
                cmd, arg = ELV_CMD_RESET_IDAC
                p4 = elv_build_02e1_payload(k5_b, c_diag, cmd=cmd, arg=arg)
                link.request_uds(b"\x2e\x02\xe1" + p4, 0x6E, timeout=4.0)
                reporter.info(
                    tr(
                        "Состояние IDac автоматически сброшено обратно в 0x00 (автообучение) после проверки загрузчика.",
                        "Automatically restored IDac state back to 0x00 (auto-learn) after bootloader check.",
                    )
                )
                return True
            except Exception as exc:  # noqa: BLE001
                reporter.warning(
                    tr(
                        f"Не удалось автоматически сбросить состояние IDac обратно в 0x00 после проверки загрузчика: {exc}",
                        f"Could not automatically restore IDac state back to 0x00 after bootloader check: {exc}",
                    )
                )
                return False

        bz = 0
        kl15_held = False
        reset_sent = False
        wfs5_ran = False
        idac_restored = False
        try:
            if not in_bl:
                if enter_programming:
                    reporter.step(
                        2,
                        total_steps,
                        tr(
                            "Авторизация WFS5 (0x3C0 KL15=1 + 31 01 02 03 + 0x01A/0x01B)",
                            "WFS5 authorization (0x3C0 KL15=1 + 31 01 02 03 + 0x01A/0x01B)",
                        ),
                    )
                try:
                    use_wfs5_creds = mode != 1 and mode != 0xFF
                    will_send_kl15 = enter_programming or (
                        use_wfs5_creds and k5_b is not None and pc_val is not None and idac_b is not None
                    )
                    if (
                        not link.via_gateway
                        and use_wfs5_creds
                        and k5_b is not None
                        and pc_val is not None
                        and idac_b is not None
                    ):
                        wfs5_ran = True
                    body, bz, wfs5_ok, wfs5_info = _request_31_01_02_03_with_wfs5(
                        link,
                        k5=k5_b if use_wfs5_creds else None,
                        power_class=pc_val if use_wfs5_creds else None,
                        idac=idac_b if use_wfs5_creds else None,
                        expected_idp=idp_b,
                        send_kl15=enter_programming,
                        bz=bz,
                    )
                    kl15_held = not link.via_gateway and will_send_kl15
                    result["preconditions_raw_hex"] = body.hex().upper()
                    result["preconditions_ok"] = len(body) == 0 or body == b"\x00"
                    result["preconditions_reasons"] = _decode_precondition_codes(body)
                    result["wfs5_handshake_ok"] = wfs5_ok
                    if wfs5_info is not None:
                        result["wfs5_handshake"] = wfs5_info
                except UdsNegativeResponse as exc:
                    result["preconditions_error"] = f"NRC 0x{exc.nrc:02X}"

            if not enter_programming:
                return result

            if not in_bl and not result["preconditions_ok"]:
                reasons = ", ".join(result["preconditions_reasons"]) or result.get("preconditions_error") or result["preconditions_raw_hex"] or "unknown"
                raise RuntimeError(
                    tr(
                        f"Условия программирования (31 01 02 03) не выполнены: {reasons}",
                        f"Programming preconditions (31 01 02 03) not met: {reasons}",
                    )
                )

            reporter.step(
                3,
                total_steps,
                tr("Вход в загрузчик (10 02), проверка SecurityAccess (27 11/12) и возврат (11 01)", "Entering bootloader (10 02), testing SecurityAccess (27 11/12) & resetting (11 01)"),
            )
            if not in_bl:
                # Keep KL15=1 fresh on 0x3C0 right before 10 02 — turning KL15 off clears `DAT_ram_ffffbfdc & 0x10`!
                if not link.via_gateway:
                    link.send_kl_status(bz & 0x0F, kl_s=True, kl_15=True)
                    bz = (bz + 1) & 0x0F
                link.request_uds(b"\x10\x02", 0x50, timeout=4.5)
            result["programming_session_ok"] = True

            resp_seed = link.request_uds(b"\x27\x11", 0x67, timeout=2.0)
            if len(resp_seed) >= 6:
                seed_u32 = struct.unpack_from(">I", resp_seed, 2)[0]
                key_u32 = elv_bootloader_seed_to_key(seed_u32)
                result["bootloader_seed_hex"] = f"{seed_u32:08X}"
                result["bootloader_key_hex"] = f"{key_u32:08X}"
                if seed_u32 != 0:
                    link.request_uds(b"\x27\x12" + struct.pack(">I", key_u32), 0x67, timeout=2.0)
                result["security_access_ok"] = True

            # Bootloader ECUReset (`FUN_ram_00008502`) ONLY accepts subfunction `0x01` (HardReset); `0x02` returns NRC 0x12.
            reset_sent = True
            with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                link.request_uds(b"\x11\x01", 0x51, timeout=3.0)
            if not _is_in_memory_bus(link):
                time.sleep(0.35)
                link.send_elv_wake_burst(2)
                time.sleep(0.05)
            post_ok, post_in_bl = link.probe_uds_channel(timeout=1.0)
            result["returned_to_app"] = bool(post_ok and not post_in_bl)
            if should_restore_unlearned_idac and wfs5_ran and result["returned_to_app"]:
                result["idac_auto_restored"] = _restore_idac_unlearned()
                idac_restored = True
        finally:
            if result.get("programming_session_ok") is True and not reset_sent:
                # Never leave ELV stuck in Bootloader Programming Session if 27 11/12 fails
                with contextlib.suppress(*TRANSPORT_ERRORS, UdsNegativeResponse, UnexpectedUdsResponse):
                    link.request_uds(b"\x11\x01", 0x51, timeout=3.0)
                if not _is_in_memory_bus(link):
                    time.sleep(0.35)
                    link.send_elv_wake_burst(2)
                    time.sleep(0.05)
            if kl15_held and not link.via_gateway:
                for _ in range(3):
                    with contextlib.suppress(*TRANSPORT_ERRORS):
                        link.send_kl_status(bz & 0x0F, kl_s=False, kl_15=False)
                    bz = (bz + 1) & 0x0F
                    if not _is_in_memory_bus(link):
                        time.sleep(0.02)
            if should_restore_unlearned_idac and wfs5_ran and not idac_restored:
                post_ok, post_in_bl = link.probe_uds_channel(timeout=1.0)
                if post_ok and not post_in_bl:
                    result["idac_auto_restored"] = _restore_idac_unlearned()
                    idac_restored = True

    return result
