"""Host-side controller for the Continental J533 transparent RSCAN0 CAN bridge RAM-applet.

Turns a supported Continental 3Q0 907 530 gateway connected on Diagnosis CAN (RSCAN0 ch3) into a temporary,
strictly ordered, bidirectional 11-bit + 29-bit CAN bridge to one of its vehicle sub-buses (default ch0
Komfort CAN: Kombi 17 FPK_E and BCM 09). No flash memory on the gateway is modified: on exit (or idle timeout)
the applet triggers a hardware `SWRESA` reset so the gateway boots cleanly back into its normal Application.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
import time
from typing import Any

import can

from contitool.can.hw_applets import (
    J533_BRIDGE_BURST_DATA,
    J533_BRIDGE_BURST_FAIL,
    J533_BRIDGE_BURST_ID,
    J533_BRIDGE_BURST_OK,
    J533_BRIDGE_END_DATA,
    J533_BRIDGE_END_ID,
    J533_BRIDGE_READY_DATA,
    J533_BRIDGE_READY_ID,
    J533_BRIDGE_STOP_DATA,
    J533_BRIDGE_STOP_ID,
    J533_BUS_CHANNELS,
    build_j533_can_bridge_applet,
)
from contitool.can.transport import J533CanLink, UdsNegativeResponse, UnexpectedUdsResponse
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter

BRIDGE_NATIVE_INTERFACES: tuple[str, ...] = ("slcan", "gs_usb", "socketcan", "pcan", "kvaser", "vector")


def bridge_bus_ok(interface: str, bus: Any = None) -> bool:
    """The adapter can carry the bridge: a native one, or a VAS 6154 / VNCI whose RawMode passes every CAN id."""
    return interface in BRIDGE_NATIVE_INTERFACES or bool(getattr(bus, "every_id_raw", False))


def bridge_bus_label(channel: int) -> str:
    """Localized human-readable label for a J533 RSCAN0 sub-bus channel."""
    spec = J533_BUS_CHANNELS.get(channel)
    if spec is None:
        return f"ch{channel}"
    _, ru, en = spec
    return f"ch{channel} — {tr(ru, en)}"


def _no_bridge_adapter(interface: str) -> RuntimeError:
    return RuntimeError(
        tr(
            f"Прозрачный CAN-мост через шлюз J533 требует адаптер с произвольным raw CAN (11 и 29 бит): "
            f"CANable / SLCAN / candleLight / SocketCAN / PCAN / Kvaser / Vector или VAS 6154 / VNCI, "
            f"принимающий в RawMode все идентификаторы. Интерфейс «{interface}» так не может (VNCI без RawMode, "
            f"VNCI, которому нужен запуск CAN1 каналом ISO-TP, или J2534 через драйвер VW).",
            f"The J533 transparent CAN bridge needs an adapter with arbitrary raw CAN (11- and 29-bit): "
            f"CANable / SLCAN / candleLight / SocketCAN / PCAN / Kvaser / Vector, or a VAS 6154 / VNCI whose RawMode "
            f"receives every identifier. Interface “{interface}” cannot (a VNCI without RawMode, a VNCI that needs "
            f"CAN1 started by an ISO-TP link, or J2534 through the VW driver).",
        )
    )


class J533CanBridge:
    """Context manager running the J533 RSCAN0 transparent CAN bridge applet for one operation."""

    def __init__(
        self,
        port: str,
        *,
        interface: str = "slcan",
        target_channel: int = 0,
        log_path: Path | None = None,
        bus: Any | None = None,
        idle_limit: int = 40_000_000,
        ready_timeout: float = 4.0,
        reset_wait: float | None = None,
        verify_app_return: bool = True,
        burst_frames: list[tuple[int, bytes]] | None = None,
        target_rx_filter: list[tuple[int, bool]] | tuple[tuple[int, bool], ...] | None = None,
        reporter: OperationReporter = NULL_REPORTER,
    ) -> None:
        if target_channel not in J533_BUS_CHANNELS:
            raise ValueError(
                f"Unsupported J533 bridge target_channel={target_channel} (expected one of {tuple(J533_BUS_CHANNELS)})"
            )
        if bus is None and interface not in BRIDGE_NATIVE_INTERFACES and interface != "dpdu":
            raise _no_bridge_adapter(interface)
        self.port = port
        self.interface = interface
        self.target_channel = target_channel
        self.log_path = log_path
        self._injected_bus = bus
        self.idle_limit = idle_limit
        self.ready_timeout = ready_timeout
        self.reset_wait = (0.05 if bus is not None else 1.4) if reset_wait is None else reset_wait
        self.verify_app_return = verify_app_return
        self.burst_frames = list(burst_frames) if burst_frames else None
        self.target_rx_filter = tuple((int(cid), bool(ext)) for cid, ext in target_rx_filter) if target_rx_filter else None
        self.reporter = reporter

        self._link: J533CanLink | None = None
        self._applet_sent: bool = False
        self.active: bool = False
        self.loader_info: dict[str, Any] = {}
        self.stop_info: dict[str, Any] = {}

    @property
    def bus(self) -> Any:
        if self._link is None:
            raise RuntimeError("J533CanBridge is not open")
        return self._link.bus

    @property
    def link(self) -> J533CanLink:
        if self._link is None:
            raise RuntimeError("J533CanBridge is not open")
        return self._link

    def _wait_beacon(self, arb_id: int, expected: bytes, timeout: float) -> bool:
        assert self._link is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rem = max(0.02, deadline - time.monotonic())
            try:
                msg = self._link.receive_frame(arb_id, timeout=rem)
            except TimeoutError:
                return False
            if bytes(msg.data) == expected:
                return True
        return False

    def start(self) -> J533CanBridge:
        from contitool.can.fpke import close_active_fpke_link
        from contitool.can.workflows import enter_ram_loader

        if self._injected_bus is None:
            close_active_fpke_link()

        bus_lbl = bridge_bus_label(self.target_channel)
        self.reporter.info(
            tr(
                f"Запуск прозрачного CAN-моста в шлюзе J533 (Diag CAN ch3 ↔ {bus_lbl})…",
                f"Starting transparent CAN bridge in J533 gateway (Diag CAN ch3 ↔ {bus_lbl})…",
            )
        )
        link = J533CanLink(
            self.port,
            interface=self.interface,
            log_path=self.log_path,
            bus=self._injected_bus,
        )
        self._link = link
        try:
            if self._injected_bus is None and not bridge_bus_ok(self.interface, link.bus):
                raise _no_bridge_adapter(self.interface)
            # On a fresh D-PDU session whose RawMode monitor has not yet seen a live bus frame, send one read-only
            # `10 03` check BEFORE entering `10 02` / RAM-Loader so a VNCI that needs CAN1 priming or falls back to
            # fixed-ID / UDS-only fails fast without disturbing the gateway.
            if (
                self._injected_bus is None
                and self.interface == "dpdu"
                and not getattr(link.bus, "_raw_rx_verified", False)
                and callable(getattr(link.bus, "fallback_from_silent_raw", None))
            ):
                with contextlib.suppress(TimeoutError, UdsNegativeResponse, UnexpectedUdsResponse):
                    link.request_uds(b"\x10\x03", 0x50, timeout=1.0)
                if not bridge_bus_ok(self.interface, link.bus):
                    raise _no_bridge_adapter(self.interface)
            self.loader_info = enter_ram_loader(link, reporter=self.reporter)
            # A VNCI may still turn out to need CAN1 primed while entering the loader (its monitor then filters ids)
            if self._injected_bus is None and not bridge_bus_ok(self.interface, link.bus):
                raise _no_bridge_adapter(self.interface)
            applet = build_j533_can_bridge_applet(
                self.target_channel,
                idle_limit=self.idle_limit,
                burst_frames=self.burst_frames,
                target_rx_filter=self.target_rx_filter,
            )
            filter_note = f", GAFL={len(self.target_rx_filter)} ID" if self.target_rx_filter else ""
            self.reporter.can_log(
                tr(
                    f"Загрузка RAM-апплета CAN-моста ({len(applet)} Б, ch3 ↔ ch{self.target_channel}{filter_note})…",
                    f"Uploading CAN-bridge RAM applet ({len(applet)} B, ch3 ↔ ch{self.target_channel}{filter_note})…",
                )
            )
            self._applet_sent = True
            link.send_loader_payload(
                applet,
                inter_frame_delay=0.0 if self._injected_bus is not None else 0.003,
                reporter=self.reporter,
                progress_label=f"J533 bridge ch{self.target_channel}",
            )
            if not self._wait_beacon(J533_BRIDGE_READY_ID, J533_BRIDGE_READY_DATA, self.ready_timeout):
                raise TimeoutError(
                    tr(
                        f"Шлюз J533 не подтвердил запуск CAN-моста (ожидался маяк 0x{J533_BRIDGE_READY_ID:03X} = J533BRDG).",
                        f"J533 gateway did not confirm CAN bridge startup (expected 0x{J533_BRIDGE_READY_ID:03X} = J533BRDG beacon).",
                    )
                )
            self.active = True
            self.reporter.success(
                tr(
                    f"Прозрачный CAN-мост J533 активен (Diag CAN ch3 ↔ {bus_lbl}).",
                    f"J533 transparent CAN bridge is active (Diag CAN ch3 ↔ {bus_lbl}).",
                )
            )
            return self
        except BaseException:
            self._close_safely(had_error=True)
            raise

    def stop(self) -> dict[str, Any]:
        return self._close_safely(had_error=False)

    def fire_burst(self, frames: list[tuple[int, bytes]], *, timeout: float = 5.0) -> None:
        """Have the gateway send its preloaded frames on the sub-bus itself, at CAN pace (`0x6F0 BURST-GO`).

        The gateway can only send the table uploaded with the applet, so `frames` must equal it: the caller asks for
        exactly the stream that will go out. Whether that stream suits the ECU is the caller's check."""
        if not self.active:
            raise RuntimeError(tr(
                "CAN-мост в шлюзе J533 не запущен — поток не отправлен.",
                "The J533 CAN bridge is not running — the stream was not sent.",
            ))
        if self.burst_frames is None or list(frames) != self.burst_frames:
            raise RuntimeError(tr(
                "Поток не отправлен: он не совпадает с таблицей кадров, загруженной в шлюз J533 вместе с мостом "
                "(или таблица не загружалась).",
                "The stream was not sent: it differs from the frame table uploaded to the J533 gateway with the "
                "bridge (or no table was uploaded).",
            ))
        self.link.send_frame(J533_BRIDGE_BURST_ID, J533_BRIDGE_BURST_DATA)
        end = time.monotonic() + timeout
        while (rem := end - time.monotonic()) > 0:
            try:
                data = bytes(self.link.receive_frame(J533_BRIDGE_END_ID, timeout=rem).data)
            except TimeoutError:
                break
            if data == J533_BRIDGE_BURST_OK:
                return
            if data == J533_BRIDGE_BURST_FAIL:
                raise RuntimeError(tr(
                    f"Шлюз J533 не смог отправить поток в {bridge_bus_label(self.target_channel)}: кадр не получил "
                    f"подтверждения (ACK), остаток потока отброшен. Проверьте питание блока и провода шины.",
                    f"The J533 gateway could not send the stream on {bridge_bus_label(self.target_channel)}: a frame "
                    f"got no ACK and the rest was dropped. Check the ECU power and the bus wiring.",
                ))
        raise TimeoutError(tr(
            f"Шлюз J533 не подтвердил отправку потока (ожидался 0x{J533_BRIDGE_END_ID:03X} BURST-OK).",
            f"The J533 gateway did not confirm the stream (expected 0x{J533_BRIDGE_END_ID:03X} BURST-OK).",
        ))

    def _close_safely(self, *, had_error: bool) -> dict[str, Any]:
        from contitool.can.workflows import LINK_ERRORS, _probe_app_or_fbl, _reset_to_application

        info: dict[str, Any] = {"was_active": self.active, "end_ack": False, "returned_to_app": False}
        link = self._link
        if link is None:
            return info

        try:
            if self.active or (had_error and self._applet_sent):
                was_active = self.active
                if was_active:
                    self.reporter.info(
                        tr(
                            "Закрытие CAN-моста и возврат шлюза J533 в штатный режим…",
                            "Closing CAN bridge and returning J533 gateway to Application mode…",
                        )
                    )
                with contextlib.suppress(*LINK_ERRORS):
                    link.drain_rx(max_frames=256, quick=True)
                ack = False
                for _attempt in range(3):
                    if getattr(getattr(link, "bus", None), "spent", False):
                        break
                    with contextlib.suppress(*LINK_ERRORS):
                        link.send_frame(J533_BRIDGE_STOP_ID, J533_BRIDGE_STOP_DATA)
                    try:
                        if self._wait_beacon(J533_BRIDGE_END_ID, J533_BRIDGE_END_DATA, 0.5):
                            ack = True
                            break
                    except LINK_ERRORS:
                        if getattr(getattr(link, "bus", None), "spent", False):
                            break
                info["end_ack"] = ack
                self.active = False

                if was_active or ack:
                    if self.reset_wait > 0:
                        time.sleep(self.reset_wait)

                    if self.verify_app_return:
                        try:
                            sess, in_fbl = _probe_app_or_fbl(link, attempts=8, allow_fbl=True)
                            info["session_after"] = sess
                            info["in_fbl"] = in_fbl
                            info["returned_to_app"] = not in_fbl
                            if not in_fbl:
                                self.reporter.can_log(
                                    tr(
                                        "Шлюз J533 вернулся в штатное приложение.",
                                        "J533 gateway returned to Application mode.",
                                    )
                                )
                            else:
                                self.reporter.warning(
                                    tr(
                                        "Внимание: шлюз J533 после выхода из CAN-моста остался в загрузчике FBL.",
                                        "Warning: J533 gateway remained in FBL bootloader after exiting the CAN bridge.",
                                    )
                                )
                        except LINK_ERRORS as exc:
                            info["return_error"] = str(exc)
                            self.reporter.warning(
                                tr(
                                    f"Не удалось подтвердить возврат шлюза J533 в штатное приложение ({exc}). "
                                    "При необходимости выключите и включите зажигание (или перезапустите питание).",
                                    f"Could not verify that the J533 gateway returned to Application mode ({exc}). "
                                    "Cycle ignition (or bench power) if needed.",
                                )
                            )
                elif had_error and self.loader_info.get("loader_ready"):
                    # Applet was sent but did not acknowledge STOPBRDG — try factory RAM-Loader reset as fallback
                    with contextlib.suppress(*LINK_ERRORS, can.CanError):
                        _reset_to_application(link, reporter=self.reporter, allow_fbl=True)
            elif had_error and self.loader_info.get("loader_ready"):
                # Failed before bridge became active while J533 was already in RAM-Loader: return it cleanly
                with contextlib.suppress(*LINK_ERRORS, can.CanError):
                    _reset_to_application(link, reporter=self.reporter, allow_fbl=True)
        finally:
            self.active = False
            self._applet_sent = False
            self._link = None
            with contextlib.suppress(Exception):
                link.close()
        self.stop_info = info
        return info

    def __enter__(self) -> J533CanBridge:
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._close_safely(had_error=exc_type is not None)


def j533_can_bridge(
    port: str,
    *,
    interface: str = "slcan",
    target_channel: int = 0,
    log_path: Path | None = None,
    bus: Any | None = None,
    idle_limit: int = 40_000_000,
    ready_timeout: float = 4.0,
    reset_wait: float | None = None,
    verify_app_return: bool = True,
    burst_frames: list[tuple[int, bytes]] | None = None,
    target_rx_filter: list[tuple[int, bool]] | tuple[tuple[int, bool], ...] | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> J533CanBridge:
    """Create a `J533CanBridge` context manager bridging Diagnosis CAN (`ch3`) <-> `target_channel`."""
    return J533CanBridge(
        port,
        interface=interface,
        target_channel=target_channel,
        log_path=log_path,
        bus=bus,
        idle_limit=idle_limit,
        ready_timeout=ready_timeout,
        reset_wait=reset_wait,
        verify_app_return=verify_app_return,
        burst_frames=burst_frames,
        target_rx_filter=target_rx_filter,
        reporter=reporter,
    )
