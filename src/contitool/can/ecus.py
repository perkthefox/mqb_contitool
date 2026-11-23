"""Multi-ECU registry, CAN topology discovery (`can_scan_bus`), and generic UDS slave diagnostics.

Supports both:
  - **Gateway topology**: connected to J533 Diagnosis CAN (`0x710/0x77A`), discovering the gateway (`19`) and
    connected slave ECUs behind it (`17` Kombi FPK_E `0x714/0x77E`, `09` BCM `0x70E/0x778`, extensible).
    When the gateway is a supported Continental `3Q0 907 530`, Level-2 transparent RAM-bridging unlocks full
    non-UDS memory access (e.g. FPK_E Level 8) directly through Diagnosis CAN.
  - **Direct CAN topology**: connected directly to a single ECU (or a gateway-less multi-ECU bench harness).
"""

from __future__ import annotations

import contextlib
import dataclasses
from typing import Any

from contitool.can.bridge import BRIDGE_NATIVE_INTERFACES, bridge_bus_label, bridge_bus_ok
from contitool.can.transport import J533CanLink
from contitool.i18n import tr
from contitool.progress import NULL_REPORTER, OperationReporter


@dataclasses.dataclass(frozen=True)
class EcuSpec:
    """Static protocol descriptor for one supported or recognized VAG MQB control unit."""

    kind: str  # "j533" | "fpke" | "bcm"
    diag_addr: str  # VW address hex: "19", "17", "09"
    uds_tx_id: int
    uds_rx_id: int
    name_ru: str
    name_en: str
    short_ru: str
    short_en: str
    is_gateway: bool = False
    gateway_channel: int | None = None  # J533 RSCAN0 channel (0 = Komfort CAN)
    needs_bridge_for_memory: bool = False
    needs_direct_wake: bool = False
    full_support: bool = True

    @property
    def name(self) -> str:
        return tr(self.name_ru, self.name_en)

    @property
    def short_name(self) -> str:
        return tr(self.short_ru, self.short_en)


ECU_SPECS: tuple[EcuSpec, ...] = (
    EcuSpec(
        kind="j533",
        diag_addr="19",
        uds_tx_id=0x710,
        uds_rx_id=0x77A,
        name_ru="Шлюз J533 (19)",
        name_en="J533 Gateway (19)",
        short_ru="Шлюз J533",
        short_en="J533 Gateway",
        is_gateway=True,
        gateway_channel=None,
        needs_bridge_for_memory=False,
        needs_direct_wake=False,
        full_support=True,
    ),
    EcuSpec(
        kind="fpke",
        diag_addr="17",
        uds_tx_id=0x714,
        uds_rx_id=0x77E,
        name_ru="Панель приборов Kombi / FPK_E (17)",
        name_en="Kombi / FPK_E Instrument Cluster (17)",
        short_ru="Панель приборов",
        short_en="FPK_E Cluster",
        is_gateway=False,
        gateway_channel=0,  # Komfort CAN (RSCAN0 ch0, STB=P11_12)
        needs_bridge_for_memory=True,
        needs_direct_wake=True,
        full_support=True,
    ),
    EcuSpec(
        kind="bcm",
        diag_addr="09",
        uds_tx_id=0x70E,
        uds_rx_id=0x778,
        name_ru="Блок бортовой сети BCM / J519 (09)",
        name_en="Central Electrics BCM / J519 (09)",
        short_ru="BCM (09)",
        short_en="BCM (09)",
        is_gateway=False,
        gateway_channel=0,  # Komfort CAN (RSCAN0 ch0, STB=P11_12)
        needs_bridge_for_memory=True,
        needs_direct_wake=True,
        full_support=True,
    ),
)

ECU_SPEC_BY_KIND: dict[str, EcuSpec] = {s.kind: s for s in ECU_SPECS}
ECU_SPEC_BY_ADDR: dict[str, EcuSpec] = {s.diag_addr.upper(): s for s in ECU_SPECS}
SLAVE_ECU_SPECS: tuple[EcuSpec, ...] = tuple(s for s in ECU_SPECS if not s.is_gateway)


def get_ecu_spec(kind: str) -> EcuSpec:
    key = kind.strip().lower()
    if key not in ECU_SPEC_BY_KIND:
        raise ValueError(f"Unknown ECU kind: {kind!r} (expected one of {tuple(ECU_SPEC_BY_KIND)})")
    return ECU_SPEC_BY_KIND[key]


@dataclasses.dataclass
class DiscoveredEcu:
    """One control unit discovered during a CAN bus scan."""

    kind: str
    diag_addr: str
    uds_tx_id: int
    uds_rx_id: int
    ident: list[dict[str, str]]
    via_gateway: bool = False
    gateway_channel: int | None = None
    bridge_available: bool = False
    in_fbl: bool = False
    app_valid: bool | None = None
    f1df: str | None = None
    unsupported: str | None = None
    memory_unavailable_reason: str | None = None
    capabilities: tuple[str, ...] = ("uds",)

    @property
    def spec(self) -> EcuSpec:
        return ECU_SPEC_BY_KIND[self.kind]

    def did_value(self, did: str) -> str:
        want = did.upper()
        for item in self.ident:
            if str(item.get("did", "")).upper() == want:
                return str(item.get("value", "")).strip()
        return ""

    @property
    def part_number(self) -> str:
        return self.did_value("F187") or self.did_value("F191") or self.spec.short_name

    @property
    def sw_version(self) -> str:
        return self.did_value("F189")

    @property
    def hw_number(self) -> str:
        return self.did_value("F191")

    @property
    def hw_version(self) -> str:
        return self.did_value("F1A3")

    @property
    def system_name(self) -> str:
        return self.did_value("F197")

    @property
    def fazit(self) -> str:
        return self.did_value("F17C")

    @property
    def vin(self) -> str:
        return self.did_value("F190")

    @property
    def can_read_memory(self) -> bool:
        return "memory" in self.capabilities or "bridge_memory" in self.capabilities

    @property
    def memory_access_available(self) -> bool:
        return self.can_read_memory

    @property
    def uds_available(self) -> bool:
        return "uds" in self.capabilities

    @property
    def unsupported_reason(self) -> str | None:
        return self.unsupported

    @property
    def bus_label(self) -> str:
        if self.gateway_channel is not None:
            return bridge_bus_label(self.gateway_channel)
        return tr("Прямой CAN", "Direct CAN")

    @property
    def access_summary(self) -> str:
        if self.unsupported:
            return tr("Не поддерживается", "Unsupported")
        if self.in_fbl:
            return tr("Загрузчик FBL (приложение не запущено)", "FBL bootloader (application not running)")
        if self.kind == "j533":
            return tr("Прямой CAN, RAM-Loader", "Direct CAN, RAM-Loader")
        if self.kind == "fpke":
            if self.via_gateway:
                if self.bridge_available:
                    ch = 0 if self.gateway_channel is None else self.gateway_channel
                    return tr(
                        f"Через шлюз J533 (RAM-мост ch{ch})",
                        f"Via J533 gateway (RAM bridge ch{ch})",
                    )
                return tr("Через шлюз (только UDS)", "Via gateway (UDS only)")
            if self.can_read_memory:
                return tr("Прямой CAN, полный доступ", "Direct CAN, full access")
            return tr("Прямой CAN (только UDS)", "Direct CAN (UDS only)")
        if self.kind == "bcm":
            if self.via_gateway:
                if self.bridge_available:
                    ch = 0 if self.gateway_channel is None else self.gateway_channel
                    return tr(
                        f"Через шлюз J533 (RAM-мост ch{ch}: IKA/GFA/FFB)",
                        f"Via J533 gateway (RAM bridge ch{ch}: IKA/GFA/FFB)",
                    )
                return tr(
                    "Через шлюз (UDS: статус / запись IKA и GFA)",
                    "Via gateway (UDS: status / write IKA & GFA)",
                )
            if self.can_read_memory:
                return tr(
                    "Прямой CAN Komfort, полный доступ (IKA/GFA/FFB)",
                    "Direct Komfort CAN, full access (IKA/GFA/FFB)",
                )
            return tr("Прямой CAN (только UDS)", "Direct CAN (UDS only)")
        return tr("UDS", "UDS")

    def to_ident_dict(self) -> dict[str, Any]:
        """Backward-compatible `can_identify()` result dictionary enriched with topology metadata."""
        out: dict[str, Any] = {
            "responding": True,
            "ecu_kind": self.kind,
            "diag_addr": self.diag_addr,
            "uds_tx_id": f"0x{self.uds_tx_id:03X}",
            "uds_rx_id": f"0x{self.uds_rx_id:03X}",
            "ident": list(self.ident),
            "via_gateway": self.via_gateway,
            "gateway_channel": self.gateway_channel,
            "bridge_available": self.bridge_available,
            "capabilities": list(self.capabilities),
        }
        if self.in_fbl:
            out["in_fbl"] = True
        if self.app_valid is not None:
            out["app_valid"] = self.app_valid
        if self.f1df is not None:
            out["f1df"] = self.f1df
        if self.unsupported:
            out["unsupported"] = self.unsupported
        if self.memory_unavailable_reason:
            out["memory_unavailable_reason"] = self.memory_unavailable_reason
        return out


@dataclasses.dataclass
class BusScanResult:
    """Result of scanning the CAN bus for a gateway and all supported/recognized control units."""

    topology: str  # "gateway" | "direct" | "none"
    ecus: list[DiscoveredEcu]
    port: str = ""
    interface: str = "slcan"
    gateway: DiscoveredEcu | None = None
    gateway_bridge_capable: bool = False
    adapter_warning: str | None = None
    scan_notes: list[str] = dataclasses.field(default_factory=list)
    scanned_targets: tuple[str, ...] = ()

    def find(self, kind: str) -> DiscoveredEcu | None:
        want = kind.strip().lower()
        return next((e for e in self.ecus if e.kind == want), None)

    @property
    def slaves(self) -> list[DiscoveredEcu]:
        return [e for e in self.ecus if not e.spec.is_gateway]

    def to_dict(self) -> dict[str, Any]:
        return {
            "topology": self.topology,
            "port": self.port,
            "interface": self.interface,
            "gateway_bridge_capable": self.gateway_bridge_capable,
            "adapter_warning": self.adapter_warning,
            "scan_notes": list(self.scan_notes),
            "ecus": [e.to_ident_dict() for e in self.ecus],
        }


def _read_ident_dids(
    link: J533CanLink,
    *,
    keepalive_direct_fpke: bool = False,
    reporter: OperationReporter = NULL_REPORTER,
) -> list[dict[str, str]]:
    from contitool.can.fpke import FPKE_KEEPALIVE_PATTERN
    from contitool.can.workflows import ECU_IDENT_DIDS, LINK_ERRORS

    ident: list[dict[str, str]] = []
    for did, ru, en in ECU_IDENT_DIDS:
        if keepalive_direct_fpke:
            for arb_id, ka_data in FPKE_KEEPALIVE_PATTERN:
                with contextlib.suppress(*LINK_ERRORS):
                    link.send_frame(arb_id, ka_data)
        try:
            raw = link.request_uds(bytes([0x22, did >> 8, did & 0xFF]), 0x62, timeout=1.5)[3:]
        except LINK_ERRORS:
            continue
        if did == 0xF190 and raw in (b"", b"\x00" * len(raw), b"\xff" * len(raw), b"-" * len(raw)):
            continue
        text = raw.rstrip(b"\x00 ").decode("latin-1")
        value = text.strip() if text and all(32 <= ord(ch) < 127 for ch in text) else raw.hex().upper()
        ident.append({"did": f"{did:04X}", "label_ru": ru, "label_en": en, "value": value})
        reporter.can_log(f"  {did:04X} {tr(ru, en)}: {value}")
    return ident


def _probe_uds_1003(link: J533CanLink, tx_id: int, rx_id: int, *, timeout: float) -> tuple[bool, bool]:
    """Probe `(tx_id -> rx_id)` with `10 03` (+ `3E 00`). Returns `(responding, in_fbl)`."""
    from contitool.can.transport import UdsNegativeResponse
    from contitool.can.workflows import LINK_ERRORS, _is_fbl_session_nrc

    link.UDS_TX_ID = tx_id
    link.UDS_RX_ID = rx_id
    try:
        link.request_uds(b"\x10\x03", 0x50, timeout=timeout)
        with contextlib.suppress(*LINK_ERRORS):
            link.request_uds(b"\x3e\x00", 0x7E, timeout=min(0.4, timeout))
        return True, False
    except UdsNegativeResponse as exc:
        if _is_fbl_session_nrc(exc):
            return True, True
        # Non-FBL NRC (e.g. 0x22 conditionsNotCorrect on BCM with KL15 off): ECU IS responding on rx_id
        with contextlib.suppress(*LINK_ERRORS):
            link.request_uds(b"\x10\x01", 0x50, timeout=min(0.4, timeout))
        return True, False
    except LINK_ERRORS:
        return False, False


def _build_gateway_ecu(link: J533CanLink, in_fbl: bool, reporter: OperationReporter) -> DiscoveredEcu:
    from contitool.can.workflows import APP_ONLY_DIDS, LINK_ERRORS, unsupported_ecu_reason

    spec = ECU_SPEC_BY_KIND["j533"]
    ident = _read_ident_dids(link, reporter=reporter)
    answered = {item["did"] for item in ident}
    f1df_hex: str | None = None
    app_valid: bool | None = None
    if in_fbl or not ({f"{did:04X}" for did in APP_ONLY_DIDS} & answered):
        try:
            raw_df = link.request_uds(b"\x22\xf1\xdf", 0x62, timeout=1.0)
            if len(raw_df) >= 4:
                f1df_val = raw_df[3]
                f1df_hex = f"{f1df_val:02X}"
                if f1df_val & 0x04:
                    in_fbl = True
                    app_valid = False
        except LINK_ERRORS:
            pass
    unsupported = unsupported_ecu_reason(ident)
    caps: tuple[str, ...] = ("uds",) if unsupported else ("uds", "memory", "backup", "restore")
    return DiscoveredEcu(
        kind="j533",
        diag_addr=spec.diag_addr,
        uds_tx_id=spec.uds_tx_id,
        uds_rx_id=spec.uds_rx_id,
        ident=ident,
        via_gateway=False,
        gateway_channel=None,
        bridge_available=False,
        in_fbl=in_fbl,
        app_valid=app_valid,
        f1df=f1df_hex,
        unsupported=unsupported,
        capabilities=caps,
    )


def _build_slave_ecu(
    spec: EcuSpec,
    ident: list[dict[str, str]],
    *,
    via_gateway: bool,
    gateway_bridge_capable: bool,
    interface: str,
    bus_injected: bool,
    in_fbl: bool,
    bridge_adapter_ok: bool = False,
) -> DiscoveredEcu:
    """`bridge_adapter_ok`: the scan found the adapter able to carry the J533 bridge (`bridge_bus_ok`)."""
    native_ok = bus_injected or (interface in BRIDGE_NATIVE_INTERFACES)
    if spec.kind == "fpke":
        if via_gateway:
            if gateway_bridge_capable:
                caps: tuple[str, ...] = ("uds", "memory", "bridge_memory")
                mem_err: str | None = None
            elif not bridge_adapter_ok:
                caps = ("uds",)
                mem_err = tr(
                    "Чтение и запись памяти приборной панели FPK_E через шлюз требуют для прозрачного RAM-моста "
                    "адаптер с произвольным raw CAN (CANable / SLCAN / candleLight или VNCI, принимающий в RawMode "
                    "все идентификаторы). UDS-диагностика, DTC, опрос катушки и обучение ключей доступны через "
                    "текущий адаптер.",
                    "Reading/writing FPK_E memory through a gateway requires an adapter with arbitrary raw CAN for the "
                    "transparent RAM bridge (CANable / SLCAN / candleLight, or a VNCI whose RawMode receives every "
                    "identifier). UDS diagnostics, DTC, LF coil polling, and key learning work over the current adapter.",
                )
            else:
                caps = ("uds",)
                mem_err = tr(
                    "Шлюз на шине не поддерживает RAM-мост Continental 3Q0 907 530. Через него доступна "
                    "UDS-диагностика панели приборов FPK_E (DTC, иммо, катушка, обучение ключей, чтение по FD11); "
                    "для чтения и записи памяти подключитесь напрямую к CAN панели приборов (T18) "
                    "или используйте шлюз Continental 3Q0 907 530.",
                    "The gateway on the bus does not support the Continental 3Q0 907 530 RAM bridge. UDS operations "
                    "on FPK_E (DTC, immo, coil, key learning, known-key FD11 read) are available; for memory "
                    "read/write, connect directly to the cluster CAN (T18) or use a Continental 3Q0 907 530 gateway.",
                )
            return DiscoveredEcu(
                kind="fpke",
                diag_addr=spec.diag_addr,
                uds_tx_id=spec.uds_tx_id,
                uds_rx_id=spec.uds_rx_id,
                ident=ident,
                via_gateway=True,
                gateway_channel=spec.gateway_channel,
                bridge_available=gateway_bridge_capable,
                in_fbl=in_fbl,
                memory_unavailable_reason=mem_err,
                capabilities=caps,
            )

        # Direct CAN connection to FPK_E
        if native_ok:
            return DiscoveredEcu(
                kind="fpke",
                diag_addr=spec.diag_addr,
                uds_tx_id=spec.uds_tx_id,
                uds_rx_id=spec.uds_rx_id,
                ident=ident,
                via_gateway=False,
                gateway_channel=None,
                bridge_available=False,
                in_fbl=in_fbl,
                capabilities=("uds", "memory"),
            )
        fpke_unsupported = tr(
            "Работа с панелью приборов Kombi / FPK_E поддерживается только через нативный CAN-адаптер "
            "(CANable / SLCAN / candleLight). Чтение и запись через VNCI / D-PDU / J2534 для панели приборов не поддерживаются.",
            "Kombi / FPK_E instrument cluster operations require a native CAN adapter "
            "(CANable / SLCAN / candleLight). Reading/writing via VNCI / D-PDU / J2534 is not supported for FPK.",
        )
        return DiscoveredEcu(
            kind="fpke",
            diag_addr=spec.diag_addr,
            uds_tx_id=spec.uds_tx_id,
            uds_rx_id=spec.uds_rx_id,
            ident=ident,
            via_gateway=False,
            gateway_channel=None,
            bridge_available=False,
            in_fbl=in_fbl,
            unsupported=fpke_unsupported,
            memory_unavailable_reason=fpke_unsupported,
            capabilities=("uds",),
        )

    if spec.kind == "bcm":
        if via_gateway:
            if gateway_bridge_capable:
                bcm_caps: tuple[str, ...] = ("uds", "memory", "bridge_memory", "dtc", "terminal")
                bcm_mem_err: str | None = None
            else:
                bcm_caps = ("uds", "dtc", "terminal")
                bcm_mem_err = tr(
                    "Чтение IKA/GFA по XCP и адаптация FFB (29-бит XCP / WFS канал 3) через шлюз требуют "
                    "шлюз Continental 3Q0 907 530 и адаптер с произвольным raw CAN (нативный или VNCI, принимающий "
                    "в RawMode все идентификаторы) для прозрачного RAM-моста ch3 ↔ ch0. "
                    "Статус KS/FFB и запись ключей (2E 00BE / 00BD) по UDS доступны.",
                    "Reading IKA/GFA via XCP and FFB adaptation (29-bit XCP / WFS Channel 3) through a gateway require "
                    "a Continental 3Q0 907 530 gateway and an adapter with arbitrary raw CAN (native, or a VNCI whose "
                    "RawMode receives every identifier) for the ch3 ↔ ch0 RAM bridge. "
                    "UDS KS/FFB status and key writing (2E 00BE / 00BD) are available.",
                )
            return DiscoveredEcu(
                kind="bcm",
                diag_addr=spec.diag_addr,
                uds_tx_id=spec.uds_tx_id,
                uds_rx_id=spec.uds_rx_id,
                ident=ident,
                via_gateway=True,
                gateway_channel=spec.gateway_channel,
                bridge_available=gateway_bridge_capable,
                in_fbl=in_fbl,
                memory_unavailable_reason=bcm_mem_err,
                capabilities=bcm_caps,
            )
        if native_ok:
            return DiscoveredEcu(
                kind="bcm",
                diag_addr=spec.diag_addr,
                uds_tx_id=spec.uds_tx_id,
                uds_rx_id=spec.uds_rx_id,
                ident=ident,
                via_gateway=False,
                gateway_channel=None,
                bridge_available=False,
                in_fbl=in_fbl,
                capabilities=("uds", "memory", "dtc", "terminal"),
            )
        return DiscoveredEcu(
            kind="bcm",
            diag_addr=spec.diag_addr,
            uds_tx_id=spec.uds_tx_id,
            uds_rx_id=spec.uds_rx_id,
            ident=ident,
            via_gateway=False,
            gateway_channel=None,
            bridge_available=False,
            in_fbl=in_fbl,
            memory_unavailable_reason=tr(
                "Работа с 29-битными протоколами BCM (XCP / WFS канал 3) требует нативный CAN-адаптер "
                "(CANable / SLCAN / candleLight).",
                "29-bit BCM protocols (XCP / WFS Channel 3) require a native CAN adapter "
                "(CANable / SLCAN / candleLight).",
            ),
            capabilities=("uds", "dtc", "terminal"),
        )

    # Any future UDS-only / planned ECU
    return DiscoveredEcu(
        kind=spec.kind,
        diag_addr=spec.diag_addr,
        uds_tx_id=spec.uds_tx_id,
        uds_rx_id=spec.uds_rx_id,
        ident=ident,
        via_gateway=via_gateway,
        gateway_channel=spec.gateway_channel if via_gateway else None,
        bridge_available=False,
        in_fbl=in_fbl,
        memory_unavailable_reason=tr(
            "Доступны идентификация UDS, чтение/сброс DTC и CAN-терминал.",
            "UDS identification, DTC read/clear, and the CAN terminal are available.",
        ),
        capabilities=("uds", "dtc", "terminal"),
    )


def can_scan_bus(
    port: str,
    *,
    interface: str = "slcan",
    target_kind: str | None = None,
    targets: tuple[str, ...] | list[str] | None = None,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> BusScanResult:
    """Scan the CAN bus for a J533 gateway and all supported/recognized control units.

    - If `target_kind` is `None` / `"all"`, probes `19` J533 first, then all registered slave ECUs (`17`, `09`)
      either routed behind the gateway (`topology="gateway"`) or directly on the CAN bus (`topology="direct"`).
    - If `target_kind` is `"j533"`, probes only `19` J533 (`0x710/0x77A`).
    - If `target_kind` is a specific slave (`"fpke"` or `"bcm"`), performs a quick gateway presence check on
      `0x710/0x77A` so Level-2 RAM-Bridge routing is detected automatically when connected via Diagnosis CAN,
      and otherwise probes the target directly on CAN (`topology="direct"`).
    """
    from contitool.can.fpke import close_active_fpke_link, open_or_reuse_fpke_link
    from contitool.can.workflows import (
        _j2534_wrapper_bus,
        _j2534_wrapper_problem,
        _probe_bcm_uds_with_wake,
        _probe_fpke_uds_with_wake,
    )

    if bus is None:
        close_active_fpke_link()

    norm_target = (target_kind or "").strip().lower()
    if norm_target in ("", "all"):
        norm_target = ""
    if targets is not None:
        wanted = tuple(dict.fromkeys(t.strip().lower() for t in targets))
    elif norm_target:
        wanted = (norm_target,)
    else:
        wanted = tuple(s.kind for s in ECU_SPECS)

    for k in wanted:
        if k not in ECU_SPEC_BY_KIND:
            raise ValueError(f"Unknown scan target ECU: {k!r}")

    ecus: list[DiscoveredEcu] = []
    gateway: DiscoveredEcu | None = None
    topology = "none"
    gw_bridge_capable = False
    bridge_adapter_ok = False
    adapter_warning: str | None = None
    scan_notes: list[str] = []
    keep_direct_fpke_alive = False

    slave_targets = [ECU_SPEC_BY_KIND[k] for k in wanted if not ECU_SPEC_BY_KIND[k].is_gateway]
    probe_gateway = ("j533" in wanted) or bool(slave_targets)
    explicit_slave_only = ("j533" not in wanted) and bool(slave_targets)
    total_steps = (1 if (probe_gateway and not explicit_slave_only) else 0) + len(slave_targets)
    step = 0

    with J533CanLink(port, interface=interface, bus=bus) as link:
        if link.interface == "dpdu" and callable(getattr(link.bus, "describe", None)):
            reporter.info(tr("Модуль D-PDU: ", "D-PDU module: ") + link.bus.describe())
            if (wrapped := _j2534_wrapper_bus(link)) is not None:
                adapter_warning = _j2534_wrapper_problem(wrapped)
                reporter.warning(adapter_warning)

        # 1. Probe J533 Gateway (19, 0x710 -> 0x77A)
        if probe_gateway:
            if not explicit_slave_only:
                step += 1
                reporter.step(step, total_steps, tr("Опрос шлюза J533 (19, 0x710 → 0x77A)", "Probing J533 gateway (19, 0x710 → 0x77A)"))
            gw_timeout = 0.25 if (explicit_slave_only and bus is None) else (0.45 if bus is not None else 1.0)
            gw_ok, gw_fbl = _probe_uds_1003(link, 0x710, 0x77A, timeout=gw_timeout)
            if gw_ok:
                topology = "gateway"
                gateway = _build_gateway_ecu(link, gw_fbl, reporter)
                ecus.append(gateway)
                bridge_adapter_ok = bus is not None or bridge_bus_ok(interface, link.bus)
                gw_bridge_capable = (gateway.unsupported is None) and (not gateway.in_fbl) and bridge_adapter_ok
                reporter.info(
                    tr(
                        f"Найден шлюз [19] {gateway.part_number}"
                        + (f" (ПО {gateway.sw_version})" if gateway.sw_version else "")
                        + (" — в загрузчике FBL" if gateway.in_fbl else ""),
                        f"Found gateway [19] {gateway.part_number}"
                        + (f" (SW {gateway.sw_version})" if gateway.sw_version else "")
                        + (" — in FBL bootloader" if gateway.in_fbl else ""),
                    )
                )
                if gateway.unsupported:
                    reporter.warning(gateway.unsupported)
                elif gw_bridge_capable:
                    reporter.can_log(
                        tr(
                            f"Доступен прозрачный CAN-мост RAM-Loader ({bridge_bus_label(0)})",
                            f"Transparent RAM-Loader CAN bridge available ({bridge_bus_label(0)})",
                        )
                    )

        # 2. Scan slave ECUs (either routed through gateway or directly on bench CAN)
        if topology == "gateway":
            assert gateway is not None
            if not slave_targets:
                pass
            elif gateway.in_fbl:
                note = tr(
                    "Шлюз J533 находится в загрузчике FBL — опрос ведомых блоков за шлюзом пропущен.",
                    "J533 gateway is in FBL bootloader — skipping slave ECU probes behind the gateway.",
                )
                scan_notes.append(note)
                reporter.warning(note)
            elif getattr(link.bus, "uds_only", False):
                note = tr(
                    "Адаптер D-PDU открыл канал только для 0x710/0x77A — опрос ведомых блоков недоступен.",
                    "This D-PDU adapter opened only 0x710/0x77A — probing slave ECUs is unavailable.",
                )
                scan_notes.append(note)
                reporter.warning(note)
            else:
                for spec in slave_targets:
                    reporter.check_cancelled()
                    step += 1
                    reporter.step(
                        step,
                        total_steps,
                        tr(
                            f"Опрос через шлюз: {spec.short_name} ({spec.diag_addr}, 0x{spec.uds_tx_id:03X} → 0x{spec.uds_rx_id:03X})",
                            f"Probing via gateway: {spec.short_name} ({spec.diag_addr}, 0x{spec.uds_tx_id:03X} → 0x{spec.uds_rx_id:03X})",
                        ),
                    )
                    ok_s, fbl_s = _probe_uds_1003(
                        link,
                        spec.uds_tx_id,
                        spec.uds_rx_id,
                        timeout=0.35 if bus is not None else 0.55,
                    )
                    if not ok_s:
                        continue
                    ident = _read_ident_dids(link, reporter=reporter)
                    ecu = _build_slave_ecu(
                        spec,
                        ident,
                        via_gateway=True,
                        gateway_bridge_capable=gw_bridge_capable,
                        interface=interface,
                        bus_injected=(bus is not None),
                        in_fbl=fbl_s,
                        bridge_adapter_ok=bridge_adapter_ok,
                    )
                    ecus.append(ecu)
                    reporter.info(
                        tr(
                            f"Найден блок [{ecu.diag_addr}] {ecu.part_number}"
                            + (f" (ПО {ecu.sw_version})" if ecu.sw_version else "")
                            + f" — {ecu.access_summary}",
                            f"Found ECU [{ecu.diag_addr}] {ecu.part_number}"
                            + (f" (SW {ecu.sw_version})" if ecu.sw_version else "")
                            + f" — {ecu.access_summary}",
                        )
                    )
        else:
            # Direct CAN topology (no gateway answered on 0x710/0x77A)
            for spec in slave_targets:
                reporter.check_cancelled()
                step += 1
                reporter.step(
                    step,
                    total_steps,
                    tr(
                        f"Прямой опрос: {spec.short_name} ({spec.diag_addr}, 0x{spec.uds_tx_id:03X} → 0x{spec.uds_rx_id:03X})",
                        f"Direct probe: {spec.short_name} ({spec.diag_addr}, 0x{spec.uds_tx_id:03X} → 0x{spec.uds_rx_id:03X})",
                    ),
                )
                if spec.kind == "fpke":
                    ok_s, fbl_s = _probe_fpke_uds_with_wake(link, bus=bus, interface=interface, reporter=reporter)
                    ka_direct = bus is None and interface in BRIDGE_NATIVE_INTERFACES
                elif spec.kind == "bcm":
                    ok_s, fbl_s = _probe_bcm_uds_with_wake(link, bus=bus, interface=interface, reporter=reporter)
                    ka_direct = False
                else:
                    ok_s, fbl_s = _probe_uds_1003(
                        link,
                        spec.uds_tx_id,
                        spec.uds_rx_id,
                        timeout=0.35 if bus is not None else 0.7,
                    )
                    ka_direct = False
                if not ok_s:
                    continue
                topology = "direct"
                ident = _read_ident_dids(link, keepalive_direct_fpke=ka_direct, reporter=reporter)
                ecu = _build_slave_ecu(
                    spec,
                    ident,
                    via_gateway=False,
                    gateway_bridge_capable=False,
                    interface=interface,
                    bus_injected=(bus is not None),
                    in_fbl=fbl_s,
                )
                ecus.append(ecu)
                if spec.kind == "fpke" and ka_direct:
                    keep_direct_fpke_alive = True
                reporter.info(
                    tr(
                        f"Найден блок [{ecu.diag_addr}] {ecu.part_number}"
                        + (f" (ПО {ecu.sw_version})" if ecu.sw_version else "")
                        + f" — {ecu.access_summary}",
                        f"Found ECU [{ecu.diag_addr}] {ecu.part_number}"
                        + (f" (SW {ecu.sw_version})" if ecu.sw_version else "")
                        + f" — {ecu.access_summary}",
                    )
                )

    if keep_direct_fpke_alive and len(ecus) == 1 and ecus[0].kind == "fpke":
        with contextlib.suppress(Exception):
            fpke_link = open_or_reuse_fpke_link(port, interface=interface)
            fpke_link.start_keepalive()

    if explicit_slave_only and topology == "gateway" and not any(e.kind in wanted for e in ecus):
        target_labels = ", ".join(
            f"[{ECU_SPEC_BY_KIND[k].diag_addr}] {ECU_SPEC_BY_KIND[k].short_name} (0x{ECU_SPEC_BY_KIND[k].uds_tx_id:03X})"
            for k in wanted
        )
        if gateway is not None and gateway.in_fbl:
            raise RuntimeError(
                tr(
                    f"Шлюз J533 [19] ({gateway.part_number}) находится в загрузчике FBL и не маршрутизирует запросы к "
                    f"{target_labels}. Сначала восстановите прошивку шлюза или подключитесь к ведомому блоку напрямую.",
                    f"J533 gateway [19] ({gateway.part_number}) is in FBL bootloader and cannot route to "
                    f"{target_labels}. Restore the gateway firmware first or connect directly to the target ECU.",
                )
            )
        if scan_notes:
            raise RuntimeError(scan_notes[-1])
        raise RuntimeError(
            tr(
                f"Шлюз J533 [19] ({gateway.part_number if gateway else '0x710'}) на связи, но целевой блок "
                f"{target_labels} за шлюзом не ответил. Проверьте питание +12 В / KL15 ведомого блока и подключение "
                "к шине Komfort CAN шлюза (T20 Pin 5 CAN-L / Pin 15 CAN-H).",
                f"J533 gateway [19] ({gateway.part_number if gateway else '0x710'}) answered, but target ECU "
                f"{target_labels} did not respond behind it. Check the slave ECU's +12 V / KL15 power and wiring "
                "to the gateway Komfort CAN bus (T20 Pin 5 CAN-L / Pin 15 CAN-H).",
            )
        )

    if not ecus:
        probed_str = ", ".join(
            f"{ECU_SPEC_BY_KIND[k].diag_addr} {ECU_SPEC_BY_KIND[k].short_name} 0x{ECU_SPEC_BY_KIND[k].uds_tx_id:03X}"
            for k in wanted
        )
        raise RuntimeError(
            tr(
                f"Блок не ответил по CAN (опрашивались: {probed_str}). Проверьте питание +12 В, массу, линии "
                "CAN-H / CAN-L (шлюз T20: Pin 19 и Pin 9; панель приборов T18: Pin 18 и Pin 17) и терминатор 120 Ом (см. «Распиновка»).",
                f"No ECU answered on CAN (probed: {probed_str}). Check +12 V power, ground, CAN-H / CAN-L "
                "(gateway T20: Pin 19 and Pin 9; cluster T18: Pin 18 and Pin 17) and that 120 Ω CAN termination is on (see “Pinout”).",
            )
        )

    return BusScanResult(
        topology=topology,
        ecus=ecus,
        port=port,
        interface=interface,
        gateway=gateway,
        gateway_bridge_capable=gw_bridge_capable,
        adapter_warning=adapter_warning,
        scan_notes=scan_notes,
        scanned_targets=wanted,
    )


def _wake_direct_fpke_once(link: J533CanLink) -> None:
    from contitool.can.fpke import FPKE_KEEPALIVE_PATTERN

    for arb_id, ka_data in FPKE_KEEPALIVE_PATTERN:
        with contextlib.suppress(Exception):
            link.send_frame(arb_id, ka_data)


def can_uds_read_dtc(
    port: str,
    tx_id: int,
    rx_id: int,
    *,
    interface: str = "slcan",
    ecu_kind: str = "generic",
    via_gateway: bool = False,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Read fault codes (`UDS 19 02 FF`) from any ECU at `(tx_id -> rx_id)` over Diagnosis or direct CAN."""
    from contitool.core import dtc as dtc_mod

    with J533CanLink(port, interface=interface, bus=bus) as link:
        link.UDS_TX_ID = tx_id
        link.UDS_RX_ID = rx_id
        reporter.step(1, 1, tr(f"Чтение ошибок DTC (0x{tx_id:03X} → 0x{rx_id:03X})", f"Reading DTCs (0x{tx_id:03X} → 0x{rx_id:03X})"))
        if ecu_kind == "fpke" and not via_gateway and bus is None and interface in BRIDGE_NATIVE_INTERFACES:
            _wake_direct_fpke_once(link)
        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x03", 0x50, timeout=1.5)
        resp = link.request_uds(b"\x19\x02\xff", 0x59, timeout=3.0)

    active_dtcs: list[dict[str, Any]] = []
    stored_dtcs: list[dict[str, Any]] = []
    untested = 0
    for off in range(3, len(resp) - 3, 4):
        code = int.from_bytes(resp[off : off + 3], "big")
        status = resp[off + 3]
        grp = dtc_mod.group(status)
        if grp == "untested":
            untested += 1
            continue
        if ecu_kind == "j533":
            disp, desc = dtc_mod.describe(code)
        elif ecu_kind == "fpke":
            disp, desc = dtc_mod.describe_fpke(code)
        elif ecu_kind == "bcm":
            disp, desc = dtc_mod.describe_bcm(code)
        else:
            disp, desc = f"0x{code:06X}", tr("Код неисправности UDS", "UDS fault code")
        entry = {
            "code": f"0x{code:06X}",
            "code_int": code,
            "display": disp,
            "description": desc,
            "status": f"0x{status:02X}",
            "status_text": dtc_mod.status_text(status),
            "group": grp,
            "active": grp == "active",
        }
        if grp == "active":
            active_dtcs.append(entry)
        else:
            stored_dtcs.append(entry)

    dtcs = active_dtcs + stored_dtcs
    if dtcs:
        reporter.info(
            tr(
                f"Найдено ошибок: {len(dtcs)} (активных: {len(active_dtcs)}, в памяти: {len(stored_dtcs)})",
                f"Found {len(dtcs)} fault(s) ({len(active_dtcs)} active, {len(stored_dtcs)} stored)",
            )
        )
        for d in dtcs:
            reporter.info(f"  [{tr('активна', 'active') if d['active'] else tr('в памяти', 'stored')}] {d['display']} — {d['description']}")
    else:
        reporter.info(tr("Ошибок в памяти блока нет.", "No trouble codes stored in the ECU."))
    return {
        "tx_id": f"0x{tx_id:03X}",
        "rx_id": f"0x{rx_id:03X}",
        "dtcs": dtcs,
        "active_count": len(active_dtcs),
        "stored_count": len(stored_dtcs),
        "untested_count": untested,
    }


def can_uds_clear_dtc(
    port: str,
    tx_id: int,
    rx_id: int,
    *,
    interface: str = "slcan",
    ecu_kind: str = "generic",
    via_gateway: bool = False,
    bus: Any | None = None,
    reporter: OperationReporter = NULL_REPORTER,
) -> dict[str, Any]:
    """Clear fault codes (`UDS 14 FF FF FF`) on any ECU at `(tx_id -> rx_id)`."""
    with J533CanLink(port, interface=interface, bus=bus) as link:
        link.UDS_TX_ID = tx_id
        link.UDS_RX_ID = rx_id
        reporter.step(1, 1, tr(f"Сброс ошибок DTC (0x{tx_id:03X} → 0x{rx_id:03X})", f"Clearing DTCs (0x{tx_id:03X} → 0x{rx_id:03X})"))
        if ecu_kind == "fpke" and not via_gateway and bus is None and interface in BRIDGE_NATIVE_INTERFACES:
            _wake_direct_fpke_once(link)
        with contextlib.suppress(Exception):
            link.request_uds(b"\x10\x03", 0x50, timeout=1.5)
        link.request_uds(b"\x14\xff\xff\xff", 0x54, timeout=3.0)
    msg = tr("Ошибки блока сброшены.", "Fault codes cleared.")
    reporter.success(msg)
    return {"ok": True, "tx_id": f"0x{tx_id:03X}", "rx_id": f"0x{rx_id:03X}", "summary": msg}
