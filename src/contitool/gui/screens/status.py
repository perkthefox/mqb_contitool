"""Turns raw dump analysis into the short state lines shown on the ECU screen."""

from __future__ import annotations

import dataclasses
import functools
from pathlib import Path

from contitool.core import KNOWN_GATEWAY_FECS, STOCK_FBL_MODULUS, STOCK_SWAP_MODULUS, check_fec_dataset_support
from contitool.can.workflows import SWAP_STATUS_ACTIVE
from contitool.core.analyzer import analyze_dflash_swap
from contitool.gui.workspace import Workspace
from contitool.i18n import tr


@dataclasses.dataclass
class State:
    """One feature's state: a short label, its tone, and a sentence of context."""

    text: str
    tone: str
    detail: str = ""
    known: bool = True
    key: str = ""  # language-independent id: stock | modified | on | off | partial | open | custom | unknown


UNKNOWN = "—"


def _unknown(need: str) -> State:
    return State(UNKNOWN, "muted", tr(f"Нужен дамп {need}", f"Requires the {need} dump"), known=False, key="unknown")


def component_protection(ws: Workspace) -> State:
    """Which ECUs this gateway accepts: factory-paired only, or also ones bound with a key."""
    inf = ws.info("cflash")
    if inf is None or inf.cflash_info is None:
        return _unknown("CodeFlash")
    mode = inf.cflash_info.hook_mode
    slots = ws.info("dflash")
    bound = (
        sum(1 for s in (slots.dflash_slots or []) if s.spec.slot > 0 and not s.empty and s.kind == "PLAIN")
        if slots
        else 0
    )
    if mode == "STOCK":
        return State(
            tr("заводская", "factory"),
            "ok",
            tr(
                "Адаптированы только заводские модули автомобиля.",
                "The gateway only works with the vehicle's factory-paired modules.",
            ),
            key="stock",
        )
    if mode in ("HYBRID", "GLOBAL_PLAIN"):
        detail = (
            tr(f"Заводские модули не затронуты, привязано своих: {bound}.", f"Factory modules untouched, {bound} bound by key.")
            if mode == "HYBRID"
            else tr("Все модули проверяются по открытому ключу.", "All modules are checked against a plaintext key.")
        )
        return State(tr("изменена", "modified"), "info", detail, key="modified")
    return State(
        tr("не распознана", "unrecognised"),
        "warn",
        tr(f"Прошивка содержит неизвестную модификацию ({mode}).", f"The firmware contains an unknown modification ({mode})."),
        key="unknown",
    )


def engineering(ws: Workspace) -> State:
    """Extended diagnostic services in the application firmware."""
    inf = ws.info("cflash")
    if inf is None or inf.cflash_info is None:
        return _unknown("CodeFlash")
    c = inf.cflash_info
    parts = [c.eng_gate_unlocked, c.ccp_blacklist_bypassed, c.a167_branch_bypassed]
    names = ("Feature 0x80/81/83", "ASAM CCP", "RAM-Loader 0x6F0")
    if all(parts):
        return State(tr("включён", "on"), "info", ", ".join(names) + ".", key="on")
    if not any(parts):
        return State(
            tr("выключен", "off"),
            "ok",
            tr(
                "Заводское состояние: инженерные службы выключены.",
                "Factory state: the engineering services are off.",
            ),
            key="off",
        )
    on = ", ".join(n for n, p in zip(names, parts, strict=True) if p)
    return State(tr("частично", "partial"), "warn", tr(f"Включено: {on}.", f"Enabled: {on}."), key="partial")


def bootloader(ws: Workspace) -> State:
    """Whether the bootloader requires VAG's signature on firmware it accepts."""
    inf = ws.info("uflash")
    if inf is None or inf.uflash_info is None:
        return _unknown("Uflash")
    u = inf.uflash_info
    if not u.signature_found:
        return State(
            tr("не распознан", "unrecognised"),
            "warn",
            tr("Сигнатура загрузчика не найдена по известному адресу.", "The bootloader signature is not at the known address."),
            key="unknown",
        )
    if u.rsa_bypassed:
        return State(
            tr("инженерный", "engineering"),
            "info",
            tr(
                "Подпись VAG не проверяется — изменённый CodeFlash записывается по CAN.",
                "The VAG signature is not checked — a modified CodeFlash can be written over CAN.",
            ),
            key="open",
        )
    return State(
        tr("заводской", "factory"),
        "ok",
        tr("Принимается только CodeFlash с подписью VAG.", "Only CodeFlash signed by VAG is accepted."),
        key="stock",
    )


def _key(ws: Workspace, which: str) -> State:
    inf = ws.info("cflash")
    if inf is None or inf.cflash_info is None:
        return _unknown("CodeFlash")
    c = inf.cflash_info
    mod, stock = (c.swap_rsa_mod, STOCK_SWAP_MODULUS) if which == "swap" else (c.fbl_rsa_mod, STOCK_FBL_MODULUS)
    if not mod or mod == stock:
        return State(tr("заводской VAG", "factory VAG"), "ok", key="stock")
    return State(tr("свой", "custom"), "info", tr(f"Модуль {mod[:6].hex().upper()}…", f"Modulus {mod[:6].hex().upper()}…"), key="custom")


def swap_key(ws: Workspace) -> State:
    """Whose key the gateway trusts for feature certificates."""
    return _key(ws, "swap")


def fbl_key(ws: Workspace) -> State:
    """Whose key the bootloader trusts for firmware signatures."""
    return _key(ws, "fbl")


def active_features(ws: Workspace) -> list[tuple[str, str, bool]]:
    """(FEC code, feature name, factory certificate?) for every active certificate in DataFlash."""
    return [(code_hex, name, factory) for _, code_hex, name, factory, _ in active_features_detailed(ws)]


def fec_name(code: int) -> str:
    ru, en = KNOWN_GATEWAY_FECS.get(code, ("Неизвестная функция", "Unknown feature"))
    return tr(ru, en).replace(f" (0x{code:08X})", "")


def active_features_detailed(ws: Workspace) -> list[tuple[int, str, str, bool, bool]]:
    """(fec_int, code_hex, feature_name, factory_eol, dataset_supported) for every active FSC in DataFlash."""
    inf = ws.info("dflash")
    sw = inf.dflash_swap if inf else None
    ds = inf.dflash_datasets if inf else None
    rows: list[tuple[int, str, str, bool, bool]] = []
    for f in sw.active_fscs if sw else []:
        ds_ok = check_fec_dataset_support(ds, f.fec_code).supported if ds is not None else False
        rows.append((f.fec_code, f"{f.fec_code:08X}", fec_name(f.fec_code), f.factory_eol, ds_ok))
    return rows


# Status bits of one feature in UDS 22 3C 00 (VW SWaP): 0xFF = active, 0xB0 = supported but no certificate
_SWAP_CHECKS = (
    (0x02, "сторнирована", "cancelled"),
    (0x04, "сертификат выпущен для другого блока (VCRN)", "the certificate is for another ECU (VCRN)"),
    (0x08, "истёк срок или не выполнено условие действия", "expired or its validity condition is not met"),
    (0x10, "не подходит к конфигурации блока", "does not fit the ECU configuration"),
    (0x20, "этой функции нет в прошивке", "this firmware has no such feature"),
    (0x40, "подпись сертификата не прошла проверку", "the certificate signature check failed"),
)


def swap_live_state(st: int) -> State:
    """What the gateway's own status byte for one feature means; `detail` lists the failed checks."""
    if st & SWAP_STATUS_ACTIVE == SWAP_STATUS_ACTIVE:  # the gateway's own test (IsFecActive)
        return State(tr("активна", "active"), "ok", key="on")
    if not st & 0x01:
        return State(tr("не активирована", "not activated"), "muted", key="off")
    why = "; ".join(tr(ru, en) for bit, ru, en in _SWAP_CHECKS if not st & bit)
    return State(tr("не принята", "rejected"), "err", why, key="err")


def swap_live_summary(features: list[dict], ws: Workspace) -> State:
    """One line over the gateway's answer, compared with the certificates in the loaded DataFlash."""
    active = {f["fsid"] for f in features if swap_live_state(f["status"]).key == "on"}
    rejected = [f["fsid"] for f in features if swap_live_state(f["status"]).key == "err"]
    inf = ws.info("dflash")
    expected = {f.fec_code for f in inf.dflash_swap.active_fscs} if inf and inf.dflash_swap else set()
    missing = rejected + sorted(expected - active - set(rejected))
    if missing:
        names = ", ".join(fec_name(c) for c in missing)
        return State(tr(f"Блок не принял: {names}", f"The ECU did not accept: {names}"), "err", key="err")
    if not active:
        return State(tr("Активных функций в блоке нет", "No features are active in the ECU"), "muted", key="off")
    text = tr(f"Активно в блоке: {len(active)}", f"Active in the ECU: {len(active)}")
    if expected:
        text += tr(" — всё, что записано в DataFlash, принято", " — everything in DataFlash was accepted")
    return State(text, "ok", key="on")


def _is_profile_fec(code: int) -> bool:
    return (code & 0xFFFFF0FF) == 0x10001000


def _active_fecs_in(path: Path | None) -> set[int]:
    try:
        return set(_active_fecs_cached(str(path), path.stat().st_mtime_ns)) if path else set()
    except OSError:
        return set()


@functools.lru_cache(maxsize=8)
def _active_fecs_cached(path: str, _mtime_ns: int) -> frozenset[int]:
    """The original dump's FeCs; read once per file version, not on every refresh of the screen."""
    try:
        return frozenset(f.fec_code for f in analyze_dflash_swap(Path(path).read_bytes()).active_fscs)
    except (OSError, ValueError):
        return frozenset()


def unsupported_active_fecs(ws: Workspace) -> list[int]:
    """Active FeCs the dataset has no data for. A driving-profile FeC counts only if it was switched on after the dump
    was opened: a profile taken out of the menu keeps its FeC, and the gateway then simply does not offer it."""
    rows = [fec for fec, _, _, _, ds_ok in active_features_detailed(ws) if not ds_ok]
    if any(_is_profile_fec(c) for c in rows):
        before = _active_fecs_in(ws.original.get("dflash"))
        rows = [c for c in rows if not _is_profile_fec(c) or c not in before]
    return rows


def dataset_state(ws: Workspace) -> State:
    """Summary of the ZDC parameterization dataset in DataFlash (0x0000..0x303F)."""
    inf = ws.info("dflash")
    if inf is None or inf.dflash_datasets is None:
        return _unknown("DataFlash")
    ds = inf.dflash_datasets
    if not ds.has_any_valid_dataset:
        return State(
            tr("датасет пуст", "dataset empty"),
            "warn",
            tr("Параметрия ZDC в DataFlash не записана.", "No ZDC dataset flashed in DataFlash."),
            key="off",
        )
    label = ds.dataset_pn or ds.maingw_tag or tr("датасет ОК", "dataset OK")
    return State(
        label,
        "ok",
        tr(f"Поддерживается FeC: {len(ds.supported_fecs)}.", f"{len(ds.supported_fecs)} FeCs supported."),
        key="on",
    )


def parameterization(ws: Workspace) -> State:
    """Navigation pill state for the Parameterization (`zdc`) page."""
    inf = ws.info("dflash")
    if inf is None or inf.dflash_datasets is None:
        return _unknown("DataFlash")
    ds = inf.dflash_datasets
    valid_cnt = sum(1 for b in ds.blocks if b.crc_ok)
    if not ds.has_any_valid_dataset:
        return State(
            tr("пусто", "empty"),
            "warn",
            tr(
                "Параметрия в этом дампе не настроена. Её можно создать по шаблону автомобиля.",
                "This dump has no parameterization yet. It can be created from a car template.",
            ),
            key="off",
        )
    unsup = unsupported_active_fecs(ws)
    if unsup:
        return State(
            tr("нужна настройка", "needs setup"),
            "warn",
            tr(
                f"Для части включённых FEC ({len(unsup)}) в параметрии нет данных. Кнопка ниже их добавит.",
                f"The parameterization has no data for some enabled FECs ({len(unsup)}). The button below adds "
                "them.",
            ),
            key="warn",
        )
    label = ds.dataset_pn or tr("настроено", "configured")
    return State(
        label,
        "ok",
        tr(
            f"Настроено разделов параметрии: {valid_cnt} из 7.",
            f"Configured parameterization sections: {valid_cnt} of 7.",
        ),
        key="on",
    )


def swap_features(ws: Workspace) -> State:
    """Feature certificates stored in DataFlash."""
    inf = ws.info("dflash")
    if inf is None or inf.dflash_swap is None:
        return _unknown("DataFlash")
    sw = inf.dflash_swap
    if not sw.initialized:
        return State(
            tr("не настроены", "not set up"),
            "muted",
            tr("Область SWaP в DataFlash пуста.", "The SWaP area in DataFlash is empty."),
            key="off",
        )
    active = len(sw.active_fscs)
    if not active:
        return State(
            tr("нет активных", "none active"),
            "muted",
            tr(f"Свободных слотов: {sw.free_slots}.", f"{sw.free_slots} free slots."),
            key="off",
        )
    return State(tr(f"активно: {active}", f"{active} active"), "info", key="on")


def passport_rows(ws: Workspace) -> list[tuple[str, str, str]]:
    """(label, value, tone) lines for the ECU identity card."""
    rows: list[tuple[str, str, str]] = []
    cf = ws.info("cflash")
    ee = ws.info("eeprom")
    e = ee.eeprom_info if ee else None
    if cf and cf.cflash_info:
        c = cf.cflash_info
        sw_pn = c.sw_pn or (e.part_number if e and c.sw_ver and e.sw_version == c.sw_ver else "")
        sw_parts = [p for p in (sw_pn, c.sw_ver) if p]
        if sw_parts:
            rows.append((tr("Версия ПО", "Software"), " · ".join(sw_parts), "muted"))
        hw_parts = [p for p in (c.hw_pn if sw_pn else "", c.hw_ver) if p]
        if hw_parts:
            rows.append((tr("Оборудование", "Hardware"), " · ".join(hw_parts), "muted"))
        rows.append(
            (
                tr("Контрольная сумма", "Checksum"),
                tr("верна", "valid") if c.crc_ok else tr("не сходится", "mismatch") if c.crc_range_count
                else tr("нет таблицы CRC: приложение стёрто или повреждено", "no CRC table: application erased or damaged"),
                "ok" if c.crc_ok else "err",
            )
        )
        if c.fazit:
            rows.append(("FAZIT", c.fazit.strip(), "muted"))
    df = ws.info("dflash")
    if df and df.dflash_swap:
        sw = df.dflash_swap
        if sw.vin:
            rows.append(("VIN", sw.vin, "muted"))
        if sw.vcrn:
            rows.append(("VCRN", sw.vcrn.hex().upper(), "muted"))
    if e:
        if not any(lbl == "VIN" for lbl, _, _ in rows) and e.vin:
            rows.append(("VIN", e.vin, "muted"))
        if not cf and (e.part_number or e.sw_version):
            sw_ee = " · ".join(p for p in (e.part_number, e.sw_version) if p)
            rows.append((tr("Версия ПО (EEPROM)", "Software (EEPROM)"), sw_ee, "muted"))
    return rows


def hardware_extras(ws: Workspace) -> State:
    """Navigation pill state for the Read-Only Hardware Extras (`hw`: M95640 EEPROM & RH850 OPBT) page."""
    has_ee = ws.info("eeprom") is not None
    has_op = ws.info("opbt") is not None
    warns = ws.read_warnings
    if warns and not (has_ee and has_op):
        return State(
            tr("предупреждение", "warning"),
            "warn",
            " ".join(warns.values()),
            key="warn",
        )
    if has_ee and has_op:
        return State(
            tr("EEPROM + OPBT", "EEPROM + OPBT"),
            "ok",
            tr("Загружены внешняя EEPROM M95640 (8 КБ) и OPBT0..OPBT8 (36 Б).", "External M95640 EEPROM (8 KB) and OPBT0..OPBT8 (36 B) loaded."),
            key="on",
        )
    if has_ee:
        return State(
            "EEPROM",
            "ok",
            tr("Загружена внешняя SPI EEPROM M95640 (8 КБ).", "External M95640 SPI EEPROM (8 KB) loaded."),
            key="partial",
        )
    if has_op:
        return State(
            "OPBT",
            "ok",
            tr("Загружены опционные байты RH850 OPBT.", "RH850 Option Bytes (OPBT) loaded."),
            key="partial",
        )
    return State(
        UNKNOWN,
        "muted",
        tr("Дампы Eeprom.bin и Opbt.bin ещё не прочитаны (режим только чтение).", "Eeprom.bin and Opbt.bin are not loaded yet (read-only)."),
        known=False,
        key="unknown",
    )
