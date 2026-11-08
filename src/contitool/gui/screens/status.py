"""Turns raw dump analysis into the short state lines shown on the ECU screen."""

from __future__ import annotations

import dataclasses

from contitool.core import KNOWN_GATEWAY_FECS, STOCK_FBL_MODULUS, STOCK_SWAP_MODULUS, check_fec_dataset_support
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
                "Блок работает только со штатно привязанными модулями автомобиля.",
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
                "Расширенная диагностика недоступна — заводское состояние.",
                "Extended diagnostics unavailable — factory state.",
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
    if st & 0x7F == 0x7F:
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


def unsupported_active_fecs(ws: Workspace) -> list[int]:
    """Active FeC codes in DataFlash that are NOT supported by the currently flashed ZDC dataset."""
    return [fec for fec, _, _, _, ds_ok in active_features_detailed(ws) if not ds_ok]


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
                "В этом дампе ещё не настроена параметрия — вы можете создать её с нуля по готовому шаблону автомобиля.",
                "No parameterization is stored in this dump yet — you can create one from a ready-made vehicle template.",
            ),
            key="off",
        )
    unsup = unsupported_active_fecs(ws)
    if unsup:
        return State(
            tr("нужна настройка", "needs setup"),
            "warn",
            tr(
                f"Часть включённых функций SWaP ({len(unsup)}) ещё не добавлена в параметрию — нажмите кнопку ниже для автоматической настройки.",
                f"{len(unsup)} enabled SWaP feature(s) are missing from the parameterization — click below to configure automatically.",
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
    if cf and cf.cflash_info:
        c = cf.cflash_info
        if c.hw_ver:
            rows.append((tr("Версия ПО", "Software"), c.hw_ver, "muted"))
        rows.append(
            (
                tr("Контрольная сумма", "Checksum"),
                tr("верна", "valid") if c.crc_ok else tr("не сходится", "mismatch"),
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
    return rows
