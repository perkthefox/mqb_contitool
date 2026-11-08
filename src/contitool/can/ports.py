"""Cross-platform serial & CAN adapter port auto-discovery for CANable / SLCAN / python-can."""

from __future__ import annotations

import dataclasses
import logging
import sys

from contitool.i18n import tr


@dataclasses.dataclass(frozen=True)
class DetectedCanPort:
    """Discovered serial/CAN channel suitable for SLCAN or native CAN interfaces."""

    device: str
    description: str
    manufacturer: str = ""
    vid: int | None = None
    pid: int | None = None
    is_likely_can: bool = False

    @property
    def display_label(self) -> str:
        parts = [self.device]
        meta = " — ".join(x for x in (self.description, self.manufacturer) if x and x.lower() != "n/a")
        if meta:
            parts.append(f"({meta})")
        if self.is_likely_can:
            parts.append("★ CAN")
        return " ".join(parts)


SUPPORTED_CAN_INTERFACES: tuple[tuple[str, str, str], ...] = (
    ("slcan", "CANable / Cantact / USB-TIN (SLCAN Serial, 500 kbit/s)", "CANable / Cantact / USB-TIN (SLCAN Serial, 500 кбит/с)"),
    ("gs_usb", "CANable candlelight / Geschwister Schneider (gs_usb)", "CANable candlelight / gs_usb (нативный USB)"),
    ("socketcan", "Linux SocketCAN (can0 / slcan0)", "Linux SocketCAN (can0 / slcan0)"),
    ("pcan", "PEAK-System PCAN-USB (PCAN_USBBUS1)", "PEAK-System PCAN-USB (PCAN_USBBUS1)"),
    ("kvaser", "Kvaser Leaf / Memorator (channel 0)", "Kvaser Leaf / Memorator (канал 0)"),
    ("vector", "Vector VN16xx (channel 0)", "Vector VN16xx (канал 0)"),
    ("j2534", "J2534 PassThru (VAS 6154A, Tactrix, Mongoose…; Windows)", "J2534 PassThru (VAS 6154A, Tactrix, Mongoose…; Windows)"),
    ("dpdu", "VAS 6154 / VNCI 6154A (D-PDU from ODIS; Windows)", "VAS 6154 / VNCI 6154A (D-PDU из ODIS; Windows)"),
)


def discover_serial_ports() -> list[DetectedCanPort]:
    """Enumerate available serial ports and rank likely CANable / USB-CDC adapters first."""
    try:
        from serial.tools import list_ports
    except ImportError:
        return []

    found: list[DetectedCanPort] = []
    for p in list_ports.comports():
        dev = p.device or ""
        if not dev:
            continue
        # On macOS prefer /dev/cu.* over blocking /dev/tty.*, skip Bluetooth/debug virtual ports
        if sys.platform == "darwin":
            low_dev = dev.lower()
            if "bluetooth" in low_dev or "debug-console" in low_dev or "wlan" in low_dev:
                continue
        desc = (p.description or "").strip()
        mfg = (p.manufacturer or "").strip()
        blob = f"{dev} {desc} {mfg}".lower()
        likely = any(
            kw in blob
            for kw in ("canable", "slcan", "cantact", "usbmodem", "ttyacm", "stm32", "candlelight", "lawicel", "com")
        )
        if p.vid in (0x16D0, 0x0483, 0x1D50, 0x0403, 0x10C4, 0x1A86):
            likely = True
        found.append(
            DetectedCanPort(
                device=dev,
                description=desc or tr("Последовательный порт", "Serial Port"),
                manufacturer=mfg,
                vid=p.vid,
                pid=p.pid,
                is_likely_can=likely,
            )
        )

    found.sort(key=lambda item: (not item.is_likely_can, item.device))
    return found


@dataclasses.dataclass(frozen=True)
class FoundAdapter:
    """An adapter the user can pick: python-can interface + channel, a readable title, and why it can't be used."""

    interface: str
    channel: str
    title: str
    detail: str
    problem: str = ""
    driver: str = ""  # D-PDU driver version, checked before connecting


_DETECTED_NAMES = {"pcan": "PEAK PCAN-USB", "kvaser": "Kvaser", "vector": "Vector", "socketcan": "SocketCAN"}


def _serial_title(p: DetectedCanPort) -> str:
    if "github" in p.description.lower():  # CANable firmware: "CANable2 b158aa7 github.com/normaldotcom/canable2.git"
        return p.description.split()[0]
    if (p.vid, p.pid) == (0x16D0, 0x117E):  # Windows shows only "USB Serial Device (COM4)"
        return "CANable"
    return p.description


def discover_adapters() -> list[FoundAdapter]:
    """Everything that looks like a CAN adapter: SLCAN serial ports, J2534 drivers, PEAK / Kvaser / Vector / SocketCAN."""
    from contitool.can.j2534 import discover_j2534

    found = [FoundAdapter("slcan", p.device, _serial_title(p), f"SLCAN · {p.device}") for p in discover_serial_ports() if p.is_likely_can]
    from contitool.can.dpdu import discover_dpdu

    # One entry per installed D-PDU driver, ODIS-E's first: they drive the same VCI, but a machine can hold several
    # (seen on one PC: OE 27.2.0, OS 31.1.0 and VCTOOL 30.4.0) and only one of them talks to a given adapter, so
    # the user picks. With several around, the row has to say which is which, not three times "VAS 6154 / VNCI".
    apis = discover_dpdu()
    for api in apis:
        version = api["version"] or "?"
        variant = api["name"].split("·")[-1].strip().upper().removeprefix("VW_D_PDU_API_").removeprefix("VW_PDUAPI_")
        title = "VAS 6154 / VNCI" if len(apis) == 1 else f"VAS 6154 / VNCI · {variant}"
        found.append(FoundAdapter("dpdu", api["name"], title, f"D-PDU {version} · {api['name']}",
                                  driver=api["version"]))
    for d in discover_j2534():
        problem = "" if d.usable else tr(f"{d.bits}-битный драйвер — не подходит", f"{d.bits}-bit driver — not usable")
        found.append(FoundAdapter("j2534", d.name, d.name, " · ".join(filter(None, ("J2534", d.vendor))), problem))
    can_log = logging.getLogger("can")
    level = can_log.level
    can_log.setLevel(logging.ERROR)  # "Kvaser canlib is unavailable" etc. just means not installed
    try:
        import can

        configs = can.detect_available_configs(interfaces=tuple(_DETECTED_NAMES))
    except Exception:  # a vendor library that fails to load just means "not found"
        configs = []
    finally:
        can_log.setLevel(level)
    for cfg in configs:
        iface, ch = str(cfg.get("interface")), str(cfg.get("channel"))
        found.append(FoundAdapter(iface, ch, _DETECTED_NAMES.get(iface, iface), f"{iface} · {ch}"))
    return found
