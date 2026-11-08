"""Gateway trouble codes: ODIS display code and description for a UDS DTC, and what its status byte means."""

from __future__ import annotations

from contitool.core.dtc_j533 import J533_DTCS
from contitool.i18n import tr

# ISO 14229-1 DTC status bits, as they read to a technician
_STATUS_WORDS = (
    ("активна сейчас", "active now"),  # 0 testFailed
    ("была в этом цикле", "failed this cycle"),  # 1 testFailedThisOperationCycle
    ("ожидает подтверждения", "pending"),  # 2 pendingDTC
    ("подтверждена", "confirmed"),  # 3 confirmedDTC
    ("не проверялась после стирания", "not tested since clear"),  # 4 testNotCompletedSinceLastClear
    ("была после стирания", "failed since clear"),  # 5 testFailedSinceLastClear
    ("не проверялась в этом цикле", "not tested this cycle"),  # 6 testNotCompletedThisOperationCycle
    ("запрошена лампа", "warning lamp requested"),  # 7 warningIndicatorRequested
)
_FAILED_ANY = 0x01 | 0x02 | 0x04 | 0x08 | 0x20


def describe(code: int) -> tuple[str, str]:
    """(ODIS display code, description). Codes outside the MQB gateway table get an empty display code."""
    hit = J533_DTCS.get(code)
    if hit is None:
        return "", tr("Нет описания для этого блока", "No description for this ECU")
    display, ru, en = hit
    return display, tr(ru, en)


def group(status: int) -> str:
    """active (failing now) | stored (failed earlier) | untested (no failure recorded — not a fault).

    `19 02 FF` also returns codes whose only bit is "not tested since clear"; those are not faults."""
    if status & 0x01:
        return "active"
    if status & _FAILED_ANY:
        return "stored"
    return "untested"


def status_text(status: int) -> str:
    return ", ".join(tr(ru, en) for bit, (ru, en) in enumerate(_STATUS_WORDS) if status & (1 << bit))
