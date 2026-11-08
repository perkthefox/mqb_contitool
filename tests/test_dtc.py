"""Gateway trouble codes: status groups, ODIS codes and descriptions, and how the ECU screen shows them."""

from __future__ import annotations

import os
import re

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from contitool.core import dtc  # noqa: E402
from contitool.core.dtc_j533 import J533_DTCS  # noqa: E402
from contitool.i18n import set_lang  # noqa: E402

# 19 02 FF answer of a 3Q0907530C SW 521 gateway: 1 active, 4 stored, 35 never tested since clear
AA_RECORDS = [
    {"dtc": c, "status": s}
    for c, s in [("821a1b", "09"), ("020257", "08"), ("03021d", "08"), ("030237", "08"), ("030231", "08")]
] + [{"dtc": f"{0x000100 + i:06x}", "status": "10"} for i in range(35)]


def test_status_byte_groups_faults_apart_from_untested_codes() -> None:
    assert dtc.group(0x09) == "active"
    assert dtc.group(0x08) == "stored"
    assert dtc.group(0x20) == "stored"  # failed since the last clear
    assert dtc.group(0x10) == "untested"  # only "not tested since clear": not a fault
    assert dtc.group(0x50) == "untested"
    set_lang("en")
    assert dtc.status_text(0x09) == "active now, confirmed"


def test_codes_resolve_to_odis_display_codes_and_descriptions() -> None:
    set_lang("ru")
    assert dtc.describe(0x020257) == ("U023500", "Нет связи с блоком 13 — адаптивный круиз-контроль (ACC)")
    set_lang("en")
    assert dtc.describe(0x821A1B)[0] == "B189CF0"
    assert dtc.describe(0x123456)[0] == ""  # unknown codes keep an empty display code


def test_table_entries_are_complete() -> None:
    assert len(J533_DTCS) >= 200
    for code, (display, ru, en) in J533_DTCS.items():
        assert 0 <= code <= 0xFFFFFF
        assert ru.strip() and en.strip(), f"{code:06X} has an empty description"
        for part in filter(None, display.split(" / ")):
            assert re.fullmatch(r"[PCBU][0-9A-F]{6}", part), f"{code:06X}: odd display code {part!r}"


def test_ecu_screen_lists_faults_and_folds_untested_codes(tmp_path) -> None:
    from conftest import make_synthetic_cflash, make_synthetic_dflash, make_synthetic_uflash

    from contitool.gui.app import create_window

    set_lang("en")
    app, win = create_window()
    folder = tmp_path / "dumps"
    folder.mkdir()
    (folder / "Cflash.bin").write_bytes(make_synthetic_cflash())
    (folder / "Dflash.bin").write_bytes(make_synthetic_dflash())
    (folder / "Uflash.bin").write_bytes(make_synthetic_uflash())
    win.open_folder(str(folder))
    screen = win.ecu_screen
    screen._dtc, screen._dtc_at = AA_RECORDS, "12:00"
    screen.select("dtc")
    screen.refresh()
    app.processEvents()

    assert screen.nav_rows["dtc"].pill.text() == "1 active"
    assert screen.actions["dtc_untested"].text() == "Show checks not run yet (35)"
    page_text = " ".join(lbl.text() for lbl in screen.page_area.widget().findChildren(type(screen.lbl_pn)))
    assert "B189CF0" in page_text and "U023500" in page_text
    assert "000100" not in page_text  # folded away

    screen._toggle_untested()
    app.processEvents()
    page_text = " ".join(lbl.text() for lbl in screen.page_area.widget().findChildren(type(screen.lbl_pn)))
    assert "000100" in page_text
    win.close()
