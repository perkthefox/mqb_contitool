#!/usr/bin/env python3
"""ContiTool Launcher — Launches the Desktop GUI Studio (default) or CLI subcommands.

Usage:
  python3 conti_cp_tool.py                 # Opens ContiTool Desktop GUI
  python3 conti_cp_tool.py --help          # Shows CLI subcommands
  python3 conti_cp_tool.py inspect ...     # Runs CLI dump inspector
  python3 conti_cp_tool.py can backup ...  # Runs live CAN backup

Made by PerkTheFox • https://vwhacking.antonperk.com
FREE COMMUNITY RESEARCH TOOL — STRICTLY NOT FOR SALE!
"""

from __future__ import annotations

from pathlib import Path
import sys

_SRC_DIR = Path(__file__).resolve().parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from contitool.cli.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
