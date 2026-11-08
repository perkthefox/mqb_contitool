"""The public repository carries no private paths, workspace names, or identifiers of real vehicles and ECUs."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".toml", ".txt", ".json", ".yml", ".yaml", ".cfg", ".ini"}

# SHA-256 of private strings (workspace and folder names, an adapter serial, real VIN / FAZIT / VCRN values), keyed
# by length. Every token and token prefix of that length is hashed, so the strings never appear in the repository.
PRIVATE_SHA256: dict[int, set[str]] = {
    8: {
        "d047b43a4e3075657b44f9c70ef2a79e905f8883a9f4b183a00161321e1712c0",
    },
    10: {
        "278dcc9852f4325996e16fdffdb894307a6f94be4d616abdfbc2c4f4138ef8c5",
        "438a901072e3508accf5ff42e7f3998593d7eeba6033229b9383cdef08a5b340",
        "fc9839a329e7121688285f61fa2b374da1dbdd762a8afce3eeb807809c895db7",
    },
    11: {
        "24cd5b727e5da52a79bba81266efec6ad9a9ae71c4c0da2bd9ba2b13d1d66460",
        "65f932c9cf1d67b5cac5b89921207d5fe6bf634064555e4629d029acf5e2b106",
    },
    14: {
        "0a922993f6402623e8de1e9a112f6718b6015b83b2a2654547e328f477cbc82b",
        "59435161b1966570573ec3e61008cc133c27f7683f23ffe1bdcc0eafc375d971",
        "f277ffe15a9d2b09ba4d98a2965cbc300851091859ada34f2db0a47cd1e2870c",
    },
    17: {
        "689febe694482fbbd69f916476ada8338aa7cd629a5b534cb25e78a44b438dd2",
        "da7d423de7c2fdd11bc37bbc677d7333d7c0b877e8bba042f72cb14b9dddc494",
    },
    23: {
        "0419ce26767367b998127cf42c1b27125d3656933d9b44ae28fb3d8ea79f2729",
        "74521e6f7a3f6545989fb8a2a5598b79ad2f55a6ff876c083f822a7799f8ad56",
        "948e666a39b5f2ad5ddc2145284e5f9d55ad0bd881f1e5208f62d36fe596e69d",
    },
}
TOKENS = (re.compile(r"[A-Za-z0-9_.\-]+"), re.compile(r"[A-Za-z0-9_]+"))
HOME_DIR = re.compile(r"/Users/[A-Za-z][A-Za-z0-9._-]*/|/home/[a-z][a-z0-9._-]*/")
VIN = re.compile(r"\b[A-HJ-NPR-Z0-9]{3}ZZZ[A-HJ-NPR-Z0-9]{8}\b")
FAZIT = re.compile(r"\b[A-Z0-9]{3}-[A-Z]{3}\d{2}\.\d{2}\.\d{10}\b")


def _repo_files() -> list[Path]:
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        files = [ROOT / line for line in out.splitlines() if line]
    except (OSError, subprocess.CalledProcessError):  # an unpacked source archive
        files = [p for p in ROOT.rglob("*") if ".git" not in p.parts and ".venv" not in p.parts]
    return [p for p in files if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES]


def _private(token: str) -> bool:
    return any(
        len(token) >= n and hashlib.sha256(token[:n].encode()).hexdigest() in hashes for n, hashes in PRIVATE_SHA256.items()
    )


def test_no_private_strings_in_the_repository() -> None:
    problems = []
    for path in _repo_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        rel = path.relative_to(ROOT)
        if HOME_DIR.search(text):
            problems.append(f"{rel}: a home directory path")
        tokens = {t for rx in TOKENS for t in rx.findall(text)}
        if any(_private(t) for t in tokens):
            problems.append(f"{rel}: a private string")
        if any(not v.endswith(("000001", "000002")) for v in VIN.findall(text)):  # test VINs end in 00000x
            problems.append(f"{rel}: a real-looking VIN")
        if any(not f.startswith("TST-") for f in FAZIT.findall(text)):  # test FAZIT IDs start with TST-
            problems.append(f"{rel}: a real-looking FAZIT ID")
    assert not problems, "\n".join(problems)


def test_the_check_itself_works(monkeypatch) -> None:
    monkeypatch.setitem(PRIVATE_SHA256, 6, {hashlib.sha256(b"secret").hexdigest()})
    assert _private("secret_value") and not _private("public")
    assert HOME_DIR.search("/Users/" + "someone/x") and not HOME_DIR.search("C:/ProgramData/x")
