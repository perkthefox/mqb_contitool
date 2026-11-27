"""Is there a newer ContiTool on GitHub? Only the public release list is asked; nothing about this PC is sent."""

from __future__ import annotations

import dataclasses
import platform as platform_mod
import re
import sys
from typing import Any

RELEASES_API = "https://api.github.com/repos/perkthefox/mqb_contitool/releases/latest"  # never drafts or pre-releases
RELEASES_PAGE = "https://github.com/perkthefox/mqb_contitool/releases/latest"
CHECK_EVERY = 20 * 3600  # seconds between automatic checks


@dataclasses.dataclass(frozen=True)
class Release:
    version: str  # as users see it: "2.0.2"
    page: str  # the release on GitHub, with its notes
    download: str  # this OS's archive, or the page when the release has none


def version_key(version: str) -> tuple[int, ...]:
    """`2.0.1e` -> (2, 0, 1, 5). A letter after a version is its n-th fix (a = 1), so 2.0.1 < 2.0.1a < 2.0.1e < 2.0.2.
    `2.1` is 2.1.0. Anything else gives (), which is never newer."""
    m = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.(\d+))?([a-z]?)", version.strip().lower())
    if not m:
        return ()
    return int(m[1]), int(m[2]), int(m[3] or 0), (ord(m[4]) - 96) if m[4] else 0


def _arch_tokens(machine: str) -> tuple[str, ...]:
    m = (machine or "").strip().lower()
    if m in ("arm64", "aarch64"):
        return ("arm64", "aarch64")
    if m in ("x86_64", "amd64", "x64"):
        return ("x86_64", "amd64", "x64")
    return (m,) if m else ()


def _download(assets: list[dict[str, Any]], platform: str, machine: str | None = None) -> str:
    """The archive scripts/build_release.py names for this OS: ...-windows-amd64.zip, -macos-arm64.dmg (or .zip),
    -linux-x86_64.tar.gz."""
    tag, exts = {"win32": ("windows", (".zip",)), "darwin": ("macos", (".dmg", ".zip"))}.get(platform, ("linux", (".tar.gz",)))
    arch_toks = _arch_tokens(platform_mod.machine() if machine is None else machine)
    candidates: list[tuple[int, str, str]] = []
    for ext_idx, ext in enumerate(exts):
        for a in assets:
            if not isinstance(a, dict):
                continue
            name = str(a.get("name", "")).lower()
            url = str(a.get("browser_download_url") or "").strip()
            if f"-{tag}-" in name and name.endswith(ext) and url.startswith("https://"):
                candidates.append((ext_idx, name, url))
    if not candidates:
        return ""
    if arch_toks:
        for _ext_idx, name, url in candidates:
            if any(f"-{tok}" in name for tok in arch_toks):
                return url
    return candidates[0][2]


def newer_release(
    data: dict[str, Any],
    current: str,
    platform: str = sys.platform,
    *,
    machine: str | None = None,
) -> Release | None:
    """The release GitHub answered with, if it is newer than `current`. Anything but a JSON object is none."""
    if not isinstance(data, dict):
        return None
    tag = str(data.get("tag_name") or "")
    tag_key = version_key(tag)
    cur_key = version_key(current)
    if not tag_key or not cur_key or tag_key <= cur_key:
        return None
    raw_page = str(data.get("html_url") or "").strip()
    page = raw_page if raw_page.startswith("https://") else RELEASES_PAGE
    dl = _download(list(data.get("assets") or []), platform, machine=machine)
    return Release(tag.lstrip("vV"), page, dl or page)
