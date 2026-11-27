"""Is there a newer ContiTool on GitHub? Only the public release list is asked; nothing about this PC is sent."""

from __future__ import annotations

import dataclasses
import platform as platform_mod
import re
import sys
from typing import Any

CHANNEL_STABLE = "stable"
CHANNEL_CANDIDATE = "candidate"
UPDATE_CHANNELS: tuple[str, ...] = (CHANNEL_STABLE, CHANNEL_CANDIDATE)

RELEASES_API = "https://api.github.com/repos/perkthefox/mqb_contitool/releases/latest"  # never drafts or pre-releases
RELEASES_LIST_API = "https://api.github.com/repos/perkthefox/mqb_contitool/releases?per_page=20"
RELEASES_PAGE = "https://github.com/perkthefox/mqb_contitool/releases/latest"
RELEASES_ALL_PAGE = "https://github.com/perkthefox/mqb_contitool/releases"
CHECK_EVERY = 20 * 3600  # seconds between automatic checks

_VERSION_RE = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?([a-z]?)(?:-rc(\d+))?")


@dataclasses.dataclass(frozen=True)
class Release:
    version: str  # as users see it: "2.2.1a" or "2.3.0-rc1"
    page: str  # the release on GitHub, with its notes
    download: str  # this OS's archive, or the page when the release has none
    prerelease: bool = False


def is_candidate_version(version: str) -> bool:
    """True when `version` carries an explicit release-candidate tag (e.g. `2.3.0-rc1`, `v2.3.0-rc2`)."""
    m = _VERSION_RE.fullmatch(version.strip().lower())
    return bool(m and m[5] is not None)


def default_channel(current: str = "") -> str:
    """Candidate builds default to `candidate`; stable builds default to `stable`."""
    return CHANNEL_CANDIDATE if is_candidate_version(current) else CHANNEL_STABLE


def normalize_channel(value: Any, *, current: str = "") -> str:
    """Return a valid channel name (`stable` or `candidate`), falling back to `default_channel(current)`."""
    raw = str(value or "").strip().lower()
    if raw in UPDATE_CHANNELS:
        return raw
    return default_channel(current)


def releases_api_url(channel: str) -> str:
    """Endpoint for the selected channel: `/releases/latest` for stable, `/releases` list for candidate."""
    return RELEASES_LIST_API if normalize_channel(channel) == CHANNEL_CANDIDATE else RELEASES_API


def version_key(version: str) -> tuple[int, ...]:
    """Parse a release version into a comparable tuple.

    `2.0.1` < `2.0.1a` < `2.0.1e` < `2.0.2` < `2.3.0-rc1` < `2.3.0-rc2` < `2.3.0-rc10` < `2.3.0`.
    `2.1` is `2.1.0`. Anything else (e.g. `nightly`, `2.0.3-dev`, `2.0.3rc1`) gives `()`, which is never newer.
    """
    m = _VERSION_RE.fullmatch(version.strip().lower())
    if not m:
        return ()
    major, minor, patch = int(m[1]), int(m[2]), int(m[3] or 0)
    letter = (ord(m[4]) - 96) if m[4] else 0
    if m[5] is not None:
        return major, minor, patch, letter, 0, int(m[5])
    return major, minor, patch, letter, 1, 0


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
    data: dict[str, Any] | list[dict[str, Any]],
    current: str,
    platform: str = sys.platform,
    *,
    machine: str | None = None,
    channel: str = CHANNEL_STABLE,
) -> Release | None:
    """Pick the newest eligible GitHub release strictly newer than `current` for `channel`.

    - `channel="stable"` strictly ignores drafts, `prerelease=True` entries, and `-rcN` tags.
    - `channel="candidate"` accepts `-rcN` candidates as well as newer final stable releases (so RC users
      automatically upgrade once the corresponding final release ships), while still skipping drafts and
      non-RC pre-releases.
    """
    chan = normalize_channel(channel, current=current)
    cur_key = version_key(current)
    if not cur_key:
        return None
    if chan == CHANNEL_STABLE:
        if not isinstance(data, dict):
            return None
        entries: list[Any] = [data]
    elif isinstance(data, dict):
        entries = [data]
    elif isinstance(data, list):
        entries = data
    else:
        return None

    best_key: tuple[int, ...] = ()
    best_item: dict[str, Any] | None = None
    best_is_pre = False
    for item in entries:
        if not isinstance(item, dict) or item.get("draft"):
            continue
        tag = str(item.get("tag_name") or "")
        tag_key = version_key(tag)
        if not tag_key or tag_key <= cur_key:
            continue
        flagged_pre = bool(item.get("prerelease"))
        tag_rc = is_candidate_version(tag)
        is_pre = flagged_pre or tag_rc
        if chan == CHANNEL_STABLE:
            if is_pre:
                continue
        else:
            # Candidate channel accepts final releases (graduation) and explicit -rcN candidates only.
            if flagged_pre and not tag_rc:
                continue
        if tag_key > best_key:
            best_key = tag_key
            best_item = item
            best_is_pre = is_pre

    if best_item is None:
        return None
    tag = str(best_item.get("tag_name") or "")
    fallback_page = RELEASES_ALL_PAGE if best_is_pre else RELEASES_PAGE
    raw_page = str(best_item.get("html_url") or "").strip()
    page = raw_page if raw_page.startswith("https://") else fallback_page
    dl = _download(list(best_item.get("assets") or []), platform, machine=machine)
    return Release(tag.lstrip("vV"), page, dl or page, prerelease=best_is_pre)
