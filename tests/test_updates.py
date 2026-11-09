"""Update check: which GitHub release counts as newer, and which file of it this OS downloads."""

from __future__ import annotations

from contitool.updates import newer_release, version_key


def _release(tag: str) -> dict:
    names = ("windows-amd64.zip", "macos-arm64.zip", "macos-arm64.dmg", "linux-x86_64.tar.gz")
    return {
        "tag_name": tag,
        "html_url": f"https://github.com/x/y/releases/tag/{tag}",
        "assets": [{"name": f"ContiTool-{tag}-{n}", "browser_download_url": f"https://dl/{tag}-{n}"} for n in names],
    }


def test_letter_fixes_order_between_releases() -> None:
    assert version_key("2.0.1") < version_key("2.0.1a") < version_key("2.0.1e") < version_key("v2.0.2") < version_key("2.1.0")
    assert version_key("nightly") == ()


def test_only_a_newer_release_is_offered_with_this_os_archive() -> None:
    assert newer_release(_release("v2.0.2"), "2.0.2") is None
    assert newer_release(_release("v2.0.1e"), "2.0.2") is None
    assert newer_release({"tag_name": "latest"}, "2.0.2") is None

    rel = newer_release(_release("v2.0.3"), "2.0.2", platform="win32")
    assert rel is not None and rel.version == "2.0.3" and rel.download.endswith("windows-amd64.zip")
    assert newer_release(_release("v2.0.3"), "2.0.2", platform="darwin").download.endswith("macos-arm64.dmg")
    assert newer_release(_release("v2.0.3"), "2.0.2", platform="linux").download.endswith("linux-x86_64.tar.gz")
    bare = newer_release({"tag_name": "v2.0.3", "html_url": "https://page"}, "2.0.2e", platform="win32")
    assert bare is not None and bare.download == "https://page"  # no archive for this OS: the release page
