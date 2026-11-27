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


def test_unparseable_current_version_never_prompts_update() -> None:
    assert newer_release(_release("v2.0.3"), "2.0.3-dev", platform="win32") is None
    assert newer_release(_release("v2.0.3"), "2.0.3rc1", platform="darwin") is None
    assert newer_release(_release("v2.0.3"), "nightly", platform="linux") is None


def test_download_prefers_matching_machine_architecture() -> None:
    rel = {
        "tag_name": "v2.1.0",
        "html_url": "https://github.com/x/y/releases/tag/v2.1.0",
        "assets": [
            {"name": "ContiTool-v2.1.0-macos-x86_64.dmg", "browser_download_url": "https://dl/macos-x86_64.dmg"},
            {"name": "ContiTool-v2.1.0-macos-arm64.dmg", "browser_download_url": "https://dl/macos-arm64.dmg"},
            {"name": "ContiTool-v2.1.0-linux-x86_64.tar.gz", "browser_download_url": "https://dl/linux-x86_64.tar.gz"},
            {"name": "ContiTool-v2.1.0-linux-aarch64.tar.gz", "browser_download_url": "https://dl/linux-aarch64.tar.gz"},
        ],
    }
    assert newer_release(rel, "2.0.0", platform="darwin", machine="arm64").download.endswith("macos-arm64.dmg")
    assert newer_release(rel, "2.0.0", platform="darwin", machine="x86_64").download.endswith("macos-x86_64.dmg")
    assert newer_release(rel, "2.0.0", platform="linux", machine="aarch64").download.endswith("linux-aarch64.tar.gz")
    assert newer_release(rel, "2.0.0", platform="linux", machine="amd64").download.endswith("linux-x86_64.tar.gz")


def test_non_https_release_urls_fall_back_to_releases_page() -> None:
    from contitool.updates import RELEASES_PAGE

    evil = {
        "tag_name": "v2.2.0",
        "html_url": "http://evil.example/release",
        "assets": [
            {"name": "ContiTool-v2.2.0-windows-amd64.zip", "browser_download_url": "javascript:alert(1)"},
            {"name": "ContiTool-v2.2.0-macos-arm64.dmg", "browser_download_url": "http://evil.example/a.dmg"},
        ],
    }
    res_win = newer_release(evil, "2.0.0", platform="win32", machine="amd64")
    res_mac = newer_release(evil, "2.0.0", platform="darwin", machine="arm64")
    assert res_win is not None and res_win.page == RELEASES_PAGE and res_win.download == RELEASES_PAGE
    assert res_mac is not None and res_mac.page == RELEASES_PAGE and res_mac.download == RELEASES_PAGE
