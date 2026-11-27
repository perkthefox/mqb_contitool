"""Update check: version ordering, strict stable/candidate channel isolation, asset matching, and Settings UI."""

from __future__ import annotations

from contitool.updates import (
    CHANNEL_CANDIDATE,
    CHANNEL_STABLE,
    RELEASES_API,
    RELEASES_LIST_API,
    RELEASES_PAGE,
    default_channel,
    is_candidate_version,
    newer_release,
    normalize_channel,
    releases_api_url,
    version_key,
)


def _release(tag: str, *, prerelease: bool = False, draft: bool = False) -> dict:
    names = ("windows-amd64.zip", "macos-arm64.zip", "macos-arm64.dmg", "linux-x86_64.tar.gz")
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "draft": draft,
        "html_url": f"https://github.com/x/y/releases/tag/{tag}",
        "assets": [{"name": f"ContiTool-{tag}-{n}", "browser_download_url": f"https://dl/{tag}-{n}"} for n in names],
    }


def test_letter_fixes_and_rc_order_between_releases() -> None:
    assert (
        version_key("2.0.1")
        < version_key("2.0.1a")
        < version_key("2.0.1e")
        < version_key("v2.0.2")
        < version_key("2.1.0")
        < version_key("2.2.1")
        < version_key("2.2.1a")
        < version_key("v2.3.0-rc1")
        < version_key("2.3.0-rc1a")
        < version_key("2.3.0-rc1b")
        < version_key("2.3.0-rc2")
        < version_key("2.3.0-rc10")
        < version_key("2.3.0")
        < version_key("2.3.0a")
    )
    assert version_key("nightly") == ()
    assert version_key("2.0.3-dev") == ()
    assert version_key("2.0.3rc1") == ()
    assert is_candidate_version("2.3.0-rc1") is True
    assert is_candidate_version("2.3.0-rc1a") is True
    assert is_candidate_version("v2.3.0-rc12") is True
    assert is_candidate_version("2.2.1a") is False
    assert is_candidate_version("2.3.0") is False
    assert default_channel("2.3.0-rc1a") == CHANNEL_CANDIDATE
    assert newer_release(_release("v2.3.0-rc1a", prerelease=True), "2.2.1a", channel=CHANNEL_STABLE) is None
    rel_rc1a = newer_release([_release("v2.3.0-rc1a", prerelease=True)], "2.3.0-rc1", channel=CHANNEL_CANDIDATE)
    assert rel_rc1a is not None and rel_rc1a.version == "2.3.0-rc1a"


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


def test_channel_isolation_prevents_stable_and_candidate_crossing() -> None:
    feed = [
        _release("v2.3.0-rc1", prerelease=True),
        _release("v2.2.1a", prerelease=False),
        _release("v2.2.1", prerelease=False),
        _release("v2.4.0-rc1", prerelease=True, draft=True),
        _release("v2.5.0-alpha1", prerelease=True),
    ]

    # Legacy 2.2.1 on stable (/releases/latest returns a single dict) sees 2.2.1a, NEVER 2.3.0-rc1
    rel_old = newer_release(_release("v2.2.1a", prerelease=False), "2.2.1", platform="win32", channel=CHANNEL_STABLE)
    assert rel_old is not None and rel_old.version == "2.2.1a" and rel_old.prerelease is False

    # Stable channel strictly rejects list payloads (from /releases) and any prerelease/-rc release
    assert newer_release(feed, "2.2.1", platform="win32", channel=CHANNEL_STABLE) is None
    assert newer_release(_release("v2.2.1a", prerelease=False), "2.2.1a", platform="win32", channel=CHANNEL_STABLE) is None
    assert newer_release(_release("v2.3.0-rc1", prerelease=True), "2.2.1a", platform="win32", channel=CHANNEL_STABLE) is None
    assert newer_release(_release("v2.3.0-rc1", prerelease=False), "2.2.1a", platform="win32", channel=CHANNEL_STABLE) is None
    assert newer_release(_release("v2.3.0", prerelease=True), "2.2.1a", platform="win32", channel=CHANNEL_STABLE) is None

    # 2.2.1a switched to candidate sees 2.3.0-rc1 (and ignores draft 2.4.0-rc1 and non-RC 2.5.0-alpha1)
    rel_cand = newer_release(feed, "2.2.1a", platform="win32", channel=CHANNEL_CANDIDATE)
    assert rel_cand is not None and rel_cand.version == "2.3.0-rc1" and rel_cand.prerelease is True

    # 2.3.0-rc1 on candidate sees nothing until 2.3.0-rc2 or final 2.3.0 ships
    assert newer_release(feed, "2.3.0-rc1", platform="win32", channel=CHANNEL_CANDIDATE) is None
    feed_rc2 = [_release("v2.3.0-rc2", prerelease=True), *feed]
    rel_rc2 = newer_release(feed_rc2, "2.3.0-rc1", platform="win32", channel=CHANNEL_CANDIDATE)
    assert rel_rc2 is not None and rel_rc2.version == "2.3.0-rc2" and rel_rc2.prerelease is True

    # Candidate user graduates cleanly to final 2.3.0 once it ships
    feed_final = [_release("v2.3.0", prerelease=False), *feed_rc2]
    rel_final = newer_release(feed_final, "2.3.0-rc2", platform="win32", channel=CHANNEL_CANDIDATE)
    assert rel_final is not None and rel_final.version == "2.3.0" and rel_final.prerelease is False

    # 2.3.0-rc1 user who switches back to stable does not get nagged to downgrade to 2.2.1a,
    # and cleanly upgrades once stable 2.3.0 ships on /releases/latest
    assert newer_release(_release("v2.2.1a", prerelease=False), "2.3.0-rc1", platform="win32", channel=CHANNEL_STABLE) is None
    rel_back_stable = newer_release(_release("v2.3.0", prerelease=False), "2.3.0-rc1", platform="win32", channel=CHANNEL_STABLE)
    assert rel_back_stable is not None and rel_back_stable.version == "2.3.0" and rel_back_stable.prerelease is False


def test_channel_defaults_and_endpoints() -> None:
    assert default_channel("2.2.1a") == CHANNEL_STABLE
    assert default_channel("2.3.0-rc1") == CHANNEL_CANDIDATE
    assert normalize_channel("candidate", current="2.2.1a") == CHANNEL_CANDIDATE
    assert normalize_channel("stable", current="2.3.0-rc1") == CHANNEL_STABLE
    assert normalize_channel("garbage", current="2.2.1a") == CHANNEL_STABLE
    assert normalize_channel("", current="2.3.0-rc1") == CHANNEL_CANDIDATE
    assert releases_api_url(CHANNEL_STABLE) == RELEASES_API
    assert releases_api_url(CHANNEL_CANDIDATE) == RELEASES_LIST_API


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


def test_settings_dialog_persists_update_channel_and_resets_skip() -> None:
    from PySide6.QtCore import QSettings

    from contitool.gui.app import create_window
    from contitool.gui.dialogs.settings import SettingsDialog
    from contitool.gui.update_check import _CHANNEL, _LAST, _SKIP, get_update_channel

    app, win = create_window()
    qs = QSettings()
    prev_chan = qs.value(_CHANNEL)
    prev_last = qs.value(_LAST)
    prev_skip = qs.value(_SKIP)
    try:
        qs.setValue(_CHANNEL, CHANNEL_STABLE)
        qs.setValue(_LAST, 9999999.0)
        qs.setValue(_SKIP, "2.2.1a")

        dlg = SettingsDialog(win)
        assert dlg.rb_stable.isChecked()
        assert dlg.warn_candidate.isHidden()

        dlg.rb_candidate.setChecked(True)
        assert not dlg.warn_candidate.isHidden()
        dlg._save_only()

        assert get_update_channel() == CHANNEL_CANDIDATE
        assert float(qs.value(_LAST, 1) or 0) == 0.0
        assert str(qs.value(_SKIP, "x") or "") == ""

        dlg2 = SettingsDialog(win)
        assert dlg2.rb_candidate.isChecked()
        dlg2.rb_stable.setChecked(True)
        dlg2._save_and_check()
        assert dlg2.check_now_requested is True
        assert get_update_channel() == CHANNEL_STABLE
    finally:
        for key, val in ((_CHANNEL, prev_chan), (_LAST, prev_last), (_SKIP, prev_skip)):
            if val is None:
                qs.remove(key)
            else:
                qs.setValue(key, val)
        win.close()
        app.processEvents()
