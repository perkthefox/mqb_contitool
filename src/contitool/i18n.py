"""Bilingual RU / EN localization state with live UI observer support."""

from __future__ import annotations

from collections.abc import Callable
import os
import types
import weakref

_LANG: str = "ru"
_LISTENERS: list[Callable[[str], None] | weakref.WeakMethod] = []


def normalize_lang_code(raw: str | None) -> str | None:
    """Normalize arbitrary language code strings into 'ru' or 'en'."""
    if raw is None:
        return None
    val = raw.strip().lower()
    if val in ("ru", "rus", "russian", "р", "ру", "рус", "русский", "1"):
        return "ru"
    if val in ("en", "eng", "english", "англ", "2"):
        return "en"
    return None


def set_lang(lang: str) -> str:
    """Set active language ('ru' or 'en') and notify registered UI listeners."""
    global _LANG
    norm = normalize_lang_code(lang)
    if norm not in ("ru", "en"):
        raise ValueError(f"Unsupported language / Неподдерживаемый язык: {lang!r} (use 'ru' or 'en')")
    changed = norm != _LANG
    _LANG = norm
    if changed:
        alive: list[Callable[[str], None] | weakref.WeakMethod] = []
        for entry in list(_LISTENERS):
            if isinstance(entry, weakref.WeakMethod):
                cb = entry()
                if cb is None:
                    continue
                try:
                    cb(_LANG)
                except RuntimeError:
                    # Underlying C++ Qt widget was already destroyed
                    continue
                alive.append(entry)
            else:
                try:
                    entry(_LANG)
                except RuntimeError:
                    # Underlying C++ Qt widget was already destroyed
                    continue
                alive.append(entry)
        _LISTENERS[:] = alive
    return _LANG


def get_lang() -> str:
    """Return active language code ('ru' or 'en')."""
    return _LANG


def tr(ru: str, en: str) -> str:
    """Return Russian or English string depending on active language."""
    return en if _LANG == "en" else ru


def subscribe_lang_change(callback: Callable[[str], None]) -> Callable[[], None]:
    """Register a callback invoked whenever `set_lang` changes the active language."""
    entry: Callable[[str], None] | weakref.WeakMethod = (
        weakref.WeakMethod(callback) if isinstance(callback, types.MethodType) else callback
    )
    _LISTENERS.append(entry)

    def _unsubscribe() -> None:
        if entry in _LISTENERS:
            _LISTENERS.remove(entry)

    return _unsubscribe


def detect_early_cli_lang(argv: list[str]) -> str | None:
    """Inspect argv / CONTI_CP_LANG before building argparse so `--help` is localized."""
    for i, tok in enumerate(argv):
        if tok in ("-l", "--lang") and i + 1 < len(argv):
            got = normalize_lang_code(argv[i + 1])
            if got:
                return got
        elif tok.startswith("--lang="):
            got = normalize_lang_code(tok.split("=", 1)[1])
            if got:
                return got
    return normalize_lang_code(os.environ.get("CONTI_CP_LANG"))
