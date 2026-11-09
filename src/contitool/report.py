"""Problem report: a zip with everything needed to understand a failed operation, plus a prefilled GitHub issue."""

from __future__ import annotations

import dataclasses
import os
import platform
import re
import sys
import time
import traceback as tb_mod
import urllib.parse
import zipfile
from pathlib import Path

from contitool import __version__
from contitool.i18n import get_lang, tr

ISSUES_PAGE = "https://github.com/perkthefox/mqb_contitool/issues"
ISSUES_URL = f"{ISSUES_PAGE}/new"
CAN_LOG_HEAD, CAN_LOG_TAIL = 300, 5000  # lines of a session can.jsonl: how it started and how it ended
DRIVER_LOG_BUDGET = 40 * 1024 * 1024  # uncompressed; the D-PDU driver rotates 8 MB files, a backup writes dozens
DRIVER_LOG_TAIL = 8 * 1024 * 1024  # a single log bigger than this goes in as its tail, never whole
URL_BODY_LIMIT = 6000  # browsers and GitHub cut longer query strings

_VIN = re.compile(r"\b([A-HJ-NPR-Z0-9]{11})[A-HJ-NPR-Z0-9]{6}\b")
_FAZIT = re.compile(r"\b([A-Z0-9]{3}-[A-Z0-9]{3}\d{2}\.\d{2}\.\d{2})\d{8}\b")


@dataclasses.dataclass
class Failure:
    title: str  # the operation, e.g. "Reading the ECU memory"
    message: str
    traceback: str = ""
    started: float = 0.0  # wall clock of the operation start: picks the session and driver logs
    finished: float = dataclasses.field(default_factory=time.time)


def mask_ids(text: str) -> str:
    """Hide the serial part of VINs and FAZIT IDs in text that may end up in a public issue."""
    return _FAZIT.sub(r"\1********", _VIN.sub(r"\1******", text))


def environment(interface: str = "", port: str = "", adapter: str = "") -> dict[str, str]:
    env = {
        "ContiTool": __version__,
        "OS": platform.platform(),
        "Python": sys.version.split()[0],
        "Language": get_lang(),
        "Adapter": " · ".join(filter(None, (adapter, interface, port))) or "-",
    }
    for mod in ("PySide6", "can"):
        try:
            env[mod] = getattr(__import__(mod), "__version__", "?")
        except Exception:  # noqa: BLE001 - a report must never fail on this
            env[mod] = "-"
    try:
        from contitool.can.dpdu import discover_dpdu

        env["D-PDU"] = ", ".join(f"{a['name']} {a['version'] or '?'}" for a in discover_dpdu()) or "-"
    except Exception:  # noqa: BLE001
        env["D-PDU"] = "-"
    return env


def driver_log_dirs() -> list[Path]:
    """Where the VW D-PDU driver writes PDUAPI_VW*.log (one folder per installed variant, OE / OS)."""
    root = os.environ.get("PROGRAMDATA")
    if not root:
        return []
    return sorted(Path(root, "Volkswagen").glob("VW_D_PDU_API_*/logs"))


def driver_logs(since: float, dirs: list[Path] | None = None, *, fallback: bool = True) -> list[Path]:
    """Driver logs written during the operation, newest first: that is the one the failure is in.

    The driver starts a new log on every PDUConstruct and writes every CAN frame into it, so a backup leaves
    megabytes of trace behind. Taking the oldest of the window first once filled a report with the trace of a
    *successful* read and nearly left out the log that held the error."""
    files = [p for d in (driver_log_dirs() if dirs is None else dirs) for p in d.glob("*.log") if p.is_file()]
    recent = sorted((p for p in files if p.stat().st_mtime >= since - 60), key=lambda p: p.stat().st_mtime)
    if not recent:
        if not fallback:
            return []
        recent = sorted(files, key=lambda p: p.stat().st_mtime)[-2:]
    picked: list[Path] = recent[-1:]
    budget = DRIVER_LOG_BUDGET - sum(p.stat().st_size for p in picked)
    for p in reversed(recent[:-1]):
        if p.stat().st_size > budget:
            continue  # one huge log in the middle must not drop the smaller older ones
        picked.append(p)
        budget -= p.stat().st_size
    return sorted(picked, key=lambda p: p.stat().st_mtime)


def session_files(out_dir: Path, since: float) -> list[Path]:
    """Files ContiTool wrote during the operation (logs, JSON results): never memory dumps (*.bin), never archives
    (*.zip — the report itself is saved into the same folder by default)."""
    if not out_dir.is_dir():
        return []
    return sorted(
        p for p in out_dir.rglob("*")
        if p.is_file() and p.suffix.lower() not in (".bin", ".zip") and p.stat().st_mtime >= since - 5
    )


def _can_log_excerpt(path: Path) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) <= CAN_LOG_HEAD + CAN_LOG_TAIL:
        return "\n".join(lines) + "\n"
    skipped = len(lines) - CAN_LOG_HEAD - CAN_LOG_TAIL
    return "\n".join(lines[:CAN_LOG_HEAD] + [f'{{"skipped_lines": {skipped}}}'] + lines[-CAN_LOG_TAIL:]) + "\n"


def issue_body(failure: Failure, env: dict[str, str], log_text: str) -> str:
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(failure.finished))
    tail = "\n".join(log_text.strip().splitlines()[-30:])
    return mask_ids(
        "### Что случилось / What happened\n"
        "<!-- Опишите, что делали и что ожидали. Describe what you did and what you expected. -->\n\n"
        f"### Операция / Operation\n{failure.title or '-'} ({when})\n\n"
        f"### Ошибка / Error\n```\n{failure.message.strip() or '-'}\n```\n\n"
        "### Окружение / Environment\n" + "".join(f"- {k}: {v}\n" for k, v in env.items()) + "\n"
        f"### Последние строки журнала / Last log lines\n```\n{tail or '-'}\n```\n\n"
        "### Архив / Archive\n"
        "<!-- Перетащите сюда архив contitool_report_*.zip. Drag the contitool_report_*.zip here. -->\n"
    )


def issue_url(failure: Failure, env: dict[str, str], log_text: str) -> str:
    title = mask_ids(f"[{__version__}] {failure.title or 'ContiTool'}: {failure.message.strip().splitlines()[0][:100] if failure.message.strip() else '-'}")
    body = issue_body(failure, env, log_text)
    if len(body) > URL_BODY_LIMIT:
        body = body[:URL_BODY_LIMIT] + "\n…\n"
    return f"{ISSUES_URL}?{urllib.parse.urlencode({'title': title, 'body': body})}"


def build_report_zip(
    dest: Path,
    failure: Failure,
    env: dict[str, str],
    log_text: str,
    out_dir: Path,
    *,
    driver_dirs: list[Path] | None = None,
) -> Path:
    """Write the report archive; returns its path."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    readme = tr(
        "Отчёт ContiTool о проблеме.\n\n"
        "issue.md — текст для GitHub Issues; contitool_log.txt — журнал программы; traceback.txt — технические детали;\n"
        "sessions/ — файлы операции (без дампов памяти *.bin; can.jsonl — начало и конец); driver_logs/ — журналы драйвера D-PDU.\n\n"
        "Внимание: сырые журналы (can.jsonl, driver_logs) могут содержать идентификаторы блока и автомобиля.\n"
        "Просмотрите архив перед публикацией.\n",
        "ContiTool problem report.\n\n"
        "issue.md — text for GitHub Issues; contitool_log.txt — program log; traceback.txt — technical details;\n"
        "sessions/ — files of the operation (no *.bin memory dumps; can.jsonl — start and end); driver_logs/ — D-PDU driver logs.\n\n"
        "Note: raw logs (can.jsonl, driver_logs) may contain ECU and vehicle identifiers.\n"
        "Review the archive before publishing it.\n",
    )
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        z.writestr("README.txt", readme)
        z.writestr("issue.md", issue_body(failure, env, log_text))
        z.writestr("contitool_log.txt", mask_ids(log_text))
        z.writestr("traceback.txt", mask_ids(failure.traceback or failure.message))
        for p in session_files(out_dir, failure.started):
            arc = "sessions/" + p.relative_to(out_dir).as_posix()
            if p.name == "can.jsonl":
                z.writestr(arc, _can_log_excerpt(p))
            elif p.stat().st_size <= 20 * 1024 * 1024:
                z.write(p, arc)
        dirs = driver_log_dirs() if driver_dirs is None else driver_dirs
        # Only the driver this operation ran on: another one's logs mislead. A 2.0.1c report for a run on the
        # ODIS-S driver came with VCTool driver logs from an hour earlier, because "the newest two anywhere" was
        # the fallback. The newest of the right driver are still taken when none falls inside the window.
        own = [d for d in dirs if d.parent.name and d.parent.name in env.get("Adapter", "")]
        for p in driver_logs(failure.started, own or dirs, fallback=bool(own)):
            arc = f"driver_logs/{p.parent.parent.name}/{p.name}"
            if p.stat().st_size > DRIVER_LOG_TAIL:  # one log now covers a whole run: keep its end, the error is there
                with p.open("rb") as fh:
                    fh.seek(-DRIVER_LOG_TAIL, os.SEEK_END)
                    z.writestr(arc, fh.read())
            else:
                z.write(p, arc)
    return dest


def failure_from_exception(exc_type: type[BaseException], exc: BaseException, tb: object) -> Failure:
    text = "".join(tb_mod.format_exception(exc_type, exc, tb))  # type: ignore[arg-type]
    return Failure(tr("Внутренняя ошибка ContiTool", "ContiTool internal error"), f"{exc_type.__name__}: {exc}", text)
