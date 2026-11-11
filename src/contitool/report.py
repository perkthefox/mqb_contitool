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
DUMP_BUDGET = 40 * 1024 * 1024  # uncompressed *.bin of the operation when dumps go in: a few full sets at most
GITHUB_ATTACH_LIMIT = 25 * 1024 * 1024  # what GitHub takes as one issue attachment
URL_LIMIT = 7500  # characters of the whole URL, encoded: GitHub refuses a new-issue URL much over 8 KB

# "_" counts as a separator: the gateway folder is <part>_<FAZIT>, and \b would not see an ID there
_VIN = re.compile(r"(?<![^\W_])([A-HJ-NPR-Z0-9]{11})[A-HJ-NPR-Z0-9]{6}(?![^\W_])")
_FAZIT = re.compile(r"(?<![^\W_])([A-Z0-9]{3}-[A-Z0-9]{3}\d{2}\.\d{2}\.\d{2})\d{8}(?![^\W_])")


@dataclasses.dataclass
class Failure:
    title: str  # the operation, e.g. "Reading the ECU memory"
    message: str
    traceback: str = ""
    started: float = 0.0  # wall clock of the operation start: picks the session and driver logs
    finished: float = dataclasses.field(default_factory=time.time)


def mask_ids(text: str) -> str:
    """Hide the serial part of VINs and FAZIT IDs, and the user's home folder (its name is the OS user name), in text
    that may end up in a public issue."""
    home = os.path.expanduser("~")
    if len(Path(home).parts) > 1:  # "~" when unknown, "/" for root: nothing to hide
        for h in {home, Path(home).as_posix()}:
            text = re.sub(re.escape(h) + r"(?![\w.-])", "~", text, flags=re.I)
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
        from contitool.can import dpdu

        if dpdu.last_module:
            env["D-PDU module"] = dpdu.last_module
    except Exception:  # noqa: BLE001
        env["D-PDU"] = "-"
    return env


def driver_log_dirs() -> list[Path]:
    """Where the VW D-PDU driver writes PDUAPI_VW*.log (one folder per installed variant, OE / OS).

    The driver builds the path as <CommonAppData>/Volkswagen/<ShortName>/logs and takes ShortName from its installer's
    registry entry; the 27.2 in dpdu/ has none, which leaves Volkswagen/logs (read from the DLL, not seen on a PC)."""
    root = os.environ.get("PROGRAMDATA")
    if not root:
        return []
    base = Path(root, "Volkswagen")
    return sorted(base.glob("VW_D_PDU_API_*/logs")) + [d for d in (base / "logs",) if d.is_dir()]


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


def session_files(out_dir: Path, since: float, *, with_dumps: bool = False) -> list[Path]:
    """Files ContiTool wrote during the operation (logs, JSON results); memory dumps (*.bin) only `with_dumps`, never
    archives (*.zip — the report itself is saved into the same folder by default), never key material (ContiTool_keys,
    *.pem — a new key pair is saved next to the dumps, and the report is meant for a public issue)."""
    if not out_dir.is_dir():
        return []
    skip = (".zip", ".pem") if with_dumps else (".bin", ".zip", ".pem")
    return sorted(
        p for p in out_dir.rglob("*")
        if p.is_file() and p.suffix.lower() not in skip and p.stat().st_mtime >= since - 5
        and "contitool_keys" not in (part.lower() for part in p.relative_to(out_dir).parts)
        and not _key_bundle(p)
    )


def _key_bundle(p: Path) -> bool:
    """A key pair saved as JSON anywhere (crypto.save_rsa1024_keypair_bundle): it holds the private exponent d_hex.
    Only small .json files are read; one that cannot be read is treated as a key."""
    if p.suffix.lower() != ".json" or p.stat().st_size > 64 * 1024:
        return False
    try:
        return b'"d_hex"' in p.read_bytes()
    except OSError:
        return True


def _can_log_excerpt(path: Path) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) <= CAN_LOG_HEAD + CAN_LOG_TAIL:
        return "\n".join(lines) + "\n"
    skipped = len(lines) - CAN_LOG_HEAD - CAN_LOG_TAIL
    return "\n".join(lines[:CAN_LOG_HEAD] + [f'{{"skipped_lines": {skipped}}}'] + lines[-CAN_LOG_TAIL:]) + "\n"


ISSUE_FORM = "problem.yml"  # .github/ISSUE_TEMPLATE/problem.yml: the keys of _issue_fields are its field ids


def _issue_fields(failure: Failure, env: dict[str, str], log_text: str) -> dict[str, str]:
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(failure.finished))
    return {
        "operation": f"{failure.title or '-'} ({when})",
        "error": failure.message.strip() or "-",
        "environment": "".join(f"- {k}: {v}\n" for k, v in env.items()),
        "log": "\n".join(log_text.strip().splitlines()[-30:]) or "-",
    }


def issue_body(failure: Failure, env: dict[str, str], log_text: str) -> str:
    """The issue as Markdown, for issue.md in the archive and the "copy text" button."""
    f = _issue_fields(failure, env, log_text)
    return mask_ids(
        "### Что случилось / What happened\n"
        "<!-- Опишите, что делали и что ожидали. Describe what you did and what you expected. -->\n\n"
        f"### Операция / Operation\n{f['operation']}\n\n"
        f"### Ошибка / Error\n```\n{f['error']}\n```\n\n"
        f"### Окружение / Environment\n{f['environment']}\n"
        f"### Последние строки журнала / Last log lines\n```\n{f['log']}\n```\n\n"
        "### Архив / Archive\n"
        "<!-- Перетащите сюда архив contitool_report_*.zip. Drag the contitool_report_*.zip here. -->\n"
    )


def issue_url(failure: Failure, env: dict[str, str], log_text: str) -> str:
    """The repository's problem form, filled in field by field (GitHub prefills a form field from the query
    parameter named after its id).

    The length is measured on the encoded URL: a Cyrillic letter takes six characters there, and a Russian log
    once made a 12.5 KB URL that GitHub would not open. Too long, the log loses lines from the top, then the
    error is shortened from its end."""
    title = mask_ids(f"[{__version__}] {failure.title or 'ContiTool'}: {failure.message.strip().splitlines()[0][:100] if failure.message.strip() else '-'}")
    fields = {k: mask_ids(v) for k, v in _issue_fields(failure, env, log_text).items()}

    def url() -> str:
        return f"{ISSUES_URL}?{urllib.parse.urlencode({'template': ISSUE_FORM, 'title': title, **fields})}"

    lines = fields["log"].splitlines()
    while len(url()) > URL_LIMIT and lines:
        lines.pop(0)
        fields["log"] = "…\n" + "\n".join(lines) if lines else "…"
    while len(url()) > URL_LIMIT and len(fields["error"]) > 80:
        fields["error"] = fields["error"][: len(fields["error"]) * 3 // 4].rstrip() + " …"
    return url()


def build_report_zip(
    dest: Path,
    failure: Failure,
    env: dict[str, str],
    log_text: str,
    out_dir: Path,
    *,
    driver_dirs: list[Path] | None = None,
    dumps: dict[str, Path] | None = None,
) -> Path:
    """Write the report archive; returns its path.

    `dumps` (None = no dumps at all): the dumps loaded in the program, by name inside dumps/ — with them also the
    memory dumps the operation itself wrote (backups before a write, readbacks), up to DUMP_BUDGET."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    readme = tr(
        "Отчёт ContiTool о проблеме.\n\n"
        "issue.md — текст для GitHub Issues; contitool_log.txt — журнал программы; traceback.txt — технические детали;\n"
        "sessions/ — файлы операции (без дампов памяти *.bin; can.jsonl — начало и конец); driver_logs/ — журналы драйвера D-PDU.\n\n"
        "Внимание: сырые журналы (can.jsonl, driver_logs) могут содержать идентификаторы блока и автомобиля.\n"
        "Просмотрите архив перед публикацией.\n"
        + ("\ndumps/ — дампы памяти, загруженные в программе; в sessions/ — дампы этой операции. В них VIN, FAZIT, VCRN "
           "и данные SWaP.\n" if dumps is not None else ""),
        "ContiTool problem report.\n\n"
        "issue.md — text for GitHub Issues; contitool_log.txt — program log; traceback.txt — technical details;\n"
        "sessions/ — files of the operation (no *.bin memory dumps; can.jsonl — start and end); driver_logs/ — D-PDU driver logs.\n\n"
        "Note: raw logs (can.jsonl, driver_logs) may contain ECU and vehicle identifiers.\n"
        "Review the archive before publishing it.\n"
        + ("\ndumps/ — the memory dumps loaded in the program; sessions/ also holds this operation's dumps. They carry "
           "VIN, FAZIT, VCRN and SWaP data.\n" if dumps is not None else ""),
    )
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        z.writestr("README.txt", readme)
        z.writestr("issue.md", issue_body(failure, env, log_text))
        z.writestr("contitool_log.txt", mask_ids(log_text))
        z.writestr("traceback.txt", mask_ids(failure.traceback or failure.message))
        for name, p in (dumps or {}).items():
            if p.is_file():
                z.write(p, f"dumps/{name}")
        budget = DUMP_BUDGET
        for p in session_files(out_dir, failure.started, with_dumps=dumps is not None):
            arc = "sessions/" + p.relative_to(out_dir).as_posix()
            if p.suffix.lower() == ".bin":
                if p.stat().st_size <= budget:
                    z.write(p, arc)
                    budget -= p.stat().st_size
            elif p.name == "can.jsonl":
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


def failure_from_exception(exc_type: type[BaseException], exc: BaseException, tb: object, started: float) -> Failure:
    """`started` picks the session and driver logs: with 0 every file ever written to the output folder went in."""
    text = "".join(tb_mod.format_exception(exc_type, exc, tb))  # type: ignore[arg-type]
    return Failure(tr("Внутренняя ошибка ContiTool", "ContiTool internal error"), f"{exc_type.__name__}: {exc}", text,
                   started=started)
