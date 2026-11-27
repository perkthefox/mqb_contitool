"""Problem report: a zip with everything needed to understand a failed operation, plus a prefilled GitHub issue."""

from __future__ import annotations

import collections
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
CAN_LOG_STREAM_LIMIT = 16 * 1024 * 1024  # files larger than this use bounded head read + bounded tail seek
CAN_LOG_TAIL_BYTES = 4 * 1024 * 1024  # tail window read for oversized can.jsonl logs
DRIVER_LOG_BUDGET = 40 * 1024 * 1024  # uncompressed; the D-PDU driver rotates 8 MB files, a backup writes dozens
DRIVER_LOG_TAIL = 8 * 1024 * 1024  # a single log bigger than this goes in as its tail, never whole
DUMP_BUDGET = 40 * 1024 * 1024  # uncompressed *.bin of the operation when dumps go in: a few full sets at most
GITHUB_ATTACH_LIMIT = 25 * 1024 * 1024  # what GitHub takes as one issue attachment
URL_LIMIT = 7500  # characters of the whole URL, encoded: GitHub refuses a new-issue URL much over 8 KB

# "_" counts as a separator: the gateway folder is <part>_<FAZIT>, and \b would not see an ID there
_VIN = re.compile(r"(?<![^\W_])([A-HJ-NPR-Z0-9]{11})([A-HJ-NPR-Z0-9]{6})(?![^\W_])", re.IGNORECASE)
_FAZIT = re.compile(r"(?<![^\W_])([A-Z0-9]{3}-[A-Z0-9]{3}\d{2}\.\d{2}\.\d{2})\d{8}(?![^\W_])", re.IGNORECASE)
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")

_SECRET_JSON_KEYS = (
    "cs",
    "kc",
    "k_ffb",
    "k_ffb_hex",
    "ika_cp3",
    "ika_hex",
    "gfa_hex",
    "gfa_working_hex",
    "gfa_raw_hex",
    "cp1_gfa",
    "S0",
    "S1",
    "slot_a_hex",
    "slot_b_hex",
    "k5_hex",
    "idcode",
    "candidate_idcode",
    "ecu_boot_sum_hex",
    "last_round_key_hex",
    "job3_output_hex",
    "encrypted_ika_final_hex",
)
_JSON_SECRET_KV = re.compile(
    r'("(?:' + "|".join(_SECRET_JSON_KEYS) + r')"\s*:\s*")((?:0x)?[0-9a-fA-F][0-9a-fA-F :\-]{7,})(")',
    re.IGNORECASE,
)
_JSON_HEX_SECRET = re.compile(
    r'("hex"\s*:\s*")((?:0x)?[0-9a-fA-F][0-9a-fA-F :\-]{15,})(")',
    re.IGNORECASE,
)
_LABELED_SECRET = re.compile(
    r"(?<![A-Za-z0-9_])((?:IKA|GFA|K_ffb|K_c|K_5|S0|S1|IDCODE)"
    r"(?:[ \t]*\([^)\n]{1,24}\))?[ \t]*(?:[:=][ \t]*|[ \t]+)(?:0x)?)"
    r"([0-9a-fA-F]{32}|(?:[0-9a-fA-F]{2}[ :\-]){15}[0-9a-fA-F]{2})(?![0-9a-fA-F])",
    re.IGNORECASE,
)

# Session files that carry raw vehicle keys/immo secrets: excluded whenever with_dumps=False
_SECRET_SESSION_FILENAMES = frozenset({
    "immo_passport.json",
    "mrr_keys.json",
    "bcm_keys.json",
    "bcm_ffb_backup.json",
    "elv_backup_report.json",
})


def _mask_vin_match(m: re.Match[str]) -> str:
    full = m.group(0)
    # Require both letters and digits, numeric last-4 serial (ISO 3779), and not pure hex
    # so common 17-char English words and hex tokens (e.g. dump_0123456789abcdef0) stay readable.
    if not (any(c.isalpha() for c in full) and any(c.isdigit() for c in full)):
        return full
    if not full[-4:].isdigit():
        return full
    if all(c in _HEX_CHARS for c in full):
        return full
    return m.group(1) + "******"


def _mask_json_hex_secret(m: re.Match[str]) -> str:
    val = m.group(2)
    clean = re.sub(r"0x", "", val, flags=re.IGNORECASE)
    clean = re.sub(r"[ :\-]+", "", clean)
    if 16 <= len(clean) <= 64 and all(c in _HEX_CHARS for c in clean):
        return f"{m.group(1)}[REDACTED]{m.group(3)}"
    return m.group(0)


@dataclasses.dataclass
class Failure:
    title: str  # the operation, e.g. "Reading the ECU memory"
    message: str
    traceback: str = ""
    started: float = 0.0  # wall clock of the operation start: picks the session and driver logs
    finished: float = dataclasses.field(default_factory=time.time)


def mask_ids(text: str) -> str:
    """Hide the serial part of VINs and FAZIT IDs, cryptographic vehicle secrets, and the user's home folder
    (its name is the OS user name) in text that may end up in a public issue."""
    home = os.path.expanduser("~")
    posix_home = home.replace("\\", "/").rstrip("/")
    if len([p for p in posix_home.split("/") if p and p != "~"]) > 1:  # "~", "/", "C:/": nothing to hide
        variants = {home, posix_home, posix_home.replace("/", "\\"), posix_home.replace("/", "\\\\")}
        for h in sorted(variants, key=len, reverse=True):
            text = re.sub(re.escape(h) + r"(?![\w.-])", "~", text, flags=re.I)
    text = _JSON_SECRET_KV.sub(r"\1[REDACTED]\3", text)
    text = _JSON_HEX_SECRET.sub(_mask_json_hex_secret, text)
    text = _LABELED_SECRET.sub(r"\1[REDACTED]", text)
    return _FAZIT.sub(r"\1********", _VIN.sub(_mask_vin_match, text))


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
    entries: list[tuple[Path, float, int]] = []
    for d in (driver_log_dirs() if dirs is None else dirs):
        try:
            candidates = list(d.glob("*.log"))
        except OSError:
            continue
        for p in candidates:
            try:
                if not p.is_file():
                    continue
                st = p.stat()
            except OSError:
                continue
            entries.append((p, st.st_mtime, st.st_size))
    recent = sorted((e for e in entries if e[1] >= since - 60), key=lambda e: e[1])
    if not recent:
        if not fallback:
            return []
        recent = sorted(entries, key=lambda e: e[1])[-2:]
    picked = recent[-1:]
    budget = DRIVER_LOG_BUDGET - sum(e[2] for e in picked)
    for e in reversed(recent[:-1]):
        if e[2] > budget:
            continue  # one huge log in the middle must not drop the smaller older ones
        picked.append(e)
        budget -= e[2]
    return [e[0] for e in sorted(picked, key=lambda e: e[1])]


def session_files(out_dir: Path, since: float, *, with_dumps: bool = False) -> list[Path]:
    """Files ContiTool wrote during the operation (logs, JSON results); memory dumps (*.bin) and secret-bearing
    artifacts only `with_dumps`, never archives (*.zip — the report itself is saved into the same folder by default),
    never key material (ContiTool_keys, *.pem — a new key pair is saved next to the dumps, and the report is meant for
    a public issue)."""
    try:
        if not out_dir.is_dir():
            return []
        candidates = list(out_dir.rglob("*"))
    except OSError:
        return []
    skip = (".zip", ".pem") if with_dumps else (".bin", ".zip", ".pem")
    found: list[Path] = []
    for p in candidates:
        try:
            if not p.is_file():
                continue
            if p.suffix.lower() in skip:
                continue
            name_lc = p.name.lower()
            if not with_dumps and (name_lc in _SECRET_SESSION_FILENAMES or name_lc.endswith(".can.log")):
                continue
            if p.stat().st_mtime < since - 5:
                continue
            rel_parts = p.relative_to(out_dir).parts
        except OSError:
            continue
        if "contitool_keys" in (part.lower() for part in rel_parts):
            continue
        if _key_bundle(p):
            continue
        found.append(p)
    return sorted(found)


def _key_bundle(p: Path) -> bool:
    """A key pair saved as JSON anywhere (crypto.save_rsa1024_keypair_bundle): it holds the private exponent d_hex.
    Only small .json files are read; one that cannot be read is treated as a key."""
    if p.suffix.lower() != ".json":
        return False
    try:
        if p.stat().st_size > 64 * 1024:
            return False
        return b'"d_hex"' in p.read_bytes()
    except OSError:
        return True


def _can_log_excerpt(path: Path) -> str:
    """Stream a bounded head + tail excerpt of a session can.jsonl without loading the full file into memory."""
    file_size = path.stat().st_size
    if file_size > CAN_LOG_STREAM_LIMIT:
        head: list[str] = []
        with path.open("rb") as fh:
            while len(head) < CAN_LOG_HEAD:
                raw_line = fh.readline()
                if not raw_line:
                    break
                head.append(raw_line.decode("utf-8", errors="replace").rstrip("\r\n"))
            head_end = fh.tell()
            tail_start = max(head_end, file_size - CAN_LOG_TAIL_BYTES)
            skipped_bytes = tail_start - head_end
            tail: collections.deque[str] = collections.deque(maxlen=CAN_LOG_TAIL)
            if tail_start < file_size:
                fh.seek(tail_start)
                if tail_start > head_end:
                    fh.readline()  # discard partial first line after seek
                for raw_line in fh:
                    tail.append(raw_line.decode("utf-8", errors="replace").rstrip("\r\n"))
        if skipped_bytes > 0:
            return "\n".join(head + [f'{{"skipped_bytes": {skipped_bytes}}}'] + list(tail)) + "\n"
        lines = head + list(tail)
        return "\n".join(lines) + "\n"

    head = []
    tail = collections.deque(maxlen=CAN_LOG_TAIL)
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\r\n")
            total += 1
            if len(head) < CAN_LOG_HEAD:
                head.append(line)
            else:
                tail.append(line)
    if total <= CAN_LOG_HEAD + CAN_LOG_TAIL:
        lines = head + list(tail)
        return "\n".join(lines) + "\n"
    skipped = total - CAN_LOG_HEAD - CAN_LOG_TAIL
    return "\n".join(head + [f'{{"skipped_lines": {skipped}}}'] + list(tail)) + "\n"


def _safe_dump_arcname(name: str, fallback: str) -> str:
    """Keep benign relative subpaths (e.g. `loaded/Cflash.bin`) while blocking path traversal or absolute paths."""
    norm = name.replace("\\", "/").strip()
    raw_parts = [part for part in norm.split("/") if part]
    if not raw_parts or norm.startswith("/") or any(part in (".", "..") or ":" in part for part in raw_parts):
        safe = Path(norm).name or fallback
    else:
        safe = "/".join(raw_parts)
    if safe in ("", ".", ".."):
        safe = fallback
    return mask_ids(f"dumps/{safe}")


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
            try:
                if not p.is_file():
                    continue
                arc = _safe_dump_arcname(name, p.name)
                raw_dump = p.read_bytes()
            except OSError:
                continue
            z.writestr(arc, raw_dump)
        budget = DUMP_BUDGET
        for p in session_files(out_dir, failure.started, with_dumps=dumps is not None):
            try:
                arc = mask_ids("sessions/" + p.relative_to(out_dir).as_posix())
                st_size = p.stat().st_size
                if p.suffix.lower() == ".bin":
                    if st_size > budget:
                        continue
                    payload: str | bytes = p.read_bytes()
                    budget -= len(payload)
                elif p.name == "can.jsonl":
                    payload = mask_ids(_can_log_excerpt(p))
                elif st_size <= 20 * 1024 * 1024:
                    if p.suffix.lower() in (".json", ".txt", ".log", ".jsonl", ".md"):
                        payload = mask_ids(p.read_text(encoding="utf-8", errors="replace"))
                    else:
                        payload = p.read_bytes()
                else:
                    continue
            except OSError:
                continue
            z.writestr(arc, payload)
        dirs = driver_log_dirs() if driver_dirs is None else driver_dirs
        # Only the driver this operation ran on: another one's logs mislead. A 2.0.1c report for a run on the
        # ODIS-S driver came with VCTool driver logs from an hour earlier, because "the newest two anywhere" was
        # the fallback. The newest of the right driver are still taken when none falls inside the window.
        own = [d for d in dirs if d.parent.name and d.parent.name in env.get("Adapter", "")]
        for p in driver_logs(failure.started, own or dirs, fallback=bool(own)):
            arc = mask_ids(f"driver_logs/{p.parent.parent.name}/{p.name}")
            try:
                st_size = p.stat().st_size
                if st_size > DRIVER_LOG_TAIL:  # one log now covers a whole run: keep its end, the error is there
                    with p.open("rb") as fh:
                        fh.seek(-DRIVER_LOG_TAIL, os.SEEK_END)
                        raw_log = fh.read()
                else:
                    raw_log = p.read_bytes()
            except OSError:
                continue
            z.writestr(arc, mask_ids(raw_log.decode("utf-8", errors="replace")))
    return dest


def failure_from_exception(exc_type: type[BaseException], exc: BaseException, tb: object, started: float) -> Failure:
    """`started` picks the session and driver logs: with 0 every file ever written to the output folder went in."""
    text = "".join(tb_mod.format_exception(exc_type, exc, tb))  # type: ignore[arg-type]
    return Failure(tr("Внутренняя ошибка ContiTool", "ContiTool internal error"), f"{exc_type.__name__}: {exc}", text,
                   started=started)
