"""Derivers: reduce a sensitive or bulky source to the facts a control needs.

A deriver runs inside the runner, on the audited host, at read time. Only
its return value is recorded as evidence; the raw bytes never leave the
function. Replay mode serves the recorded derived value, so everything
downstream of a deriver is replayable without the source.

Each deriver is bound to the paths it may read. That binding is the only way
to reach a source that ``policy.check_read`` refuses.
"""

from __future__ import annotations

import base64
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

Derived = dict[str, Any]


@dataclass(frozen=True)
class Deriver:
    name: str
    paths: re.Pattern[str]
    fn: Callable[[bytes], Derived]
    max_bytes: int = 4 * 1024 * 1024


DERIVERS: dict[str, Deriver] = {}


def deriver(name: str, paths: str, max_bytes: int = 4 * 1024 * 1024):
    def register(fn: Callable[[bytes], Derived]) -> Callable[[bytes], Derived]:
        DERIVERS[name] = Deriver(name, re.compile(paths), fn, max_bytes)
        return fn
    return register


def _lines(data: bytes) -> list[str]:
    return data.decode("utf-8", "replace").splitlines()


@deriver("shadow_empty_passwords", r"/etc/shadow")
def shadow_empty_passwords(data: bytes) -> Derived:
    """Usernames whose password field is empty. Hashes are never kept."""
    empty = []
    entries = 0
    for line in _lines(data):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split(":")
        entries += 1
        if len(fields) > 1 and fields[1] == "":
            empty.append(fields[0])
    return {"entries": entries, "empty_password_users": empty}


_KEY_TYPE = re.compile(
    r"(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)"
    r"|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com"
    r"|ssh-(rsa|ed25519|dss)-cert-v01@openssh\.com"
    r"|ecdsa-sha2-nistp(256|384|521)-cert-v01@openssh\.com)"
)


def _split_options(line: str) -> tuple[str, str]:
    """Split a leading options field (which may contain quoted spaces)."""
    in_quote = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_quote = not in_quote
        elif ch in " \t" and not in_quote:
            return line[:i], line[i:].lstrip()
    return line, ""


def _option_names(options: str) -> list[str]:
    names, current, in_quote = [], "", False
    for ch in options + ",":
        if ch == '"':
            in_quote = not in_quote
        if ch == "," and not in_quote:
            names.append(current.split("=", 1)[0].strip().lower())
            current = ""
        else:
            current += ch
    return [n for n in names if n]


def _rsa_bits(blob_b64: str) -> int | None:
    try:
        blob = base64.b64decode(blob_b64, validate=True)
        fields = []
        pos = 0
        for _ in range(3):  # key type, e, n
            (length,) = struct.unpack(">I", blob[pos:pos + 4])
            fields.append(blob[pos + 4:pos + 4 + length])
            pos += 4 + length
        n = fields[2].lstrip(b"\x00")
        return len(n) * 8 - (8 - n[0].bit_length()) if n else None
    except Exception:  # malformed key body: report as unknown size
        return None


@deriver("authorized_keys", r"/.+/\.ssh/authorized_keys2?")
def authorized_keys(data: bytes) -> Derived:
    """Per key: type, comment, option names, RSA size. Never the key body."""
    entries, invalid = [], 0
    for lineno, raw in enumerate(_lines(data), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split(None, 1)
        options = ""
        if not _KEY_TYPE.fullmatch(tokens[0]):
            options, line = _split_options(line)
            tokens = line.split(None, 1)
            if not tokens or not _KEY_TYPE.fullmatch(tokens[0]):
                invalid += 1
                continue
        key_type = tokens[0]
        rest = tokens[1].split(None, 1) if len(tokens) > 1 else []
        body = rest[0] if rest else ""
        comment = rest[1].strip() if len(rest) > 1 else ""
        entries.append({
            "line": lineno,
            "type": key_type,
            "comment": comment,
            "options": _option_names(options),
            "bits": _rsa_bits(body) if key_type == "ssh-rsa" else None,
        })
    return {"entries": entries, "invalid_lines": invalid}


_BACKUP_WORDS = re.compile(
    r"backup|dump|pg_dump|mysqldump|restic|borg|rsync|rclone|duplicity|snapshot|tar\b",
    re.IGNORECASE)
_PRUNE_WORDS = re.compile(
    r"-mtime\s+\+?\d+.*(-delete|rm\b)|\bprune\b|\bforget\b|--keep-|logrotate|retention"
    r"|--max-age|-mmin\s+\+?\d+.*-delete", re.IGNORECASE)
_CRON_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")


@deriver("cron_schedules",
         r"/etc/crontab|/etc/cron\.d/[^/]+|/var/spool/cron/(crontabs/)?[^/]+")
def cron_schedules(data: bytes) -> Derived:
    """Schedules and keyword flags only. Command text (which may embed
    credentials) is not kept."""
    entries = []
    for raw in _lines(data):
        line = raw.strip()
        if not line or line.startswith("#") or _CRON_ENV.match(line):
            continue
        if line.startswith("@"):
            parts = line.split(None, 1)
            schedule, command = parts[0], parts[1] if len(parts) > 1 else ""
        else:
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            schedule, command = " ".join(parts[:5]), parts[5]
        entries.append({
            "schedule": schedule,
            "backup_related": bool(_BACKUP_WORDS.search(command)),
            "pruning": bool(_PRUNE_WORDS.search(command)),
        })
    return {"entries": entries}


@deriver("lynis_report", r"/var/log/lynis-report\.dat")
def lynis_report(data: bytes) -> Derived:
    """Score, timestamps and test IDs. Host inventory in the report is dropped."""
    keep = {"hardening_index", "report_datetime_start", "report_datetime_end",
            "lynis_version", "os", "os_version"}
    out: Derived = {"warnings": [], "suggestions": []}
    for line in _lines(data):
        key, sep, value = line.partition("=")
        if not sep:
            continue
        if key in keep:
            out[key] = value.strip()
        elif key in ("warning[]", "suggestion[]"):
            test_id = value.split("|", 1)[0].strip()
            out["warnings" if key == "warning[]" else "suggestions"].append(test_id)
    return out


_F2B_BAN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}) \d{2}:\d{2}:\d{2}[,.]\d+ .*\[([^\]]+)\] Ban ")


@deriver("fail2ban_log_bans", r"/var/log/fail2ban\.log(\.1)?", max_bytes=64 * 1024 * 1024)
def fail2ban_log_bans(data: bytes) -> Derived:
    """Ban counts per jail per day. Banned addresses are not kept."""
    counts: dict[str, dict[str, int]] = {}
    for line in _lines(data):
        m = _F2B_BAN.match(line)
        if m:
            day, jail = m.groups()
            counts.setdefault(jail, {}).setdefault(day, 0)
            counts[jail][day] += 1
    return {"bans_by_jail_day": counts}


_UU_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+ INFO (.*)$")


@deriver("unattended_upgrades_log",
         r"/var/log/unattended-upgrades/unattended-upgrades\.log(\.1)?",
         max_bytes=64 * 1024 * 1024)
def unattended_upgrades_log(data: bytes) -> Derived:
    """Timestamps of script runs and of runs that installed packages."""
    runs, upgrades = [], []
    for line in _lines(data):
        m = _UU_TS.match(line)
        if not m:
            continue
        ts, msg = m.groups()
        if msg.startswith("Starting unattended upgrades script"):
            runs.append(ts)
        elif msg.startswith("Packages that will be upgraded:"):
            upgrades.append({"at": ts, "packages": len(msg.split(":", 1)[1].split())})
    return {"runs": runs[-50:], "upgrades": upgrades[-50:],
            "run_count": len(runs), "upgrade_count": len(upgrades)}
