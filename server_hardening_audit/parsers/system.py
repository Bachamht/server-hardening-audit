"""Parsers for packages, services, accounts and system configuration."""

from __future__ import annotations

import json
import re
from typing import Any

from . import ParseError, parser


@parser("json")
def json_doc(raw: str) -> Any:
    try:
        return json.loads(raw) if raw.strip() else None
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc}") from exc


_APT_LINE = re.compile(r"^(?P<pkg>[^/\s]+)/(?P<suites>\S+)\s+(?P<ver>\S+)\s+(?P<arch>\S+)")


@parser("apt_upgradable")
def apt_upgradable(raw: str) -> list[dict[str, Any]]:
    """`apt list --upgradable`."""
    out = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("Listing") or s.startswith("WARNING") or s.startswith("N:"):
            continue
        m = _APT_LINE.match(s)
        if not m:
            raise ParseError(f"unexpected apt list line: {s[:80]!r}")
        suites = m.group("suites").split(",")
        out.append({
            "package": m.group("pkg"), "version": m.group("ver"), "suites": suites,
            "security": any(x.endswith("-security") or x.endswith("/security") for x in suites),
        })
    return out


@parser("dpkg_status")
def dpkg_status(raw: str) -> dict[str, dict[str, str]]:
    """`dpkg-query -W -f '${Package}\\t${db:Status-Abbrev}\\t${Version}\\n'`."""
    out = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise ParseError(f"unexpected dpkg-query line: {line[:80]!r}")
        pkg, status, version = (p.strip() for p in parts)
        out[pkg] = {"status": status, "version": version, "installed": status.startswith("ii")}
    return out


@parser("systemctl_show")
def systemctl_show(raw: str) -> list[dict[str, str]]:
    """`systemctl show -p A,B unit1 unit2`: blank-line separated blocks."""
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in raw.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        key, sep, val = line.partition("=")
        if not sep:
            raise ParseError(f"unexpected systemctl show line: {line[:80]!r}")
        current[key] = val
    if current:
        blocks.append(current)
    return blocks


@parser("unit_list")
def unit_list(raw: str) -> list[str]:
    """`systemctl list-units --no-legend --plain` / list-timers: unit names."""
    out = []
    for line in raw.splitlines():
        for tok in line.split():
            if re.fullmatch(r"[A-Za-z0-9@_.:\\-]+\.(service|timer|socket|target|mount|path)",
                            tok):
                out.append(tok)
                break
    return out


@parser("fail2ban_status")
def fail2ban_status(raw: str) -> dict[str, str]:
    """`fail2ban-client status [jail]`: tree of 'Key:<tab>value' lines."""
    out = {}
    for line in raw.splitlines():
        s = line.lstrip(" |`-")
        key, sep, val = s.partition(":")
        if sep and key.strip():
            out[key.strip().lower()] = val.strip()
    if not out:
        raise ParseError("unrecognised fail2ban-client output")
    return out


def _colon_file(raw: str, fields: int) -> list[list[str]]:
    rows = []
    for line in raw.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < fields:
            raise ParseError(f"malformed line: {line[:40]!r}")
        rows.append(parts)
    return rows


@parser("passwd")
def passwd(raw: str) -> list[dict[str, Any]]:
    return [{"name": p[0], "uid": int(p[2]), "gid": int(p[3]), "home": p[5], "shell": p[6]}
            for p in _colon_file(raw, 7)]


@parser("group")
def group(raw: str) -> dict[str, dict[str, Any]]:
    return {p[0]: {"gid": int(p[2]), "members": [m for m in p[3].split(",") if m]}
            for p in _colon_file(raw, 4)}


@parser("systemd_ini")
def systemd_ini(raw: str) -> dict[str, dict[str, str]]:
    """systemd-style INI (journald.conf): section -> key -> last value."""
    out: dict[str, dict[str, str]] = {}
    section = ""
    for line in raw.splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1]
            continue
        key, sep, val = s.partition("=")
        if sep:
            out.setdefault(section, {})[key.strip()] = val.strip()
    return out


_APT_CONF = re.compile(r'^\s*([A-Za-z0-9:_-]+)\s+"([^"]*)"\s*;')


@parser("apt_conf")
def apt_conf(raw: str) -> dict[str, str]:
    """Flat `Key::Path "value";` lines from apt.conf.d (nested blocks ignored)."""
    out = {}
    for line in raw.splitlines():
        m = _APT_CONF.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out
