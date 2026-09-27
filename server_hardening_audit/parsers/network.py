"""Parsers for listening sockets and host firewall front-ends."""

from __future__ import annotations

import re
from typing import Any

from . import ParseError, parser

_PROC = re.compile(r'\("([^"]+)",pid=(\d+)')


def split_hostport(local: str) -> tuple[str, str | None, int]:
    """'0.0.0.0:22' / '[::]:22' / '127.0.0.53%lo:53' / '*:80' -> addr, iface, port."""
    addr, sep, port = local.rpartition(":")
    if not sep or not port.isdigit():
        raise ParseError(f"cannot parse local address {local!r}")
    iface = None
    if addr.startswith("[") and addr.endswith("]"):
        addr = addr[1:-1]
    if "%" in addr:
        addr, iface = addr.split("%", 1)
    return addr, iface, int(port)


@parser("ss_listeners")
def ss_listeners(raw: str) -> list[dict[str, Any]]:
    """`ss -tlnpH` / `ss -ulnpH` rows."""
    out = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        cols = line.split()
        if len(cols) < 5:
            raise ParseError(f"unexpected ss line: {line[:80]!r}")
        state = cols[0]
        proto = "tcp" if state == "LISTEN" else "udp" if state in ("UNCONN", "ESTAB") else None
        if proto is None:
            raise ParseError(f"unexpected ss state {state!r}")
        addr, iface, port = split_hostport(cols[3])
        rest = " ".join(cols[5:])
        out.append({
            "proto": proto, "addr": addr, "iface": iface, "port": port,
            "process": sorted({m.group(1) for m in _PROC.finditer(rest)}),
        })
    return out


_UFW_RULE = re.compile(
    r"^(?:\[\s*\d+\]\s*)?(?P<to>.+?)\s{2,}(?P<action>ALLOW|DENY|REJECT|LIMIT)"
    r"(?:\s+(?P<dir>IN|OUT|FWD))?\s{2,}(?P<from>.+?)\s*$")


@parser("ufw_status")
def ufw_status(raw: str) -> dict[str, Any]:
    """`ufw status verbose`."""
    out: dict[str, Any] = {"active": None, "default_incoming": None, "rules": []}
    in_rules = False
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("Status:"):
            out["active"] = s.split(":", 1)[1].strip() == "active"
        elif s.startswith("Default:"):
            m = re.search(r"(\w+) \(incoming\)", s)
            out["default_incoming"] = m.group(1) if m else None
        elif s.startswith("--"):
            in_rules = True
        elif in_rules and s:
            m = _UFW_RULE.match(s)
            if not m:
                raise ParseError(f"unexpected ufw rule line: {s[:80]!r}")
            to = m.group("to").strip()
            src = m.group("from").strip()
            out["rules"].append({
                "to": to.replace(" (v6)", ""), "action": m.group("action"),
                "direction": m.group("dir") or "IN", "from": src.replace(" (v6)", ""),
                "v6": "(v6)" in to or "(v6)" in src,
            })
    if out["active"] is None:
        raise ParseError("no 'Status:' line in ufw output")
    return out


@parser("iptables_rules")
def iptables_rules(raw: str) -> dict[str, Any]:
    """`iptables -S` / `ip6tables -S`."""
    policies: dict[str, str] = {}
    rules: list[str] = []
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("-P "):
            parts = s.split()
            if len(parts) != 3:
                raise ParseError(f"unexpected policy line {s!r}")
            policies[parts[1]] = parts[2]
        elif s.startswith("-A "):
            rules.append(s)
        elif s.startswith("-N ") or not s or s.startswith("#"):
            continue
        else:
            raise ParseError(f"unexpected iptables -S line {s[:80]!r}")
    return {"policies": policies, "rules": rules}


_NFT_TABLE = re.compile(r"^table (\w+) (\S+) \{")
_NFT_CHAIN = re.compile(r"^chain (\S+) \{")
_NFT_HOOK = re.compile(
    r"type (\w+) hook (\w+)(?: device \S+)? priority [^;]+;\s*(?:policy (\w+);)?")


@parser("nft_ruleset")
def nft_ruleset(raw: str) -> dict[str, Any]:
    """`nft list ruleset` (text form): tables, chains, hooks, policies, rules."""
    chains: list[dict[str, Any]] = []
    table = None
    chain: dict[str, Any] | None = None
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _NFT_TABLE.match(s)
        if m:
            table = {"family": m.group(1), "name": m.group(2)}
            continue
        m = _NFT_CHAIN.match(s)
        if m and table is not None:
            chain = {**table, "chain": m.group(1), "hook": None, "type": None,
                     "policy": None, "rules": []}
            chains.append(chain)
            continue
        if s == "}":
            if chain is not None:
                chain = None
            else:
                table = None
            continue
        if chain is not None:
            m = _NFT_HOOK.search(s)
            if m and chain["hook"] is None and s.startswith("type "):
                chain["type"], chain["hook"] = m.group(1), m.group(2)
                chain["policy"] = m.group(3) or "accept"
            else:
                chain["rules"].append(s)
    return {"chains": chains}


@parser("firewalld_list")
def firewalld_list(raw: str) -> dict[str, Any]:
    """`firewall-cmd --list-all`."""
    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines:
        raise ParseError("empty firewall-cmd output")
    out: dict[str, Any] = {"zone": lines[0].split()[0]}
    for line in lines[1:]:
        key, sep, val = line.strip().partition(":")
        if sep:
            out[key.strip()] = val.strip()
    return out
