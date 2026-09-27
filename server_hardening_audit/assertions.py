"""Assertion operators: facts -> PASS / FAIL / UNKNOWN.

An assertion names a ``source`` (a check name, optionally followed by a
dotted path into its structured result) and operator-specific arguments.
An argument may be a literal or ``{ param = "profile.<field>" }``; profile
values are passed in as structured data, never substituted into strings.

Operators never infer PASS from missing data: a missing source or key is
UNKNOWN with a reason.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

PASS, FAIL, UNKNOWN = "PASS", "FAIL", "UNKNOWN"


@dataclass
class Outcome:
    verdict: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Context:
    facts: dict[str, Any]
    exit_codes: dict[str, int | None]
    profile: dict[str, Any]
    now: datetime


class Missing(Exception):
    """A source or parameter could not be resolved -> UNKNOWN."""


_MISSING = object()


def resolve_source(ctx: Context, source: str) -> Any:
    name, *path = source.split(".")
    if name not in ctx.facts:
        raise Missing(f"no data for source {name!r}")
    value = ctx.facts[name]
    for part in path:
        if not isinstance(value, dict) or part not in value:
            raise Missing(f"{source}: key {part!r} not present")
        value = value[part]
    if isinstance(value, dict) and "__unknown__" in value:
        raise Missing(value["__unknown__"])
    return value


def arg(raw: dict[str, Any], key: str, ctx: Context, default: Any = _MISSING) -> Any:
    value = raw.get(key, default)
    if value is _MISSING:
        raise Missing(f"argument {key!r} missing")
    if isinstance(value, dict) and set(value) == {"param"}:
        pname = value["param"]
        if not pname.startswith("profile.") or pname[8:] not in ctx.profile:
            raise Missing(f"unknown parameter {pname!r}")
        return ctx.profile[pname[8:]]
    return value


@dataclass(frozen=True)
class Op:
    name: str
    fn: Callable[[dict[str, Any], Context], Outcome]
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()

    def validate(self, raw: dict[str, Any]) -> str | None:
        keys = set(raw) - {"op"}
        missing = [k for k in self.required if k not in raw]
        if missing:
            return f"{self.name}: missing argument(s) {', '.join(missing)}"
        extra = keys - set(self.required) - set(self.optional)
        if extra:
            return f"{self.name}: unknown argument(s) {', '.join(sorted(extra))}"
        return None

    def evaluate(self, raw: dict[str, Any], ctx: Context) -> Outcome:
        try:
            return self.fn(raw, ctx)
        except Missing as exc:
            return Outcome(UNKNOWN, str(exc))


OPS: dict[str, Op] = {}


def op(name: str, required: tuple[str, ...] = (), optional: tuple[str, ...] = ()):
    def register(fn: Callable[[dict[str, Any], Context], Outcome]):
        OPS[name] = Op(name, fn, required, optional)
        return fn
    return register


def evaluate(raw: dict[str, Any], ctx: Context) -> Outcome:
    return OPS[raw["op"]].evaluate(raw, ctx)


def _norm(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


# --- Combinators --------------------------------------------------------------


@op("all_of", required=("of",))
def all_of(raw: dict[str, Any], ctx: Context) -> Outcome:
    outs = [evaluate(sub, ctx) for sub in raw["of"]]
    parts = [{"op": s["op"], "verdict": o.verdict, "summary": o.summary, **o.details}
             for s, o in zip(raw["of"], outs, strict=True)]
    failed = [o for o in outs if o.verdict == FAIL]
    unknown = [o for o in outs if o.verdict == UNKNOWN]
    if failed:
        summary = "; ".join(o.summary for o in failed)
        if unknown:
            summary += " (also undetermined: " + "; ".join(o.summary for o in unknown) + ")"
        return Outcome(FAIL, summary, {"parts": parts})
    if unknown:
        return Outcome(UNKNOWN, "; ".join(o.summary for o in unknown), {"parts": parts})
    return Outcome(PASS, "; ".join(o.summary for o in outs), {"parts": parts})


@op("any_of", required=("of",))
def any_of(raw: dict[str, Any], ctx: Context) -> Outcome:
    outs = [evaluate(sub, ctx) for sub in raw["of"]]
    parts = [{"op": s["op"], "verdict": o.verdict, "summary": o.summary, **o.details}
             for s, o in zip(raw["of"], outs, strict=True)]
    passed = [o for o in outs if o.verdict == PASS]
    if passed:
        return Outcome(PASS, passed[0].summary, {"parts": parts})
    if any(o.verdict == UNKNOWN for o in outs):
        return Outcome(UNKNOWN, "; ".join(o.summary for o in outs if o.verdict == UNKNOWN),
                       {"parts": parts})
    return Outcome(FAIL, "; ".join(o.summary for o in outs), {"parts": parts})


# --- Value operators ----------------------------------------------------------


@op("kv_equals", required=("source", "expect"), optional=("optional",))
def kv_equals(raw: dict[str, Any], ctx: Context) -> Outcome:
    data = resolve_source(ctx, raw["source"])
    if not isinstance(data, dict):
        raise Missing(f"{raw['source']} is not a key/value mapping")
    expect = arg(raw, "expect", ctx)
    optional = set(arg(raw, "optional", ctx, []))
    wrong, absent, observed = [], [], {}
    for key, want in expect.items():
        allowed = want if isinstance(want, list) else [want]
        if isinstance(data.get(key), dict) and "__unknown__" in data[key]:
            absent.append(f"{key} ({data[key]['__unknown__']})")
            continue
        if key not in data or data[key] is None:
            if key not in optional:
                absent.append(key)
            continue
        observed[key] = data[key]
        if _norm(data[key]) not in [_norm(a) for a in allowed]:
            shown = allowed[0] if len(allowed) == 1 else " or ".join(map(str, allowed))
            wrong.append(f"{key} is {data[key]!r} (expected {shown!r})")
    details = {"observed": observed}
    if wrong:
        return Outcome(FAIL, "; ".join(wrong), details)
    if absent:
        return Outcome(UNKNOWN, f"undetermined: {', '.join(absent)}", details)
    return Outcome(PASS, ", ".join(f"{k} = {v}" for k, v in observed.items()), details)


def _text(value: Any) -> str:
    if isinstance(value, list):
        return "\n".join(map(str, value))
    if not isinstance(value, str):
        raise Missing("source is not text")
    return value


@op("regex_present", required=("source", "pattern"), optional=("description",))
def regex_present(raw: dict[str, Any], ctx: Context) -> Outcome:
    text = _text(resolve_source(ctx, raw["source"]))
    what = raw.get("description", f"/{raw['pattern']}/")
    m = re.search(raw["pattern"], text, re.MULTILINE)
    if m:
        return Outcome(PASS, f"found {what}", {"match": m.group(0)[:200]})
    return Outcome(FAIL, f"{what} not found")


@op("regex_absent", required=("source", "pattern"), optional=("description",))
def regex_absent(raw: dict[str, Any], ctx: Context) -> Outcome:
    text = _text(resolve_source(ctx, raw["source"]))
    what = raw.get("description", f"/{raw['pattern']}/")
    hits = [m.group(0)[:200] for m in re.finditer(raw["pattern"], text, re.MULTILINE)]
    if hits:
        return Outcome(FAIL, f"found {what} ({len(hits)}x)", {"matches": hits[:20]})
    return Outcome(PASS, f"no {what}")


@op("exit_code", required=("source", "expect"))
def exit_code(raw: dict[str, Any], ctx: Context) -> Outcome:
    name = raw["source"]
    if name not in ctx.exit_codes or ctx.exit_codes[name] is None:
        raise Missing(f"no exit code recorded for {name!r}")
    want = raw["expect"] if isinstance(raw["expect"], list) else [raw["expect"]]
    rc = ctx.exit_codes[name]
    verdict = PASS if rc in want else FAIL
    return Outcome(verdict, f"{name} exited {rc}", {"exit_code": rc})


def _items(value: Any) -> list[Any]:
    if isinstance(value, (list, dict)):
        return list(value)
    raise Missing("source is not a list")


@op("count_at_least", required=("source", "min"), optional=("description",))
def count_at_least(raw: dict[str, Any], ctx: Context) -> Outcome:
    items = _items(resolve_source(ctx, raw["source"]))
    need = arg(raw, "min", ctx)
    what = raw.get("description", raw["source"])
    verdict = PASS if len(items) >= need else FAIL
    return Outcome(verdict, f"{len(items)} {what} (need at least {need})",
                   {"count": len(items), "items": items[:50]})


@op("count_at_most", required=("source", "max"), optional=("description",))
def count_at_most(raw: dict[str, Any], ctx: Context) -> Outcome:
    items = _items(resolve_source(ctx, raw["source"]))
    limit = arg(raw, "max", ctx)
    what = raw.get("description", raw["source"])
    if len(items) <= limit:
        text = f"no {what}" if not items else f"{len(items)} {what} (at most {limit} allowed)"
        return Outcome(PASS, text, {"count": len(items), "items": items[:50]})
    shown = ", ".join(str(i) for i in items[:5]) + (" ..." if len(items) > 5 else "")
    return Outcome(FAIL, f"{len(items)} {what} — {shown}",
                   {"count": len(items), "items": items[:50]})


def _number(raw: dict[str, Any], ctx: Context) -> float:
    value = resolve_source(ctx, raw["source"])
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Missing(f"{raw['source']} is not a number")
    return value


@op("value_at_least", required=("source", "min"), optional=("description",))
def value_at_least(raw: dict[str, Any], ctx: Context) -> Outcome:
    value, need = _number(raw, ctx), arg(raw, "min", ctx)
    what = raw.get("description", raw["source"])
    return Outcome(PASS if value >= need else FAIL, f"{what} = {value:g} (need >= {need})",
                   {"value": value})


@op("value_at_most", required=("source", "max"), optional=("description",))
def value_at_most(raw: dict[str, Any], ctx: Context) -> Outcome:
    value, limit = _number(raw, ctx), arg(raw, "max", ctx)
    what = raw.get("description", raw["source"])
    return Outcome(PASS if value <= limit else FAIL, f"{what} = {value:g} (limit {limit})",
                   {"value": value})


# --- File metadata operators --------------------------------------------------


def _stats(value: Any) -> list[dict[str, Any]]:
    stats = value if isinstance(value, list) else [value]
    if not all(isinstance(s, dict) and "exists" in s for s in stats):
        raise Missing("source is not stat data")
    return stats


@op("mode_at_most", required=("source", "max"))
def mode_at_most(raw: dict[str, Any], ctx: Context) -> Outcome:
    limit = int(str(raw["max"]), 8)
    stats = [s for s in _stats(resolve_source(ctx, raw["source"])) if s["exists"]]
    if not stats:
        return Outcome(PASS, "no matching files")
    loose = [f"{s['path']} is {s['mode']:04o}" for s in stats if s["mode"] & ~limit]
    if loose:
        return Outcome(FAIL, f"permissions wider than {raw['max']}: " + ", ".join(loose[:5]),
                       {"too_permissive": loose})
    return Outcome(PASS, f"{len(stats)} file(s) no wider than {raw['max']}")


@op("owner_is", required=("source", "owner"))
def owner_is(raw: dict[str, Any], ctx: Context) -> Outcome:
    owners = raw["owner"] if isinstance(raw["owner"], list) else [raw["owner"]]
    stats = [s for s in _stats(resolve_source(ctx, raw["source"])) if s["exists"]]
    if not stats:
        return Outcome(PASS, "no matching files")
    wrong = [f"{s['path']} owned by {s['owner'] or s['uid']}" for s in stats
             if s["owner"] not in owners]
    if wrong:
        return Outcome(FAIL, "; ".join(wrong[:5]), {"wrong_owner": wrong})
    return Outcome(PASS, f"{len(stats)} file(s) owned by {'/'.join(owners)}")


@op("age_at_most", required=("source", "max_hours"), optional=("description",))
def age_at_most(raw: dict[str, Any], ctx: Context) -> Outcome:
    limit = arg(raw, "max_hours", ctx)
    stats = [s for s in _stats(resolve_source(ctx, raw["source"]))
             if s["exists"] and s.get("mtime") is not None]
    what = raw.get("description", raw["source"])
    if not stats:
        return Outcome(FAIL, f"{what}: nothing found")
    newest = max(stats, key=lambda s: s["mtime"])
    age = (ctx.now.timestamp() - newest["mtime"]) / 3600
    details = {"newest": newest["path"], "age_hours": round(age, 1)}
    verdict = PASS if age <= limit else FAIL
    return Outcome(verdict, f"{what}: newest is {age:.1f}h old (limit {limit}h)", details)


# --- Network ------------------------------------------------------------------

# DHCP clients bind their port on a specific interface; that is expected.
DHCP_CLIENT_PORTS = {68, 546}


def is_loopback(addr: str) -> bool:
    if addr in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


@op("public_listeners_within", required=("source", "ports"), optional=("udp_ports",))
def public_listeners_within(raw: dict[str, Any], ctx: Context) -> Outcome:
    sources = raw["source"] if isinstance(raw["source"], list) else [raw["source"]]
    listeners: list[dict[str, Any]] = []
    for src in sources:
        listeners.extend(_items(resolve_source(ctx, src)))
    tcp_ok = set(arg(raw, "ports", ctx))
    udp_ok = set(arg(raw, "udp_ports", ctx, []))
    exposed, unexpected, exempt = [], [], []
    for li in listeners:
        if is_loopback(li["addr"]):
            continue
        label = f"{li['proto']}/{li['port']} on {li['addr'] or '*'}" + (
            f"%{li['iface']}" if li.get("iface") else "")
        if li.get("process"):
            label += f" ({','.join(li['process'])})"
        exposed.append(label)
        allowed = tcp_ok if li["proto"] == "tcp" else udp_ok
        if li["port"] in allowed:
            continue
        if li["proto"] == "udp" and li["port"] in DHCP_CLIENT_PORTS and li.get("iface"):
            exempt.append(label)
            continue
        unexpected.append(label)
    details = {"non_loopback": sorted(set(exposed)), "unexpected": sorted(set(unexpected)),
               "exempt_dhcp_client": sorted(set(exempt)),
               "declared_tcp": sorted(tcp_ok), "declared_udp": sorted(udp_ok)}
    if unexpected:
        return Outcome(FAIL, "undeclared non-loopback listeners: "
                       + ", ".join(sorted(set(unexpected))[:8]), details)
    return Outcome(PASS, f"{len(set(exposed))} non-loopback listener(s), all on declared ports",
                   details)
