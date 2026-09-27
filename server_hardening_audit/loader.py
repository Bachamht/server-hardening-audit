"""Load and validate controls and profiles.

Control files are data. They may name a parser, a collector or an assertion
operator, but cannot contain code; validation rejects any name that is not
registered in the engine, and any key the schema does not define.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    from ._vendor import tomli as tomllib  # type: ignore[no-redef]


class ConfigError(Exception):
    """A control, profile or attestation file is invalid. Exit code 3."""


SEVERITIES = ("critical", "high", "medium", "low")
DOMAINS = ("access", "network", "patching", "detection", "resilience", "baseline")
PLATFORMS = ("debian", "ubuntu", "rhel")
CHECK_TYPES = ("cmd", "file", "glob", "stat", "collector", "manual")
ID_RE = re.compile(r"[A-Z]{3}-\d{2}")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
SAVE_AS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# --- Bundled data -------------------------------------------------------------


def _bundled_root():
    pkg = resources.files("server_hardening_audit")
    data = pkg.joinpath("_data")
    if data.is_dir():
        return data  # inside the .pyz
    return Path(__file__).resolve().parent.parent  # source checkout


def bundled_bytes(relpath: str) -> bytes:
    node = _bundled_root()
    for part in relpath.split("/"):
        node = node.joinpath(part)
    return node.read_bytes()


def bundled_names(subdir: str) -> list[str]:
    node = _bundled_root().joinpath(subdir)
    return sorted(p.name for p in node.iterdir() if p.name.endswith(".toml"))


def parse_toml(data: bytes, origin: str) -> dict[str, Any]:
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{origin}: {exc}") from exc


# --- Controls -----------------------------------------------------------------


@dataclass
class Check:
    type: str
    name: str
    spec: dict[str, Any]

    def get(self, key: str, default: Any = None) -> Any:
        return self.spec.get(key, default)


@dataclass
class Control:
    id: str
    title: str
    domain: str
    severity: str
    platforms: list[str]
    implemented: list[str]
    checks: list[Check]
    assertion: dict[str, Any] | None
    rationale: str
    remediation: str
    disruptive: bool
    limitations: str
    manual: str | None
    manual_part: dict[str, Any] | None
    refs: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class ControlSet:
    controls: list[Control]
    sha256: str
    origin: str

    def by_id(self, cid: str) -> Control | None:
        return next((c for c in self.controls if c.id == cid), None)


def _require(cond: bool, where: str, msg: str) -> None:
    if not cond:
        raise ConfigError(f"{where}: {msg}")


def _only_keys(table: dict[str, Any], allowed: set[str], where: str) -> None:
    extra = set(table) - allowed
    _require(not extra, where, f"unknown key(s): {', '.join(sorted(extra))}")


_CHECK_KEYS = {
    "cmd": {"argv", "parser", "save_as", "name", "ok_exit", "missing", "missing_reason"},
    "file": {"path", "parser", "save_as", "name", "missing", "missing_reason"},
    "glob": {"pattern", "save_as", "name"},
    "stat": {"path", "save_as", "name"},
    "collector": {"collector", "params", "name"},
    "manual": {"instructions", "name"},
}


def _check(raw: dict[str, Any], where: str) -> Check:
    from . import collectors, parsers

    ctype = raw.get("type")
    _require(ctype in CHECK_TYPES, where, f"type must be one of {CHECK_TYPES}")
    spec = {k: v for k, v in raw.items() if k != "type"}
    _only_keys(spec, _CHECK_KEYS[ctype], where)
    if ctype == "cmd":
        argv = spec.get("argv")
        _require(isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv),
                 where, "argv must be a non-empty list of strings")
        _require(all(isinstance(x, int) for x in spec.get("ok_exit", [0])), where,
                 "ok_exit must be a list of integers")
    if ctype in ("file", "stat"):
        _require(isinstance(spec.get("path"), str) and spec["path"].startswith("/"),
                 where, "path must be absolute")
    if ctype == "glob":
        _require(isinstance(spec.get("pattern"), str) and spec["pattern"].startswith("/"),
                 where, "pattern must be absolute")
    if ctype in ("cmd", "file"):
        parser = spec.setdefault("parser", "text")
        _require(parser in parsers.PARSERS, where, f"unknown parser {parser!r}")
        _require(spec.get("missing", "unknown") in ("unknown", "na", "fact"), where,
                 "missing must be unknown, na or fact")
    if ctype == "collector":
        cname = spec.get("collector")
        _require(cname in collectors.COLLECTORS, where, f"unknown collector {cname!r}")
        _require(isinstance(spec.get("params", {}), dict), where, "params must be a table")
    if ctype == "manual":
        _require(isinstance(spec.get("instructions"), str), where, "instructions required")
    if "save_as" in spec:
        _require(bool(SAVE_AS_RE.fullmatch(spec["save_as"])), where, "invalid save_as")
    default_name = {
        "collector": spec.get("collector"), "manual": "manual",
    }.get(ctype) or Path(spec.get("save_as", ctype)).stem
    name = spec.get("name", default_name.replace(".", "-").lower())
    _require(bool(NAME_RE.fullmatch(name)), where, f"invalid check name {name!r}")
    return Check(ctype, name, spec)


def _assertion(raw: Any, where: str) -> dict[str, Any]:
    from . import assertions

    _require(isinstance(raw, dict), where, "assert must be a table")
    op = raw.get("op")
    _require(op in assertions.OPS, where, f"unknown assertion op {op!r}")
    if op in ("all_of", "any_of"):
        subs = raw.get("of")
        _require(isinstance(subs, list) and subs, where, f"{op} needs a non-empty 'of' list")
        for i, sub in enumerate(subs):
            _assertion(sub, f"{where}.of[{i}]")
    else:
        problem = assertions.OPS[op].validate(raw)
        _require(problem is None, where, problem or "")
    return raw


_CONTROL_KEYS = {"id", "title", "domain", "severity", "platforms", "implemented", "check",
                 "assert", "text", "refs", "manual_part"}
_REF_KEYS = {"iso27001_2022", "essential_eight", "cis"}


def _control(raw: dict[str, Any], seen: set[str]) -> Control:
    cid = raw.get("id", "?")
    where = f"control {cid}"
    _only_keys(raw, _CONTROL_KEYS, where)
    _require(isinstance(cid, str) and bool(ID_RE.fullmatch(cid)), where, "invalid id")
    _require(cid not in seen, where, "duplicate id")
    seen.add(cid)
    _require(isinstance(raw.get("title"), str) and raw["title"], where, "title required")
    _require(raw.get("domain") in DOMAINS, where, f"domain must be one of {DOMAINS}")
    _require(raw.get("severity") in SEVERITIES, where, f"severity must be one of {SEVERITIES}")
    platforms = raw.get("platforms", list(PLATFORMS))
    implemented = raw.get("implemented", platforms)
    for plist in (platforms, implemented):
        _require(isinstance(plist, list) and set(plist) <= set(PLATFORMS), where,
                 f"platforms must be a subset of {PLATFORMS}")
    checks = [_check(c, f"{where} check[{i}]") for i, c in enumerate(raw.get("check", []))]
    names = [c.name for c in checks]
    _require(len(names) == len(set(names)), where, "check names must be unique")
    manual_checks = [c for c in checks if c.type == "manual"]
    _require(len(manual_checks) <= 1, where, "at most one manual check")
    _require(not (manual_checks and len(checks) > 1), where,
             "a manual check cannot be combined with automated checks; use manual_part")
    assertion = raw.get("assert")
    if manual_checks:
        _require(assertion is None, where, "manual controls take no assert")
    else:
        _require(bool(checks), where, "at least one check required")
        assertion = _assertion(assertion, f"{where} assert")
    text = raw.get("text", {})
    _only_keys(text, {"rationale", "remediation", "disruptive", "limitations"}, f"{where} text")
    _require(isinstance(text.get("rationale"), str), where, "text.rationale required")
    _require(isinstance(text.get("remediation"), str), where, "text.remediation required")
    _require(isinstance(text.get("disruptive"), bool), where, "text.disruptive must be bool")
    refs = raw.get("refs", {})
    _only_keys(refs, _REF_KEYS, f"{where} refs")
    for k in _REF_KEYS:
        refs.setdefault(k, [])
        _require(all(isinstance(r, str) for r in refs[k]), where, f"refs.{k} must be strings")
    manual_part = raw.get("manual_part")
    if manual_part is not None:
        _only_keys(manual_part, {"when", "instructions"}, f"{where} manual_part")
        _require(isinstance(manual_part.get("when"), str)
                 and manual_part["when"].startswith("profile."), where,
                 "manual_part.when must name a profile field")
        _require(isinstance(manual_part.get("instructions"), str), where,
                 "manual_part.instructions required")
    return Control(
        id=cid, title=raw["title"], domain=raw["domain"], severity=raw["severity"],
        platforms=platforms, implemented=implemented, checks=checks, assertion=assertion,
        rationale=text["rationale"].strip(), remediation=text["remediation"].strip(),
        disruptive=text["disruptive"], limitations=text.get("limitations", "").strip(),
        manual=manual_checks[0].spec["instructions"].strip() if manual_checks else None,
        manual_part=manual_part, refs=refs,
    )


def load_controls(path: str | None = None) -> ControlSet:
    """Load a controls file or every *.toml in a directory. Default: bundled."""
    blobs: list[tuple[str, bytes]] = []
    if path is None:
        for name in bundled_names("controls"):
            blobs.append((f"controls/{name}", bundled_bytes(f"controls/{name}")))
    else:
        p = Path(path)
        files = sorted(p.glob("*.toml")) if p.is_dir() else [p]
        try:
            blobs = [(str(f), f.read_bytes()) for f in files]
        except OSError as exc:
            raise ConfigError(str(exc)) from exc
    _require(bool(blobs), path or "controls", "no control files found")
    digest = hashlib.sha256()
    controls: list[Control] = []
    seen: set[str] = set()
    for origin, data in blobs:
        digest.update(data)
        doc = parse_toml(data, origin)
        _only_keys(doc, {"control"}, origin)
        for raw in doc.get("control", []):
            controls.append(_control(raw, seen))
    return ControlSet(controls, digest.hexdigest(), path or "bundled")


# --- Profiles -----------------------------------------------------------------

PROFILE_DEFAULTS: dict[str, Any] = {
    "name": "unnamed",
    "description": "",
    "public_ports": [22],
    "public_udp_ports": [],
    "tls_domains": [],
    "tls_min_days": 14,
    "rpo_hours": 24,
    "backup_paths": [],
    "backup_offsite_required": True,
    "max_image_age_days": 60,
    "admin_users": [],
    "service_users": [],
    "apt_lists_max_age_hours": 48,
    "disk_paths": ["/"],
    "min_free_percent": 20,
    "min_free_inodes_percent": 10,
    "lynis_max_age_days": 90,
}


def _type_ok(value: Any, default: Any) -> bool:
    if isinstance(default, bool):
        return isinstance(value, bool)
    if isinstance(default, int):
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, list):
        return isinstance(value, list) and all(isinstance(v, (str, int)) for v in value)
    return False


def load_profile(path: str | None = None, data: bytes | None = None) -> dict[str, Any]:
    if data is not None:
        origin = path or "profile"
    elif path is None:
        origin, data = "profiles/minimal.toml", bundled_bytes("profiles/minimal.toml")
    else:
        try:
            origin, data = path, Path(path).read_bytes()
        except OSError as exc:
            raise ConfigError(str(exc)) from exc
    raw = parse_toml(data, origin)
    _only_keys(raw, set(PROFILE_DEFAULTS), origin)
    profile = dict(PROFILE_DEFAULTS)
    for key, value in raw.items():
        _require(_type_ok(value, PROFILE_DEFAULTS[key]), origin,
                 f"{key} has the wrong type (expected like {PROFILE_DEFAULTS[key]!r})")
        profile[key] = value
    for key in ("public_ports", "public_udp_ports"):
        _require(all(isinstance(p, int) and 0 < p < 65536 for p in profile[key]), origin,
                 f"{key} must be port numbers")
    profile["_source"] = data.decode("utf-8")
    return profile
