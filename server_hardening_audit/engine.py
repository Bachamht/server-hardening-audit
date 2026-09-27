"""Evaluate controls against a host (live or replayed) and produce findings."""

from __future__ import annotations

import traceback
from dataclasses import asdict, dataclass, field
from typing import Any

from . import assertions, collectors, parsers
from .loader import Control
from .runner import Runner

PASS, FAIL, NA, UNKNOWN, MANUAL = "PASS", "FAIL", "NA", "UNKNOWN", "MANUAL"
VERDICTS = (PASS, FAIL, NA, UNKNOWN, MANUAL)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
VERDICT_ORDER = {FAIL: 0, UNKNOWN: 1, MANUAL: 2, PASS: 3, NA: 4}
RHEL_IDS = {"rhel", "centos", "rocky", "almalinux", "fedora", "ol"}


@dataclass
class Finding:
    id: str
    title: str
    domain: str
    severity: str
    verdict: str
    basis: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    refs: dict[str, list[str]] = field(default_factory=dict)
    remediation: dict[str, Any] = field(default_factory=dict)
    risk_acceptance: dict[str, Any] | None = None
    rationale: str = ""
    limitations: str = ""
    instructions: str | None = None

    def to_json(self) -> dict[str, Any]:
        out = asdict(self)
        if out["instructions"] is None:
            del out["instructions"]
        return out


class _Stop(Exception):
    def __init__(self, verdict: str, reason: str):
        super().__init__(reason)
        self.verdict = verdict
        self.reason = reason


# --- Host ---------------------------------------------------------------------


def fingerprint(runner: Runner) -> dict[str, Any]:
    runner.begin("_host")
    info = runner.host()
    osr_text = None
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        res = runner.read(path)
        if res.exists and res.content:
            osr_text = res.content
            break
    osr = parsers.parse("env_kv", osr_text) if osr_text else {}
    virt = runner.run(["systemd-detect-virt"])
    virtualization = virt.stdout.strip() if virt.error is None else None
    ids = {osr.get("ID", "")} | set(osr.get("ID_LIKE", "").split())
    tags = set()
    if "ubuntu" in ids:
        tags.add("ubuntu")
    if "debian" in ids or "ubuntu" in ids:
        tags.add("debian")
    if ids & RHEL_IDS:
        tags.add("rhel")
    return {
        "hostname": info.hostname, "kernel": info.kernel, "machine": info.machine,
        "euid": info.euid, "os": osr.get("PRETTY_NAME", "unknown"),
        "os_id": osr.get("ID"), "os_version": osr.get("VERSION_ID"),
        "virtualization": virtualization, "platform_tags": sorted(tags),
    }


# --- Controls -----------------------------------------------------------------


def _run_checks(control: Control, runner: Runner, profile: dict[str, Any],
                host: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int | None],
                                              dict[str, Any]]:
    facts: dict[str, Any] = {}
    exit_codes: dict[str, int | None] = {}
    collected: dict[str, Any] = {}
    for check in control.checks:
        if check.type == "cmd":
            argv = check.get("argv")
            res = runner.run(argv, check.get("save_as"))
            if res.error_kind == "missing" and check.get("missing") == "na":
                raise _Stop(NA, check.get("missing_reason") or f"{argv[0]} is not installed")
            if res.error:
                raise _Stop(UNKNOWN, f"`{' '.join(argv)}`: {res.error}")
            if res.returncode not in check.get("ok_exit", [0]):
                tail = (res.stderr.strip().splitlines() or [""])[-1][:200]
                raise _Stop(UNKNOWN, f"`{' '.join(argv)}` exited {res.returncode}: {tail}")
            exit_codes[check.name] = res.returncode
            facts[check.name] = _parse(check.get("parser"), res.stdout, argv[0])
        elif check.type == "file":
            path = check.get("path")
            res = runner.read(path, check.get("save_as"))
            if res.error:
                raise _Stop(UNKNOWN, f"{path}: {res.error}")
            if not res.exists:
                mode = check.get("missing", "fact")
                if mode == "na":
                    raise _Stop(NA, check.get("missing_reason") or f"{path} does not exist")
                if mode == "unknown":
                    raise _Stop(UNKNOWN, check.get("missing_reason") or f"{path} does not exist")
                facts[check.name] = None
            else:
                facts[check.name] = _parse(check.get("parser"), res.content or "", path)
        elif check.type == "glob":
            res = runner.glob(check.get("pattern"), check.get("save_as"))
            if res.error:
                raise _Stop(UNKNOWN, f"{check.get('pattern')}: {res.error}")
            facts[check.name] = [asdict(m) for m in res.matches]
        elif check.type == "stat":
            res = runner.stat(check.get("path"), check.get("save_as"))
            if res.error:
                raise _Stop(UNKNOWN, f"{check.get('path')}: {res.error}")
            facts[check.name] = asdict(res)
        elif check.type == "collector":
            coll = collectors.COLLECTORS[check.get("collector")]
            ctx = collectors.CollectContext(runner, profile, check.get("params", {}), host)
            try:
                value = coll.fn(ctx)
            except collectors.NotApplicable as exc:
                raise _Stop(NA, str(exc)) from exc
            except collectors.Undetermined as exc:
                raise _Stop(UNKNOWN, str(exc)) from exc
            facts[check.name] = value
            collected[check.name] = value
    return facts, exit_codes, collected


def _parse(name: str, text: str, what: str) -> Any:
    try:
        return parsers.parse(name, text)
    except parsers.ParseError as exc:
        raise _Stop(UNKNOWN, f"could not parse output of {what}: {exc}") from exc


def evaluate(control: Control, runner: Runner, profile: dict[str, Any],
             host: dict[str, Any]) -> Finding:
    finding = Finding(
        id=control.id, title=control.title, domain=control.domain,
        severity=control.severity, verdict=UNKNOWN, basis="verified", summary="",
        refs={k: list(v) for k, v in control.refs.items()},
        remediation={"summary": control.remediation, "disruptive": control.disruptive},
        rationale=control.rationale, limitations=control.limitations,
    )
    tags = set(host.get("platform_tags", []))
    if not tags:
        finding.summary = "could not identify the host platform (no usable /etc/os-release)"
        return finding
    if not tags & set(control.platforms):
        finding.verdict = NA
        finding.summary = (f"not applicable to this platform ({host.get('os')}); applies to "
                           f"{', '.join(control.platforms)}")
        return finding
    if not tags & set(control.implemented):
        finding.summary = (f"no implementation for this platform ({host.get('os')}) in this "
                           f"version; implemented for {', '.join(control.implemented)}")
        return finding
    if control.manual is not None:
        finding.verdict = MANUAL
        finding.basis = "attested"
        finding.summary = "requires an operator procedure and an attestation"
        finding.instructions = control.manual
        return finding
    try:
        facts, exit_codes, collected = _run_checks(control, runner, profile, host)
        ctx = assertions.Context(facts, exit_codes, profile, runner.now)
        outcome = assertions.evaluate(control.assertion, ctx)
    except _Stop as stop:
        finding.verdict, finding.summary = stop.verdict, stop.reason
        return finding
    except Exception as exc:  # engine bug: report, never crash the run
        finding.summary = f"internal error: {type(exc).__name__}: {exc}"
        finding.details = {"traceback": traceback.format_exc(limit=5)}
        return finding
    finding.verdict, finding.summary = outcome.verdict, outcome.summary
    finding.details = {"assertion": outcome.details, **(
        {"collected": collected} if collected else {})}
    part = control.manual_part
    if part and outcome.verdict == PASS and profile.get(part["when"][8:]):
        finding.verdict = MANUAL
        finding.summary += " -- remaining part needs an attestation"
        finding.instructions = part["instructions"].strip()
    return finding


def sort_key(f: Finding | dict[str, Any]) -> tuple[int, int, str]:
    d = f if isinstance(f, dict) else asdict(f)
    return (SEVERITY_ORDER[d["severity"]], VERDICT_ORDER[d["verdict"]], d["id"])


def exit_code(findings: list[dict[str, Any]]) -> int:
    """0 no FAIL; 1 FAIL but none critical; 2 critical FAIL."""
    fails = [f for f in findings if f["verdict"] == FAIL]
    if any(f["severity"] == "critical" for f in fails):
        return 2
    return 1 if fails else 0
