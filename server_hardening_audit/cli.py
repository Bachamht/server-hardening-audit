"""Command-line interface.

Exit codes: 0 = no FAIL; 1 = FAIL, none critical; 2 = critical FAIL;
3 = the tool itself failed (bad input, unreadable files, internal error).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__, collectors, engine, evidence, policy, redact, report
from .loader import ConfigError, Control, load_controls, load_profile
from .runner import LiveRunner, ReplayRunner

EXIT_TOOL_ERROR = 3


class ToolError(Exception):
    pass


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# --- list -----------------------------------------------------------------------


def _describe_check(check) -> list[str]:
    def flag(argv: list[str]) -> str:
        return "" if policy.check(argv) else "   [REFUSED BY POLICY]"

    if check.type == "cmd":
        return [f"run   {' '.join(check.get('argv'))}{flag(check.get('argv'))}"]
    if check.type == "file":
        return [f"read  {check.get('path')}"]
    if check.type == "glob":
        return [f"list  {check.get('pattern')}   (metadata only)"]
    if check.type == "stat":
        return [f"stat  {check.get('path')}"]
    if check.type == "manual":
        return ["manual: operator procedure, resolved by an attestation"]
    coll = collectors.COLLECTORS[check.get("collector")]
    lines = [f"collector {coll.name}:"]
    for step in coll.plan:
        lines.append("  " + step.render())
    if check.get("params"):
        lines.append(f"  params: {json.dumps(check.get('params'))}")
    return lines


def cmd_list(args: argparse.Namespace) -> int:
    cs = load_controls(args.controls)
    print(f"# {len(cs.controls)} controls from {cs.origin} (sha256 {cs.sha256})")
    print("# Every operation the audit can perform is listed below. Commands run without a")
    print("# shell, from a fixed PATH, only if they match the allowlist in policy.py.")
    print("# Every run also reads /etc/os-release and runs `systemd-detect-virt`.\n")
    for c in cs.controls:
        print(f"{c.id}  [{c.severity}]  {c.title}")
        for check in c.checks:
            for line in _describe_check(check):
                print(f"    {line}")
        print()
    return 0


# --- audit ----------------------------------------------------------------------


def _select(controls: list[Control], only: str | None) -> list[Control]:
    if not only:
        return controls
    wanted = [x.strip().upper() for x in only.split(",") if x.strip()]
    known = {c.id for c in controls}
    unknown = [w for w in wanted if w not in known]
    if unknown:
        raise ToolError(f"unknown control id(s): {', '.join(unknown)}")
    return [c for c in controls if c.id in wanted]


def _run_dir(out: Path, started: datetime, hostname: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9.-]", "-", hostname or "host")[:63] or "host"
    base = out / f"{started:%Y%m%dT%H%M%SZ}-{safe}"
    path, n = base, 1
    while path.exists():
        n += 1
        path = Path(f"{base}-{n}")
    return path


def cmd_audit(args: argparse.Namespace) -> int:
    cs = load_controls(args.controls)
    selected = _select(cs.controls, args.only)
    replay_run: dict[str, Any] | None = None
    if args.replay:
        rdir = Path(args.replay)
        try:
            replay_run = json.loads((rdir / "run.json").read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise ToolError(f"{rdir}: not a run directory ({exc})") from exc
        started = _parse_iso(replay_run["started_at"])
        runner = ReplayRunner(started, rdir / "evidence")
        profile = (load_profile(args.profile) if args.profile else
                   load_profile(replay_run["profile"].get("path"),
                                data=replay_run["profile"]["source"].encode()))
    else:
        started = datetime.now(timezone.utc).replace(microsecond=0)
        runner = LiveRunner(started)
        profile = load_profile(args.profile)

    host = engine.fingerprint(runner)
    if runner.mode == "live" and host["euid"] != 0:
        print("warning: not running as root; many controls will be UNKNOWN", file=sys.stderr)
    run_dir = _run_dir(Path(args.out), started, host["hostname"])
    ev_dir = run_dir / "evidence"
    evidence.make_private_dir(ev_dir)
    evidence.write_scope(ev_dir, "_host", runner.calls.get("_host", []))

    findings = []
    for control in selected:
        runner.begin(control.id)
        finding = engine.evaluate(control, runner, profile, host)
        finding.evidence = evidence.write_scope(ev_dir, control.id,
                                                runner.calls.get(control.id, []))
        findings.append(finding.to_json())

    finished = (_parse_iso(replay_run["finished_at"]) if replay_run
                else datetime.now(timezone.utc))
    run = {
        "schema_version": "1",
        "tool": dict(report.TOOL),
        "id": run_dir.name, "mode": runner.mode,
        "replay_of": replay_run["id"] if replay_run else None,
        "started_at": _iso(started), "finished_at": _iso(finished),
        "host": host,
        "profile": {"name": profile["name"], "path": args.profile,
                    "source": profile["_source"]},
        "controls": {"origin": cs.origin, "sha256": cs.sha256,
                     "selected": [c.id for c in selected]},
    }
    doc = report.build_doc(run, findings)
    evidence.write_json(run_dir / "run.json", run)
    evidence.write_json(run_dir / "findings.json", doc)
    evidence.write_text(run_dir / "report.md", report.render_markdown(doc, run))
    evidence.write_manifest(run_dir)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f["verdict"]] = counts.get(f["verdict"], 0) + 1
    summary = ", ".join(f"{counts.get(v, 0)} {v}" for v in engine.VERDICTS)
    print(f"{run_dir}\n{len(findings)} controls: {summary}")
    return engine.exit_code(findings)


# --- report ---------------------------------------------------------------------


def cmd_report(args: argparse.Namespace) -> int:
    if args.framework or args.attest:
        raise ToolError("--framework and --attest are not available in this build yet")
    run_dir = Path(args.run_dir)
    try:
        run = json.loads((run_dir / "run.json").read_text())
        doc = json.loads((run_dir / "findings.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolError(f"{run_dir}: not a run directory ({exc})") from exc
    errors = report.validate(doc)
    if errors:
        raise ToolError("findings.json is invalid: " + "; ".join(errors[:5]))
    if args.format == "json":
        print(json.dumps(doc, indent=2, ensure_ascii=False))
    else:
        print(report.render_markdown(doc, run))
    return engine.exit_code(doc["findings"])


# --- redact-check ---------------------------------------------------------------


def cmd_redact_check(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        raise ToolError(f"{path} does not exist")
    hits, scanned = redact.scan_path(path)
    for hit in hits:
        print(hit)
    if hits:
        print(f"redact-check: {len(hits)} finding(s) in {scanned} file(s)", file=sys.stderr)
        return 1
    print(f"redact-check: clean ({scanned} file(s) scanned)")
    return 0


def _not_yet(name: str):
    def handler(args: argparse.Namespace) -> int:
        raise ToolError(f"`{name}` is not available in this build yet")
    return handler


# --- entry point ----------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors; 2 means 'critical FAIL' here."""

    def error(self, message: str):  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_TOOL_ERROR)


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="server-hardening-audit",
        description="Read-only Linux server hardening audit with evidence-backed reports.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("list", help="show every command and file each control will use")
    s.add_argument("--controls", help="controls file or directory (default: bundled)")
    s.set_defaults(fn=cmd_list)

    s = sub.add_parser("audit", help="audit this host (or replay saved evidence)")
    s.add_argument("--profile", help="host profile TOML (default: bundled minimal)")
    s.add_argument("--controls", help="controls file or directory (default: bundled)")
    s.add_argument("--out", default="audit-runs", help="parent directory for the run")
    s.add_argument("--only", help="comma-separated control ids")
    s.add_argument("--replay", metavar="RUN_DIR",
                   help="evaluate recorded evidence instead of the live host")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("report", help="re-render a run's report")
    s.add_argument("run_dir")
    s.add_argument("--framework", choices=["essential-eight", "iso27001-2022"])
    s.add_argument("--attest", action="append", default=[], metavar="FILE")
    s.add_argument("--format", choices=["md", "json"], default="md")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("probe", help="probe a host from outside (operator machine)")
    s.add_argument("host")
    s.set_defaults(fn=_not_yet("probe"))
    s = sub.add_parser("diff", help="compare two runs")
    s.add_argument("run_a")
    s.add_argument("run_b")
    s.set_defaults(fn=_not_yet("diff"))
    s = sub.add_parser("scrub", help="produce a publishable copy of a run")
    s.add_argument("run_dir")
    s.set_defaults(fn=_not_yet("scrub"))

    s = sub.add_parser("redact-check", help="scan files for secrets before publishing")
    s.add_argument("path")
    s.set_defaults(fn=cmd_redact_check)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ConfigError, ToolError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    except KeyboardInterrupt:
        return EXIT_TOOL_ERROR
    except Exception as exc:  # last resort: never exit 0/1/2 on a crash
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR
