"""findings.json and report.md.

The report is a pure function of findings.json plus run.json, so it can be
re-rendered at any time from a saved run (``report RUN_DIR``).
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .engine import SEVERITY_ORDER, VERDICTS, sort_key

SCHEMA_VERSION = "1"
TOOL = {"name": "server-hardening-audit", "version": __version__}

INHERENT_LIMITS = [
    "Cloud-provider security groups, network ACLs and upstream firewalls are invisible "
    "from inside the host.",
    "Application code, application configuration and data-layer permissions are not "
    "assessed.",
    "Backup copies held on other systems cannot be verified from this host; they rely on "
    "attestation.",
    "Results describe the host at the time of the run. They are not continuous monitoring.",
    "Known-vulnerability (CVE) matching is out of scope.",
]


def build_doc(run: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": dict(TOOL),
        "run": {
            "id": run["id"], "mode": run["mode"], "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "host": {k: run["host"].get(k) for k in
                     ("hostname", "os", "kernel", "virtualization", "euid")},
            "profile": run["profile"]["name"], "controls_sha256": run["controls"]["sha256"],
        },
        "findings": sorted(findings, key=sort_key),
    }


def upgrade(doc: dict[str, Any]) -> dict[str, Any]:
    """Read findings written by earlier 0.1.0 development builds, which gave
    unattested MANUAL findings basis 'attested' (or 'verified'). In place."""
    for f in doc.get("findings", []):
        if isinstance(f, dict) and f.get("verdict") == "MANUAL" and f.get("basis") != "pending":
            f["basis"] = "pending"
    return doc


# --- Validation (no jsonschema dependency) ------------------------------------

_FINDING_FIELDS = {
    "id": str, "title": str, "domain": str, "severity": str, "verdict": str, "basis": str,
    "summary": str, "details": dict, "evidence": list, "refs": dict, "remediation": dict,
}


def validate(doc: Any) -> list[str]:
    """Structural check of a findings.json document. Empty list = valid."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["document is not an object"]
    if doc.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION!r}")
    tool = doc.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != TOOL["name"] \
            or not isinstance(tool.get("version"), str):
        errors.append("tool must name server-hardening-audit and a version")
    run = doc.get("run")
    if not isinstance(run, dict):
        errors.append("run must be an object")
    else:
        for key in ("id", "started_at", "finished_at", "profile", "controls_sha256"):
            if not isinstance(run.get(key), str):
                errors.append(f"run.{key} must be a string")
        if not isinstance(run.get("host"), dict):
            errors.append("run.host must be an object")
    findings = doc.get("findings")
    if not isinstance(findings, list):
        return errors + ["findings must be a list"]
    seen = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{where} is not an object")
            continue
        for key, typ in _FINDING_FIELDS.items():
            if not isinstance(f.get(key), typ):
                errors.append(f"{where}.{key} must be {typ.__name__}")
        if f.get("id") in seen:
            errors.append(f"{where}: duplicate id {f.get('id')}")
        seen.add(f.get("id"))
        if f.get("verdict") not in VERDICTS:
            errors.append(f"{where}.verdict {f.get('verdict')!r} is not one of {VERDICTS}")
        if f.get("severity") not in SEVERITY_ORDER:
            errors.append(f"{where}.severity {f.get('severity')!r} is invalid")
        if f.get("basis") not in ("verified", "attested", "pending"):
            errors.append(f"{where}.basis must be verified, attested or pending")
        if (f.get("verdict") == "MANUAL") != (f.get("basis") == "pending"):
            errors.append(f"{where}: MANUAL, and only MANUAL, has basis pending")
        if f.get("verdict") in ("NA", "UNKNOWN") and not f.get("summary"):
            errors.append(f"{where}: {f.get('verdict')} requires a reason in summary")
        if f.get("verdict") in ("PASS", "FAIL") and f.get("basis") == "verified" \
                and not f.get("evidence"):
            errors.append(f"{where}: a verified {f.get('verdict')} must cite evidence")
        rem = f.get("remediation", {})
        if isinstance(rem, dict) and not isinstance(rem.get("disruptive"), bool):
            errors.append(f"{where}.remediation.disruptive must be bool")
        if "risk_acceptance" not in f:
            errors.append(f"{where}.risk_acceptance must be present (null if none)")
    return errors


# --- Markdown -----------------------------------------------------------------


def verdict_label(f: dict[str, Any]) -> str:
    label = f["verdict"]
    if f["basis"] == "attested" and f["verdict"] in ("PASS", "FAIL"):
        label += " · attested"
    ra = f.get("risk_acceptance")
    if ra and f["verdict"] == "FAIL":
        label += f" · risk accepted (review by {ra.get('review_by', '?')})"
        if ra.get("expired"):
            label += " · REVIEW OVERDUE"
    return label


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(doc: dict[str, Any], run: dict[str, Any]) -> str:
    host = run["host"]
    findings = doc["findings"]
    out: list[str] = []
    w = out.append
    w(f"# Server hardening audit — {host.get('hostname') or 'host'}\n")
    w("| | |\n|---|---|")
    w(f"| Host | {_cell(host.get('hostname'))} — {_cell(host.get('os'))}, "
      f"{_cell(host.get('kernel'))}, virtualization: {_cell(host.get('virtualization'))} |")
    w(f"| Run | `{run['id']}` · {run['started_at']} → {run['finished_at']} · {run['mode']}"
      + (f" of `{run['replay_of']}`" if run.get("replay_of") else "") + " |")
    w(f"| Tool | {doc['tool']['name']} {doc['tool']['version']} |")
    w(f"| Profile | {_cell(run['profile']['name'])} |")
    w(f"| Controls | {_cell(run['controls']['origin'])} · sha256 "
      f"`{run['controls']['sha256'][:16]}…` · {len(findings)} evaluated |")
    for af in doc.get("attestation_files", []):
        w(f"| Attestation | `{_cell(af['file'])}` · sha256 `{af['sha256'][:16]}…` · "
          f"{af['attestations']} attestation(s), {af['risk_acceptances']} risk acceptance(s), "
          f"{af.get('notes', 0)} note(s) |")
    priv = ("root" if host.get("euid") == 0
            else f"uid {host.get('euid')} (not root: expect UNKNOWN results)")
    w(f"| Privileges | {priv} |\n")
    w("**Scope.** This report covers the technical controls of one Linux host, as observed "
      "from inside the host by a read-only tool at the time shown. It is not an assessment "
      "of an organisation. `PASS` is backed by machine-collected evidence; `PASS · attested` "
      "is backed by an operator's signed statement. Nothing on the host was changed.\n")

    w("## Summary\n")
    cols = ["FAIL", "UNKNOWN", "MANUAL", "PASS", "NA"]
    w("| Severity | " + " | ".join(cols) + " |")
    w("|---|" + "---:|" * len(cols))
    for sev in SEVERITY_ORDER:
        counts = [sum(1 for f in findings if f["severity"] == sev and f["verdict"] == v)
                  for v in cols]
        w(f"| {sev} | " + " | ".join(str(c) if c else "·" for c in counts) + " |")
    w("")

    w("## Findings\n")
    w("| ID | Severity | Verdict | Control | Result |")
    w("|---|---|---|---|---|")
    for f in findings:
        w(f"| [{f['id']}](#{f['id'].lower()}) | {f['severity']} | **{verdict_label(f)}** | "
          f"{_cell(f['title'])} | {_cell(f['summary'])} |")
    w("")

    w("## Controls\n")
    for f in findings:
        w(f"### {f['id']}\n")
        w(f"**{f['title']}** — {f['severity']}, {f['domain']}\n")
        w(f"- **Verdict:** {verdict_label(f)}")
        w(f"- **Result:** {f['summary']}")
        for h in f.get("details", {}).get("highlights", []):
            w(f"- **Key fact:** {h}")
        if f.get("evidence"):
            w("- **Evidence:** " + ", ".join(f"`{e}`" for e in f["evidence"]))
        if f.get("instructions"):
            w(f"- **Operator procedure:** {' '.join(f['instructions'].split())}")
        details = f.get("details", {})
        for a in details.get("attestations", []):
            w(f"- **Attested** {a['verdict']} by {a['performed_by']} at {a['performed_at']} "
              f"(`{a['file']}`): {a['method']}")
            if a.get("measurements"):
                w("  - Measurements: " + ", ".join(f"{k} = {v}"
                                                    for k, v in a["measurements"].items()))
            for e in a.get("evidence", []):
                digest = f"sha256 `{e['sha256'][:16]}…`" if e["sha256"] else "**file missing**"
                w(f"  - Evidence: `{e['path']}` ({digest})")
        if details.get("automated_result") and f["basis"] == "attested":
            ar = details["automated_result"]
            w(f"- **Automated result before attestation:** {ar['verdict']} — {ar['summary']}")
        for n in details.get("notes", []):
            w(f"- **Operator note** ({n['author']}, `{n['file']}`): {n['text']}")
        for c in details.get("corroboration", []):
            if c["agrees"]:
                agree = "agrees"
            elif c["verdict"] == "FAIL":
                agree = "**CONTRADICTS the host result**"
            else:  # an external PASS cannot see everything a verified FAIL covers
                agree = "found no problem within its scope; the host result stands"
            w(f"- **External check** ({c['source']}, {c['performed_at']}) {agree}: "
              f"{c['verdict']} — {c['method']}")
        if f.get("rationale"):
            w(f"- **Why it matters:** {' '.join(f['rationale'].split())}")
        rem = f.get("remediation", {})
        if f["verdict"] in ("FAIL", "UNKNOWN", "MANUAL") and rem.get("summary"):
            impact = "may interrupt service" if rem.get("disruptive") else "non-disruptive"
            w(f"- **Remediation** ({impact}): {rem['summary']}")
        if f.get("limitations"):
            w(f"- **Limitations:** {' '.join(f['limitations'].split())}")
        ra = f.get("risk_acceptance")
        if ra:
            w(f"- **Risk accepted** by {ra.get('accepted_by')}: {ra.get('reason')} "
              f"(review by {ra.get('review_by')})")
        w("")

    w("## What this report does not cover\n")
    open_items = [f for f in findings if f["verdict"] in ("NA", "UNKNOWN", "MANUAL")]
    if open_items:
        w("Controls without a verified result:\n")
        w("| ID | Verdict | Reason |")
        w("|---|---|---|")
        for f in sorted(open_items, key=lambda x: (x["verdict"], x["id"])):
            w(f"| {f['id']} | {f['verdict']} | {_cell(f['summary'])} |")
        w("")
    else:
        w("Every control has a PASS or FAIL result.\n")
    w("Inherent limits of this tool:\n")
    for item in INHERENT_LIMITS:
        w(f"- {item}")
    limits = [f for f in findings if f.get("limitations")]
    if limits:
        w("\nControl-specific limits:\n")
        for f in limits:
            w(f"- **{f['id']}:** {' '.join(f['limitations'].split())}")
    w("")
    return "\n".join(out)
