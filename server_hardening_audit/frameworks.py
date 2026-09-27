"""Framework views: the same findings seen through a framework's clauses.

A framework file lists clauses ("requirements") with their applicability to
a Linux server. Controls point at clauses through ``refs``. A view
aggregates the findings of every control that points at a clause.

NOT APPLICABLE (the clause does not apply to this kind of host) and NOT
ASSESSED (it applies, but nothing here gives evidence for it) are kept
apart throughout; conflating them is the easiest way to overstate coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .loader import ConfigError, ControlSet, bundled_bytes, bundled_names, parse_toml

NAMES = ("essential-eight", "iso27001-2022")
REF_KEY = {"essential-eight": "essential_eight", "iso27001-2022": "iso27001_2022"}
APPLICABILITY = ("applicable", "not_applicable")
TERM_KEYS = ("pass", "fail", "no_visibility", "pending", "partial", "not_assessed",
             "not_applicable", "withheld")


@dataclass
class Requirement:
    id: str
    summary: str
    applicability: str
    strategy: str | None = None
    coverage: str = "full"
    rationale: str = ""
    needs_review: bool = False
    controls: list[str] = field(default_factory=list)


@dataclass
class Framework:
    id: str
    meta: dict[str, Any]
    requirements: list[Requirement]
    strategies: list[dict[str, str]]
    beyond: list[dict[str, Any]]

    @property
    def terms(self) -> dict[str, str]:
        return self.meta["terms"]


def _req(raw: dict[str, Any], where: str) -> Requirement:
    allowed = {"id", "strategy", "summary", "applicability", "coverage", "rationale",
               "needs_review"}
    extra = set(raw) - allowed
    if extra:
        raise ConfigError(f"{where}: unknown key(s) {sorted(extra)}")
    for key in ("id", "summary", "applicability"):
        if not isinstance(raw.get(key), str):
            raise ConfigError(f"{where}: {key} required")
    if raw["applicability"] not in APPLICABILITY:
        raise ConfigError(f"{where}: applicability must be one of {APPLICABILITY}")
    if raw.get("coverage", "full") not in ("full", "partial"):
        raise ConfigError(f"{where}: coverage must be full or partial")
    return Requirement(**raw)


def load(name: str, controls: ControlSet) -> Framework:
    """Load a bundled framework and attach the controls that reference it."""
    if f"{name}.toml" not in bundled_names("frameworks"):
        raise ConfigError(f"unknown framework {name!r}")
    doc = parse_toml(bundled_bytes(f"frameworks/{name}.toml"), f"frameworks/{name}.toml")
    meta = doc.get("framework", {})
    if meta.get("id") != name:
        raise ConfigError(f"frameworks/{name}.toml: framework.id must be {name!r}")
    terms = meta.get("terms", {})
    missing = [k for k in TERM_KEYS if k not in terms]
    if missing:
        raise ConfigError(f"{name}: framework.terms missing {missing}")
    reqs = [_req(r, f"{name} requirement {r.get('id')}") for r in doc.get("requirement", [])]
    by_id = {r.id: r for r in reqs}
    if len(by_id) != len(reqs):
        raise ConfigError(f"{name}: duplicate requirement id")
    strategies = doc.get("strategy", [])
    sids = {s["id"] for s in strategies}
    for r in reqs:
        if strategies and r.strategy not in sids:
            raise ConfigError(f"{name}: {r.id} names unknown strategy {r.strategy!r}")
    known = {c.id for c in controls.controls}
    for control in controls.controls:
        for ref in control.refs.get(REF_KEY[name], []):
            if ref not in by_id:
                raise ConfigError(f"{control.id} references unknown {name} clause {ref!r}")
            if by_id[ref].applicability == "not_applicable":
                raise ConfigError(f"{control.id} references {ref}, which is not applicable")
            by_id[ref].controls.append(control.id)
    for b in doc.get("beyond", []):
        unknown = set(b.get("controls", [])) - known
        if unknown:
            raise ConfigError(f"{name}: beyond entry names unknown controls {sorted(unknown)}")
    return Framework(name, meta, reqs, strategies, doc.get("beyond", []))


# --- Evaluation -----------------------------------------------------------------


def outcome(req: Requirement, findings: dict[str, dict[str, Any]],
            withheld: set[str]) -> tuple[str, list[dict[str, Any]]]:
    """Return (outcome key, evidence rows) for one requirement."""
    if req.applicability == "not_applicable":
        return "not_applicable", []
    rows = []
    for cid in req.controls:
        if cid in withheld:
            rows.append({"control": cid, "verdict": "WITHHELD"})
        elif cid in findings:
            f = findings[cid]
            rows.append({"control": cid, "verdict": f["verdict"], "basis": f["basis"],
                         "risk_accepted": bool(f.get("risk_acceptance"))})
    verdicts = [r["verdict"] for r in rows]
    if "WITHHELD" in verdicts:
        return "withheld", rows
    if not rows or all(v == "NA" for v in verdicts):
        return "not_assessed", rows
    if "FAIL" in verdicts:
        return "fail", rows
    if req.coverage == "partial":
        return "partial", rows
    if "UNKNOWN" in verdicts:
        return "no_visibility", rows
    if "MANUAL" in verdicts:
        return "pending", rows
    return "pass", rows


def evaluate(fw: Framework, doc: dict[str, Any]) -> dict[str, Any]:
    findings = {f["id"]: f for f in doc["findings"]}
    withheld = set(doc.get("withheld", []))
    reqs = []
    for r in fw.requirements:
        key, rows = outcome(r, findings, withheld)
        reqs.append({"id": r.id, "strategy": r.strategy, "summary": r.summary,
                     "applicability": r.applicability, "coverage": r.coverage,
                     "rationale": r.rationale, "needs_review": r.needs_review,
                     "outcome": key, "outcome_label": fw.terms[key], "evidence": rows})
    strategies = []
    for s in fw.strategies:
        mine = [r for r in reqs if r["strategy"] == s["id"]]
        applicable = [r for r in mine if r["applicability"] == "applicable"]
        if not applicable:
            result = "Not applicable"
        elif any(r["outcome"] == "fail" for r in applicable):
            result = "Not achieved"
        elif all(r["outcome"] == "pass" for r in applicable):
            result = "Achieved"
        else:
            result = "Not determined"
        counts: dict[str, int] = {}
        for r in mine:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
        strategies.append({"id": s["id"], "name": s["name"], "ml1": result,
                           "requirements": len(mine), "applicable": len(applicable),
                           "counts": counts})
    beyond = []
    for b in fw.beyond:
        rows = [{"control": c, "verdict": findings[c]["verdict"]} for c in b["controls"]
                if c in findings and c not in withheld]
        beyond.append({**b, "evidence": rows})
    return {
        "framework": fw.id, "name": fw.meta["name"],
        "sources": fw.meta.get("source", []),
        "assessed_levels": fw.meta.get("assessed_levels"),
        "run": doc["run"]["id"], "requirements": reqs, "strategies": strategies,
        "beyond": beyond,
    }


def needs_review(fw: Framework) -> list[Requirement]:
    return [r for r in fw.requirements if r.needs_review]


# --- Markdown -------------------------------------------------------------------


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _evidence(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "—"
    parts = []
    for r in rows:
        v = r["verdict"]
        if r.get("basis") == "attested" and v in ("PASS", "FAIL"):
            v += " · attested"
        if r.get("risk_accepted"):
            v += " · risk accepted"
        parts.append(f"{r['control']} {v}")
    return ", ".join(parts)


def _para(text: str) -> str:
    return " ".join(text.split())


def render_markdown(fw: Framework, view: dict[str, Any], run: dict[str, Any]) -> str:
    meta = fw.meta
    out: list[str] = []
    w = out.append
    w(f"# {meta['name']} — {run['host'].get('hostname') or 'host'}\n")
    w(f"> {_para(meta['disclaimer'])}\n")
    w(f"Run `{run['id']}` · {run['started_at']} · profile {run['profile']['name']}\n")
    if meta.get("scope_quote"):
        w("**Scope of the framework, in ASD's words:**\n")
        w(f"> \"{_para(meta['scope_quote'])}\"  \n> — {meta['scope_quote_source']}\n")
    if meta.get("applicability_note"):
        w(_para(meta["applicability_note"]) + "\n")
    w(f"**How results are combined.** {_para(meta['rule'])}\n")
    if fw.id == "essential-eight":
        w("Only Maturity Level One is assessed. Maturity Levels Two and Three are "
          "**not assessed in this version**.\n")

    reqs = view["requirements"]
    if view["strategies"]:
        w("## Maturity Level One by mitigation strategy\n")
        w("| Strategy | ML1 result | Applicable requirements | Effective | Ineffective |"
          " Not assessed / no visibility |")
        w("|---|---|---:|---:|---:|---:|")
        for s in view["strategies"]:
            c = s["counts"]
            open_ = sum(c.get(k, 0) for k in ("no_visibility", "pending", "partial",
                                               "not_assessed", "withheld"))
            w(f"| {s['name']} | **{s['ml1']}** | {s['applicable']} of {s['requirements']} | "
              f"{c.get('pass', 0)} | {c.get('fail', 0)} | {open_} |")
        w("")

    assessed = [r for r in reqs if r["outcome"] not in ("not_applicable", "not_assessed")]
    w("## Requirements with host evidence\n")
    if assessed:
        w("| Requirement | Summary | Outcome | Evidence |")
        w("|---|---|---|---|")
        for r in assessed:
            mark = " †" if r["needs_review"] else ""
            w(f"| {r['id']}{mark} | {_cell(r['summary'])} | **{r['outcome_label']}** | "
              f"{_cell(_evidence(r['evidence']))} |")
        w("")
        partial = [r for r in assessed if r["outcome"] == "partial"]
        if partial:
            w("*Partial evidence* means the checks can disprove the requirement but cannot "
              "prove it on their own:\n")
            for r in partial:
                w(f"- **{r['id']}:** {_para(r['rationale'])}")
            w("")
    else:
        w("No requirement has host evidence in this run.\n")

    not_assessed = [r for r in reqs if r["outcome"] == "not_assessed"]
    w(f"## Not assessed ({len(not_assessed)})\n")
    w("These requirements apply to a server like this one, but this run holds no evidence "
      "for them. They are gaps in coverage, not passes.\n")
    if not_assessed:
        w("| Requirement | Summary | Why |")
        w("|---|---|---|")
        for r in not_assessed:
            why = r["rationale"] or "no control in this version provides evidence"
            if r["evidence"]:
                why += " (mapped controls were not applicable on this host: " + \
                    ", ".join(e["control"] for e in r["evidence"]) + ")"
            w(f"| {r['id']} | {_cell(r['summary'])} | {_cell(why)} |")
        w("")

    na = [r for r in reqs if r["outcome"] == "not_applicable"]
    w(f"## Not applicable ({len(na)})\n")
    w("These requirements do not apply to a Linux server.\n")
    if na:
        w("| Requirement | Summary | Why |")
        w("|---|---|---|")
        for r in na:
            mark = " †" if r["needs_review"] else ""
            w(f"| {r['id']}{mark} | {_cell(r['summary'])} | {_cell(r['rationale'])} |")
        w("")

    if view["beyond"]:
        w("## Evidence towards higher maturity levels (not assessed)\n")
        w("| Level | Strategy | Requirement | Evidence | Note |")
        w("|---|---|---|---|---|")
        names = {s["id"]: s["name"] for s in fw.strategies}
        for b in view["beyond"]:
            w(f"| ML{b['level']} | {names.get(b['strategy'], b['strategy'])} | "
              f"{_cell(b['summary'])} | {_cell(_evidence(b['evidence']))} | "
              f"{_cell(b.get('note', ''))} |")
        w("")

    if any(r["needs_review"] for r in reqs):
        w("† Applicability or mapping judgement flagged for review.\n")
    w("## Sources\n")
    for s in view["sources"]:
        w(f"- *{s['title']}*, {s['publisher']}, {s['version']}. {s['url']} "
          f"({s['licence']}). Used for: {s['used_for']}.")
    if fw.id == "essential-eight":
        w("\nRequirement IDs are assigned by this tool and are not ASD identifiers. "
          "Summaries are paraphrases; the maturity model is the authoritative text.")
    w("")
    return "\n".join(out)
