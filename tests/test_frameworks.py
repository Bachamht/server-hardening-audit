"""Framework layer: loading, mapping integrity, aggregation rules, views."""

import json

import pytest
from replay_fixture import build_run
from test_engine import _audit, _composite, _first

from server_hardening_audit import cli, frameworks
from server_hardening_audit.frameworks import Requirement, outcome
from server_hardening_audit.loader import load_controls

CONTROLS = load_controls()


@pytest.mark.parametrize("name", frameworks.NAMES)
def test_framework_loads_and_every_ref_resolves(name):
    fw = frameworks.load(name, CONTROLS)
    mapped = {c for r in fw.requirements for c in r.controls}
    key = frameworks.REF_KEY[name]
    referencing = {c.id for c in CONTROLS.controls if c.refs.get(key)}
    assert mapped == referencing


def test_e8_has_all_ml1_requirements_and_strategies():
    fw = frameworks.load("essential-eight", CONTROLS)
    counts = {}
    for r in fw.requirements:
        counts[r.strategy] = counts.get(r.strategy, 0) + 1
    # Appendix A of the November 2023 maturity model.
    assert counts == {"PA": 9, "PO": 8, "MFA": 7, "RAP": 7, "AC": 3, "OM": 4, "UAH": 4,
                      "RB": 6}
    assert [s["name"] for s in fw.strategies] == [
        "Patch applications", "Patch operating systems", "Multi-factor authentication",
        "Restrict administrative privileges", "Application control",
        "Restrict Microsoft Office macros", "User application hardening", "Regular backups"]
    assert "not an Essential Eight maturity assessment of an organisation" in \
        " ".join(fw.meta["disclaimer"].split())


def test_iso_uses_numbers_not_titles():
    fw = frameworks.load("iso27001-2022", CONTROLS)
    assert all(r.id.startswith(("A.5.", "A.8.")) for r in fw.requirements)
    assert 15 <= len(fw.requirements) <= 20


def _req(**kw):
    base = {"id": "X-1", "summary": "s", "applicability": "applicable", "controls": ["C-01"]}
    return Requirement(**{**base, **kw})


def _f(verdict, **extra):
    return {"C-01": {"verdict": verdict, "basis": "verified", **extra}}


@pytest.mark.parametrize("verdict,coverage,expected", [
    ("PASS", "full", "pass"),
    ("FAIL", "full", "fail"),
    ("UNKNOWN", "full", "no_visibility"),
    ("MANUAL", "full", "pending"),
    ("NA", "full", "not_assessed"),
    ("PASS", "partial", "partial"),   # partial evidence can never prove a requirement
    ("FAIL", "partial", "fail"),      # ...but it can disprove one
])
def test_requirement_outcomes(verdict, coverage, expected):
    assert outcome(_req(coverage=coverage), _f(verdict), set())[0] == expected


def test_not_applicable_and_not_assessed_are_distinct():
    assert outcome(_req(applicability="not_applicable", controls=[]), {}, set())[0] == \
        "not_applicable"
    assert outcome(_req(controls=[]), {}, set())[0] == "not_assessed"


def test_risk_accepted_fail_stays_ineffective():
    key, rows = outcome(_req(), _f("FAIL", risk_acceptance={"reason": "r"}), set())
    assert key == "fail" and rows[0]["risk_accepted"]


def test_withheld_controls_are_not_reported_as_not_assessed():
    assert outcome(_req(), {}, {"C-01"})[0] == "withheld"


def test_unknown_ref_is_rejected(tmp_path):
    text = (tmp_path / "c.toml")
    from test_loader import BASE
    text.write_text(BASE.replace('disruptive = false', 'disruptive = false\n[control.refs]\n'
                                 'essential_eight = ["PO-ML9-99"]'))
    with pytest.raises(Exception, match="unknown essential-eight clause"):
        frameworks.load("essential-eight", load_controls(str(text)))


def test_e8_strategy_results(tmp_path, capsys):
    scopes, profile = _composite(_first("FAIL"))
    src = build_run(tmp_path, scopes, profile)
    _, run_dir, _ = _audit(src, tmp_path / "out")
    capsys.readouterr()
    assert cli.main(["report", str(run_dir), "--framework", "essential-eight",
                     "--format", "json"]) == 2
    view = json.loads(capsys.readouterr().out)
    by = {s["id"]: s["ml1"] for s in view["strategies"]}
    assert by["PO"] == "Not achieved"          # PAT-01/PAT-02 fail
    assert by["AC"] == "Not applicable"
    assert by["OM"] == "Not applicable" and by["UAH"] == "Not applicable"
    assert by["MFA"] == "Not determined"       # applicable, no host evidence


@pytest.mark.parametrize("name", frameworks.NAMES)
def test_markdown_view_sections(tmp_path, capsys, name):
    scopes, profile = _composite(_first("PASS"))
    src = build_run(tmp_path, scopes, profile)
    _, run_dir, _ = _audit(src, tmp_path / "out")
    out = tmp_path / "view.md"
    cli.main(["report", str(run_dir), "--framework", name, "--out", str(out)])
    md = out.read_text()
    assert "## Not assessed" in md and "## Not applicable" in md
    assert md.index("## Not assessed") < md.index("## Not applicable")
    if name == "essential-eight":
        assert "not assessed in this version" in md
        assert "internet-connected information technology networks" in md
