"""Attestations and risk acceptances (SPEC 9.3)."""

import datetime as dt
import json

import pytest
from replay_fixture import build_run
from test_engine import _audit, _composite, _first

from server_hardening_audit import attest, cli, report
from server_hardening_audit.loader import ConfigError

RESTORE = '''
[[attestation]]
control = "RES-02"
verdict = "PASS"
method = "Restored latest dump into a throwaway database; reconciled row counts per table."
performed_at = 2026-10-12T05:10:00Z
performed_by = "operator with AI agent"
evidence = ["restore/row-counts.txt"]
[attestation.measurements]
restore_seconds = 130
dump_bytes = 39845888

[[risk_acceptance]]
control = "ACC-06"
reason = "Key-only SSH from a single admin device; FIDO2 keys planned."
accepted_by = "owner"
review_by = 2026-12-31
'''


@pytest.fixture
def failing_run(tmp_path, capsys):
    scopes, profile = _composite(_first("FAIL"))
    src = build_run(tmp_path, scopes, profile)
    _, run_dir, doc = _audit(src, tmp_path / "out")
    capsys.readouterr()
    return run_dir, doc


def _write(tmp_path, text, name="a.toml"):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def _apply(doc, path, today=dt.date(2026, 10, 1)):
    a, r, files = attest.load([path])
    return attest.apply(doc, a, r, files, today)


def test_manual_control_resolved_by_attestation(tmp_path, failing_run):
    _, doc = failing_run
    (tmp_path / "restore").mkdir()
    (tmp_path / "restore" / "row-counts.txt").write_text("website 12 12\n")
    out, warnings = _apply(doc, _write(tmp_path, RESTORE))
    f = next(x for x in out["findings"] if x["id"] == "RES-02")
    assert (f["verdict"], f["basis"]) == ("PASS", "attested")
    assert f["details"]["attestations"][0]["measurements"]["restore_seconds"] == 130
    assert f["details"]["attestations"][0]["evidence"][0]["sha256"]
    assert f["details"]["automated_result"]["verdict"] == "MANUAL"
    assert warnings == []
    assert report.validate(out) == []
    assert report.verdict_label(f) == "PASS · attested"


def test_missing_evidence_file_is_warned(tmp_path, failing_run):
    _, doc = failing_run
    _, warnings = _apply(doc, _write(tmp_path, RESTORE))
    assert any("not found" in w for w in warnings)


def test_risk_acceptance_keeps_fail(tmp_path, failing_run):
    _, doc = failing_run
    out, _ = _apply(doc, _write(tmp_path, RESTORE))
    f = next(x for x in out["findings"] if x["id"] == "ACC-06")
    assert f["verdict"] == "FAIL"
    assert f["risk_acceptance"]["review_by"] == "2026-12-31"
    assert not f["risk_acceptance"]["expired"]
    assert report.verdict_label(f) == "FAIL · risk accepted (review by 2026-12-31)"
    out2, _ = _apply(doc, _write(tmp_path, RESTORE), today=dt.date(2027, 1, 5))
    f2 = next(x for x in out2["findings"] if x["id"] == "ACC-06")
    assert "REVIEW OVERDUE" in report.verdict_label(f2)


def test_risk_acceptance_on_non_fail_is_ignored(tmp_path, failing_run):
    _, doc = failing_run
    text = RESTORE.replace('control = "ACC-06"', 'control = "RES-03"')
    doc = json.loads(json.dumps(doc))
    for f in doc["findings"]:
        if f["id"] == "RES-03":
            f["verdict"] = "PASS"
    out, warnings = _apply(doc, _write(tmp_path, text))
    assert next(x for x in out["findings"] if x["id"] == "RES-03")["risk_acceptance"] is None
    assert any("ignored" in w for w in warnings)


def _corroborate(control, verdict):
    return f'''
[[attestation]]
control = "{control}"
verdict = "{verdict}"
method = "external probe"
performed_at = "2026-10-12T05:10:00Z"
performed_by = "probe"
source = "probe"
'''


def test_external_fail_overrides_verified_pass(tmp_path, capsys):
    scopes, profile = _composite(_first("PASS"))
    src = build_run(tmp_path, scopes, profile)
    _, _, doc = _audit(src, tmp_path / "out")
    out, warnings = _apply(doc, _write(tmp_path, _corroborate("ACC-01", "FAIL")))
    f = next(x for x in out["findings"] if x["id"] == "ACC-01")
    assert (f["verdict"], f["basis"]) == ("FAIL", "attested")
    assert f["details"]["corroboration"][0]["agrees"] is False
    assert any("contradicts" in w for w in warnings)


def test_attestation_cannot_turn_verified_fail_into_pass(tmp_path, failing_run):
    _, doc = failing_run
    out, warnings = _apply(doc, _write(tmp_path, _corroborate("ACC-01", "PASS")))
    assert next(x for x in out["findings"] if x["id"] == "ACC-01")["verdict"] == "FAIL"
    assert any("FAIL stands" in w for w in warnings)


@pytest.mark.parametrize("bad,msg", [
    ('verdict = "PASS"', 'verdict = "MAYBE"'),
    ('performed_at = 2026-10-12T05:10:00Z', 'performed_at = 2026-10-12T05:10:00'),
    ('method = "Restored', 'methd = "Restored'),
])
def test_invalid_attestations_rejected(tmp_path, bad, msg):
    with pytest.raises(ConfigError):
        attest.load([_write(tmp_path, RESTORE.replace(bad, msg, 1))])


def test_attestation_for_unknown_control_rejected(tmp_path, failing_run):
    _, doc = failing_run
    with pytest.raises(ConfigError, match="not in this run"):
        _apply(doc, _write(tmp_path, _corroborate("XYZ-01", "PASS")))


def test_report_with_attest_and_e8_view(tmp_path, failing_run, capsys):
    run_dir, _ = failing_run
    path = _write(tmp_path, RESTORE)
    assert cli.main(["report", str(run_dir), "--attest", path]) == 2
    md = capsys.readouterr().out
    assert "**PASS · attested**" in md and "Attested** PASS by operator with AI agent" in md
    assert "risk accepted (review by 2026-12-31)" in md
    cli.main(["report", str(run_dir), "--attest", path, "--framework", "essential-eight",
              "--format", "json"])
    view = json.loads(capsys.readouterr().out)
    rb4 = next(r for r in view["requirements"] if r["id"] == "RB-ML1-04")
    assert rb4["outcome"] == "pass" and rb4["evidence"][0]["basis"] == "attested"


def test_notes_are_shown_and_never_change_verdicts(tmp_path, failing_run):
    _, doc = failing_run
    note = '[[note]]\ncontrol = "ACC-01"\nauthor = "operator"\ntext = "Root logs in with a key."\n'
    out, _ = _apply(doc, _write(tmp_path, note))
    f = next(x for x in out["findings"] if x["id"] == "ACC-01")
    before = next(x for x in doc["findings"] if x["id"] == "ACC-01")
    assert f["verdict"] == before["verdict"] and f["basis"] == before["basis"]
    assert f["details"]["notes"] == [{"text": "Root logs in with a key.", "author": "operator",
                                      "file": "a.toml"}]
    md = __import__("server_hardening_audit.report", fromlist=["x"]).render_markdown(
        out, json.loads((failing_run[0] / "run.json").read_text()))
    assert "**Operator note** (operator, `a.toml`): Root logs in with a key." in md
