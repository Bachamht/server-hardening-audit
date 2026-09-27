"""End-to-end replay: a whole host, evidence round-trip, manifest, report."""

import json

from replay_fixture import build_run, load_fixture, scenario_calls
from test_controls import CONTROLS, MANUAL

from server_hardening_audit import cli, evidence, report


def _composite(scenario_pick):
    scopes, profile = {}, {}
    for control in CONTROLS:
        doc = load_fixture(control.id)
        sc = scenario_pick(control.id, doc["scenario"])
        calls, prof = scenario_calls(doc, sc)
        scopes[control.id] = calls
        for k, v in prof.items():
            if k in profile and profile[k] != v and isinstance(v, list):
                profile[k] = sorted(set(profile[k]) | set(v))
            else:
                profile.setdefault(k, v)
    return scopes, profile


def _first(expect):
    def pick(cid, scenarios):
        for sc in scenarios:
            if sc["expect"] == expect and "os" not in sc:
                return sc
        return next(sc for sc in scenarios if sc["expect"] == "MANUAL")
    return pick


def _audit(src, out, *extra):
    rc = cli.main(["audit", "--replay", str(src), "--out", str(out), *extra])
    (run_dir,) = list(out.iterdir())
    return rc, run_dir, json.loads((run_dir / "findings.json").read_text())


def test_all_pass_host_round_trips(tmp_path, capsys):
    scopes, profile = _composite(_first("PASS"))
    profile["backup_offsite_required"] = False
    src = build_run(tmp_path, scopes, profile)
    rc, run1, doc1 = _audit(src, tmp_path / "out1")
    verdicts = {f["id"]: f["verdict"] for f in doc1["findings"]}
    assert {k for k, v in verdicts.items() if v != "PASS"} == MANUAL, verdicts
    assert rc == 0
    assert report.validate(doc1) == []
    assert evidence.verify_manifest(run1) == []

    # Replaying the replay's own output yields the same findings.
    rc2, run2, doc2 = _audit(run1, tmp_path / "out2")
    strip = [{k: v for k, v in f.items() if k != "evidence"} for f in doc2["findings"]]
    assert strip == [{k: v for k, v in f.items() if k != "evidence"} for f in doc1["findings"]]
    assert rc2 == rc
    run_meta = json.loads((run2 / "run.json").read_text())
    assert run_meta["mode"] == "replay" and run_meta["replay_of"] == run1.name
    # Same evidence bytes, file for file.
    for f in (run1 / "evidence").rglob("*"):
        if f.is_file() and f.name != "index.json":
            assert (run2 / f.relative_to(run1)).read_bytes() == f.read_bytes(), f


def test_failing_host_exit_code_and_report(tmp_path, capsys):
    scopes, profile = _composite(_first("FAIL"))
    src = build_run(tmp_path, scopes, profile)
    rc, run_dir, doc = _audit(src, tmp_path / "out")
    assert rc == 2  # critical FAILs present
    md = (run_dir / "report.md").read_text()
    for section in ("## Summary", "## Findings", "## Controls",
                    "## What this report does not cover"):
        assert section in md
    for mid in MANUAL:
        assert f"| {mid} | MANUAL |" in md
    assert "Cloud-provider security groups" in md


def test_key_facts_reach_the_report(tmp_path, capsys):
    scopes, profile = _composite(_first("PASS"))
    src = build_run(tmp_path, scopes, profile)
    _, run_dir, doc = _audit(src, tmp_path / "out")
    md = (run_dir / "report.md").read_text()
    assert "**Key fact:** Lynis 3.1.2 hardening index 67" in md
    assert "**Key fact:** warning SSH-7408: Consider hardening SSH configuration" in md
    assert "**Key fact:** fail2ban jail 'sshd': 3 ban(s) in the last 7 days" in md
    lynis = next(f for f in doc["findings"] if f["id"] == "BAS-01")
    assert "_highlights" not in lynis["details"]["collected"]["lynis"]
    # findings are ordered by severity, then verdict
    sev = [f["severity"] for f in doc["findings"]]
    order = ["critical", "high", "medium", "low"]
    assert sev == sorted(sev, key=order.index)


def test_secrets_in_sources_never_reach_the_run_directory(tmp_path, capsys):
    scopes, profile = _composite(_first("PASS"))
    src = build_run(tmp_path, scopes, profile)
    _, run_dir, _ = _audit(src, tmp_path / "out")
    blob = "\n".join(p.read_text(errors="replace") for p in run_dir.rglob("*") if p.is_file())
    assert "do-not-store-me" not in blob  # PGPASSWORD in a cron line (RES-01)
    assert "AAAAC3NzaC1lZDI1NTE5AAAAIC4mX0" not in blob  # key body (ACC-02/06)
    assert "pg_dump-app.sh" not in blob  # cron command text


def test_exit_code_one_for_noncritical_fail(tmp_path, capsys):
    doc = load_fixture("BAS-04")
    sc = next(s for s in doc["scenario"] if s["expect"] == "FAIL")
    calls, prof = scenario_calls(doc, sc)
    src = build_run(tmp_path, {"BAS-04": calls}, prof)
    rc, _, _ = _audit(src, tmp_path / "out")
    assert rc == 1


def test_unsupported_platform_is_unknown_with_reason(tmp_path, capsys):
    src = build_run(tmp_path, {"ACC-04": []}, None, os_name="alpine")
    _, _, doc = _audit(src, tmp_path / "out", "--only", "ACC-04")
    (f,) = doc["findings"]
    assert f["verdict"] == "UNKNOWN" and "platform" in f["summary"]


def test_report_rerenders_from_saved_run(tmp_path, capsys):
    scopes, profile = _composite(_first("FAIL"))
    src = build_run(tmp_path, scopes, profile)
    _, run_dir, _ = _audit(src, tmp_path / "out")
    capsys.readouterr()
    rc = cli.main(["report", str(run_dir)])
    out = capsys.readouterr().out
    assert out.strip() == (run_dir / "report.md").read_text().strip()
    assert rc == 2
