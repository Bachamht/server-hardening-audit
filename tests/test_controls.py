"""Per-control PASS/FAIL (and NA/UNKNOWN) scenarios, judged via `audit --replay`."""

import json
from pathlib import Path

import pytest
from replay_fixture import FIXTURES, build_run, load_fixture, scenario_calls

from server_hardening_audit import cli, report
from server_hardening_audit.loader import load_controls

CONTROLS = load_controls().controls
MANUAL = {c.id for c in CONTROLS if c.manual is not None}


def _cases():
    for control in CONTROLS:
        path = FIXTURES / "controls" / f"{control.id}.toml"
        if not path.exists():
            continue
        doc = load_fixture(control.id)
        for sc in doc.get("scenario", []):
            yield pytest.param(control.id, doc, sc, id=f"{control.id}: {sc['name']}")


def replay(tmp_path: Path, scopes, profile=None, os_name="ubuntu-24.04", only=None):
    src = build_run(tmp_path, scopes, profile, os_name)
    out = tmp_path / "out"
    argv = ["audit", "--replay", str(src), "--out", str(out)]
    if only:
        argv += ["--only", only]
    rc = cli.main(argv)
    run_dir = next(out.iterdir())
    return rc, run_dir, json.loads((run_dir / "findings.json").read_text())


@pytest.mark.parametrize("cid,doc,scenario", list(_cases()))
def test_scenario(tmp_path, cid, doc, scenario):
    calls, profile = scenario_calls(doc, scenario)
    rc, run_dir, findings = replay(tmp_path, {cid: calls}, profile,
                                   scenario.get("os", "ubuntu-24.04"), cid)
    assert report.validate(findings) == []
    (f,) = findings["findings"]
    assert f["verdict"] == scenario["expect"], f["summary"]
    if "summary_contains" in scenario:
        assert scenario["summary_contains"] in f["summary"]
    assert rc in (0, 1, 2)


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: c.id)
def test_every_control_has_pass_and_fail_fixtures(control):
    path = FIXTURES / "controls" / f"{control.id}.toml"
    assert path.exists(), f"no fixture file for {control.id}"
    expected = {sc["expect"] for sc in load_fixture(control.id).get("scenario", [])}
    if control.id in MANUAL:
        assert "MANUAL" in expected
    else:
        assert {"PASS", "FAIL"} <= expected, f"{control.id} has {expected}"
