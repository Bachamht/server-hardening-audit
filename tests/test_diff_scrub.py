"""diff and scrub."""

import json

import pytest
from replay_fixture import build_run
from test_engine import _audit, _composite, _first

from server_hardening_audit import cli

SENSITIVE = {
    "testhost": "prod-web-7.mysite.com.au",
    "203.0.113.10": "45.76.12.34",
    "site-a.example": "shop.mysite.com.au",
    "opsadmin": "zhangwei",
}


def _run(tmp_path, pick, name):
    scopes, profile = _composite(_first(pick))
    profile["tls_domains"] = ["site-a.example"]
    profile["admin_users"] = ["opsadmin"]
    src = build_run(tmp_path / name, scopes, profile)
    _, run_dir, _ = _audit(src, tmp_path / name / "out")
    return run_dir


def _inject(run_dir):
    """Make the run look like a real host: real-looking names and addresses."""
    for fname in ("run.json", "findings.json", "report.md"):
        p = run_dir / fname
        text = p.read_text()
        for fake, real in SENSITIVE.items():
            text = text.replace(fake, real)
        p.write_text(text)


def test_diff_reports_regressions(tmp_path, capsys):
    a = _run(tmp_path, "PASS", "a")
    b = _run(tmp_path, "FAIL", "b")
    capsys.readouterr()
    assert cli.main(["diff", str(a), str(b)]) == 0
    md = capsys.readouterr().out
    assert "regressed" in md and "| NET-02" in md
    cli.main(["diff", str(a), str(b), "--format", "json"])
    d = json.loads(capsys.readouterr().out)
    assert any(c["id"] == "ACC-01" and c["direction"] == "regressed" for c in d["changed"])
    assert "tcp/5432 on 0.0.0.0 (postgres)" in d["listeners"]["opened"]


MAP = '''
[replace]
"prod-web-7.mysite.com.au" = "host-01"
"shop.mysite.com.au" = "site-a.example"
"mysite.com.au" = "example.org"
"zhangwei" = "<admin-user>"
'''


@pytest.fixture
def real_run(tmp_path, capsys):
    run = _run(tmp_path, "FAIL", "r")
    _inject(run)
    capsys.readouterr()
    return run


def test_scrub_removes_mapped_values_and_addresses(tmp_path, real_run, capsys):
    (tmp_path / "map.toml").write_text(MAP)
    out = tmp_path / "examples"
    rc = cli.main(["scrub", str(real_run), "--map", str(tmp_path / "map.toml"),
                   "--out", str(out), "--note", "Host identifiers redacted; all measurements "
                   "are real."])
    assert rc == 0, capsys.readouterr().err
    names = sorted(p.name for p in out.iterdir())
    assert names == ["sample-essential-eight.md", "sample-findings.json",
                     "sample-iso27001-2022.md", "sample-report.md"]
    blob = "\n".join(p.read_text() for p in out.iterdir()).lower()
    for real in SENSITIVE.values():
        assert real.lower() not in blob
    assert "45.76.12.34" not in blob and "192.0.2.10" in blob
    assert "127.0.0.1" in blob            # loopback is kept: it carries meaning
    assert "host-01" in blob
    assert "all measurements are real" in blob
    assert cli.main(["redact-check", str(out)]) == 0


def test_scrub_keeps_numbers(tmp_path, real_run, capsys):
    (tmp_path / "map.toml").write_text(MAP)
    out = tmp_path / "examples"
    cli.main(["scrub", str(real_run), "--map", str(tmp_path / "map.toml"), "--out", str(out)])
    orig = json.loads((real_run / "findings.json").read_text())
    pub = json.loads((out / "sample-findings.json").read_text())

    def numbers(o):
        if isinstance(o, bool):
            return []
        if isinstance(o, (int, float)):
            return [o]
        if isinstance(o, dict):
            return [n for v in o.values() for n in numbers(v)]
        if isinstance(o, list):
            return [n for v in o for n in numbers(v)]
        return []
    assert numbers(orig["findings"]) == numbers(pub["findings"])


def test_scrub_refuses_when_a_secret_survives(tmp_path, real_run, capsys):
    p = real_run / "findings.json"
    doc = json.loads(p.read_text())
    doc["findings"][0]["summary"] += " DATABASE_URL=postgres://app:hunter2@db/app"
    p.write_text(json.dumps(doc))
    (tmp_path / "map.toml").write_text(MAP)
    out = tmp_path / "examples"
    rc = cli.main(["scrub", str(real_run), "--map", str(tmp_path / "map.toml"),
                   "--out", str(out)])
    assert rc == 1 and not out.exists()
    assert "hunter2" not in capsys.readouterr().err


def test_map_whose_placeholder_contains_the_original_is_rejected(tmp_path, real_run, capsys):
    (tmp_path / "map.toml").write_text('[replace]\n"zhangwei" = "zhangwei-user"\n')
    rc = cli.main(["scrub", str(real_run), "--map", str(tmp_path / "map.toml"),
                   "--out", str(tmp_path / "o")])
    assert rc == 3 and not (tmp_path / "o").exists()


def test_tool_output_never_trips_the_redaction_gate(tmp_path, capsys):
    """The tool's own wording must not look like a secret, or scrub would
    refuse every real report."""
    for pick in ("PASS", "FAIL"):
        run = _run(tmp_path, pick, pick)
        assert cli.main(["redact-check", str(run / "report.md")]) == 0
        assert cli.main(["redact-check", str(run / "findings.json")]) == 0


def test_drop_controls_are_withheld_not_not_assessed(tmp_path, real_run, capsys):
    (tmp_path / "map.toml").write_text(MAP)
    out = tmp_path / "examples"
    cli.main(["scrub", str(real_run), "--map", str(tmp_path / "map.toml"), "--out", str(out),
              "--drop-controls", "NET-02,PAT-02"])
    pub = json.loads((out / "sample-findings.json").read_text())
    assert {f["id"] for f in pub["findings"]}.isdisjoint({"NET-02", "PAT-02"})
    assert pub["withheld"] == ["NET-02", "PAT-02"]
    e8 = (out / "sample-essential-eight.md").read_text()
    assert "PO-ML1-05" in e8 and "Withheld from this copy" in e8
    assert "0.0.0.0 (postgres)" not in (out / "sample-report.md").read_text()

