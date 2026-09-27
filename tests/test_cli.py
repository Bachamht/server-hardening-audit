import pytest

from server_hardening_audit import cli
from server_hardening_audit.loader import load_controls


def test_list_shows_every_control_and_command(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    for c in load_controls().controls:
        assert c.id in out
    assert "run   ss -tlnpH" in out
    assert "raw content not stored" in out
    assert "REFUSED" not in out


def test_usage_errors_exit_3(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["nope"])
    assert exc.value.code == 3


def test_config_errors_exit_3(tmp_path, capsys):
    assert cli.main(["list", "--controls", str(tmp_path / "missing.toml")]) == 3
    assert cli.main(["audit", "--replay", str(tmp_path), "--out", str(tmp_path / "o")]) == 3


def test_unknown_only_id_exits_3(tmp_path, capsys):
    assert cli.main(["audit", "--only", "XXX-99", "--out", str(tmp_path)]) == 3
    assert not any(tmp_path.iterdir())


def test_redact_check(tmp_path, capsys):
    (tmp_path / "ok.md").write_text("PASS\n")
    assert cli.main(["redact-check", str(tmp_path)]) == 0
    (tmp_path / "bad.md").write_text("DATABASE_URL=postgres://u:pw@h/db\n")
    assert cli.main(["redact-check", str(tmp_path)]) == 1
