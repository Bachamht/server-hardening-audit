import pytest

from server_hardening_audit.loader import ConfigError, load_controls, load_profile

BASE = '''
[[control]]
id = "TST-01"
title = "t"
domain = "access"
severity = "low"
[[control.check]]
type = "cmd"
argv = ["ss", "-tlnpH"]
parser = "ss_listeners"
save_as = "ss.txt"
[control.assert]
op = "count_at_most"
source = "ss"
max = 0
[control.text]
rationale = "r"
remediation = "m"
disruptive = false
'''


def load(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text)
    return load_controls(str(p))


def test_valid_minimal_control(tmp_path):
    assert load(tmp_path, BASE).controls[0].checks[0].name == "ss"


@pytest.mark.parametrize("old,new,msg", [
    ('parser = "ss_listeners"', 'parser = "eval"', "unknown parser"),
    ('op = "count_at_most"', 'op = "exec"', "unknown assertion op"),
    ('type = "cmd"', 'type = "shell"', "type must be"),
    ('severity = "low"', 'severity = "urgent"', "severity"),
    ('id = "TST-01"', 'id = "tst1"', "invalid id"),
    ('disruptive = false', 'disruptive = "no"', "disruptive"),
    ('max = 0', 'max = 0\nlimit = 3', "unknown argument"),
    ('save_as = "ss.txt"', 'save_as = "../../etc/x"', "invalid save_as"),
    ('title = "t"', 'title = "t"\ncode = "import os"', "unknown key"),
])
def test_invalid_controls_are_rejected(tmp_path, old, new, msg):
    with pytest.raises(ConfigError, match=msg):
        load(tmp_path, BASE.replace(old, new))


def test_unknown_collector_and_duplicate_id(tmp_path):
    bad = BASE.replace('type = "cmd"\nargv = ["ss", "-tlnpH"]\nparser = "ss_listeners"\n'
                       'save_as = "ss.txt"', 'type = "collector"\ncollector = "rm_rf"')
    with pytest.raises(ConfigError, match="unknown collector"):
        load(tmp_path, bad)
    with pytest.raises(ConfigError, match="duplicate id"):
        load(tmp_path, BASE + BASE)


def test_profile_validation(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('public_ports = [22, 443]\nadmin_users = ["a"]\n')
    prof = load_profile(str(p))
    assert prof["public_ports"] == [22, 443] and prof["rpo_hours"] == 24
    p.write_text("public_prots = [22]\n")
    with pytest.raises(ConfigError, match="unknown key"):
        load_profile(str(p))
    p.write_text("public_ports = [70000]\n")
    with pytest.raises(ConfigError, match="port numbers"):
        load_profile(str(p))
    p.write_text('rpo_hours = "24"\n')
    with pytest.raises(ConfigError, match="wrong type"):
        load_profile(str(p))


def test_bundled_profiles_load():
    for name in ("profiles/minimal.toml", "profiles/single-vps-webhost.toml"):
        assert load_profile(name)["name"]
