"""probe: TCP states, SSH method parsing, attestation generation. Loopback only."""

import socket
import sys

from server_hardening_audit import probe, tomlw
from server_hardening_audit.loader import parse_toml

SSH_STDERR = """OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024
debug1: Connecting to 192.0.2.10 [192.0.2.10] port 22.
debug1: Connection established.
debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
debug1: Authenticating to 192.0.2.10:22 as 'admin'
debug1: Authentications that can continue: publickey,password
debug1: No more authentication methods to try.
admin@192.0.2.10: Permission denied (publickey,password).
"""


def test_tcp_states_on_loopback():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    open_port = srv.getsockname()[1]
    tmp = socket.socket()
    tmp.bind(("127.0.0.1", 0))
    closed_port = tmp.getsockname()[1]
    tmp.close()
    try:
        assert probe.tcp_state("127.0.0.1", open_port, 1.0) == "open"
        assert probe.tcp_state("127.0.0.1", closed_port, 1.0) == "closed"
    finally:
        srv.close()


def test_parse_ssh_methods():
    assert probe.parse_ssh_methods(SSH_STDERR) == ["password", "publickey"]
    assert probe.parse_ssh_methods("ssh: connect to host x port 22: Connection refused") is None


def test_ssh_argv_offers_no_credentials():
    argv = probe.ssh_argv("192.0.2.10", 22, "admin")
    joined = " ".join(argv)
    for opt in ("PubkeyAuthentication=no", "PasswordAuthentication=no",
                "KbdInteractiveAuthentication=no", "IdentityAgent=none", "BatchMode=yes",
                "UserKnownHostsFile=/dev/null"):
        assert opt in joined
    assert argv[:3] == ["ssh", "-F", "/dev/null"]
    assert "-i" not in argv


def _result():
    return {
        "addresses": {"ipv4": "192.0.2.10", "ipv6": "2001:db8::10"},
        "ports_requested": [22, 80, 443, 5432],
        "ports": {"ipv4": {"22": "open", "80": "open", "443": "open", "5432": "filtered"},
                  "ipv6": {"22": "open", "80": "open", "443": "open", "5432": "open"}},
        "ssh": [{"user": "admin", "methods": ["publickey"]},
                {"user": "root", "methods": ["publickey"]}],
        "tls": [{"domain": "site-a.example", "verified": True, "days_left": 60.0}],
        "finished_at": "2026-10-12T05:10:00Z",
    }


def test_attestations_catch_ipv6_only_exposure():
    atts = {a["control"]: a for a in probe.attestations(_result(), [22, 80, 443], 14)}
    assert atts["NET-04"]["verdict"] == "FAIL"
    assert atts["NET-04"]["measurements"]["unexpected_open_ports"] == [5432]
    assert atts["ACC-01"]["verdict"] == "PASS"
    assert atts["NET-05"]["verdict"] == "PASS"


def test_password_offered_fails_acc01():
    r = _result()
    r["ssh"][0]["methods"] = ["password", "publickey"]
    atts = {a["control"]: a for a in probe.attestations(r, [22, 80, 443, 5432], 14)}
    assert atts["ACC-01"]["verdict"] == "FAIL"
    assert atts["NET-04"]["verdict"] == "PASS"


def test_no_public_ports_means_no_net04():
    assert "NET-04" not in {a["control"] for a in probe.attestations(_result(), None, 14)}


def test_attestation_file_round_trips(tmp_path):
    atts = probe.attestations(_result(), [22, 80, 443], 14)
    probe.write(tmp_path, {**_result(), "tool": {}}, atts)
    doc = parse_toml((tmp_path / "probe-attestation.toml").read_bytes(), "x")
    assert [a["control"] for a in doc["attestation"]] == [a["control"] for a in atts]
    assert doc["attestation"][0]["measurements"]["open_ipv6"] == [22, 80, 443, 5432]


def test_tomlw_escapes():
    text = tomlw.dumps({"a": 'quote " and \\ backslash\nnewline', "b": [1, 2], "c": True,
                        "t": {"x y": 1.5}})
    if sys.version_info >= (3, 11):
        import tomllib
        assert tomllib.loads(text)["a"] == 'quote " and \\ backslash\nnewline'
    doc = parse_toml(text.encode(), "t")
    assert doc["t"]["x y"] == 1.5 and doc["b"] == [1, 2] and doc["c"] is True
