import pytest
from replay_fixture import RAW

from server_hardening_audit import redact

SECRETS = [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "DATABASE_URL=postgres://app:hunter2@127.0.0.1:5432/app",
    "https://deploy:ghp_notreal@github.com/x/y.git",
    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
    "token: ghp_" + "a1B2" * 9,
    "glpat-" + "x" * 20,
    "xoxb-123456789012-abcdefghij",
    "AIza" + "S" * 35,
    "sk_live_" + "4" * 24,
    "ANTHROPIC_API_KEY=sk-ant-" + "Z" * 40,
    "BOT_TOKEN=123456789:AA" + "h" * 33,
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "root:$6$rounds=5000$saltsalt$" + "k" * 40 + ":19000:0:99999:7:::",
    "password = s3cr3t-value",
    '"api_key": "abcd1234efgh"',
    "SECRET_KEY=django-insecure-abc",
]


@pytest.mark.parametrize("line", SECRETS)
def test_known_secret_samples_are_caught(line):
    assert redact.scan_text(line), line


@pytest.mark.parametrize("line", [
    "passwordauthentication no",
    "PermitEmptyPasswords no",
    "password = <redacted>",
    "token: ${TOKEN}",
    "api_key = changeme",
    "kbdinteractiveauthentication no",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4mX0 admin@laptop",
])
def test_benign_lines_pass(line):
    assert redact.scan_text(line) == []


def test_hits_never_contain_the_secret(tmp_path):
    (tmp_path / "a.txt").write_text("x\npassword = hunter2\n")
    hits, scanned = redact.scan_path(tmp_path)
    assert scanned == 1 and [str(h) for h in hits] == [f"{tmp_path}/a.txt:2: password assignment"]


def test_synthetic_sshd_output_is_clean():
    assert redact.scan_text((RAW / "sshd-T-hardened.synthetic.txt").read_text()) == []
