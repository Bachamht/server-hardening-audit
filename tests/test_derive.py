"""Derivers keep derived facts only: never hashes, key bodies or commands."""

import json

from replay_fixture import RAW

from server_hardening_audit import derive


def test_shadow_keeps_usernames_only():
    data = b"root:$6$abcdefgh$" + b"X" * 86 + b":19000:0:99999:7:::\nguest::19000::::::\n"
    out = derive.shadow_empty_passwords(data)
    assert out == {"entries": 2, "empty_password_users": ["guest"]}
    assert "$6$" not in json.dumps(out)


def test_authorized_keys_never_keeps_key_material():
    raw = (RAW / "authorized_keys-bad.synthetic.txt").read_text()
    out = json.dumps(derive.authorized_keys(raw.encode()))
    for line in raw.splitlines():
        for token in line.split():
            if token.startswith("AAAA"):
                assert token not in out
    assert "backup-only" not in out  # option values are dropped, names kept
    assert '"command"' in out


def test_cron_never_keeps_command_text():
    raw = b"PGPASSWORD=s3cret\n30 3 * * * root PGPASSWORD=s3cret pg_dump app > /b/x.sql\n"
    out = json.dumps(derive.cron_schedules(raw))
    assert "s3cret" not in out and "pg_dump" not in out
    assert json.loads(out)["entries"] == [
        {"schedule": "30 3 * * *", "backup_related": True, "pruning": False}]


def test_lynis_drops_host_inventory():
    raw = (RAW / "lynis-report.synthetic.txt").read_bytes()
    out = derive.lynis_report(raw)
    assert out["hardening_index"] == "67"
    assert "203.0.113.10" not in json.dumps(out) and "testhost" not in json.dumps(out)


def test_fail2ban_counts_without_addresses():
    raw = (RAW / "fail2ban-log.synthetic.txt").read_bytes()
    out = derive.fail2ban_log_bans(raw)
    assert out == {"bans_by_jail_day": {"sshd": {"2026-09-18": 1, "2026-09-19": 1,
                                                 "2026-09-20": 1}}}
