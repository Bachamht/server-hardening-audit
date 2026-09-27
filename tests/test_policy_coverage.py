"""Static policy coverage (SPEC 4.4): every argv a control or collector can
run passes the allowlist; raw reads and derivers stay within their bounds;
the live runner never executes a refused command."""

import re
import subprocess

import pytest

from server_hardening_audit import collectors, derive, policy
from server_hardening_audit.loader import load_controls
from server_hardening_audit.runner import LiveRunner

SAMPLES = {
    "<user>": "admin", "<unit>...": "ssh.service", "<container-id>...": "5f1a2b3c4d5e",
    "<image-id>...": "sha256:aa11bb22", "<ssh-jail>": "sshd",
    "<bantime|findtime|maxretry>": "bantime", "<home>": "/home/admin",
    "<file>": "x.conf", "<dir>": "/etc/systemd/journald.conf.d", "<key>": "kernel/kptr_restrict",
    "<backup_path>": "/var/backups", "<file>.conf": "10-x.conf",
}


def _fill(text: str) -> str:
    for k, v in SAMPLES.items():
        text = text.replace(k, v)
    assert "<" not in text or "user=" in text, f"unfilled placeholder in {text!r}"
    return text.replace("<user>", "admin")


def _plan_steps():
    for coll in collectors.COLLECTORS.values():
        for step in coll.plan:
            yield pytest.param(coll.name, step, id=f"{coll.name}:{step.op}:{' '.join(step.target)}")


@pytest.mark.parametrize("name,step", list(_plan_steps()))
def test_collector_plan_is_allowed(name, step):
    if step.op == "run":
        argv = [_fill(t) for t in step.target]
        assert policy.check(argv), f"{name}: {argv} refused: {policy.check(argv).reason}"
    elif step.op == "read":
        path = _fill(step.target[0])
        assert policy.check_read(path), f"{name}: raw read of {path} refused"
    elif step.op == "derive":
        deriver, path = step.target
        assert deriver in derive.DERIVERS
        assert derive.DERIVERS[deriver].paths.fullmatch(_fill(path)), path


def test_control_argv_are_allowed():
    for control in load_controls().controls:
        for check in control.checks:
            if check.type == "cmd":
                assert policy.check(check.get("argv")), (control.id, check.get("argv"))
            if check.type == "file":
                assert policy.check_read(check.get("path")), (control.id, check.get("path"))


def test_every_collector_is_used_and_has_a_plan():
    used = {c.get("collector") for ctl in load_controls().controls for c in ctl.checks
            if c.type == "collector"}
    assert used == set(collectors.COLLECTORS)
    assert all(c.plan for c in collectors.COLLECTORS.values())


@pytest.mark.parametrize("path", [
    "/etc/shadow", "/etc/gshadow", "/root/.ssh/authorized_keys", "/home/a/.ssh/id_ed25519",
    "/etc/ssh/ssh_host_ed25519_key", "/etc/ssl/private/site.key", "/srv/app/.env",
    "/srv/app/.env.production", "/opt/app/config.pem", "/etc/../etc/shadow",
    "/etc/ssh/sshd_config.d/../../shadow", "/var/lib/postgresql/16/main/pg_hba.conf",
    "/home/deploy/app/docker-compose.yml", "/proc/1/environ", "relative/path", "/etc/crontab",
    "/var/log/lynis-report.dat",
])
def test_raw_reads_of_sensitive_or_unlisted_paths_are_refused(path):
    assert not policy.check_read(path)


@pytest.mark.parametrize("path", [
    "/etc/os-release", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/50-cloud-init.conf",
    "/etc/sudoers.d/90-cloud-init-users", "/proc/sys/kernel/kptr_restrict",
    "/var/run/reboot-required.pkgs", "/etc/apt/apt.conf.d/20auto-upgrades",
])
def test_raw_reads_of_listed_paths_are_allowed(path):
    assert policy.check_read(path)


def test_tls_only_to_loopback():
    assert policy.check_connect("127.0.0.1", 443)
    assert not policy.check_connect("192.0.2.1", 443)
    assert not policy.check_connect("example.org", 443)


class _Boom(Exception):
    pass


def test_live_runner_never_executes_refused_commands(monkeypatch):
    def fail(*a, **kw):
        raise _Boom("subprocess.run must not be called")
    monkeypatch.setattr(subprocess, "run", fail)
    runner = LiveRunner(now=None)
    for argv in (["systemctl", "restart", "nginx"], ["ufw", "allow", "22"],
                 ["docker", "compose", "up", "-d"], ["sh", "-c", "id"]):
        res = runner.run(argv)
        assert res.error_kind == "denied"
    # the refusal itself is recorded as evidence
    assert all(c.result["error_kind"] == "denied" for c in runner.calls["_host"])


def test_live_runner_refuses_deriver_outside_its_paths():
    runner = LiveRunner(now=None)
    assert runner.derive("authorized_keys", "/etc/shadow").error_kind == "denied"
    assert runner.derive("shadow_empty_passwords", "/etc/passwd").error_kind == "denied"
    assert runner.derive("nope", "/etc/shadow").error_kind == "denied"
    assert runner.read("/etc/shadow").error_kind == "denied"


def test_live_runner_uses_fixed_path_and_minimal_env(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(kw, argv=argv)

        class P:
            returncode, stdout, stderr = 0, b"", b""
        return P()
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr("server_hardening_audit.runner.untrusted_executable", lambda p: None)
    monkeypatch.setenv("PATH", "/tmp/evil:/usr/bin")
    monkeypatch.setattr("shutil.which", lambda prog, path=None: f"{path.split(':')[0]}/{prog}"
                        if path and "/tmp/evil" not in path else None)
    LiveRunner(now=None).run(["ss", "-tlnpH"])
    assert seen["shell"] is False
    assert seen["env"]["PATH"].startswith("/usr/local/sbin")
    assert "DOCKER_HOST" not in seen["env"]
    assert re.match(r"^/usr/local/sbin/ss$", seen["argv"][0])


@pytest.mark.parametrize("uid,mode,ok", [
    (0, 0o100755, True),
    (1000, 0o100755, False),   # owned by a normal user
    (0, 0o100775, False),      # group-writable
    (0, 0o100757, False),      # world-writable
])
def test_untrusted_executables_are_refused(monkeypatch, uid, mode, ok):
    import os

    from server_hardening_audit import runner as runner_mod
    monkeypatch.setattr(os.path, "realpath", lambda p: "/opt/evil/bin/ss")
    real_stat = os.stat
    monkeypatch.setattr(os, "stat", lambda p, *a, **k: (
        type("S", (), {"st_uid": uid, "st_mode": mode if p.endswith("/ss") else 0o40755})()
        if p.startswith("/opt/evil") else real_stat(p, *a, **k)))
    reason = runner_mod.untrusted_executable("/usr/bin/ss")
    assert (reason is None) == ok, reason


def test_live_runner_refuses_untrusted_binary(monkeypatch):
    from server_hardening_audit import runner as runner_mod
    monkeypatch.setattr(runner_mod.shutil, "which", lambda prog, path=None: "/opt/evil/ss")
    monkeypatch.setattr(runner_mod, "untrusted_executable", lambda p: "not owned by root")

    def boom(*a, **k):
        raise AssertionError("must not execute")
    monkeypatch.setattr(subprocess, "run", boom)
    res = LiveRunner(now=None).run(["ss", "-tlnpH"])
    assert res.error_kind == "denied" and "not owned by root" in res.error
