"""Tests for the command allowlist (SPEC: read-only guarantee)."""

import pytest

from server_hardening_audit import policy

ALLOWED = [
    ["sshd", "-T"],
    ["sshd", "-T", "-C", "user=admin,host=example.org,addr=192.0.2.10"],
    ["ss", "-tlnpH"],
    ["ss", "-ulnpH"],
    ["systemctl", "is-active", "fail2ban"],
    ["systemctl", "is-enabled", "apt-daily-upgrade.timer", "unattended-upgrades.service"],
    ["systemctl", "show", "-p", "User,Group,DynamicUser", "nginx.service"],
    ["systemctl", "show", "--property=ActiveState", "--value", "ssh.service"],
    ["systemctl", "list-timers", "--all", "--no-pager", "apt-daily*"],
    ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"],
    ["systemctl", "cat", "ssh.service"],
    ["ufw", "status"],
    ["ufw", "status", "verbose"],
    ["ufw", "status", "numbered"],
    ["fail2ban-client", "ping"],
    ["fail2ban-client", "status"],
    ["fail2ban-client", "status", "sshd"],
    ["fail2ban-client", "get", "sshd", "bantime"],
    ["docker", "ps", "-q"],
    ["docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}"],
    ["docker", "inspect", "--type", "container", "a1b2c3", "d4e5f6"],
    ["docker", "port", "webapp"],
    ["docker", "version", "--format", "{{.Server.Version}}"],
    ["docker", "info"],
    ["docker", "image", "ls", "--no-trunc"],
    ["docker", "image", "inspect", "ghcr.io/example/app:1.2@sha256:abc"],
    ["journalctl", "--no-pager", "-u", "fail2ban", "--since", "7 days ago", "-o", "cat"],
    ["journalctl", "--no-pager", "--disk-usage"],
    ["journalctl", "--no-pager", "-q", "_COMM=sshd", "-n", "200"],
    ["iptables", "-S"],
    ["iptables", "-S", "DOCKER-USER"],
    ["iptables", "-t", "nat", "-S"],
    ["ip6tables", "-S"],
    ["iptables", "-L", "INPUT", "-n", "-v", "--line-numbers"],
    ["ip6tables", "-n", "-L"],
    ["nft", "list", "ruleset"],
    ["nft", "-j", "list", "ruleset"],
    ["firewall-cmd", "--state"],
    ["firewall-cmd", "--zone=public", "--list-all"],
    ["apt", "list", "--upgradable"],
    ["apt", "list", "--installed", "openssh-server"],
    ["dpkg-query", "-W", "-f", "${Package} ${Version}\n", "openssh-server"],
    ["dpkg-query", "-l"],
    ["dpkg-query", "-s", "unattended-upgrades"],
    ["sudo", "-l", "-U", "deploy"],
    ["sudo", "-n", "-l", "-U", "www-data"],
    ["timedatectl", "show"],
    ["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
    ["timedatectl", "status"],
    ["systemd-detect-virt"],
    ["ps", "-eo", "user,pid,comm", "--no-headers"],
]

# State-changing or otherwise unsafe invocations. Every one must be refused.
DENIED = [
    # systemctl state changes
    ["systemctl", "restart", "nginx"],
    ["systemctl", "stop", "ssh"],
    ["systemctl", "start", "fail2ban"],
    ["systemctl", "reload", "ssh"],
    ["systemctl", "enable", "--now", "ufw"],
    ["systemctl", "disable", "fail2ban"],
    ["systemctl", "mask", "ssh"],
    ["systemctl", "daemon-reload"],
    ["systemctl", "show", "-H", "otherhost", "ssh"],
    ["systemctl", "--host=otherhost", "is-active", "ssh"],
    ["systemctl", "is-active", "--", "-ssh"],
    ["systemctl", "kill", "nginx"],
    ["systemctl", "isolate", "rescue.target"],
    # ufw
    ["ufw", "allow", "22"],
    ["ufw", "deny", "3000"],
    ["ufw", "enable"],
    ["ufw", "disable"],
    ["ufw", "reset"],
    ["ufw", "reload"],
    ["ufw", "delete", "1"],
    ["ufw", "--force", "enable"],
    ["ufw", "status", "verbose", "extra"],
    # fail2ban
    ["fail2ban-client", "set", "sshd", "unbanip", "192.0.2.1"],
    ["fail2ban-client", "unban", "--all"],
    ["fail2ban-client", "reload"],
    ["fail2ban-client", "start"],
    ["fail2ban-client", "stop"],
    ["fail2ban-client", "get", "sshd"],
    ["fail2ban-client", "get", "sshd", "bantime", "extra"],
    ["fail2ban-client", "get", "sshd", "dbfile"],
    # docker
    ["docker", "compose", "up", "-d"],
    ["docker", "compose", "down"],
    ["docker", "run", "--rm", "-v", "/:/host", "alpine"],
    ["docker", "exec", "webapp", "sh"],
    ["docker", "rm", "-f", "webapp"],
    ["docker", "stop", "webapp"],
    ["docker", "start", "webapp"],
    ["docker", "pull", "nginx"],
    ["docker", "system", "prune", "-af"],
    ["docker", "image", "rm", "nginx"],
    ["docker", "image", "prune"],
    ["docker", "-H", "tcp://192.0.2.1:2375", "ps"],
    ["docker", "--context", "remote", "ps"],
    ["docker", "ps", "--filter", "name=x"],
    ["docker", "inspect", "-", "x"],
    ["docker", "inspect", "--format", "-H"],
    # journalctl
    ["journalctl", "--vacuum-time=1s"],
    ["journalctl", "--no-pager", "--vacuum-size=1K"],
    ["journalctl", "--no-pager", "--rotate"],
    ["journalctl", "--no-pager", "--flush"],
    ["journalctl", "--no-pager", "--sync"],
    ["journalctl", "--no-pager", "--relinquish-var"],
    ["journalctl", "--no-pager", "--setup-keys"],
    ["journalctl", "--no-pager", "-f"],
    ["journalctl", "-u", "ssh"],  # pager not disabled
    ["journalctl", "--no-pager", "--since=-1h"],
    # iptables / nft
    ["iptables", "-A", "INPUT", "-j", "ACCEPT"],
    ["iptables", "-I", "INPUT", "1", "-j", "DROP"],
    ["iptables", "-D", "INPUT", "1"],
    ["iptables", "-F"],
    ["iptables", "-X"],
    ["iptables", "-P", "INPUT", "ACCEPT"],
    ["iptables", "-N", "NEWCHAIN"],
    ["iptables", "-S", "-F"],
    ["iptables", "-L"],  # would do DNS lookups without -n
    ["ip6tables", "-F"],
    ["nft", "flush", "ruleset"],
    ["nft", "add", "rule", "inet", "filter", "input", "accept"],
    ["nft", "-f", "/tmp/rules.nft"],
    ["nft", "list", "ruleset", "extra"],
    # firewalld
    ["firewall-cmd", "--reload"],
    ["firewall-cmd", "--add-port=5432/tcp"],
    ["firewall-cmd", "--list-all", "--add-service=ssh"],
    ["firewall-cmd", "--permanent"],
    # packages
    ["apt", "install", "lynis"],
    ["apt", "upgrade", "-y"],
    ["apt", "update"],
    ["apt", "remove", "fail2ban"],
    ["apt", "list"],
    ["apt", "list", "--upgradable", "-o", "APT::Get::Assume-Yes=true"],
    ["apt-get", "update"],
    ["apt-get", "install", "-y", "x"],
    ["unattended-upgrade", "--dry-run"],
    ["dpkg", "-i", "x.deb"],
    ["dpkg-query", "--admindir=/tmp", "-l"],
    # sudo / sshd / time
    ["sudo", "rm", "-rf", "/"],
    ["sudo", "-l"],
    ["sudo", "-l", "-U", "deploy", "id"],
    ["sudo", "-u", "root", "id"],
    ["sudo", "-l", "-U", "-root"],
    ["sshd"],
    ["sshd", "-t"],
    ["sshd", "-D"],
    ["sshd", "-T", "-f", "/tmp/sshd_config"],
    ["sshd", "-T", "-o", "PasswordAuthentication=yes"],
    ["sshd", "-T", "-C", "user=root;id"],
    ["timedatectl", "set-ntp", "false"],
    ["timedatectl", "set-time", "2020-01-01"],
    ["timedatectl", "-H", "otherhost", "show"],
    # programs that are never allowed
    ["lynis", "audit", "system"],
    ["sysctl", "-a"],
    ["sysctl", "-w", "net.ipv4.ip_forward=1"],
    ["openssl", "s_client", "-connect", "example.org:443"],
    ["sh", "-c", "id"],
    ["bash", "-c", "ss -tlnp | grep 22"],
    ["python3", "-c", "print(1)"],
    ["rm", "-rf", "/var/backups"],
    ["chown", "-R", "root:", "/srv"],
    ["tee", "/etc/ssh/sshd_config"],
    ["crontab", "-r"],
    ["reboot"],
    ["pg_dump", "webapp"],
    # malformed / smuggling attempts
    [],
    [""],
    ["/usr/sbin/sshd", "-T"],
    ["./ss", "-tlnpH"],
    ["ss", "-tlnpH", "\x00"],
    ["ss -tlnpH"],
    ["ss", "-tlnpH; reboot"],
    ["ss", "-tlnpH", "|", "sh"],
    ["systemctl", "is-active", "ssh$(reboot)"],
    ["systemctl", "is-active", "ssh`reboot`"],
    ["ss", "-tlnpH", "x" * 1000],
    ["systemctl", "is-active"] + ["ssh"] * 100,
]


def _id(argv):
    return " ".join(argv)[:60] or "<empty>"


@pytest.mark.parametrize("argv", ALLOWED, ids=_id)
def test_allowed(argv):
    decision = policy.check(argv)
    assert decision.allowed, decision.reason


@pytest.mark.parametrize("argv", DENIED, ids=_id)
def test_denied(argv):
    decision = policy.check(argv)
    assert not decision.allowed
    assert decision.reason


def test_denial_reason_names_the_problem():
    decision = policy.check(["systemctl", "restart", "nginx"])
    assert "systemctl" in decision.reason
    decision = policy.check(["lynis", "audit", "system"])
    assert "not on the allowlist" in decision.reason


def test_non_list_argv_is_denied():
    assert not policy.check("ss -tlnpH")
    assert not policy.check(None)
    assert not policy.check(["ss", 1])


def test_every_program_has_rules():
    for prog, rules in policy.RULES.items():
        assert rules, prog
        assert "/" not in prog


@pytest.mark.parametrize("verb", [
    "restart", "stop", "start", "reload", "enable", "disable", "mask", "unmask",
    "daemon-reload", "kill", "isolate", "reboot", "poweroff", "set-property", "edit",
    "reset-failed", "preset", "link", "revert",
])
def test_systemctl_mutating_verbs_denied(verb):
    assert not policy.check(["systemctl", verb, "ssh.service"])
    assert not policy.check(["systemctl", "--no-pager", verb, "ssh.service"])


@pytest.mark.parametrize("flag", ["-A", "-I", "-D", "-R", "-F", "-X", "-P", "-N", "-E", "-Z"])
def test_iptables_mutating_flags_denied(flag):
    for prog in ("iptables", "ip6tables"):
        assert not policy.check([prog, flag, "INPUT"])
        assert not policy.check([prog, "-S", flag, "INPUT"])
        assert not policy.check([prog, "-n", "-L", flag, "INPUT"])
