"""Detection-domain collectors: brute-force response, log retention, integrity."""

from __future__ import annotations

import posixpath
from datetime import timedelta
from typing import Any

from . import (
    CollectContext,
    collector,
    derived,
    listing,
    read,
    run,
    stat,
    unknown,
)
from .patching import DPKG_FMT, dpkg_installed

F2B_PARAMS = ("bantime", "findtime", "maxretry", "backend")
F2B_LOGS = ("/var/log/fail2ban.log", "/var/log/fail2ban.log.1")


def _unit_states(ctx: CollectContext, units: list[str]) -> dict[str, str]:
    res = ctx.cmd(["systemctl", "is-active", *units], ok=tuple(range(0, 5)))
    return dict(zip(units, res.stdout.split(), strict=False))


@collector("brute_force", plan=[
    run("systemctl", "is-active", "fail2ban", "sshguard", "crowdsec"),
    run("fail2ban-client", "status"),
    run("fail2ban-client", "status", "<ssh-jail>"),
    run("fail2ban-client", "get", "<ssh-jail>", "<bantime|findtime|maxretry|backend>"),
    derived("fail2ban_log_bans", "/var/log/fail2ban.log",
            "and fail2ban.log.1; ban counts per day, no addresses"),
    run("journalctl", "--no-pager", "-u", "fail2ban", "--since", "7 days ago", "-o", "cat",
        note="only if fail2ban writes no log file"),
])
def brute_force(ctx: CollectContext) -> dict[str, Any]:
    states = _unit_states(ctx, ["fail2ban", "sshguard", "crowdsec"])
    active = [u for u, s in states.items() if s == "active"]
    out: dict[str, Any] = {"services": states, "protection_active": bool(active)}
    if "fail2ban" not in active:
        out["ssh_jail_present"] = False
        if active:
            out["ssh_jail_present"] = unknown(f"{active[0]} detected; its SSH coverage is not "
                                              "inspected in this version")
            out["bans_observed"] = unknown(f"ban activity is not measured for {active[0]} "
                                           "in this version")
        else:
            out["bans_observed"] = 0
        return out
    status = ctx.parse("fail2ban_status", ctx.cmd(["fail2ban-client", "status"]).stdout,
                       "fail2ban-client status")
    jails = [j.strip() for j in status.get("jail list", "").split(",") if j.strip()]
    ssh_jails = [j for j in jails if "ssh" in j]
    out.update({"jails": jails, "ssh_jail_present": bool(ssh_jails)})
    if not ssh_jails:
        out["bans_observed"] = 0
        return out
    jail = ssh_jails[0]
    js = ctx.parse("fail2ban_status", ctx.cmd(["fail2ban-client", "status", jail]).stdout,
                   "fail2ban-client status jail")
    total = int(js.get("total banned", "0") or 0)
    params = {p: ctx.cmd(["fail2ban-client", "get", jail, p]).stdout.strip()
              for p in F2B_PARAMS}
    since = (ctx.runner.now - timedelta(days=7)).strftime("%Y-%m-%d")
    bans_7d, source = 0, None
    for path in F2B_LOGS:
        value = ctx.derive("fail2ban_log_bans", path)
        if value is None:
            continue
        source = source or path
        for day, n in value["bans_by_jail_day"].get(jail, {}).items():
            if day >= since:
                bans_7d += n
    if source is None:
        res = ctx.try_cmd(["journalctl", "--no-pager", "-u", "fail2ban", "--since",
                           "7 days ago", "-o", "cat"])
        if res is not None:
            source = "journal"
            bans_7d = sum(1 for ln in res.stdout.splitlines() if f"[{jail}] Ban " in ln)
    out.update({"jail": jail, "total_banned_since_start": total, "bans_7d": bans_7d,
                "ban_log_source": source, "params": params,
                "bans_observed": max(total, bans_7d)})
    return out


JOURNALD_DIRS = ("/usr/lib/systemd/journald.conf.d", "/run/systemd/journald.conf.d",
                 "/etc/systemd/journald.conf.d")
SYSLOG_AUTH = ("/var/log/auth.log", "/var/log/secure")


@collector("auth_log_persistence", plan=[
    read("/etc/systemd/journald.conf"),
    listing("<dir>/*.conf", "journald.conf.d under /usr/lib, /run and /etc"),
    read("<dir>/<file>.conf"),
    stat("/var/log/journal"),
    stat("/var/log/auth.log"),
    stat("/var/log/secure"),
])
def auth_log_persistence(ctx: CollectContext) -> dict[str, Any]:
    storage = "auto"
    main = ctx.parsed("systemd_ini", "/etc/systemd/journald.conf") or {}
    storage = main.get("Journal", {}).get("Storage", storage)
    dropins: dict[str, str] = {}
    for d in JOURNALD_DIRS:  # later directories override same-named files
        for entry in ctx.glob(f"{d}/*.conf"):
            dropins[posixpath.basename(entry["path"])] = entry["path"]
    for name in sorted(dropins):
        conf = ctx.parsed("systemd_ini", dropins[name]) or {}
        storage = conf.get("Journal", {}).get("Storage", storage)
    storage = storage.lower()
    journal_dir = ctx.stat("/var/log/journal")
    journal_persistent = storage == "persistent" or (
        storage == "auto" and journal_dir["exists"] and journal_dir["kind"] == "dir")
    syslog = None
    for path in SYSLOG_AUTH:
        st = ctx.stat(path)
        if st["exists"]:
            syslog = {"path": path, "age_hours": ctx.age_hours(st["mtime"])}
            break
    syslog_fresh = bool(syslog) and syslog["age_hours"] <= 24 * 7
    return {"journald_storage": storage, "journal_dir_exists": journal_dir["exists"],
            "journal_persistent": journal_persistent, "syslog_auth_log": syslog,
            "auth_logs_persistent": journal_persistent or syslog_fresh,
            "dropins": sorted(dropins.values())}


@collector("integrity_tools", plan=[
    run("systemctl", "is-active", "auditd"),
    run("dpkg-query", "-W", "-f", DPKG_FMT, "auditd", "aide", "debsums"),
])
def integrity_tools(ctx: CollectContext) -> dict[str, Any]:
    states = _unit_states(ctx, ["auditd"])
    pkgs = dpkg_installed(ctx, "auditd", "aide", "debsums")
    return {"auditd_active": states.get("auditd") == "active",
            "auditd_installed": pkgs["auditd"], "aide_installed": pkgs["aide"],
            "debsums_installed": pkgs["debsums"]}

