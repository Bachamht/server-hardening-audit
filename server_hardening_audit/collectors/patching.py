"""Patching-domain collectors.

The engine never runs `apt-get update` or `unattended-upgrade --dry-run`:
the first rewrites /var/lib/apt/lists, the second writes logs and takes the
apt lock. Instead it reads the state those tools leave behind and reports
how fresh that state is.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import (
    CollectContext,
    Undetermined,
    batched,
    collector,
    derived,
    listing,
    read,
    run,
    stat,
    unknown,
)
from .network import running_containers

DPKG_FMT = "${Package}\t${db:Status-Abbrev}\t${Version}\n"
UU_LOG = "/var/log/unattended-upgrades/unattended-upgrades.log"


def dpkg_installed(ctx: CollectContext, *packages: str) -> dict[str, bool]:
    res = ctx.cmd(["dpkg-query", "-W", "-f", DPKG_FMT, *packages], ok=(0, 1))
    status = ctx.parse("dpkg_status", res.stdout, "dpkg-query")
    return {p: status.get(p, {}).get("installed", False) for p in packages}


def _log_time(ts: str) -> float:
    # unattended-upgrades logs local time without a zone; read as UTC. The
    # error (the host's UTC offset) is small against the 48h threshold.
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


@collector("auto_updates", plan=[
    run("dpkg-query", "-W", "-f", DPKG_FMT, "unattended-upgrades"),
    listing("/etc/apt/apt.conf.d/*"),
    read("/etc/apt/apt.conf.d/<file>", "APT::Periodic settings"),
    run("systemctl", "is-enabled", "apt-daily.timer", "apt-daily-upgrade.timer"),
    stat("/var/lib/apt/periodic/unattended-upgrades-stamp"),
    derived("unattended_upgrades_log", UU_LOG, "run and upgrade timestamps only"),
])
def auto_updates(ctx: CollectContext) -> dict[str, Any]:
    installed = dpkg_installed(ctx, "unattended-upgrades")["unattended-upgrades"]
    periodic: dict[str, str] = {}
    for entry in ctx.glob("/etc/apt/apt.conf.d/*"):
        if entry["kind"] == "file":
            periodic.update({k: v for k, v in (ctx.parsed("apt_conf", entry["path"]) or {})
                            .items() if k.startswith("APT::Periodic::")})
    enabled = periodic.get("APT::Periodic::Unattended-Upgrade", "0") not in ("0", "")
    timers = ctx.cmd(["systemctl", "is-enabled", "apt-daily.timer", "apt-daily-upgrade.timer"],
                     ok=(0, 1)).stdout.split()
    timer_enabled = len(timers) == 2 and all(t in ("enabled", "static") for t in timers)
    stamp = ctx.stat("/var/lib/apt/periodic/unattended-upgrades-stamp")
    log = ctx.derive("unattended_upgrades_log", UU_LOG) or {}
    last_run = _log_time(log["runs"][-1]) if log.get("runs") else None
    last_upgrade = _log_time(log["upgrades"][-1]["at"]) if log.get("upgrades") else None
    candidates = [t for t in (stamp.get("mtime") if stamp["exists"] else None, last_run) if t]
    activity: Any = ctx.age_hours(max(candidates)) if candidates else unknown(
        "no unattended-upgrades stamp or log entries found")
    return {
        "installed": installed, "enabled": enabled, "timer_enabled": timer_enabled,
        "timers": dict(zip(["apt-daily.timer", "apt-daily-upgrade.timer"], timers, strict=False)),
        "periodic": periodic, "last_activity_age_hours": activity,
        "last_upgrade_age_days": None if last_upgrade is None
        else round((ctx.now_ts - last_upgrade) / 86400, 1),
        "runs_logged": log.get("run_count", 0), "upgrades_logged": log.get("upgrade_count", 0),
    }


@collector("apt_backlog", plan=[
    stat("/var/lib/apt/periodic/update-success-stamp", "package list freshness"),
    stat("/var/lib/apt/lists", "fallback freshness"),
    run("apt", "list", "--upgradable"),
    stat("/var/run/reboot-required"),
    read("/var/run/reboot-required.pkgs"),
])
def apt_backlog(ctx: CollectContext) -> dict[str, Any]:
    stamp = ctx.stat("/var/lib/apt/periodic/update-success-stamp")
    if not stamp["exists"]:
        stamp = ctx.stat("/var/lib/apt/lists")
    if not stamp["exists"]:
        raise Undetermined("no apt package lists found")
    lists_age = ctx.age_hours(stamp["mtime"])
    res = ctx.cmd(["apt", "list", "--upgradable"])
    pkgs = ctx.parse("apt_upgradable", res.stdout, "apt list --upgradable")
    security: Any = sorted(p["package"] for p in pkgs if p["security"])
    limit = ctx.profile["apt_lists_max_age_hours"]
    if lists_age > limit:
        security = unknown(
            f"package lists are {lists_age:.0f}h old (limit {limit}h); the backlog cannot be "
            "judged, and this tool does not run `apt-get update` because that changes the host")
    reboot = ctx.stat("/var/run/reboot-required")
    reboot_pkgs = (ctx.text("/var/run/reboot-required.pkgs") or "").split() if reboot["exists"] \
        else []
    return {"lists_age_hours": lists_age, "lists_source": stamp["path"],
            "security_upgrades": security, "upgradable_total": len(pkgs),
            "reboot_required": reboot["exists"],
            "reboot_required_age_hours": ctx.age_hours(reboot["mtime"]) if reboot["exists"]
            else None,
            "reboot_packages": sorted(set(reboot_pkgs))}


@collector("image_age", plan=[
    run("docker", "ps", "-q", "--no-trunc"),
    run("docker", "inspect", "--type", "container", "<container-id>..."),
    run("docker", "image", "inspect", "<image-id>..."),
])
def image_age(ctx: CollectContext) -> dict[str, Any]:
    docs = running_containers(ctx)
    if not docs:
        return {"containers": 0, "images": [], "violations": []}
    image_ids = sorted({d["Image"] for d in docs if d.get("Image")})
    created: dict[str, str] = {}
    for chunk in batched(image_ids):
        out = ctx.cmd(["docker", "image", "inspect", *chunk])
        for img in ctx.parse("json", out.stdout, "docker image inspect") or []:
            created[img["Id"]] = img.get("Created", "")
    limit = ctx.profile["max_image_age_days"]
    images, violations = [], []
    for d in docs:
        ref = (d.get("Config") or {}).get("Image", "?")
        ts = created.get(d.get("Image", ""))
        if not ts:
            raise Undetermined(f"no creation time for image of {d.get('Name', '?')}")
        when = datetime.fromisoformat(ts[:26].rstrip("Z").split(".")[0]).replace(
            tzinfo=timezone.utc)
        age = round((ctx.now_ts - when.timestamp()) / 86400, 1)
        images.append({"container": d.get("Name", "?").lstrip("/"), "image": ref,
                       "created": when.isoformat(), "age_days": age})
        if age > limit:
            violations.append(f"{d.get('Name', '?').lstrip('/')}: {ref} built {age:.0f} days ago")
    return {"containers": len(docs), "images": images, "violations": violations}

