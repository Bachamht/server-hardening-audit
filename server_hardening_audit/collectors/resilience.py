"""Resilience-domain collectors: backups and headroom."""

from __future__ import annotations

import re
from typing import Any

from . import (
    CollectContext,
    PlanStep,
    Undetermined,
    collector,
    derived,
    listing,
    run,
    stat,
    unknown,
)

BACKUP_UNIT = re.compile(r"backup|dump|restic|borg|snapshot|rsnapshot|duplicity", re.I)
PRUNE_UNIT = re.compile(r"prune|forget|cleanup|retention|rotate", re.I)
CRON_SOURCES = ("/etc/crontab",)
CRON_GLOBS = ("/etc/cron.d/*", "/var/spool/cron/crontabs/*")


@collector("backups", plan=[
    derived("cron_schedules", "/etc/crontab", "schedules and keyword flags; commands not kept"),
    listing("/etc/cron.d/*"),
    derived("cron_schedules", "/etc/cron.d/<file>"),
    listing("/var/spool/cron/crontabs/*"),
    derived("cron_schedules", "/var/spool/cron/crontabs/<user>"),
    run("systemctl", "list-timers", "--all", "--no-legend", "--plain"),
    listing("<backup_path>/*", "and <backup_path>/*/*; metadata only, never content"),
])
def backups(ctx: CollectContext) -> dict[str, Any]:
    paths = ctx.profile["backup_paths"]
    if not paths:
        raise Undetermined("profile declares no backup_paths; nothing to measure against RPO")
    schedules, pruning = [], []
    cron_files = list(CRON_SOURCES)
    for pattern in CRON_GLOBS:
        cron_files += [e["path"] for e in ctx.glob(pattern) if e["kind"] == "file"]
    for path in cron_files:
        value = ctx.derive("cron_schedules", path)
        for entry in (value or {}).get("entries", []):
            if entry["backup_related"]:
                schedules.append(f"cron {path}: {entry['schedule']}")
            if entry["pruning"]:
                pruning.append(f"cron {path}: {entry['schedule']}")
    timers = ctx.try_cmd(["systemctl", "list-timers", "--all", "--no-legend", "--plain"])
    if timers is not None:
        for unit in ctx.parse("unit_list", timers.stdout, "systemctl list-timers"):
            if BACKUP_UNIT.search(unit):
                schedules.append(f"timer {unit}")
            if PRUNE_UNIT.search(unit) and BACKUP_UNIT.search(unit):
                pruning.append(f"timer {unit}")
    files = []
    for base in paths:
        for pattern in (f"{base.rstrip('/')}/*", f"{base.rstrip('/')}/*/*"):
            files += [e for e in ctx.glob(pattern) if e["kind"] == "file"]
    newest = max(files, key=lambda e: e["mtime"]) if files else None
    newest_age: Any = ctx.age_hours(newest["mtime"]) if newest else unknown(
        f"no files found under {', '.join(paths)}")
    retention: Any = True if pruning else unknown(
        "no pruning visible in cron entries or timer names (it may live inside a script); "
        "confirm the retention policy by attestation")
    return {"scheduled": bool(schedules), "schedules": schedules, "pruning": pruning,
            "retention_evidence": retention, "backup_files": len(files),
            "newest": newest["path"] if newest else None, "newest_age_hours": newest_age,
            "newest_size": newest["size"] if newest else None}


@collector("disk_headroom", plan=[
    PlanStep("statvfs", ("<each profile disk_paths entry>",)),
])
def disk_headroom(ctx: CollectContext) -> dict[str, Any]:
    mounts, violations = [], []
    min_free = ctx.profile["min_free_percent"]
    min_inodes = ctx.profile["min_free_inodes_percent"]
    for path in ctx.profile["disk_paths"]:
        v = ctx.runner.statvfs(path)
        if v.error:
            raise Undetermined(f"{path}: {v.error}")
        free = round(100 * v.bavail / v.blocks, 1) if v.blocks else None
        inodes = round(100 * v.favail / v.files, 1) if v.files else None
        mounts.append({"path": path, "free_percent": free, "inodes_free_percent": inodes})
        if free is not None and free < min_free:
            violations.append(f"{path}: {free}% space free (< {min_free}%)")
        if inodes is not None and inodes < min_inodes:
            violations.append(f"{path}: {inodes}% inodes free (< {min_inodes}%)")
    return {"mounts": mounts, "violations": violations}


@collector("backup_permissions", plan=[
    stat("<backup_path>", "each profile backup_paths entry"),
    listing("<backup_path>/*", "and <backup_path>/*/*; metadata only, never content"),
])
def backup_permissions(ctx: CollectContext) -> dict[str, Any]:
    """Other accounts must not read backups, and must not change or delete them."""
    paths = ctx.profile["backup_paths"]
    if not paths:
        raise Undetermined("profile declares no backup_paths")
    violations, checked = [], 0
    for base in paths:
        root = ctx.stat(base)
        if not root["exists"]:
            raise Undetermined(f"backup path {base} does not exist")
        entries = [root]
        for pattern in (f"{base.rstrip('/')}/*", f"{base.rstrip('/')}/*/*"):
            entries += ctx.glob(pattern)
        for e in entries:
            if e["kind"] == "dir":
                if e["mode"] & 0o022 and not e["mode"] & 0o1000:
                    violations.append(f"{e['path']}: directory mode {e['mode']:04o} lets other "
                                      "accounts create or delete files")
            elif e["kind"] == "file":
                checked += 1
                if e["mode"] & 0o007:
                    violations.append(f"{e['path']}: mode {e['mode']:04o} gives all accounts "
                                      "access")
                elif e["mode"] & 0o020:
                    violations.append(f"{e['path']}: mode {e['mode']:04o} is group-writable "
                                      f"(group {e['group']})")
    return {"files_checked": checked, "violations": violations}
