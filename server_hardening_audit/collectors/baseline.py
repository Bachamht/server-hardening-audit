"""Baseline-domain collectors: Lynis report, kernel parameters, time, MAC."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import CollectContext, Undetermined, collector, derived, read, run

LYNIS_REPORT = "/var/log/lynis-report.dat"


@collector("lynis_report", plan=[
    derived("lynis_report", LYNIS_REPORT, "score, dates and test IDs only; Lynis is not run"),
])
def lynis_report(ctx: CollectContext) -> dict[str, Any]:
    value = ctx.derive("lynis_report", LYNIS_REPORT)
    if value is None:
        raise Undetermined(f"no Lynis report at {LYNIS_REPORT}; running Lynis is an operator "
                           "action (it writes to /var/log), see skills/ for guidance")
    ended = value.get("report_datetime_end") or value.get("report_datetime_start")
    if not ended or "hardening_index" not in value:
        raise Undetermined("Lynis report is incomplete (no end time or hardening index)")
    when = datetime.strptime(ended, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    warnings = value.get("warnings", [])
    suggestions = value.get("suggestions", [])
    highlights = [
        f"Lynis {value.get('lynis_version', '?')} hardening index {value['hardening_index']}, "
        f"report from {ended} UTC",
        f"{len(warnings)} warning(s): {', '.join(warnings) or 'none'}",
        f"{len(suggestions)} suggestion(s)" + (f", e.g. {', '.join(suggestions[:8])}"
                                               if suggestions else ""),
    ]
    return {"_highlights": highlights, "suggestions": suggestions,
            "hardening_index": int(value["hardening_index"]),
            "report_age_days": round((ctx.now_ts - when.timestamp()) / 86400, 1),
            "report_time": ended, "lynis_version": value.get("lynis_version"),
            "warnings": value.get("warnings", []),
            "suggestion_count": len(value.get("suggestions", []))}


@collector("sysctl_proc", plan=[
    read("/proc/sys/<key>", "each key named in the control's params; sysctl is never called"),
])
def sysctl_proc(ctx: CollectContext) -> dict[str, Any]:
    out = {}
    for key in ctx.params.get("keys", []):
        value = ctx.text("/proc/sys/" + key.replace(".", "/"))
        if value is not None:
            out[key] = value.strip()
    return out


TIME_SERVICES = ["systemd-timesyncd", "chrony", "chronyd", "ntp", "ntpsec"]


@collector("time_sync", plan=[
    run("timedatectl", "show"),
    run("systemctl", "is-active", *TIME_SERVICES),
])
def time_sync(ctx: CollectContext) -> dict[str, Any]:
    show = ctx.parse("env_kv", ctx.cmd(["timedatectl", "show"]).stdout, "timedatectl show")
    res = ctx.cmd(["systemctl", "is-active", *TIME_SERVICES], ok=tuple(range(0, 5)))
    states = dict(zip(TIME_SERVICES, res.stdout.split(), strict=False))
    return {"ntp_synchronized": show.get("NTPSynchronized") == "yes",
            "ntp_enabled": show.get("NTP") == "yes",
            "services_active": [s for s, st in states.items() if st == "active"],
            "timezone": show.get("Timezone")}


@collector("mac_status", plan=[
    read("/sys/module/apparmor/parameters/enabled"),
    read("/sys/kernel/security/apparmor/profiles", "profile modes"),
    read("/sys/fs/selinux/enforce"),
])
def mac_status(ctx: CollectContext) -> dict[str, Any]:
    aa = (ctx.text("/sys/module/apparmor/parameters/enabled") or "").strip()
    if aa == "Y":
        profiles = ctx.text("/sys/kernel/security/apparmor/profiles")
        if profiles is None:
            raise Undetermined("AppArmor is enabled but its profile list is not readable")
        enforce = sum(1 for ln in profiles.splitlines() if ln.endswith("(enforce)"))
        complain = sum(1 for ln in profiles.splitlines() if ln.endswith("(complain)"))
        return {"mac": "apparmor", "enforcing": enforce > 0, "enforce_profiles": enforce,
                "complain_profiles": complain}
    se = ctx.text("/sys/fs/selinux/enforce")
    if se is not None:
        return {"mac": "selinux", "enforcing": se.strip() == "1"}
    return {"mac": "none", "enforcing": False}
