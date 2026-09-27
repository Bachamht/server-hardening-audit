"""Compare two runs: what changed between an audit and its re-run."""

from __future__ import annotations

from typing import Any

from .engine import VERDICT_ORDER

# Lower is worse; used to call a change an improvement or a regression.
_RANK = {"FAIL": 0, "UNKNOWN": 1, "MANUAL": 2, "NA": 3, "PASS": 4}


def _listeners(doc: dict[str, Any]) -> set[str] | None:
    f = next((x for x in doc["findings"] if x["id"] == "NET-02"), None)
    try:
        return set(f["details"]["assertion"]["non_loopback"])
    except (TypeError, KeyError):
        return None


def _lynis(doc: dict[str, Any]) -> int | None:
    f = next((x for x in doc["findings"] if x["id"] == "BAS-01"), None)
    try:
        return f["details"]["collected"]["lynis"]["hardening_index"]
    except (TypeError, KeyError):
        return None


def compare(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    fa = {f["id"]: f for f in a["findings"]}
    fb = {f["id"]: f for f in b["findings"]}
    changed = []
    for cid in sorted(set(fa) & set(fb)):
        va, vb = fa[cid]["verdict"], fb[cid]["verdict"]
        if va != vb or fa[cid]["basis"] != fb[cid]["basis"]:
            direction = ("improved" if _RANK[vb] > _RANK[va] else
                         "regressed" if _RANK[vb] < _RANK[va] else "changed")
            changed.append({"id": cid, "title": fb[cid]["title"],
                            "severity": fb[cid]["severity"], "before": va, "after": vb,
                            "direction": direction, "summary_after": fb[cid]["summary"]})
    changed.sort(key=lambda c: (c["direction"] != "regressed", VERDICT_ORDER[c["after"]],
                                c["id"]))
    la, lb = _listeners(a), _listeners(b)
    return {
        "run_a": a["run"]["id"], "run_b": b["run"]["id"],
        "changed": changed,
        "unchanged": len(set(fa) & set(fb)) - len(changed),
        "added": sorted(set(fb) - set(fa)), "removed": sorted(set(fa) - set(fb)),
        "listeners": None if la is None or lb is None else {
            "opened": sorted(lb - la), "closed": sorted(la - lb)},
        "lynis": {"before": _lynis(a), "after": _lynis(b)},
        "tool_versions": [a["tool"]["version"], b["tool"]["version"]],
        "controls_sha256": [a["run"]["controls_sha256"], b["run"]["controls_sha256"]],
    }


def render_markdown(d: dict[str, Any]) -> str:
    out = [f"# Audit diff: `{d['run_a']}` → `{d['run_b']}`\n"]
    w = out.append
    if d["controls_sha256"][0] != d["controls_sha256"][1]:
        w("> The two runs used different control definitions; some changes may come from "
          "the controls rather than the host.\n")
    reg = sum(1 for c in d["changed"] if c["direction"] == "regressed")
    imp = sum(1 for c in d["changed"] if c["direction"] == "improved")
    w(f"{imp} improved, {reg} regressed, {d['unchanged']} unchanged.\n")
    if d["changed"]:
        w("| Control | Severity | Before | After | Direction | Now |")
        w("|---|---|---|---|---|---|")
        for c in d["changed"]:
            now = c["summary_after"].replace("|", "\\|")
            w(f"| {c['id']} {c['title']} | {c['severity']} | {c['before']} | **{c['after']}** "
              f"| {c['direction']} | {now} |")
        w("")
    if d["added"] or d["removed"]:
        w(f"Controls added: {', '.join(d['added']) or 'none'}; "
          f"removed: {', '.join(d['removed']) or 'none'}.\n")
    ls = d["listeners"]
    if ls is None:
        w("Non-loopback listeners: not comparable (NET-02 missing or undetermined in a run).\n")
    elif ls["opened"] or ls["closed"]:
        w("Non-loopback listeners:\n")
        for x in ls["opened"]:
            w(f"- opened: {x}")
        for x in ls["closed"]:
            w(f"- closed: {x}")
        w("")
    else:
        w("Non-loopback listeners: unchanged.\n")
    ly = d["lynis"]
    if ly["before"] is not None or ly["after"] is not None:
        w(f"Lynis hardening index: {ly['before']} → {ly['after']}\n")
    return "\n".join(out)
