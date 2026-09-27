"""Build replayable run directories from compact TOML scenarios.

A scenario lists the operations a control performs and what the host
answered. This helper writes them in the exact evidence layout a live run
produces, so tests drive the real ``audit --replay`` path.

Call fields (all optional unless noted):
  op            cmd | read | derive | stat | glob | statvfs | tls   (required)
  cmd:     argv, stdout | stdout_file, replace=[[old,new],...], returncode, stderr,
           missing=true, error, error_kind
  read:    path, content | content_file, replace, missing=true, error, error_kind
  derive:  deriver, path, content | content_file (run through the real deriver) | value,
           missing=true, error, error_kind
  stat:    path, exists, kind, mode ("0644"), owner, group, size, age_hours, error, error_kind
  glob:    pattern, matches = [ {stat fields} ]
  statvfs: path, blocks, bavail, files, favail
  tls:     host, port, sni, verified, days_left, issuer, error, error_kind
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from server_hardening_audit import derive
from server_hardening_audit.loader import parse_toml

FIXTURES = Path(__file__).parent / "fixtures"
RAW = FIXTURES / "raw"
NOW = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)

OS_RELEASE = {
    "ubuntu-24.04": 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nNAME="Ubuntu"\nVERSION_ID="24.04"\n'
                    "ID=ubuntu\nID_LIKE=debian\n",
    "ubuntu-22.04": 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
                    "ID=ubuntu\nID_LIKE=debian\n",
    "debian-12": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nVERSION_ID="12"\nID=debian\n',
    "rocky-9": 'PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\nVERSION_ID="9.4"\nID="rocky"\n'
               'ID_LIKE="rhel centos fedora"\n',
    "alpine": 'PRETTY_NAME="Alpine Linux v3.20"\nID=alpine\nVERSION_ID=3.20.0\n',
}


def _text(call: dict[str, Any], inline: str, file_key: str) -> str | None:
    if inline in call:
        text = call[inline]
    elif file_key in call:
        text = (RAW / call[file_key]).read_text()
    else:
        return None
    for old, new in call.get("replace", []):
        assert old in text, f"replace target {old!r} not in fixture"
        text = text.replace(old, new)
    return text


def _err(call: dict[str, Any]) -> dict[str, Any]:
    if "error" in call:
        return {"error": call["error"], "error_kind": call.get("error_kind", "failed")}
    return {"error": None, "error_kind": None}


def _stat(s: dict[str, Any]) -> dict[str, Any]:
    exists = s.get("exists", True)
    mtime = (NOW - timedelta(hours=s.get("age_hours", 1))).timestamp() if exists else None
    return {
        "path": s["path"], "exists": exists, "kind": s.get("kind", "file") if exists else None,
        "mode": int(s.get("mode", "0644"), 8) if exists else None,
        "uid": 0 if exists else None, "gid": 0 if exists else None,
        "owner": s.get("owner", "root") if exists else None,
        "group": s.get("group", s.get("owner", "root")) if exists else None,
        "size": s.get("size", 1024) if exists else None, "mtime": mtime, **_err(s),
    }


def _entry(n: int, call: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    op = call["op"]
    fname: str | None = f"{n:02d}-{op}.txt" if op in ("cmd", "read") else f"{n:02d}-{op}.json"
    content = None
    if op == "cmd":
        key = {"argv": call["argv"]}
        if call.get("missing"):
            result = {"argv": call["argv"], "returncode": None, "stderr": "",
                      "error": f"{call['argv'][0]}: command not found", "error_kind": "missing"}
        else:
            result = {"argv": call["argv"], "returncode": call.get("returncode", 0),
                      "stderr": call.get("stderr", ""), **_err(call)}
        content = _text(call, "stdout", "stdout_file") or ""
    elif op == "read":
        key = {"path": call["path"]}
        content = _text(call, "content", "content_file")
        exists = not call.get("missing") and "error" not in call
        result = {"path": call["path"], "exists": exists, **_err(call)}
        if not exists:
            fname, content = None, None
    elif op == "derive":
        key = {"deriver": call["deriver"], "path": call["path"]}
        raw = _text(call, "content", "content_file")
        value = call.get("value")
        if raw is not None:
            value = derive.DERIVERS[call["deriver"]].fn(raw.encode())
        exists = not call.get("missing") and "error" not in call
        result = {"path": call["path"], "deriver": call["deriver"], "exists": exists,
                  "value": value if exists else None, **_err(call)}
    elif op == "stat":
        key = {"path": call["path"]}
        result = _stat(call)
    elif op == "glob":
        key = {"pattern": call["pattern"]}
        matches = [_stat(m) for m in call.get("matches", [])]
        result = {"pattern": call["pattern"], "matches": matches, "truncated": False,
                  **_err(call)}
    elif op == "statvfs":
        key = {"path": call["path"]}
        result = {"path": call["path"], "blocks": call.get("blocks"), "bavail": call.get("bavail"),
                  "files": call.get("files"), "favail": call.get("favail"), **_err(call)}
    elif op == "tls":
        key = {"host": call.get("host", "127.0.0.1"), "port": call.get("port", 443),
               "sni": call["sni"]}
        not_after = None
        if "days_left" in call:
            not_after = (NOW + timedelta(days=call["days_left"])).isoformat()
        result = {**key, "verified": call.get("verified", True), "not_after": not_after,
                  "subject_cn": call["sni"], "issuer_cn": call.get("issuer", "Test CA"),
                  **_err(call)}
    else:
        raise ValueError(f"unknown op {op}")
    return {"n": n, "op": op, **key, "file": fname, "result": result}, content


def _write_scope(evidence: Path, scope: str, calls: list[dict[str, Any]]) -> None:
    d = evidence / scope
    d.mkdir(parents=True, exist_ok=True)
    index = []
    for n, call in enumerate(calls, 1):
        entry, content = _entry(n, call)
        if entry["file"]:
            if call["op"] in ("cmd", "read"):
                (d / entry["file"]).write_text(content or "")
            else:
                (d / entry["file"]).write_text(json.dumps(entry["result"]))
        index.append(entry)
    (d / "index.json").write_text(json.dumps({"scope": scope, "calls": index}))


def host_calls(os_name: str) -> list[dict[str, Any]]:
    return [
        {"op": "read", "path": "/etc/os-release", "content": OS_RELEASE[os_name]},
        {"op": "cmd", "argv": ["systemd-detect-virt"], "stdout": "kvm\n"},
    ]


def to_toml(values: dict[str, Any]) -> str:
    def fmt(v: Any) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, str):
            return json.dumps(v)
        if isinstance(v, list):
            return "[" + ", ".join(fmt(x) for x in v) + "]"
        raise TypeError(type(v))
    return "".join(f"{k} = {fmt(v)}\n" for k, v in values.items())


def build_run(root: Path, scopes: dict[str, list[dict[str, Any]]],
              profile: dict[str, Any] | None = None, os_name: str = "ubuntu-24.04",
              euid: int = 0) -> Path:
    """Write a replayable run directory under ``root`` and return its path."""
    run_dir = root / "replay-src"
    evidence = run_dir / "evidence"
    _write_scope(evidence, "_host", host_calls(os_name))
    # The host op has no key; append it to the _host index by hand.
    idx_path = evidence / "_host" / "index.json"
    idx = json.loads(idx_path.read_text())
    n = len(idx["calls"]) + 1
    host_result = {"hostname": "testhost", "kernel": "Linux 6.8.0", "machine": "x86_64",
                   "euid": euid, "error": None, "error_kind": None}
    (evidence / "_host" / f"{n:02d}-host.json").write_text(json.dumps(host_result))
    idx["calls"].append({"n": n, "op": "host", "file": f"{n:02d}-host.json",
                         "result": host_result})
    idx_path.write_text(json.dumps(idx))
    for scope, calls in scopes.items():
        _write_scope(evidence, scope, calls)
    prof = {"name": "fixture", **(profile or {})}
    run = {
        "schema_version": "1", "id": "fixture-run", "mode": "live", "replay_of": None,
        "started_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": {}, "profile": {"name": prof["name"], "path": None, "source": to_toml(prof)},
        "controls": {"origin": "fixture", "sha256": "0" * 64, "selected": list(scopes)},
    }
    (run_dir / "run.json").write_text(json.dumps(run))
    return run_dir


def load_fixture(control_id: str) -> dict[str, Any]:
    """A control fixture file: optional [profile], [shared.<name>] call sets and
    [[scenario]] entries (name, expect, optional os, use, profile, call)."""
    return parse_toml((FIXTURES / "controls" / f"{control_id}.toml").read_bytes(), control_id)


def scenario_calls(doc: dict[str, Any], scenario: dict[str, Any]) -> tuple[
        list[dict[str, Any]], dict[str, Any]]:
    """Scenario calls first (they win on duplicate keys), then shared sets."""
    calls = list(scenario.get("call", []))
    for name in scenario.get("use", []):
        calls += doc["shared"][name]["call"]
    return calls, {**doc.get("profile", {}), **scenario.get("profile", {})}
