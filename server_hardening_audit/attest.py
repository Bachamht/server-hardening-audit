"""Attestations and risk acceptances.

An attestation is an operator's signed statement about something the host
cannot show from inside: a restore drill, an off-host backup copy, what the
internet can reach. It resolves a MANUAL (or UNKNOWN) finding, and the
result is marked ``basis = attested`` so it never reads as machine-verified.

Against a finding that is already machine-verified, an attestation can only
corroborate or make things worse: an external observation that contradicts
a verified PASS turns it into FAIL (what the internet can reach beats what
the configuration says); it can never turn a verified FAIL into PASS.

A risk acceptance records that a FAIL is known and tolerated until a review
date. The verdict stays FAIL.
"""

from __future__ import annotations

import copy
import datetime as dt
from pathlib import Path
from typing import Any

from .evidence import sha256_file
from .loader import ConfigError, parse_toml

ATTEST_KEYS = {"control", "verdict", "method", "performed_at", "performed_by", "evidence",
               "measurements", "source"}
RISK_KEYS = {"control", "reason", "accepted_by", "review_by"}
NOTE_KEYS = {"control", "text", "author"}


def _iso(value: Any, where: str) -> str:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            raise ConfigError(f"{where}: performed_at needs a timezone (e.g. ...Z)")
        return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ConfigError(f"{where}: performed_at is not ISO 8601") from exc
        return _iso(parsed, where)
    raise ConfigError(f"{where}: performed_at must be a datetime")


def _date(value: Any, where: str) -> str:
    if isinstance(value, dt.datetime):
        return value.date().isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value).isoformat()
        except ValueError as exc:
            raise ConfigError(f"{where}: review_by must be a date (YYYY-MM-DD)") from exc
    raise ConfigError(f"{where}: review_by must be a date")


def load(paths: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]],
                                    list[dict[str, Any]]]:
    """Return (attestations, risk acceptances + notes, file records).

    Notes ride along with risk acceptances (entries with a "text" key)."""
    attestations, risks, files = [], [], []
    for p in paths:
        path = Path(p)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ConfigError(str(exc)) from exc
        doc = parse_toml(data, p)
        extra = set(doc) - {"attestation", "risk_acceptance", "note"}
        if extra:
            raise ConfigError(f"{p}: unknown top-level key(s) {sorted(extra)}")
        files.append({"file": path.name, "sha256": sha256_file(path),
                      "attestations": len(doc.get("attestation", [])),
                      "risk_acceptances": len(doc.get("risk_acceptance", [])),
                      "notes": len(doc.get("note", []))})
        for i, raw in enumerate(doc.get("note", [])):
            where = f"{p} note[{i}]"
            if set(raw) - NOTE_KEYS or not {"control", "text", "author"} <= set(raw):
                raise ConfigError(f"{where}: needs exactly control, text and author")
            risks.append({"control": raw["control"], "text": " ".join(raw["text"].split()),
                          "author": raw["author"], "file": path.name})
        for i, raw in enumerate(doc.get("attestation", [])):
            where = f"{p} attestation[{i}]"
            extra = set(raw) - ATTEST_KEYS
            if extra:
                raise ConfigError(f"{where}: unknown key(s) {sorted(extra)}")
            for key in ("control", "verdict", "method", "performed_at", "performed_by"):
                if key not in raw:
                    raise ConfigError(f"{where}: {key} is required")
            if raw["verdict"] not in ("PASS", "FAIL"):
                raise ConfigError(f"{where}: verdict must be PASS or FAIL")
            evidence = []
            for rel in raw.get("evidence", []):
                target = (path.parent / rel)
                evidence.append({"path": rel, "sha256": sha256_file(target)
                                 if target.is_file() else None})
            attestations.append({
                "control": raw["control"], "verdict": raw["verdict"],
                "method": " ".join(str(raw["method"]).split()),
                "performed_at": _iso(raw["performed_at"], where),
                "performed_by": str(raw["performed_by"]), "evidence": evidence,
                "measurements": dict(raw.get("measurements", {})),
                "source": raw.get("source", "operator"), "file": path.name,
            })
        for i, raw in enumerate(doc.get("risk_acceptance", [])):
            where = f"{p} risk_acceptance[{i}]"
            extra = set(raw) - RISK_KEYS
            if extra:
                raise ConfigError(f"{where}: unknown key(s) {sorted(extra)}")
            missing = RISK_KEYS - set(raw)
            if missing:
                raise ConfigError(f"{where}: missing {sorted(missing)}")
            risks.append({"control": raw["control"], "reason": " ".join(raw["reason"].split()),
                          "accepted_by": raw["accepted_by"],
                          "review_by": _date(raw["review_by"], where), "file": path.name})
    return attestations, risks, files


def apply(doc: dict[str, Any], attestations: list[dict[str, Any]],
          risks: list[dict[str, Any]], files: list[dict[str, Any]],
          today: dt.date | None = None) -> tuple[dict[str, Any], list[str]]:
    """Return (a new findings document with attestations applied, warnings)."""
    today = today or dt.datetime.now(dt.timezone.utc).date()
    out = copy.deepcopy(doc)
    by_id = {f["id"]: f for f in out["findings"]}
    warnings: list[str] = []
    for a in attestations:
        f = by_id.get(a["control"])
        if f is None:
            raise ConfigError(f"attestation for {a['control']}, which is not in this run")
        for e in a["evidence"]:
            if e["sha256"] is None:
                warnings.append(f"{a['control']}: attestation evidence {e['path']} not found "
                                f"next to {a['file']}")
        record = {k: a[k] for k in ("verdict", "method", "performed_at", "performed_by",
                                    "evidence", "measurements", "source", "file")}
        if f["verdict"] in ("MANUAL", "UNKNOWN"):
            f.setdefault("details", {}).setdefault("attestations", []).append(record)
            prior = f.get("details", {}).get("automated_result")
            if prior is None:
                f["details"]["automated_result"] = {"verdict": f["verdict"],
                                                    "summary": f["summary"]}
            attested = [x["verdict"] for x in f["details"]["attestations"]]
            f["verdict"] = "FAIL" if "FAIL" in attested else "PASS"
            f["basis"] = "attested"
            f["summary"] = f"{f['verdict']} by attestation: {a['method']}"
            f.pop("instructions", None)
        else:
            f.setdefault("details", {}).setdefault("corroboration", []).append(
                {**record, "agrees": a["verdict"] == f["verdict"]})
            if f["verdict"] == "PASS" and a["verdict"] == "FAIL":
                f["details"]["automated_result"] = {"verdict": "PASS", "summary": f["summary"]}
                f["verdict"], f["basis"] = "FAIL", "attested"
                f["summary"] = (f"FAIL: external observation contradicts the verified PASS "
                                f"({a['method']})")
                warnings.append(f"{a['control']}: attestation contradicts a verified PASS; "
                                "verdict set to FAIL")
            elif f["verdict"] == "FAIL" and a["verdict"] == "PASS":
                warnings.append(f"{a['control']}: attestation says PASS but the verified "
                                "result is FAIL; the FAIL stands")
    for r in risks:
        f = by_id.get(r["control"])
        if f is None:
            raise ConfigError(f"entry for {r['control']}, which is not in this run")
        if "text" in r:  # an operator note: shown, never changes a verdict
            f.setdefault("details", {}).setdefault("notes", []).append(
                {"text": r["text"], "author": r["author"], "file": r["file"]})
            continue
        if f["verdict"] != "FAIL":
            warnings.append(f"{r['control']}: risk acceptance ignored; verdict is "
                            f"{f['verdict']}, not FAIL")
            continue
        f["risk_acceptance"] = {
            "reason": r["reason"], "accepted_by": r["accepted_by"],
            "review_by": r["review_by"],
            "expired": dt.date.fromisoformat(r["review_by"]) < today, "file": r["file"]}
    out["attestation_files"] = files
    return out, warnings
