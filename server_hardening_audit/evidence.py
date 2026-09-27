"""Evidence layout and integrity manifest.

    <run>/evidence/<SCOPE>/index.json      every recorded call, in order
    <run>/evidence/<SCOPE>/<nn>-<name>     stdout / file content / JSON result
    <run>/MANIFEST.sha256                  sha256sum-compatible, over evidence/

The layout is exactly what ``audit --replay`` reads back. Empty command
output is still written: an empty file is the proof that a check found
nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .runner import Call

MANIFEST = "MANIFEST.sha256"


def _write(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def make_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)


def write_json(path: Path, obj: Any) -> None:
    _write(path, json.dumps(obj, indent=2, sort_keys=False, ensure_ascii=False) + "\n")


def write_text(path: Path, text: str) -> None:
    _write(path, text)


def write_scope(evidence_dir: Path, scope: str, calls: list[Call]) -> list[str]:
    """Write one scope's calls. Returns run-relative evidence paths."""
    d = evidence_dir / scope
    make_private_dir(d)
    index = []
    written = []
    for call in calls:
        fname: str | None = call.filename()
        if call.op in ("cmd", "read"):
            if call.op == "read" and call.content is None:
                fname = None
            else:
                write_text(d / fname, call.content or "")
        else:
            write_json(d / fname, call.result)
        if fname:
            written.append(f"evidence/{scope}/{fname}")
        index.append({"n": call.n, "op": call.op, **call.key, "file": fname,
                      "result": call.result})
    write_json(d / "index.json", {"scope": scope, "calls": index})
    # The index records every operation, including ones whose answer was
    # "does not exist" and so produced no file of their own.
    return [f"evidence/{scope}/index.json", *written] if calls else written


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(run_dir: Path) -> None:
    lines = []
    for path in sorted((run_dir / "evidence").rglob("*")):
        if path.is_file():
            rel = path.relative_to(run_dir).as_posix()
            lines.append(f"{sha256_file(path)}  {rel}")
    write_text(run_dir / MANIFEST, "\n".join(lines) + ("\n" if lines else ""))


def verify_manifest(run_dir: Path) -> list[str]:
    """Return a list of problems; empty means every listed file matches and
    no evidence file is unlisted."""
    problems = []
    listed = set()
    manifest = run_dir / MANIFEST
    if not manifest.exists():
        return [f"{MANIFEST} is missing"]
    for line in manifest.read_text().splitlines():
        digest, _, rel = line.partition("  ")
        listed.add(rel)
        path = run_dir / rel
        if not path.is_file():
            problems.append(f"missing: {rel}")
        elif sha256_file(path) != digest:
            problems.append(f"checksum mismatch: {rel}")
    for path in (run_dir / "evidence").rglob("*"):
        if path.is_file() and path.relative_to(run_dir).as_posix() not in listed:
            problems.append(f"not in manifest: {path.relative_to(run_dir).as_posix()}")
    return problems
