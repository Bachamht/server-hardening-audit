"""Validate a run produced inside a CI container.

usage: check_run.py RUNS_PARENT EXIT_CODE [ID=VERDICT[|VERDICT...] ...]

Checks: exit code is 0/1/2, findings.json is structurally valid, MANIFEST
matches, no control hit a parse or internal error, and any given
expectations hold. Prints a verdict table for the CI log.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from server_hardening_audit import evidence, report  # noqa: E402


def main() -> int:
    parent, rc, *expectations = sys.argv[1:]
    runs = [p for p in Path(parent).iterdir() if p.is_dir()]
    assert len(runs) == 1, f"expected one run in {parent}, found {runs}"
    run_dir = runs[0]
    problems = []
    if int(rc) not in (0, 1, 2):
        problems.append(f"exit code {rc} (tool error)")
    doc = json.loads((run_dir / "findings.json").read_text())
    fails = [f for f in doc["findings"] if f["verdict"] == "FAIL"]
    want_rc = 2 if any(f["severity"] == "critical" for f in fails) else 1 if fails else 0
    if int(rc) != want_rc:
        problems.append(f"exit code {rc}, but the findings imply {want_rc}")
    problems += report.validate(doc)
    problems += evidence.verify_manifest(run_dir)
    verdicts, table = {}, []
    for f in doc["findings"]:
        verdicts[f["id"]] = f["verdict"]
        table.append(f"{f['id']:7} {f['verdict']:8} {f['summary'][:110]}")
        for bad in ("internal error", "could not parse", "no recorded result"):
            if bad in f["summary"]:
                problems.append(f"{f['id']}: {f['summary']}")
    for exp in expectations:
        cid, _, allowed = exp.partition("=")
        if verdicts.get(cid) not in allowed.split("|"):
            problems.append(f"{cid}: expected {allowed}, got {verdicts.get(cid)}")
    print("\n".join(table))
    # GitHub annotations: readable through the public checks API, unlike logs.
    label = Path(parent).name
    print(f"::notice title=verdicts {label} (rc={rc})::" + _escape("\n".join(table)))
    for p in problems:
        print(f"::error title=check_run {label}::{_escape(p)}")
    return 1 if problems else 0


def _escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


if __name__ == "__main__":
    sys.exit(main())
