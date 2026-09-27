# Attestations and risk acceptances

Some facts cannot be observed from inside a host: what the internet can
reach, whether a backup actually restores, whether a copy exists on another
system. For these, an operator records a signed statement — an
**attestation** — and passes it to `report` or `scrub` with `--attest`.

Attested results are always marked as such. The report shows
`PASS · attested`, never a plain `PASS`, and `findings.json` records
`"basis": "attested"` together with the attestation itself.

## File format

TOML. A file may hold any number of `[[attestation]]` and
`[[risk_acceptance]]` entries.

```toml
[[attestation]]
control = "RES-02"                  # required: a control id in the run
verdict = "PASS"                    # required: PASS or FAIL
method = "Restored latest dump into a throwaway database; reconciled row counts per table."
performed_at = 2026-10-12T05:10:00Z # required: with a timezone
performed_by = "operator with AI agent"
evidence = ["restore/row-counts.txt", "restore/timing.txt"]  # optional
source = "operator"                 # optional; the probe writes "probe"
[attestation.measurements]          # optional: numbers you measured
restore_seconds = 130
dump_bytes = 39845888

[[risk_acceptance]]
control = "ACC-06"
reason = "Key-only SSH from a single admin device; FIDO2 keys planned."
accepted_by = "owner"
review_by = 2026-12-31
```

- `evidence` paths are relative to the attestation file. The report records
  each file's sha256, or flags it as missing. Evidence stays with the
  operator; it is not copied into the run directory.
- Unknown keys are rejected, so a typo cannot silently drop a field.

## How attestations change results

| Finding before | Attestation | Result |
|---|---|---|
| MANUAL or UNKNOWN | PASS | PASS · attested |
| MANUAL or UNKNOWN | FAIL | FAIL · attested |
| PASS (verified) | PASS | PASS, with the attestation listed as corroboration |
| PASS (verified) | FAIL | **FAIL · attested** — an external observation contradicting the host's own view wins (what the internet reaches beats what the configuration says) |
| FAIL (verified) | PASS | FAIL stands; the contradiction is reported as a warning |
| NA | any | unchanged; listed as corroboration |

Several attestations for one MANUAL control combine: any FAIL makes it FAIL.

The automated result that existed before the attestation is kept in
`details.automated_result`, so a reader can see what the host itself showed.

## Risk acceptance

A risk acceptance records that a FAIL is known and tolerated until a review
date.

- It applies only to FAIL findings; on anything else it is ignored with a
  warning.
- The verdict **stays FAIL**. The report shows
  `FAIL · risk accepted (review by 2026-12-31)`, and `REVIEW OVERDUE` once
  the date has passed.
- It does not change the exit code, and in the Essential Eight view the
  requirement stays Ineffective: ASD's assessment process guide does not
  allow risk acceptance to stand in for implementing a control.

## Where attestations come from

| Control | Typical source |
|---|---|
| NET-04 | `probe` from the operator's machine writes it (`probe-attestation.toml`) |
| NET-05 | `probe` (external view of the certificates); corroborates the in-host check |
| ACC-01 | `probe` (methods the SSH server advertises); corroborates the in-host check |
| RES-01 | operator, when the profile requires an off-host copy: list the copy on the other system |
| RES-02 | operator, after the restore drill described in the agent skill |

Any UNKNOWN control can also be resolved by an attestation when the operator
has verified the fact another way — say how in `method`.
