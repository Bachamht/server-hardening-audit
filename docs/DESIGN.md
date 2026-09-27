# Design

This document records the decisions behind server-hardening-audit and why
they were made. The short version: a security tool that runs as root must
be the most constrained program on the machine, and a report that claims
something must show where the claim came from.

## Layers: what the engine decides, and what it leaves to people

```
controls/*.toml     what to check, how to judge it, which framework clauses it evidences
frameworks/*.toml   clauses, their applicability to a Linux server, sources
profiles/*.toml     what this host is supposed to look like (public ports, RPO, admins)
        │
engine              run (read-only, allowlisted, no shell) → parse → judge → store evidence
        │
audit-runs/<run>/   findings.json · report.md · evidence/ · MANIFEST.sha256
        │
skills/…/SKILL.md   agent: scoping, manual procedures, triage, remediation proposals
```

**Deterministic work belongs to the engine**: running commands, parsing
their output, deciding PASS or FAIL against a stated rule, keeping the
evidence. The same input always produces the same verdict, and a replay of
saved evidence reproduces it exactly.

**Judgement belongs to people and the agent**: which FAIL is acceptable in
this architecture, what to fix first, whether a restore drill proved
anything, whether a risk is worth accepting. Those decisions enter the
record as attestations and risk acceptances, marked as such.

## Read-only, enforced in code

### A default-deny command allowlist

`policy.py` holds, for each allowed program, the exact argument grammars it
may be called with: fixed subcommands, allowed options and the shape of
their values, the shape and number of positional arguments. Anything that
does not match — an unknown program, an unknown subcommand, an option not
listed, a positional starting with `-`, a `--` terminator, a path in
`argv[0]` — is refused. A refusal is not an error that stops the run: the
control reports UNKNOWN with the reason, and the refusal is recorded as
evidence.

This is the same principle the tool audits in firewalls: deny by default,
allow the minimum, and make every allowance explicit and reviewable. A
denylist of dangerous verbs would be the ufw-with-default-allow of command
policies — one forgotten verb away from failure.

The allowlist is tested both ways: every command a control or collector
can issue passes it, and a long list of state-changing invocations
(`systemctl restart`, `ufw allow`, `docker compose up`, `iptables -A`,
`journalctl --vacuum-time`, `sudo rm`, …) is refused.

### No shell

Commands run as argument vectors with `shell=False`, resolved against a
fixed `PATH`, with a minimal environment (`LC_ALL=C.UTF-8`, no pager, no
colour, nothing inherited such as `DOCKER_HOST`). Where the manual procedure
would use a pipe (`ss -tlnp | grep …`), the engine runs one command and
does the filtering in Python. This removes shell injection as a class and
makes the allowlist precise: what is matched is exactly what runs.

Before running a resolved program, the runner also checks that the binary
and its directory are owned by root and not writable by group or others. A
program that another account could have replaced is not run (UNKNOWN, with
the reason): an allowlisted name is only as trustworthy as the file behind
it.

### Default-deny reads, and derived evidence for sensitive sources

Raw file reads copy content into the evidence pack, so they are limited to
an allowlist of configuration paths as well. Sensitive or bulky sources are
reachable only through **derivers**: named functions bound to specific
paths that run inside the runner and return a summary. Only the summary is
stored.

| Source | What is kept |
|---|---|
| `/etc/shadow` | usernames whose password field is empty; hashes never leave the function |
| `authorized_keys` | per key: type, comment, option names, RSA size; never the key body or option values |
| crontabs | schedule and two flags (backup-related, pruning); command text can embed credentials |
| Lynis report | score, dates, warning IDs; the report's host inventory is dropped |
| fail2ban log | ban counts per jail per day; no addresses |
| unattended-upgrades log | run and upgrade timestamps |
| `.env`, private keys, database URLs | never read |

A replayed run serves the recorded summary, so every step downstream of a
deriver is replayable without the source.

TLS checks connect only to loopback; the external view is the job of
`probe`, which runs on the operator's machine.

### Commands the tool deliberately does not run

| Not run | Why | Instead |
|---|---|---|
| `apt-get update` | rewrites `/var/lib/apt/lists` | reads the existing lists and reports their age; older than the profile allows → the backlog is UNKNOWN, not guessed |
| `unattended-upgrade --dry-run` | writes logs and takes the apt lock | reads the configuration, timers, the periodic stamp and the log |
| `lynis audit system` | writes `/var/log/lynis*` | reads an existing report (BAS-01); running Lynis is an operator action |
| `sysctl` | a tool that can also write | reads `/proc/sys/…` directly |
| `openssl s_client` | a general-purpose network client | the standard library `ssl` module, loopback only |

## Controls cannot contain code

A control file names a parser, a collector and an assertion operator; the
loader rejects any name not registered in the engine and any key the schema
does not define. Parameters from the profile reach operators as structured
values (`{ param = "profile.public_ports" }`), never by string templating.
Loading a control file therefore cannot make anyone execute anything — the
worst a hostile control file can do is ask for a command the allowlist
refuses.

Multi-step checks (enumerate containers, then inspect them) are
**collectors**: trusted engine code that declares every operation it may
perform. `list` prints those declarations, and the policy tests check them.

## Verdicts, and never inferring PASS from silence

| Verdict | Meaning |
|---|---|
| PASS | the check ran and the result meets the rule |
| FAIL | the check ran and the result does not |
| NA | the control does not apply here — always with the reason |
| UNKNOWN | it applies but could not be checked — always with the reason |
| MANUAL | inherently needs a person; resolved by an attestation |

A missing command, a permission error, unparseable output or stale package
lists are UNKNOWN. An empty output is evidence (the file is kept), but it is
only a PASS when the rule says emptiness is the goal — "no listener outside
the declared ports", not "nothing went wrong".

### Verified and attested

Every finding has a basis: `verified` (machine-collected evidence),
`attested` (an operator's statement), or `pending` (a MANUAL finding still
waiting for its attestation — nothing has been claimed yet). The report shows `PASS · attested`
differently from `PASS`. An attestation resolves MANUAL and UNKNOWN
findings. It cannot turn a verified FAIL into PASS; an external observation
that contradicts a verified PASS turns it into FAIL. A risk acceptance
never changes a FAIL.

## Not applicable is not the same as not assessed

In framework views, a clause that does not apply to a Linux server (Office
macros) is **NOT APPLICABLE**. A clause that applies but has no evidence in
this run (vulnerability scanning cadence) is **NOT ASSESSED**. They are
listed in separate sections. Merging them is the most common way tools like
this overstate their coverage.

Two further rules keep the views honest:

- Evidence that covers only part of a clause (`coverage = "partial"`) can
  show the clause is not met, but a PASS leaves it NOT ASSESSED with the
  evidence listed.
- A control withheld from a published copy shows as withheld, not as not
  assessed.

The Essential Eight view follows ASD's assessment process guide: its outcome
terms, and its rule that a mitigation strategy meets a maturity level only if
every applicable requirement is effective.

## Replay

`audit --replay RUN` evaluates the evidence of a previous run instead of the
live host. The runner records every operation with its arguments and result
in `evidence/<ID>/index.json`; the replay runner serves those results back
after applying the same policy checks, and evaluates them against the
original run's timestamp so age-based rules give the same answer.

This gives three things:

- the whole engine is testable without root or a real host — every
  control's PASS and FAIL fixtures run through the same code path as a live
  audit;
- a report can be regenerated after the report format changes, from the
  original evidence, without touching the host again;
- a third party can re-derive the verdicts from the evidence pack.

## Zero dependencies and a single .pyz

The tool runs on hosts where installing packages is itself a change to be
audited. It uses only the Python standard library (TOML parsing on 3.10
comes from a vendored copy of `tomli`, MIT-licensed) and ships as one
`zipapp` file with the controls, frameworks and profiles inside. The costs:
no YAML, no rich CLI libraries, a hand-written JSON structure check instead
of jsonschema, and a small TOML writer for the attestations `probe` emits.
Python 3.10 is the floor because it is what Ubuntu 22.04 ships.

## Publishing results

A run directory is a map of the host and stays private. `scrub` produces a
publishable copy: a private map file replaces names with placeholders
(consistently, so the report still reads), addresses become documentation
addresses, numbers are never changed, and controls describing unfixed
exploitable issues can be withheld. It refuses to write anything if the
redaction gate finds a secret or any mapped original value or replaced
address survives.

## Quality gate

There is no hosted CI. `make check` runs ruff, the test suite, builds the
`.pyz` and runs it, and applies the redaction gate to `examples/`; it runs
before every commit. `make integration` runs a full audit and probe inside
Ubuntu containers on a machine where that is safe.
