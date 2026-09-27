# server-hardening-audit

Read-only Linux server hardening audit that produces evidence-backed reports
mapped to the ASD Essential Eight and ISO/IEC 27001:2022.

It checks one host against a declarative list of controls, keeps the
evidence behind every verdict, and writes a report a person can read and a
`findings.json` a program can diff. What it cannot see from inside the host
— what the internet can reach, whether a backup restores — is resolved by
explicit, signed attestations, and the report keeps the two apart.

> **Only use this tool on systems you are authorised to test.**

## Quick start

Needs Python 3.10 or newer on the host. Nothing to install.

```bash
curl -LO https://github.com/Bachamht/server-hardening-audit/releases/latest/download/server-hardening-audit.pyz
python3 server-hardening-audit.pyz list            # every command and file it will touch
sudo python3 server-hardening-audit.pyz audit      # writes ./audit-runs/<timestamp>-<host>/
```

To build it yourself from a checkout instead: `python3 tools/build_pyz.py`
(it lands in `dist/`).

Give it a profile describing the host so it can tell intended exposure from
accidental exposure:

```bash
sudo python3 server-hardening-audit.pyz audit --profile my-host.toml
```

`profiles/single-vps-webhost.toml` is a starting point. A profile for a real
host names its domains and accounts — keep it private.

## What you get

```
audit-runs/20261012T051000Z-host-01/
  report.md          verdict summary, one section per control, and what the report does not cover
  findings.json      machine-readable findings (schema_version 1)
  evidence/<ID>/     the raw output behind every verdict, with an index of every operation
  MANIFEST.sha256    checksums of the evidence (sha256sum -c MANIFEST.sha256)
  run.json           tool version, control-file hash, profile, host fingerprint
```

Verdicts are `PASS`, `FAIL`, `NA` (does not apply here, with the reason),
`UNKNOWN` (should have been checkable but was not, with the reason) and
`MANUAL` (needs an operator procedure). Exit codes: 0 no FAIL, 1 FAIL,
2 critical FAIL, 3 tool error.

A sanitised report from a real production host is in [`examples/`](examples/).

Other commands:

| Command | Purpose |
|---|---|
| `report RUN --attest FILE` | Re-render a run with attestations and risk acceptances applied |
| `report RUN --framework essential-eight` | Essential Eight Maturity Level One view |
| `report RUN --framework iso27001-2022` | ISO/IEC 27001:2022 Annex A coverage view |
| `probe HOST` | From your own machine: ports per address family, SSH auth methods (no credentials offered), TLS |
| `diff RUN_A RUN_B` | What changed between two runs |
| `scrub RUN --map FILE --out DIR` | Publishable copy: placeholders, documentation IP ranges, refuses if anything leaks |
| `redact-check PATH` | Secret scanner for anything you are about to publish |
| `audit --replay RUN` | Re-evaluate saved evidence without touching any host |

## Security model

A tool that runs as root is its own biggest risk, so read-only is enforced
in code rather than promised:

- **Default-deny command allowlist.** Every command is matched against a
  per-program grammar of read-only invocations (`policy.py`). Anything
  else — an unknown program, subcommand, option or argument shape — is
  refused and reported as UNKNOWN. `systemctl restart`, `ufw allow`,
  `docker run`, `iptables -A`, `apt-get update` all fail the policy.
- **No shell.** Commands run as argument vectors from a fixed `PATH` with a
  minimal environment. There are no pipes, redirects or substitutions to
  inject into.
- **Default-deny file reads.** Raw reads are limited to an allowlist of
  configuration paths. Sensitive sources (`/etc/shadow`, `authorized_keys`,
  crontabs, Lynis reports, logs) are read only by named derivers that keep a
  derived summary — usernames with empty passwords, key types and comments,
  schedules — and never the content.
- **Controls are data.** A control file can name a parser, collector or
  assertion; it cannot contain code.

`list` prints everything the audit can do before you give it root. The
reasoning behind each of these decisions is in
[`docs/DESIGN.md`](docs/DESIGN.md).

## What it is and is not

It is a way to turn host checks into an **evidence-backed report that maps
to frameworks**, with the honest parts — not applicable, not assessed,
attested — kept visible.

It is not a replacement for existing scanners, and it works well next to
them:

- [Lynis](https://cisofy.com/lynis/) runs hundreds of hardening tests and
  produces a hardening index. This tool reads an existing Lynis report
  (BAS-01) instead of re-implementing it, and never runs Lynis itself
  because Lynis writes to `/var/log`.
- [OpenSCAP](https://www.open-scap.org/) evaluates hosts against SCAP
  content such as published benchmark profiles. If you need a benchmark
  compliance scan, use it; this tool's control set is small and opinionated.

Non-goals are listed at the end.

## Framework coverage, honestly

**ASD Essential Eight.** Only Maturity Level One is assessed; Levels Two and
Three are reported as not assessed. ASD scopes the Essential Eight to
organisations' networks, not single hosts:

> "The Essential Eight has been designed to protect organisations'
> internet-connected information technology networks."
> — *Essential Eight maturity model*, ASD, November 2023

So the view assesses only the requirements that apply to a single Linux
server, and says so at the top. Of the 48 Level One requirements, 22 do not
apply to a server (workstation application control, Office macros, browser
hardening), and most of the rest concern organisational processes that
cannot be observed from inside a host. Those are listed as **not
assessed** — separately from **not applicable** — rather than counted as
passes. Evidence that only partly covers a requirement can show it is not
met but never that it is. The view uses ASD's own assessment outcome terms
(Effective, Ineffective, No visibility, Not assessed, Not applicable).
Requirement IDs such as `PO-ML1-05` are assigned by this tool, not by ASD.

**ISO/IEC 27001:2022.** A subset of Annex A (mostly chapter 8, technological
controls) shows which checks provide host-level evidence for which control.
Control titles are copyrighted, so only numbers and this project's own
one-line summaries appear. A PASS means the host's configuration supports
the control; it is not a statement of conformity.

**CIS Benchmarks.** CIS mapping not provided. Benchmark item numbers change
between versions and cannot be verified without the specific benchmark
text. The control schema has a `refs.cis` field for anyone who can.

## Platform support

- **Debian and Ubuntu** (22.04, 24.04): all controls implemented.
- **RHEL family**: runs; controls that depend on apt/dpkg (PAT-01, PAT-02,
  DET-03) report UNKNOWN with the reason "no implementation for this
  platform in this version".
- Inside containers, controls owned by the platform (firewall, time sync,
  systemd services) report UNKNOWN or NA with their reasons rather than
  failing.

## Writing controls

Controls live in `controls/*.toml`: checks (commands, files, collectors), one
assertion, explanatory text and framework references. See
[`docs/WRITING-CONTROLS.md`](docs/WRITING-CONTROLS.md). Every control ships
with PASS and FAIL fixtures that are evaluated through `audit --replay`.

## Using it with an AI agent

`skills/server-hardening-audit/SKILL.md` teaches an agent to drive the tool:
scope the engagement, run `list` and `audit`, investigate UNKNOWNs instead of
guessing, guide the operator through restore drills and external probes,
write attestations, triage findings, and propose fixes grouped by blast
radius — never changing anything without approval.

For Claude Code, copy the skill directory into your skills folder:

```bash
mkdir -p ~/.claude/skills
cp -r skills/server-hardening-audit ~/.claude/skills/
```

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install pytest ruff
make check PYTHON=.venv/bin/python     # ruff, pytest, build the .pyz, redaction gate on examples/
make integration IMAGE=ubuntu:24.04    # full audit and probe inside a container (needs Docker)
```

Tests run offline: every control is evaluated from recorded evidence through
the same code path a live run uses. Do not run the integration target on a
production host.

## Non-goals

These are deliberate. They keep the tool small enough to trust with root.

- **No automatic remediation.** The tool never changes the host. It reports
  what is true and suggests fixes; applying them is a human decision.
- **No remote execution, resident agent, or central console.** It runs
  locally on the audited host, once, and exits.
- **Not a replacement for Lynis, OpenSCAP or CIS-CAT.**
- **No vulnerability scanning** (no CVE matching).
- **No organisational compliance maturity assessment.** It assesses the
  technical controls of a single host, not an organisation.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Vendored `tomli` is
MIT-licensed. Essential Eight text quoted in this repository is © Commonwealth
of Australia, used under CC BY 4.0.
