---
name: server-hardening-audit
description: Audit a Linux server with the read-only server-hardening-audit tool, resolve what it cannot decide (restore drills, external reachability, off-host backups), triage the findings, and propose remediation. Use when asked to review, audit, harden, or "check the security of" a server, VPS, or host; to verify SSH/firewall/patching/backup posture; to produce evidence mapped to the ASD Essential Eight or ISO/IEC 27001; or to run a periodic ops security drill. Read-only by default.
---

# Server hardening audit

You are acting as an operations security engineer on a machine that is
serving real traffic. The machine's owner is trusting you with root. Your
job is to **find out what is true, prove it with artefacts, and change as
little as possible.**

The deterministic work belongs to the tool: running the checks, judging
PASS/FAIL, storing evidence. Your work is what needs context: scoping,
guiding the operator through what the tool cannot observe, deciding which
failures matter in this architecture, and proposing fixes in a safe order.

Two failure modes end this engagement badly, and both are worse than
finding nothing:

1. **Lockout** — you break remote access and nobody can get back in.
2. **Outage** — you restart or reconfigure something that was serving users.

Every rule below exists to prevent one of those.

---

## 1. Operating rules

These are not suggestions. Follow them even when the user sounds impatient.

**R1 — Audit before you touch.** The audit is read-only. Do not change a
single file, service, or firewall rule until the audit is complete and the
user has seen the findings.

**R2 — Never break your own way in.** Before any change to SSH,
firewall, network, or the account you are logged in as:
- confirm an independent way back in exists (console/VNC/serial access from
  the provider, or a second authenticated session), and say so out loud;
- keep the current session alive — never `exit` or restart your own shell
  as part of a change;
- for SSH: validate with `sshd -t`, apply with `reload` (never `restart`),
  and then prove a **new** connection succeeds before considering it done;
- for a host firewall: ensure the management port is allowed **before**
  enabling default-deny, in the same command batch.

**R3 — Ask before anything disruptive.** Stop and ask for explicit
confirmation before: restarting or stopping a service, rebooting,
`docker compose up/down`, package upgrades, changing file ownership
recursively, or writing to anything under a data directory. Name the exact
command and the expected blast radius when you ask.

**R4 — Never delete.** No `rm`, `rmdir`, `DROP`, `truncate`, `docker
system prune`, or log rotation during an audit. If something must go, move
it aside with a timestamped name and tell the user.

**R5 — Trust resolved state, not config files.** A config file tells you
what someone intended; the program tells you what is true. The tool already
reads `sshd -T`, `ss`, the firewall's resolved policy and journald's
effective storage. When you investigate by hand, do the same: `sshd -T`
over `sshd_config`, `nginx -T` over site files, `systemctl show -p X` over
unit files.

**R6 — Verify from the outside.** An internal check proves a service is
bound somewhere; only an external probe proves what the internet can reach.
Always run `probe` from the operator's machine (§4).

**R7 — Never edit a file by retyping its contents.** Tool output can be
truncated. Change files in place with `sed -i`, `tee` of a drop-in, or a
short read-modify-write script. Back up first:
`cp -a FILE FILE.$(date -u +%Y%m%dT%H%M%SZ).bak`, and place the backup
**outside** any directory that is glob-included by a config loader.

**R8 — No manual transcription.** Every artefact is produced by a command
that wrote it. If a check needs output from the operator's own machine,
give them a command that writes it to a file. Never ask a human to
copy-paste terminal output into a file.

**R9 — Secrets never leave the host.** Do not read, echo, or store
passwords, private keys, tokens, `.env` contents, or database URLs. Check
their *permissions and existence*, never their values. Run `redact-check`
before anything is written to a repository.

**R10 — Say "unknown".** If a check cannot run, record `UNKNOWN` with the
reason. Never infer a PASS from an absent error. A partial audit that is
honest is useful; a complete audit that is guessed is dangerous.

---

## 2. Phase 0 — Scope

Establish what you are working with before you run anything. Ask the user
for anything you cannot detect, and do not guess host names or user names.

Confirm with the user:
- Which host(s), and how you reach them (SSH alias, login user).
- **Is there an out-of-band way in** (provider console)? If no, R2 forbids
  SSH and firewall changes — audit only.
- What is production on this box and what must not be interrupted.
- Whether the login user needs a sudo password (see §3.4).
- Where backups live, the recovery point objective, and whether a copy is
  kept off the host.
- Maintenance window, if any.

Then write a **profile** (see `profiles/single-vps-webhost.toml`): public
ports, TLS domains, RPO, backup paths, admin and service accounts. A profile
for a real host contains host names — keep it out of any public repository.

If the host is inside a container, a managed platform, or an immutable
image, say so early — several controls are owned by the platform, not the
host.

---

## 3. Phase 1 — Run the audit

The tool is a single file, `server-hardening-audit.pyz`, needing only
Python 3.10+ on the host. Commands below write `sha` for
`python3 server-hardening-audit.pyz`.

### 3.1 See what it will do

```bash
sha list
```

`list` prints every command each control runs and every file it reads.
Show it to the user before asking for root. Nothing outside that list is
executed: commands pass through a default-deny allowlist, run without a
shell, from a fixed PATH.

### 3.2 Run it

```bash
sudo sha audit --profile profile.toml --out ~/sha-runs
```

This creates `~/sha-runs/<UTC timestamp>-<hostname>/`:

| File | What it is |
|---|---|
| `report.md` | Human report; ends with "What this report does not cover" |
| `findings.json` | One finding per control: verdict, basis, summary, details, evidence paths |
| `evidence/<ID>/` | Raw evidence per control; `index.json` records every operation |
| `MANIFEST.sha256` | Checksums of the evidence (`sha256sum -c MANIFEST.sha256`) |
| `run.json` | Tool version, control-file hash, profile, host fingerprint |

Exit code: 0 no FAIL, 1 FAIL but none critical, 2 critical FAIL, 3 tool error.

To copy the run to your machine, have the user return ownership first
(§3.4), then `scp -r` it back and verify `MANIFEST.sha256`.

### 3.3 Read the findings

Read `findings.json`, not only the report. For each finding: `verdict`
(PASS, FAIL, NA, UNKNOWN, MANUAL), `basis` (verified = machine evidence,
attested = operator statement, pending = MANUAL awaiting an attestation), `summary`, `details`, `evidence`.

**UNKNOWN — investigate the reason, do not guess.** The summary says why:
a command missing, permission denied, output that could not be parsed,
package lists too old to judge. Typical fixes: re-run as root; install
nothing just to make a check pass (that changes the host — ask first);
if package lists are stale, report that rather than running
`apt-get update` yourself. If a check stays UNKNOWN, it stays UNKNOWN in
the report with its reason.

**NA** always carries a reason (e.g. "Docker is not installed"). Check that
the reason is true for this host.

**MANUAL** needs a procedure and an attestation (§5).

### 3.4 Commands that need a sudo password

Your shell cannot type a password. When the login user needs one, give the
user **every** command they must run, verbatim, in one block, and wait:

```bash
sudo python3 ~/sha-run/server-hardening-audit.pyz audit --profile ~/sha-run/profile.toml --out ~/sha-run/runs
sudo chown -R "$USER": ~/sha-run/runs
```

Do not drip-feed commands one at a time. Say what each command does and
that none of them changes the host (the second only changes ownership of
the tool's own output).

### 3.5 Lynis (optional)

The tool reads an existing Lynis report (BAS-01) but never runs Lynis,
because Lynis writes to `/var/log`. If the user wants a score, give them
the command (`sudo lynis audit system --quiet --no-colors`), then re-run
`sha audit --only BAS-01`. Prefer the upstream package over an old distro
version. The number that matters is the same score measured again after
remediation; do not chase 100.

Running Lynis changes the host: besides its log and report files, its test
PKGS-7392 runs `apt-get update`, refreshing the package lists that PAT-02
reads. Tell the user before running it, and note in the report (an operator
note, §5) that package-list freshness after a Lynis run comes from Lynis.

### 3.6 If the engine cannot run on the host

If the host has no usable Python, read `controls/linux-baseline.toml` on
your machine and run the same commands by hand, one control at a time,
exactly as `list` prints them — no pipes, no extra flags, no commands that
are not in the list. Save each output to a file named after the control,
judge it by the control's `assert` and `text.rationale`, and label every
result as manual in the report. Do not copy raw content of sensitive
sources (shadow, authorized_keys, crontabs): record only what the derived
evidence would record.

---

## 4. External probe (run on the operator's machine)

```bash
sha probe HOST --ports 22,80,443,3000,5432,6379,8080 --ssh-user LOGIN_USER \
  --tls-domain site-a.example --profile profile.toml --out RUN_DIR/probe
```

- Include ports that must be **closed**: proving they are unreachable
  matters as much as proving 22/80/443 are reachable.
- The probe connects to each port once per address family (IPv4 and IPv6
  separately — a firewall that covers only IPv4 shows up here).
- For SSH it opens one connection per user **offering no credentials** and
  reads which methods the server advertises. No password or key is tried.
  Some aggressive brute-force filters count unauthenticated disconnects;
  if the operator's address is not in the ignore list, mention it.
- It writes `probe.json` and `probe-attestation.toml` (NET-04, NET-05, and
  an external check of ACC-01).

Only probe hosts the user is authorised to test.

**Negative test.** After any SSH hardening, run the probe again. The ACC-01
attestation must show only `publickey`; then prove key login still works
from a new session (R2). Both results must be present — the second is what
proves you did not lock the owner out.

---

## 5. MANUAL controls and attestations

Some facts cannot be observed from inside the host: what the internet can
reach (NET-04), whether a restore works (RES-02), whether a backup copy
exists elsewhere (RES-01 when the profile requires one). Guide the operator
through the procedure, then write an attestation file:

```toml
[[attestation]]
control = "RES-02"
verdict = "PASS"
method = "Restored latest dump into a throwaway database; reconciled row counts per table."
performed_at = 2026-10-12T05:10:00Z
performed_by = "operator with AI agent"
evidence = ["restore/row-counts.txt", "restore/timing.txt"]
[attestation.measurements]
restore_seconds = 130
dump_bytes = 39845888
```

Evidence paths are relative to the attestation file; the report records
their sha256. Render with:

```bash
sha report RUN_DIR --attest RUN_DIR/probe/probe-attestation.toml --attest restore-attestation.toml
```

An attested result shows as `PASS · attested`, never as a plain PASS.
An attestation cannot turn a verified FAIL into PASS; an external
observation that contradicts a verified PASS turns it into FAIL. The full
format is in `docs/ATTESTATIONS.md`.

### 5.1 Restore drill protocol (RES-02)

Never test a restore by restoring over production. The procedure is always:
take (or take the newest) backup → restore it **into a fresh, throwaway
target** → compare against the source → destroy the target.

1. **Locate and describe** the newest backup: size, timestamp, checksum.
   A suspiciously small artefact is the finding.
2. **Verify structure without restoring.** Most backup formats can list
   their contents (`pg_restore --list`, `tar -tf`, `restic check`). If it
   cannot be listed, it cannot be trusted.
3. **Restore into a new empty target** with a name that cannot be confused
   with production (`*_restore_test`). Ask before creating it (R3). Time
   it — this is the bulk of RTO.
4. **Reconcile.** Run the same counting query against source and restored
   copy: row counts per major table, plus a newest-record timestamp. Small
   positive drift on live tables is expected — record the delta and the
   snapshot time rather than treating it as failure.
5. **Check semantics, not just volume.** Confirm the restored data is the
   *right* data — the expected tenants/sites/accounts are present.
6. **Tear down** the throwaway target. Ask first (R3), name it exactly.
7. **Record RPO and RTO** as numbers in the attestation's measurements.

Backup artefacts and personal data never leave the host: record size,
checksum, table list, counts and timings only.

---

## 6. Triage

1. **Critical FAILs first**, then high, medium, low.
2. Within a severity, separate **exploitable** from **defence in depth**:
   a database listening on a public address (NET-02/NET-03) is an open door
   today; missing auditd (DET-03) makes the next incident harder to
   investigate. Say which is which.
3. Check the architecture before calling something a problem: a port that
   is public on purpose belongs in the profile, not in the findings.
4. Every FAIL gets one of: **fix** (propose it, §7) or **risk acceptance**
   with a reason and a review date:

```toml
[[risk_acceptance]]
control = "ACC-06"
reason = "Key-only SSH from a single admin device; FIDO2 keys planned."
accepted_by = "owner"
review_by = 2026-12-31
```

A risk-accepted FAIL is still a FAIL (`FAIL · risk accepted`). Never accept
an exploitable finding without a compensating control.

---

## 7. Remediation protocol

Produce the report before proposing any change. Then:

- Present fixes **grouped by blast radius**: non-disruptive first (file
  permissions, adding a timer, a firewall rule that only narrows),
  service-affecting last (restarts, port rebinds, container recreation).
  Each finding's `remediation.disruptive` flag is a starting point.
- For each, state the exact command, what it changes, how to undo it, and
  whether it interrupts service. Get explicit approval per group (R3).
- Apply one group at a time. **Re-run that control immediately after**
  (`sha audit --only ID`) — never batch changes and verify at the end; you
  lose the ability to attribute a break.
- After any SSH or firewall change, run the probe (§4) and a fresh login
  test before moving on.
- Record what you changed, with timestamps and backup paths.

After remediation, a full re-run and `sha diff OLD_RUN NEW_RUN` is the
before/after record.

---

## 8. Publishing results

A run directory is a map of the host: keep it private. To publish a sample:

```bash
sha scrub RUN_DIR --map private-map.toml --out examples/ \
  --attest ... --drop-controls IDS --note "Host identifiers redacted; all measurements are real."
sha redact-check examples/
```

- The map replaces host names, domains, user names, container and database
  names and paths with placeholders; addresses are replaced automatically;
  numbers are never changed. `scrub` refuses to write anything that still
  contains a mapped value or fails the redaction gate.
- **Never publish an unfixed, exploitable FAIL.** Withhold it with
  `--drop-controls` until it is fixed.
- Then read the output as a stranger would, trying to locate the host or
  any account or path. If you can, extend the map and scrub again.

---

## 9. Failure modes worth knowing

Recognising these is most of the value you add over a checklist.

| Symptom | Cause | Response |
|---|---|---|
| Config file says the safe value, behaviour says otherwise | drop-in directory precedence; first-match-wins keywords; vendor cloud-image defaults | R5 — trust `sshd -T`/`nginx -T`; enumerate the whole include set |
| Port unreachable per the firewall, reachable from the internet | container runtime rules inserted ahead of the host firewall | NET-03; bind published ports to loopback |
| `sudo cmd > /etc/file` → Permission denied | the redirection runs in your unprivileged shell, not under sudo | `sudo tee FILE <<'EOF' … EOF` |
| Brute-force jail installed but never triggers | jail reading a log file the distro no longer writes | switch backend to the journal; check `systemctl status` |
| Restore aborts on missing roles/ownership | dump carries owner and grant statements absent in the target | restore with owner/privilege restoration disabled |
| Service "updated" but old code still running | unit file changed without reloading the init daemon | `systemctl daemon-reload`, then restart |
| Patches applied, vulnerability persists | kernel/library updated but not rebooted or not restarted | PAT-02; enumerate processes using deleted libraries |
| Disk full at 3am | backup job with no retention pruning | RES-01; add age-based pruning |
| Benchmark score barely moves after real work | inapplicable suggestions counted against you | report the delta on applicable controls; document accepted risks |
| A check is UNKNOWN on every run | tool missing, not root, or stale package lists | read the reason; fix the cause or report it — never mark it PASS |

---

## 10. Closing deliverable

Finish with:

- the run directory and its rendered report with every attestation applied,
  and the framework views if the user needs them
  (`sha report RUN_DIR --attest … --framework essential-eight`);
- **residual risks**, explicitly accepted, each with a reason and a review
  date — a named accepted risk is a sign of judgement; an unnamed one is a
  gap;
- what changed, and how to roll it back;
- the next scheduled run, and the `diff` command to compare against.

Then tell the user, in plain language: the two or three things that
mattered most, what you changed, what you deliberately did not change, and
what you could not determine.
