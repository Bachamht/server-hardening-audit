---
name: server-hardening-audit
description: Audit and harden a Linux server against a fixed control catalogue, produce a reproducible evidence pack, and optionally drill backup restore. Use when asked to review, audit, harden, or "check the security of" a server, VPS, or host; to verify SSH/firewall/patching/backup posture; to produce a hardening checklist or evidence for a report; or to run a periodic ops security drill. Read-only by default.
---

# Server hardening audit

You are acting as an operations security engineer on a machine that is
serving real traffic. The machine's owner is trusting you with root. Your
job is to **find out what is true, prove it with artefacts, and change as
little as possible.**

Two failure modes end this engagement badly, and both are worse than
finding nothing:

1. **Lockout** — you break remote access and nobody can get back in.
2. **Outage** — you restart or reconfigure something that was serving users.

Every rule below exists to prevent one of those.

---

## 1. Operating rules

These are not suggestions. Follow them even when the user sounds impatient.

**R1 — Audit before you touch.** Phase 1 is read-only. Do not change a
single file, service, or firewall rule until the audit is complete and the
user has seen the findings.

**R2 — Never break your own way in.** Before any change to SSH,
firewall, network, or the account you are logged in as:
- confirm an independent way back in exists (console/VNC/serial access from
  the provider, or a second authenticated session), and say so out loud;
- keep the current session alive — never `exit` or restart your own shell
  as part of a change;
- for SSH: validate with `sshd -t`, apply with `reload` (never `restart`),
  and then prove a **new** connection succeeds before considering it done.
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
what someone intended; the program tells you what is true. Always prefer:
`sshd -T` over `/etc/ssh/sshd_config`, `nginx -T` over site files,
`ss -tlnp` over "what should be listening", `systemctl show -p X` over unit
files, `iptables -S` over the firewall front-end alone. Layered
config directories, drop-ins, and precedence rules are the single most
common source of false "we're fine" conclusions.

**R6 — Verify from the outside.** An internal check proves a service is
bound somewhere; only an external probe proves what the internet can reach.
Whenever the user can run a command from another host, have them do the
external check, or run it yourself from a different network location.

**R7 — Never edit a file by retyping its contents.** Tool output can be
truncated. Change files in place with `sed -i`, `tee` of a drop-in, or a
short read-modify-write script. Back up first:
`cp -a FILE FILE.$(date -u +%Y%m%dT%H%M%SZ).bak`, and place the backup
**outside** any directory that is glob-included by a config loader.

**R8 — No manual transcription.** Every artefact in the evidence pack is
produced by a command that wrote it. If a check needs output from the
operator's own machine, give them a script that captures it to a file.
Never ask a human to copy-paste terminal output into a file.

**R9 — Secrets never leave the host.** Do not read, echo, or store
passwords, private keys, tokens, `.env` contents, or database URLs. Check
their *permissions and existence*, never their values. Run the redaction
gate (§6) before anything is written to a repo.

**R10 — Say "unknown".** If a check cannot run, record `UNKNOWN` with the
reason. Never infer a PASS from an absent error. A partial audit that is
honest is useful; a complete audit that is guessed is dangerous.

---

## 2. Phase 0 — Scope and fingerprint

Establish what you are working with before you check anything. Ask the user
for anything you cannot detect.

Confirm with the user:
- Which host(s), and how you reach them.
- **Is there an out-of-band way in** (provider console)? If no, R2 forbids
  SSH and firewall changes — audit only.
- What is production on this box and what must not be interrupted.
- Maintenance window, if any.
- Where the evidence pack should be written.

Then fingerprint the host (read-only, safe anywhere):

```bash
{ date -u; hostname; uname -srm; cat /etc/os-release | head -3; uptime; } 2>/dev/null
command -v systemctl apt dnf yum ufw firewall-cmd nft iptables docker podman fail2ban-client lynis 2>/dev/null
systemd-detect-virt 2>/dev/null; df -h / /var 2>/dev/null
```

Adapt every later command from this fingerprint:

| Dimension | Variants you must handle |
|---|---|
| Package manager | `apt` (Debian/Ubuntu) · `dnf`/`yum` (RHEL family) · `zypper` · `apk` |
| Auto-patching | `unattended-upgrades` · `dnf-automatic` · `zypper-automatic` |
| Firewall | `ufw` · `firewalld` · raw `nftables`/`iptables` · **cloud-provider security group** (may be the real perimeter — ask) |
| Logging | `/var/log/auth.log` (Debian) · `/var/log/secure` (RHEL) · journald only (newer Ubuntu/Fedora) |
| Brute-force defence | `fail2ban` · `sshguard` · `CrowdSec` · provider-level |
| Containers | `docker` · `podman` · `k8s` — changes who owns ports and users |
| Init | `systemd` assumed; on others, translate or mark UNKNOWN |

If the host is inside a container, a managed platform, or an immutable
image, say so early — several controls below are owned by the platform, not
the host, and should be marked `N/A (platform-owned)` rather than FAIL.

---

## 3. Phase 1 — The control catalogue (read-only)

Run these. For each, record: the command, its raw output as an artefact,
and a verdict of `PASS` / `FAIL` / `N/A` / `UNKNOWN`.

Severity is what to use when ranking findings: **CRIT** = likely remote
compromise path, fix today. **HIGH** = meaningful exposure or no recovery
path. **MED** = weakens defence in depth. **LOW** = hygiene.

### ACCESS — who can get in

**ACC-01 · Remote login uses keys, not passwords** — CRIT
```bash
sshd -T 2>/dev/null | grep -iE '^(passwordauthentication|permitrootlogin|pubkeyauthentication|kbdinteractiveauthentication|challengeresponseauthentication|permitemptypasswords|maxauthtries|port|allowusers|allowgroups|x11forwarding)\b'
grep -n '^Include' /etc/ssh/sshd_config
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null
grep -rniE 'PasswordAuthentication|PermitRootLogin' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
```
PASS: `passwordauthentication no`, `permitrootlogin no` (or
`prohibit-password` with a stated reason), `kbdinteractiveauthentication no`,
`permitemptypasswords no`.

Note the `Include` glob pattern before you judge the drop-in directory:
only files matching that glob are loaded, and **first match wins** for a
given keyword — a low-numbered drop-in overrides the main file, and a
renamed backup (`*.bak`) is inert. Cloud images commonly ship a
vendor drop-in that re-enables password login; never conclude from the main
file alone (R5).

**ACC-02 · Key material hygiene** — HIGH
```bash
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] && { echo "== $f"; ls -l "$f"; awk '{print $1, $NF}' "$f"; }
done 2>/dev/null
```
Record key **types and comments only, never the key body**. PASS: every key
is attributable to a person or system the owner recognises; files are `600`;
no `authorized_keys2`; no unexpected `command=`/`from=` entries; prefer
ed25519 or RSA ≥ 3072.

**ACC-03 · Service accounts are unprivileged** — HIGH
```bash
awk -F: '$3>=1000 && $1!="nobody"{print $1":"$3":"$7}' /etc/passwd
getent group sudo wheel adm docker lxd 2>/dev/null
grep -rhv '^\s*#' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^\s*$'
ps -eo user,pid,comm --sort=user | awk '$1=="root"' | head -40
systemctl show -p User,Group,DynamicUser $(systemctl list-units --type=service --state=running --no-legend | awk '{print $1}') 2>/dev/null | paste - - - | grep -v 'User=$' 
```
PASS: the account running each application is not in `sudo`/`wheel`/`docker`
(**membership in the container group is equivalent to root** — a user who can
run containers can mount the host filesystem), no `NOPASSWD: ALL` for
application accounts, and no application process running as root. Privileged
system daemons (init, sshd, the web server's master process binding
privileged ports) are expected root and are not findings.

**ACC-04 · No stale or passwordless accounts** — MED
```bash
awk -F: '($2==""){print "EMPTY PASSWORD: "$1}' /etc/shadow 2>/dev/null
lastlog 2>/dev/null | awk 'NR==1 || !/Never logged in/' | head -20
```

### NETWORK — what the internet can reach

**NET-01 · Firewall default-deny with a minimal allow-list** — CRIT
```bash
ufw status verbose 2>/dev/null || firewall-cmd --list-all 2>/dev/null || nft list ruleset 2>/dev/null || iptables -S
```
PASS: inbound default is deny/drop; the allow-list contains only ports with
a named owner; **IPv6 is covered too** (a v4-only ruleset with a
v6-listening service is a silent hole). If a cloud security group is the
real perimeter, audit that instead and say so.

**NET-02 · Only intended services listen publicly** — CRIT
```bash
ss -tlnp; ss -ulnp
ss -tlnpH | awk '{print $4}' | grep -E '^(0\.0\.0\.0|\*|\[::\]):' | grep -vE ':(22|80|443)$'
```
Adjust the final exclusion list to the ports the user declared in Phase 0.
PASS: the last command prints nothing. Databases, caches, admin panels,
metrics endpoints, and application servers behind a reverse proxy must bind
`127.0.0.1`/`::1`, not `0.0.0.0`. Loopback-only resolver stubs are normal.

**NET-03 · Container runtime is not bypassing the firewall** — CRIT
```bash
docker ps --format '{{.Names}}: {{.Ports}}' 2>/dev/null
iptables -S DOCKER 2>/dev/null; iptables -S DOCKER-USER 2>/dev/null
```
Docker inserts its own forwarding rules ahead of the host firewall, so a
published port is reachable from the internet **even when the firewall
never allowed it**. PASS: every published port is bound to a loopback
address (`127.0.0.1:host:container`), or is genuinely meant to be public.
A container that only needs to be reached by a sibling container should
publish no host port at all.

**NET-04 · External reachability matches intent** — CRIT
From a different network (operator's laptop, another host):
```bash
nmap -Pn -p 22,80,443,3000,3306,5432,6379,8080,9000,27017 TARGET
```
PASS: only the intended ports are `open`; everything else `filtered` or
`closed`. This is the only check that proves NET-01..03 actually hold (R6).

**NET-05 · TLS is current** — MED
```bash
for d in DOMAIN1 DOMAIN2; do echo "== $d"; echo | openssl s_client -connect "$d":443 -servername "$d" 2>/dev/null | openssl x509 -noout -dates -issuer; done
```
PASS: > 14 days to expiry and automated renewal is in place.

### PATCHING — how fast known holes close

**PAT-01 · Security updates install automatically** — HIGH
```bash
# Debian/Ubuntu
cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
unattended-upgrade --dry-run --debug 2>&1 | tail -20
systemctl list-timers 'apt-daily*' --all 2>/dev/null
tail -50 /var/log/unattended-upgrades/unattended-upgrades.log 2>/dev/null
# RHEL family
systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null && echo enabled; grep -E '^(apply_updates|upgrade_type)' /etc/dnf/automatic.conf 2>/dev/null
```
PASS: enabled, has run recently, and the log shows real upgrades over the
last month.

**PAT-02 · No backlog, no deferred reboot** — HIGH
```bash
apt-get update -qq 2>/dev/null && apt list --upgradable 2>/dev/null | grep -i security
dnf updateinfo list security 2>/dev/null
[ -f /var/run/reboot-required ] && cat /var/run/reboot-required.pkgs || echo "no reboot pending"
needs-restarting -r 2>/dev/null
```
PASS: no pending security packages; no reboot-required flag. **A kernel
patch installed but not rebooted into is not applied** — treat a
long-standing flag as HIGH, not LOW.

### DETECTION — will you know, and can you prove it later

**DET-01 · Brute-force response is active and working** — MED
```bash
systemctl is-active fail2ban; systemctl is-enabled fail2ban
fail2ban-client status; fail2ban-client status sshd
for p in bantime findtime maxretry; do echo -n "$p: "; fail2ban-client get sshd $p; done
journalctl -u fail2ban --since "7 days ago" 2>/dev/null | grep -c 'Ban '
```
PASS: active, enabled at boot, and **cumulative bans > 0** — a live
internet-facing SSH port always attracts attempts, so a zero count means it
is not reading the right log source, not that the internet is peaceful. On
newer distros without `/var/log/auth.log`, the jail needs
`backend = systemd`; a service that fails to start on a missing log file is
a common silent failure.

**DET-02 · Authentication logs exist and are retained** — MED
```bash
journalctl --disk-usage; grep -E '^\s*(Storage|MaxRetentionSec|SystemMaxUse)' /etc/systemd/journald.conf
ls -l /var/log/auth.log /var/log/secure 2>/dev/null
```
PASS: journald `Storage=persistent` (volatile logs vanish on reboot,
destroying incident evidence) and a retention window the user considers
adequate.

**DET-03 · Audit / integrity tooling** — LOW
```bash
systemctl is-active auditd 2>/dev/null; command -v aide debsums rkhunter 2>/dev/null
```

### RESILIENCE — can you come back

**RES-01 · Backups exist, are recent, and are off-box** — CRIT
```bash
crontab -l 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null
systemctl list-timers --all 2>/dev/null | grep -iE 'backup|dump'
ls -la /var/backups/ /opt/backups/ ~/backups 2>/dev/null
```
PASS: scheduled, newest artefact within the stated RPO, retention pruning
exists (unpruned backups fill the disk and cause the outage they were meant
to survive), **and at least one copy lives on another system** — a backup
on the host it protects does not survive that host.

**RES-02 · Restore drill succeeds** — CRIT. See §4; this is the control
most often assumed and least often tested.

**RES-03 · Headroom** — MED
```bash
df -h; df -i; free -h
```
PASS: > 20% free on `/` and the data volume, inodes not exhausted.

### BASELINE — the second opinion

**BAS-01 · Benchmark score recorded** — LOW
```bash
lynis audit system --quiet --no-colors
grep -E '^(hardening_index|warning|suggestion)' /var/log/lynis-report.dat
```
Prefer the upstream package over a distro version that may be years old.
The absolute number matters less than **the same number measured again
after remediation** — a before/after delta is the deliverable. Do not chase
100: many suggestions assume separate partitions, mandatory access control,
or no compiler, and are inapplicable or actively harmful to the workload.
Triage suggestions by (small change × real risk reduction × no service
impact) and act on a handful.

**BAS-02 · Kernel network/memory parameters** — LOW
```bash
sysctl -a 2>/dev/null | grep -E 'kptr_restrict|dmesg_restrict|rp_filter|accept_redirects|accept_source_route|tcp_syncookies|randomize_va_space'
```

---

## 4. Phase 2 — Restore drill

Never test a restore by restoring over production. The procedure is always:
take (or take the newest) backup → restore it **into a fresh, throwaway
target** → compare against the source → destroy the target.

1. **Locate and describe** the newest backup: size, timestamp, checksum.
   A suspiciously small artefact is the finding.
2. **Verify structure without restoring.** Most backup formats can list
   their contents (`pg_restore --list`, `tar -tf`, `restic check`). If it
   cannot be listed, it cannot be trusted.
3. **Restore into a new empty target** with a name that cannot be confused
   with production (`*_restore_test`). Time it — this is the bulk of RTO.
4. **Reconcile.** Run the same counting query/command against source and
   restored copy: row counts per major table, plus a newest-record
   timestamp. Small positive drift on live tables is expected (the system
   kept working during the drill) — record the delta and the snapshot time
   rather than treating it as failure.
5. **Check semantics, not just volume.** Confirm the restored data is the
   *right* data — the expected tenants/sites/accounts are present. Restoring
   a healthy backup of the wrong database is a real and recurring failure.
6. **Tear down** the throwaway target. Ask first (R3), name it exactly.
7. **Record RPO and RTO** as numbers: RPO from backup frequency, RTO from
   measured restore time plus realistic cutover.

---

## 5. Phase 3 — Report, then remediate

Produce the report before proposing any change.

**findings.md** — one row per control:

| ID | Control | Verdict | Severity | Evidence | What it means | Proposed fix |
|---|---|---|---|---|---|---|

Also emit **findings.json** (`[{id, title, verdict, severity, evidence,
rationale, fix_command, disruptive}]`) so the run can be diffed against the
next one.

Then, for remediation:

- Present fixes **grouped by blast radius**: non-disruptive first (file
  permissions, adding a timer, a firewall rule that only narrows),
  service-affecting last (restarts, port rebinds, container recreation).
- For each, state the exact command, what it changes, how to undo it, and
  whether it interrupts service. Get explicit approval per group (R3).
- Apply one group at a time. **Re-run that control's check immediately
  after** — never batch changes and verify at the end; you lose the ability
  to attribute a break.
- After any SSH or firewall change, run the external probe (R6) and a fresh
  login test before moving on.
- Record what you changed in a changelog with timestamps and backup paths.

**Negative tests.** For access controls, proving the door opens is half the
job; prove the closed doors are closed. Capture these to a file from the
client side rather than by hand (R8):

```bash
#!/usr/bin/env bash
# access-negative-test.sh TARGET_HOST LOGIN_USER  -> writes access-negative-test.txt
set -uo pipefail
H="$1"; U="$2"; OUT=access-negative-test.txt
{
  echo "== $(date -u +%FT%TZ) target=$H"
  echo "--- password auth must be refused"
  ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o BatchMode=yes \
      "$U@$H" true 2>&1 | tail -2
  echo "--- root login must be refused"
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o BatchMode=yes \
      "root@$H" true 2>&1 | tail -2
  echo "--- key login must still work"
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 -o BatchMode=yes \
      "$U@$H" 'echo KEY_LOGIN_OK' 2>&1 | tail -2
} | tee "$OUT"
```
Expected: the first two end in `Permission denied (publickey)`, the third
prints `KEY_LOGIN_OK`. **All three lines must be present** — the third is
what proves you did not lock the owner out.

If a rate-limiting control is tested by deliberately failing logins, warn
the user first that the source address will be banned, and know the
unban command before you start.

---

## 6. Evidence discipline

An audit whose outputs cannot be re-read later is an opinion. Produce a
pack that a third party could check.

Layout, one directory per run:

```
<pack>/<YYYY-MM-DD>-<host>/
  00-scope.md            # what was audited, by whom, with what access, what was out of scope
  raw/<CONTROL-ID>.txt   # verbatim output, one file per control
  findings.md
  findings.json
  changelog.md           # every change made, with timestamps and backup paths
  MANIFEST.txt           # sha256 of every file in raw/
  checklist.md           # the one-page summary
```

Rules:

- Capture with `| tee raw/<ID>.txt` as you go; never reconstruct afterwards.
- Disable colour output for anything you save (`--no-colors`, `NO_COLOR=1`);
  ANSI escapes make stored output unreadable.
- **Empty output is evidence.** Keep the empty file — it is the proof that
  a "find anything bad" check found nothing.
- Checksum at the end: `find raw -type f -exec sha256sum {} + | sort -k2 > MANIFEST.txt`.
- **Redaction gate — run before anything leaves the host or enters a repo:**
  ```bash
  grep -rniE 'password|passwd|secret|token|api[_-]?key|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY|DATABASE_URL|://[^/ ]*:[^@/ ]*@' <pack>/ || echo "REDACTION GATE PASSED"
  ```
  Anything matched is removed or masked before commit. Backup artefacts
  (database dumps, archives) never enter the pack — store their size,
  checksum, and content listing instead.
- Treat the pack as **sensitive**: it is a map of the host. Private
  repository only.

---

## 7. Failure modes worth knowing

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

---

## 8. Closing deliverable

Finish with a one-page `checklist.md` that someone who was not present can
act on:

- one row per control: ID, what was checked, verdict, evidence path,
  whether it was fixed during this run;
- **residual risks**, explicitly accepted, each with a reason and a review
  date — a named accepted risk is a sign of judgement; an unnamed one is a
  gap;
- what changed, and how to roll it back;
- the next scheduled run.

Then tell the user, in plain language: the two or three things that
mattered most, what you changed, what you deliberately did not change, and
what you could not determine.
