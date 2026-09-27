# Server hardening audit — host-01

> Generated against a production host running two public sites. Host identifiers redacted; all measurements are real.

| | |
|---|---|
| Host | host-01 — Ubuntu 24.04.4 LTS, Linux 6.8.0-142-generic, virtualization: microsoft |
| Run | `20260927T084403Z-host-01` · 2026-09-27T08:44:03Z → 2026-09-27T08:44:06Z · replay of `20260927T084403Z-host-01` |
| Tool | server-hardening-audit 0.1.0 |
| Profile | prod-vps |
| Controls | bundled · sha256 `ec37d1ba9a675455…` · 25 evaluated |
| Attestation | `probe-attestation.public.toml` · sha256 `c6f0cb7fb60db4c2…` · 2 attestation(s), 0 risk acceptance(s), 0 note(s) |
| Attestation | `risk-acceptance.toml` · sha256 `4d382fcabe9901ac…` · 0 attestation(s), 2 risk acceptance(s), 0 note(s) |
| Attestation | `operator-notes.toml` · sha256 `e553460cfba177d2…` · 0 attestation(s), 0 risk acceptance(s), 9 note(s) |
| Privileges | root |

**Scope.** This report covers the technical controls of one Linux host, as observed from inside the host by a read-only tool at the time shown. It is not an assessment of an organisation. `PASS` is backed by machine-collected evidence; `PASS · attested` is backed by an operator's signed statement. Nothing on the host was changed.

## Summary

| Severity | FAIL | UNKNOWN | MANUAL | PASS | NA |
|---|---:|---:|---:|---:|---:|
| critical | 1 | · | 2 | 4 | · |
| high | 1 | · | · | 5 | · |
| medium | · | · | · | 7 | · |
| low | · | · | · | 5 | · |

## Findings

| ID | Severity | Verdict | Control | Result |
|---|---|---|---|---|
| [ACC-01](#acc-01) | critical | **FAIL · risk accepted (review by 2026-12-31)** | SSH accepts keys only and refuses root login | permitrootlogin is 'without-password' (expected 'no') |
| [NET-04](#net-04) | critical | **PASS · attested** | External reachability matches the declared public ports | PASS by attestation: TCP connect probe of 14 ports on ipv4 192.0.2.10 from the operator's network (the list of probed internal ports is omitted from the public copy) |
| [RES-01](#res-01) | critical | **MANUAL** | Backups exist, are recent and have a retention policy | scheduled = True, retention_evidence = True; age of newest backup (hours) = 5.7 (limit 24) -- remaining part needs an attestation |
| [RES-02](#res-02) | critical | **MANUAL** | A restore drill has succeeded | requires an operator procedure and an attestation |
| [NET-01](#net-01) | critical | **PASS** | Host firewall denies by default, allows minimally, covers IPv6 | default_deny_v4 = True, default_deny_v6 = True; no ports open to any source beyond the declared public ports |
| [NET-02](#net-02) | critical | **PASS** | Only intended services listen on non-loopback addresses | 7 non-loopback listener(s), all on declared ports |
| [NET-03](#net-03) | critical | **PASS** | Container ports do not bypass the host firewall | no container ports published on non-loopback addresses outside the declared public ports |
| [ACC-06](#acc-06) | high | **FAIL · risk accepted (review by 2026-12-31)** | Administrative access requires multiple factors | mfa_enforced is False (expected True) |
| [ACC-02](#acc-02) | high | **PASS** | authorized_keys files are clean and attributable | no authorized_keys problems |
| [ACC-03](#acc-03) | high | **PASS** | Application accounts hold no privileges | no privileged application or undeclared accounts |
| [ACC-05](#acc-05) | high | **PASS** | sudoers grants no passwordless full root to non-administrators | no NOPASSWD: ALL grants to non-administrators |
| [PAT-01](#pat-01) | high | **PASS** | Automatic security updates are enabled and running | installed = True, enabled = True, timer_enabled = True; hours since unattended-upgrades last ran = 1.8 (limit 48) |
| [PAT-02](#pat-02) | high | **PASS** | No pending security updates and no pending reboot | no pending security updates; reboot_required = False |
| [ACC-04](#acc-04) | medium | **PASS** | No account has an empty password | no accounts with an empty password |
| [DET-01](#det-01) | medium | **PASS** | Brute-force protection is active and working | protection_active = True, ssh_jail_present = True; SSH bans observed = 382 (need >= 1) |
| [DET-02](#det-02) | medium | **PASS** | Authentication logs persist across reboots | auth_logs_persistent = True |
| [NET-05](#net-05) | medium | **PASS** | TLS certificates are valid and not close to expiry | no certificate problems |
| [PAT-03](#pat-03) | medium | **PASS** | Running container images are not stale | no containers running images older than max_image_age_days |
| [RES-03](#res-03) | medium | **PASS** | Disk space and inode headroom | no filesystems below the headroom threshold |
| [RES-04](#res-04) | medium | **PASS** | Backups are not readable or modifiable by other accounts | no backup files or directories open to other accounts |
| [BAS-01](#bas-01) | low | **PASS** | A recent Lynis baseline score is recorded | age of the Lynis report (days) = 0 (limit 90) |
| [BAS-02](#bas-02) | low | **PASS** | Kernel network and memory hardening parameters | kernel.kptr_restrict = 1, kernel.dmesg_restrict = 1, kernel.randomize_va_space = 2, net.ipv4.tcp_syncookies = 1, net.ipv4.conf.all.rp_filter = 2, net.ipv4.conf.all.accept_redirects = 0, net.ipv4.conf.all.send_redirects = 0, net.ipv4.conf.all.accept_source_route = 0, net.ipv6.conf.all.accept_redirects = 0 |
| [BAS-03](#bas-03) | low | **PASS** | System time is synchronised | ntp_synchronized = True |
| [BAS-04](#bas-04) | low | **PASS** | Mandatory access control is enforcing | enforcing = True |
| [DET-03](#det-03) | low | **PASS** | Audit or file-integrity tooling is present | auditd_active = True |

## Controls

### ACC-01

**SSH accepts keys only and refuses root login** — critical, access

- **Verdict:** FAIL · risk accepted (review by 2026-12-31)
- **Result:** permitrootlogin is 'without-password' (expected 'no')
- **Evidence:** `evidence/ACC-01/index.json`, `evidence/ACC-01/01-sshd-T.txt`, `evidence/ACC-01/02-etc_ssh_sshd_config`, `evidence/ACC-01/03-glob-etc_ssh_sshd_config.d_.json`, `evidence/ACC-01/04-etc_ssh_sshd_config.d_50-cloud-init.conf`
- **External check** (probe, 2026-09-27T07:52:44Z) found no problem within its scope; the host result stands: PASS — Unauthenticated SSH connection offering no credentials; methods advertised by the server were read from the handshake
- **Why it matters:** Password logins make the host a target for credential stuffing and brute force; direct root login removes the audit trail of who acted. The verdict uses the configuration sshd itself resolves (`sshd -T`), not the main config file: drop-in files, Include order (first match wins) and cloud-image defaults routinely override what sshd_config appears to say.
- **Remediation** (may interrupt service): Set PasswordAuthentication no, KbdInteractiveAuthentication no and PermitRootLogin no in the first-loaded drop-in; validate with `sshd -t`, apply with a reload, then prove a new key login works before closing the current session.
- **Limitations:** Match blocks are evaluated for root and each declared admin user from localhost; Match rules keyed on other source addresses are not evaluated.
- **Risk accepted** by owner: Root may log in with a key only; password login is off. The only authorised key lives on the owner's own laptop and there are no other administrators, so exploiting this requires compromising that laptop first, which is outside this host's control. (review by 2026-12-31)

### NET-04

**External reachability matches the declared public ports** — critical, network

- **Verdict:** PASS · attested
- **Result:** PASS by attestation: TCP connect probe of 14 ports on ipv4 192.0.2.10 from the operator's network (the list of probed internal ports is omitted from the public copy)
- **Attested** PASS by server-hardening-audit 0.1.0.dev0 probe at 2026-09-27T07:52:44Z (`probe-attestation.public.toml`): TCP connect probe of 14 ports on ipv4 192.0.2.10 from the operator's network (the list of probed internal ports is omitted from the public copy)
  - Measurements: declared_public_ports = [22, 80, 443], unexpected_open_ports = [], open_ipv4 = [22]
  - Evidence: `probe.json` (sha256 `d8a2c619e22d94bd…`)
- **Automated result before attestation:** MANUAL — requires an operator procedure and an attestation
- **Operator note** (operator with AI agent, `operator-notes.toml`): The external probe ran from the owner's own network at 07:52 UTC, before the 08:28 reboot. The reboot changed no firewall rule or listener (NET-01 and NET-02 are identical in both runs), so the result still describes this host.
- **Why it matters:** Every in-host check proves what is configured; only a probe from outside proves what the internet can reach. It is the only control that confirms NET-01 to NET-03 actually hold.

### RES-01

**Backups exist, are recent and have a retention policy** — critical, resilience

- **Verdict:** MANUAL
- **Result:** scheduled = True, retention_evidence = True; age of newest backup (hours) = 5.7 (limit 24) -- remaining part needs an attestation
- **Key fact:** 8 backup file(s) under <backup-path>
- **Key fact:** newest: app-2026-09-27.dump, 1303630282 bytes, 5.7h old
- **Key fact:** oldest kept: 173.7h old
- **Key fact:** schedules: cron /var/spool/cron/crontabs/root: <schedule>; timer dpkg-db-backup.timer
- **Evidence:** `evidence/RES-01/index.json`, `evidence/RES-01/01-glob-etc_cron.d_.json`, `evidence/RES-01/02-glob-var_spool_cron_crontabs_.json`, `evidence/RES-01/03-derived-cron_schedules-etc-crontab.json`, `evidence/RES-01/04-derived-cron_schedules-etc-cron.d-job-a.json`, `evidence/RES-01/05-derived-cron_schedules-etc-cron.d-certbot.json`, `evidence/RES-01/06-derived-cron_schedules-etc-cron.d-e2scrub_all.json`, `evidence/RES-01/07-derived-cron_schedules-etc-cron.d-job-b.json`, `evidence/RES-01/08-derived-cron_schedules-etc-cron.d-sysstat.json`, `evidence/RES-01/09-derived-cron_schedules-var-spool-cron-crontabs-r.json`, `evidence/RES-01/10-systemctl-list-timers-all-no-legend-plain.txt`, `evidence/RES-01/11-glob-var_backups_app_.json`, `evidence/RES-01/12-glob-var_backups_app_-_.json`
- **Operator procedure:** A backup kept only on the host it protects does not survive that host. Confirm a copy of the newest backup exists on another system (list it there, with its size and timestamp) and record an attestation for RES-01.
- **Operator note** (operator with AI agent, `operator-notes.toml`): Local backups verified: nightly pg dump at <time> from root's crontab, about 1.3 GB each, eight kept (about seven days). Whether a copy exists off the host is not known to the owner; verification deferred on 2026-09-27.
- **Why it matters:** Backups must be scheduled, fresh within the recovery point objective, and pruned -- an unpruned backup job fills the disk and causes the outage it was meant to survive. Only metadata of backup files is read.
- **Remediation** (non-disruptive): Schedule the backup (cron or a systemd timer), add age-based pruning, and copy each backup off the host.
- **Limitations:** Off-host copies cannot be verified from inside the host; they are covered by attestation.

### RES-02

**A restore drill has succeeded** — critical, resilience

- **Verdict:** MANUAL
- **Result:** requires an operator procedure and an attestation
- **Operator procedure:** Restore the newest backup into a new, throwaway target whose name cannot be confused with production (e.g. *_restore_test). Time the restore, reconcile row counts (or file counts) per major table against the source, confirm the restored data is the expected data, then remove the throwaway target. Record method, measurements and timing in an attestation for RES-02. The agent skill describes the full protocol.
- **Operator note** (operator with AI agent, `operator-notes.toml`): Restore drill deferred by the owner on 2026-09-27. The planned target (an Umami database) does not exist on this host, and the app databases are production and out of bounds for this run.
- **Why it matters:** A backup that has never been restored is an assumption. The drill measures recovery time and proves the backup contains the right data.
- **Remediation** (non-disruptive): Run the drill; fix whatever it reveals (missing roles, wrong database, truncated dumps) and repeat.

### NET-01

**Host firewall denies by default, allows minimally, covers IPv6** — critical, network

- **Verdict:** PASS
- **Result:** default_deny_v4 = True, default_deny_v6 = True; no ports open to any source beyond the declared public ports
- **Key fact:** front-end: ufw; default deny IPv4 True, IPv6 True
- **Key fact:** open to any source: 22
- **Evidence:** `evidence/NET-01/index.json`, `evidence/NET-01/01-ufw-status-verbose.txt`, `evidence/NET-01/02-etc_default_ufw`, `evidence/NET-01/03-proc_sys_net_ipv6_conf_all_disable_ipv6`
- **Operator note** (operator with AI agent, `operator-notes.toml`): Ports 80 and 443 are allowed only from Cloudflare's published address ranges (origin locked to the CDN); SSH on 22 is open to any source with ufw rate limiting.
- **Why it matters:** Default-deny means a service started by mistake is unreachable until someone decides otherwise. A ruleset that filters IPv4 only leaves every IPv6-listening service exposed. The front-end is identified (ufw, firewalld, nftables, iptables) and its resolved policy is read.
- **Limitations:** Cloud-provider security groups and network ACLs are invisible from inside the host; if they are the real perimeter, review them separately.

### NET-02

**Only intended services listen on non-loopback addresses** — critical, network

- **Verdict:** PASS
- **Result:** 7 non-loopback listener(s), all on declared ports
- **Evidence:** `evidence/NET-02/index.json`, `evidence/NET-02/01-ss-tcp.txt`, `evidence/NET-02/02-ss-udp.txt`
- **Why it matters:** Databases, caches, admin panels and application servers reachable from the internet are the most common entry point. Anything outside the declared public port set must bind a loopback address. Container ports published by Docker appear here too, as docker-proxy listeners.

### NET-03

**Container ports do not bypass the host firewall** — critical, network

- **Verdict:** PASS
- **Result:** no container ports published on non-loopback addresses outside the declared public ports
- **Evidence:** `evidence/NET-03/index.json`, `evidence/NET-03/01-docker-ps-q-no-trunc.txt`
- **Why it matters:** Docker inserts its own forwarding rules ahead of the host firewall, so a port published on 0.0.0.0 is reachable from the internet even when ufw never allowed it. The host firewall's own view (NET-01) will not show the hole; the published bindings will.
- **Limitations:** Rules in the DOCKER-USER chain are not evaluated; external probing (NET-04) is what proves the result.

### ACC-06

**Administrative access requires multiple factors** — high, access

- **Verdict:** FAIL · risk accepted (review by 2026-12-31)
- **Result:** mfa_enforced is False (expected True)
- **Evidence:** `evidence/ACC-06/index.json`, `evidence/ACC-06/01-sshd-T.txt`, `evidence/ACC-06/02-etc_passwd`, `evidence/ACC-06/03-glob-bin_.ssh_authorized_keys.json`, `evidence/ACC-06/04-glob-home_ci-user_.ssh_authorized_keys.json`, `evidence/ACC-06/05-derived-authorized_keys-home-ci-user-.ssh-authori.json`, `evidence/ACC-06/06-glob-root_.ssh_authorized_keys.json`, `evidence/ACC-06/07-derived-authorized_keys-root-.ssh-authorized_key.json`, `evidence/ACC-06/08-glob-var_lib_postgresql_.ssh_authorized_keys.json`
- **Why it matters:** A private key on a laptop is one factor: whoever holds the file (and its passphrase, which the server cannot verify) gets in. MFA for SSH means sshd requires two methods (AuthenticationMethods) or every authorized key is a FIDO hardware key (sk-* types) that proves physical presence. Most hosts fail this control; that is an honest result, not a defect.
- **Remediation** (may interrupt service): Enrol FIDO2 keys (`ssh-keygen -t ed25519-sk`) for administrators and remove other keys, or require a second method with AuthenticationMethods publickey,keyboard-interactive plus a TOTP PAM module.
- **Risk accepted** by owner: Single administrator using key-only SSH from one personal device; a second factor is not required at this time. Revisit if more administrators or devices are added. (review by 2026-12-31)

### ACC-02

**authorized_keys files are clean and attributable** — high, access

- **Verdict:** PASS
- **Result:** no authorized_keys problems
- **Evidence:** `evidence/ACC-02/index.json`, `evidence/ACC-02/01-etc_passwd`, `evidence/ACC-02/02-glob-bin_.ssh_authorized_keys.json`, `evidence/ACC-02/03-glob-home_ci-user_.ssh_authorized_keys.json`, `evidence/ACC-02/04-derived-authorized_keys-home-ci-user-.ssh-authori.json`, `evidence/ACC-02/05-glob-root_.ssh_authorized_keys.json`, `evidence/ACC-02/06-derived-authorized_keys-root-.ssh-authorized_key.json`, `evidence/ACC-02/07-glob-var_lib_postgresql_.ssh_authorized_keys.json`
- **Why it matters:** Every authorized key is a standing credential. Keys nobody can attribute, weak key types, deprecated authorized_keys2 files and loose permissions are how access outlives the people and systems it was granted to. Only key type, comment and option names are recorded -- never key material.
- **Limitations:** Whether each key's owner is still entitled to access is a human judgement; the key inventory is listed in the details for review.

### ACC-03

**Application accounts hold no privileges** — high, access

- **Verdict:** PASS
- **Result:** no privileged application or undeclared accounts
- **Evidence:** `evidence/ACC-03/index.json`, `evidence/ACC-03/01-etc_passwd`, `evidence/ACC-03/02-etc_group`, `evidence/ACC-03/03-ps-eo-user-32-comm-no-headers.txt`, `evidence/ACC-03/04-systemctl-list-units-type-service-state-running-.txt`, `evidence/ACC-03/05-systemctl-show-p-Id-User-DynamicUser-auditd.serv.txt`, `evidence/ACC-03/06-systemctl-show-p-Id-User-DynamicUser-systemd-jou.txt`
- **Operator note** (operator with AI agent, `operator-notes.toml`): Fixed on 2026-09-27 08:25 UTC: the unused provider default account was removed from all supplementary groups (sudo, lxd, adm and others), its shell set to nologin, the account expired and its password kept locked. It had no SSH keys. Change and undo command recorded in the host's remediation log.
- **Why it matters:** An application compromise should not become a host compromise. Membership in sudo, wheel, admin, adm, lxd or docker is privilege: anyone who can start containers can mount the host filesystem, so the docker group is equivalent to root. Accounts that own processes or run services must not hold any of these, and privileged human accounts must be declared.

### ACC-05

**sudoers grants no passwordless full root to non-administrators** — high, access

- **Verdict:** PASS
- **Result:** no NOPASSWD: ALL grants to non-administrators
- **Evidence:** `evidence/ACC-05/index.json`, `evidence/ACC-05/01-etc_sudoers`, `evidence/ACC-05/02-glob-etc_sudoers.d_.json`, `evidence/ACC-05/03-etc_sudoers.d_README`, `evidence/ACC-05/04-etc_sudoers.d_comments-svc`, `evidence/ACC-05/05-etc_group`
- **Why it matters:** `NOPASSWD: ALL` turns any code execution as that account into root without a second secret. Cloud images often grant it to the default user. Only files sudo actually loads are considered: files in sudoers.d whose names contain a dot or end in '~' are ignored by sudo and reported separately.

### PAT-01

**Automatic security updates are enabled and running** — high, patching

- **Verdict:** PASS
- **Result:** installed = True, enabled = True, timer_enabled = True; hours since unattended-upgrades last ran = 1.8 (limit 48)
- **Key fact:** last unattended-upgrades activity: 1.8h ago
- **Key fact:** 10 upgrade run(s) and 54 run(s) in the current log
- **Evidence:** `evidence/PAT-01/index.json`, `evidence/PAT-01/01-dpkg-query-W-f-Package-db-Status-Abbrev-Version-.txt`, `evidence/PAT-01/02-glob-etc_apt_apt.conf.d_.json`, `evidence/PAT-01/03-etc_apt_apt.conf.d_01-vendor-ubuntu`, `evidence/PAT-01/04-etc_apt_apt.conf.d_01autoremove`, `evidence/PAT-01/05-etc_apt_apt.conf.d_02autoremove-postgresql`, `evidence/PAT-01/06-etc_apt_apt.conf.d_10periodic`, `evidence/PAT-01/07-etc_apt_apt.conf.d_15update-stamp`, `evidence/PAT-01/08-etc_apt_apt.conf.d_20apt-esm-hook.conf`, `evidence/PAT-01/09-etc_apt_apt.conf.d_20archive`, `evidence/PAT-01/10-etc_apt_apt.conf.d_20auto-upgrades`, `evidence/PAT-01/11-etc_apt_apt.conf.d_20packagekit`, `evidence/PAT-01/12-etc_apt_apt.conf.d_20snapd.conf`, `evidence/PAT-01/13-etc_apt_apt.conf.d_50appstream`, `evidence/PAT-01/14-etc_apt_apt.conf.d_50command-not-found`, `evidence/PAT-01/15-etc_apt_apt.conf.d_50unattended-upgrades`, `evidence/PAT-01/16-etc_apt_apt.conf.d_70debconf`, `evidence/PAT-01/17-etc_apt_apt.conf.d_99Recommended`, `evidence/PAT-01/18-etc_apt_apt.conf.d_99needrestart`, `evidence/PAT-01/19-etc_apt_apt.conf.d_99update-notifier`, `evidence/PAT-01/20-systemctl-is-enabled-apt-daily.timer-apt-daily-u.txt`, `evidence/PAT-01/21-stat-var_lib_apt_periodic_unattended-upgrades-st.json`, `evidence/PAT-01/22-derived-unattended_upgrades_log-var-log-unattend.json`
- **Why it matters:** Most compromises use known, already-patched vulnerabilities. Enabled is not enough: the timer must be active and the tool must actually have run recently. This tool does not run unattended-upgrade itself (a dry run writes logs and takes the apt lock); it reads the configuration, the timers, the periodic stamp and the log.

### PAT-02

**No pending security updates and no pending reboot** — high, patching

- **Verdict:** PASS
- **Result:** no pending security updates; reboot_required = False
- **Key fact:** package lists 0.0h old; 45 upgradable package(s)
- **Evidence:** `evidence/PAT-02/index.json`, `evidence/PAT-02/01-stat-var_lib_apt_periodic_update-success-stamp.json`, `evidence/PAT-02/02-apt-list-upgradable.txt`, `evidence/PAT-02/03-stat-var_run_reboot-required.json`
- **Operator note** (operator with AI agent, `operator-notes.toml`): Fixed on 2026-09-27: the owner rebooted into kernel 6.8.0-142 (previously 6.8.0-139 was running while the new kernel had been installed for 49 h). The reboot also activated libaudit1 upgraded as a dependency of auditd.
- **Why it matters:** A kernel or library update installed but not rebooted into is not applied. The backlog is judged from the package lists already on the host; the tool does not run `apt-get update` (it rewrites /var/lib/apt/lists), so when the lists are older than the profile allows, the backlog is reported UNKNOWN rather than guessed.

### ACC-04

**No account has an empty password** — medium, access

- **Verdict:** PASS
- **Result:** no accounts with an empty password
- **Evidence:** `evidence/ACC-04/index.json`, `evidence/ACC-04/01-derived-shadow_empty_passwords-etc-shadow.json`
- **Why it matters:** An empty password field allows login without any secret wherever password authentication is accepted (console, su, some PAM stacks). Only the usernames are recorded; password hashes are never stored.

### DET-01

**Brute-force protection is active and working** — medium, detection

- **Verdict:** PASS
- **Result:** protection_active = True, ssh_jail_present = True; SSH bans observed = 382 (need >= 1)
- **Key fact:** fail2ban jail 'sshd': 382 ban(s) in the last 7 days (source: /var/log/fail2ban.log), 49 since the service started
- **Key fact:** bantime 86400s, findtime 3600s, maxretry 3
- **Evidence:** `evidence/DET-01/index.json`, `evidence/DET-01/01-systemctl-is-active-fail2ban-sshguard-crowdsec.txt`, `evidence/DET-01/02-fail2ban-client-status.txt`, `evidence/DET-01/03-fail2ban-client-status-sshd.txt`, `evidence/DET-01/04-fail2ban-client-get-sshd-bantime.txt`, `evidence/DET-01/05-fail2ban-client-get-sshd-findtime.txt`, `evidence/DET-01/06-fail2ban-client-get-sshd-maxretry.txt`, `evidence/DET-01/07-derived-fail2ban_log_bans-var-log-fail2ban.log.json`, `evidence/DET-01/08-derived-fail2ban_log_bans-var-log-fail2ban.log.1.json`
- **Why it matters:** An internet-facing SSH port always attracts attempts, so a protection tool that has never banned anything is almost certainly reading the wrong log source (for example a jail watching /var/log/auth.log on a journald-only system). Zero bans is treated as FAIL, not as a quiet internet.

### DET-02

**Authentication logs persist across reboots** — medium, detection

- **Verdict:** PASS
- **Result:** auth_logs_persistent = True
- **Evidence:** `evidence/DET-02/index.json`, `evidence/DET-02/01-etc_systemd_journald.conf`, `evidence/DET-02/02-glob-usr_lib_systemd_journald.conf.d_-.conf.json`, `evidence/DET-02/03-glob-run_systemd_journald.conf.d_-.conf.json`, `evidence/DET-02/04-glob-etc_systemd_journald.conf.d_-.conf.json`, `evidence/DET-02/05-etc_systemd_journald.conf.d_99-maxuse.conf`, `evidence/DET-02/06-usr_lib_systemd_journald.conf.d_syslog.conf`, `evidence/DET-02/07-stat-var_log_journal.json`, `evidence/DET-02/08-stat-var_log_auth.log.json`
- **Why it matters:** Volatile logs vanish on reboot, taking incident evidence with them. The effective journald storage mode is resolved from journald.conf and its drop-ins (Storage=auto persists only if /var/log/journal exists); a syslog-written auth log also counts.

### NET-05

**TLS certificates are valid and not close to expiry** — medium, network

- **Verdict:** PASS
- **Result:** no certificate problems
- **Evidence:** `evidence/NET-05/index.json`, `evidence/NET-05/01-tls-site-a.example.json`, `evidence/NET-05/02-tls-www.site-a.example.json`, `evidence/NET-05/03-tls-site-b.example.json`, `evidence/NET-05/04-tls-www.site-b.example.json`, `evidence/NET-05/05-tls-verify.site-b.example.json`
- **Why it matters:** An expired or invalid certificate is an outage for users and trains them to click through warnings. Each declared domain is checked on this host's own port 443 with SNI, against the system CA store.

### PAT-03

**Running container images are not stale** — medium, patching

- **Verdict:** PASS
- **Result:** no containers running images older than max_image_age_days
- **Evidence:** `evidence/PAT-03/index.json`, `evidence/PAT-03/01-docker-ps-q-no-trunc.txt`
- **Why it matters:** Host patching does not reach inside containers. An image built months ago carries the vulnerabilities of its base layer from that date.
- **Limitations:** Image age is a proxy: a recent build of an old base image passes. CVE matching is out of scope.

### RES-03

**Disk space and inode headroom** — medium, resilience

- **Verdict:** PASS
- **Result:** no filesystems below the headroom threshold
- **Key fact:** /: 35.7% space free, 97.4% inodes free
- **Evidence:** `evidence/RES-03/index.json`, `evidence/RES-03/01-statvfs.json`
- **Why it matters:** A full disk stops databases, logging and backups at once. Inode exhaustion does the same with space still free.

### RES-04

**Backups are not readable or modifiable by other accounts** — medium, resilience

- **Verdict:** PASS
- **Result:** no backup files or directories open to other accounts
- **Evidence:** `evidence/RES-04/index.json`, `evidence/RES-04/01-stat-var.json`, `evidence/RES-04/02-stat-var_backups.json`, `evidence/RES-04/03-stat-var_backups_app.json`, `evidence/RES-04/04-glob-var_backups_app_.json`, `evidence/RES-04/05-glob-var_backups_app_-_.json`
- **Why it matters:** A backup readable by every account leaks the whole data set to any compromised service; a backup directory that other accounts can write to lets ransomware running as one of them delete or overwrite it. Files must grant nothing to other accounts and must not be group-writable; directories must not let other accounts add or remove files. Only metadata is read.
- **Limitations:** Covers backups under the declared backup_paths on this host, taking parent directories into account; ACLs and access to off-host copies are not checked.

### BAS-01

**A recent Lynis baseline score is recorded** — low, baseline

- **Verdict:** PASS
- **Result:** age of the Lynis report (days) = 0 (limit 90)
- **Key fact:** Lynis 3.1.8 hardening index 69, report from 2026-09-27 08:44:03 UTC
- **Key fact:** 5 warning(s)
- **Key fact:** warning NETW-2704: Nameserver 2001:db8::1 does not respond
- **Key fact:** warning NETW-2704: Nameserver 2001:db8::2 does not respond
- **Key fact:** warning DBS-1828: PostgreSQL configuration file /etc/postgresql/16/main/postgresql.conf is world readable and might leak sensitive details
- **Key fact:** warning DBS-1828: PostgreSQL configuration file /etc/postgresql/16/main/start.conf is world readable and might leak sensitive details
- **Key fact:** warning DBS-1828: PostgreSQL configuration file /etc/postgresql/16/main/pg_ctl.conf is world readable and might leak sensitive details
- **Key fact:** 47 suggestion(s) across 32 tests: BOOT-5122, BOOT-5264, KRNL-5820, AUTH-9229, AUTH-9230, AUTH-9282, AUTH-9284, AUTH-9286 ×2, AUTH-9328, FILE-6310 ×3, USB-1000, PKGS-7346, PKGS-7370, PKGS-7394, NETW-2704 ×2, NETW-3200 ×4, FIRE-4513, HTTP-6710, SSH-7408 ×9, LOGG-2154, BANN-7126, BANN-7130, ACCT-9622, ACCT-9626, ACCT-9630, FINT-4350, TOOL-5002, FILE-7524, HOME-9304, KRNL-6000, HRDN-7222, HRDN-7230
- **Evidence:** `evidence/BAS-01/index.json`, `evidence/BAS-01/01-derived-lynis_report-var-log-lynis-report.dat.json`
- **Operator note** (operator with AI agent, `operator-notes.toml`): Lynis 3.1.8 (upstream, run from a temporary checkout) scored 67 before remediation and 69 after; the reboot-needed warning KRNL-5830 is gone. Remaining warnings: NETW-2704 (IPv6 resolvers unreachable; expected, the host has no global IPv6 address) and DBS-1828 (default world-readable PostgreSQL configuration files without credentials; low). Lynis test PKGS-7392 runs apt-get update, so package-list freshness right after a Lynis run comes from Lynis.
- **Why it matters:** Lynis gives a broad second opinion. This tool reads the existing report (score, date, warning IDs); it does not run Lynis, which writes to /var/log. The number that matters is the same score measured again after remediation, not the absolute value.

### BAS-02

**Kernel network and memory hardening parameters** — low, baseline

- **Verdict:** PASS
- **Result:** kernel.kptr_restrict = 1, kernel.dmesg_restrict = 1, kernel.randomize_va_space = 2, net.ipv4.tcp_syncookies = 1, net.ipv4.conf.all.rp_filter = 2, net.ipv4.conf.all.accept_redirects = 0, net.ipv4.conf.all.send_redirects = 0, net.ipv4.conf.all.accept_source_route = 0, net.ipv6.conf.all.accept_redirects = 0
- **Evidence:** `evidence/BAS-02/index.json`, `evidence/BAS-02/01-proc_sys_kernel_kptr_restrict`, `evidence/BAS-02/02-proc_sys_kernel_dmesg_restrict`, `evidence/BAS-02/03-proc_sys_kernel_randomize_va_space`, `evidence/BAS-02/04-proc_sys_net_ipv4_tcp_syncookies`, `evidence/BAS-02/05-proc_sys_net_ipv4_conf_all_rp_filter`, `evidence/BAS-02/06-proc_sys_net_ipv4_conf_all_accept_redirects`, `evidence/BAS-02/07-proc_sys_net_ipv4_conf_all_send_redirects`, `evidence/BAS-02/08-proc_sys_net_ipv4_conf_all_accept_source_route`, `evidence/BAS-02/09-proc_sys_net_ipv6_conf_all_accept_redirects`
- **Operator note** (operator with AI agent, `operator-notes.toml`): Fixed on 2026-09-27 08:26 UTC: net.ipv4.conf.all/default.send_redirects set to 0 in a sysctl.d drop-in and applied; it persisted across the reboot.
- **Why it matters:** These parameters limit kernel address leaks, enable full ASLR, resist SYN floods and refuse routing tricks (redirects, source routing, spoofed sources). Values are read from /proc/sys; sysctl is never invoked.

### BAS-03

**System time is synchronised** — low, baseline

- **Verdict:** PASS
- **Result:** ntp_synchronized = True
- **Evidence:** `evidence/BAS-03/index.json`, `evidence/BAS-03/01-timedatectl-show.txt`, `evidence/BAS-03/02-systemctl-is-active-systemd-timesyncd-chrony-chr.txt`
- **Why it matters:** Log correlation, certificate validation and TOTP all depend on correct time. Incident timelines built from skewed clocks are wrong.

### BAS-04

**Mandatory access control is enforcing** — low, baseline

- **Verdict:** PASS
- **Result:** enforcing = True
- **Evidence:** `evidence/BAS-04/index.json`, `evidence/BAS-04/01-sys_module_apparmor_parameters_enabled`, `evidence/BAS-04/02-sys_kernel_security_apparmor_profiles`
- **Why it matters:** AppArmor or SELinux confines compromised services to what their profile allows. It is a weak counterpart of application control: it restricts what confined programs do, not which programs may run.

### DET-03

**Audit or file-integrity tooling is present** — low, detection

- **Verdict:** PASS
- **Result:** auditd_active = True
- **Evidence:** `evidence/DET-03/index.json`, `evidence/DET-03/01-systemctl-is-active-auditd.txt`, `evidence/DET-03/02-dpkg-query-W-f-Package-db-Status-Abbrev-Version-.txt`
- **Operator note** (operator with AI agent, `operator-notes.toml`): Fixed on 2026-09-27 08:26 UTC: auditd installed (3.1.2) and enabled with its default rules; needrestart was suspended during installation so no production service was restarted. AIDE was not installed.
- **Why it matters:** After an incident, the first questions are what ran and what changed. auditd records security-relevant events; AIDE detects file changes. debsums presence is reported but does not pass the control on its own.

## What this report does not cover

Controls without a verified result:

| ID | Verdict | Reason |
|---|---|---|
| RES-01 | MANUAL | scheduled = True, retention_evidence = True; age of newest backup (hours) = 5.7 (limit 24) -- remaining part needs an attestation |
| RES-02 | MANUAL | requires an operator procedure and an attestation |

Inherent limits of this tool:

- Cloud-provider security groups, network ACLs and upstream firewalls are invisible from inside the host.
- Application code, application configuration and data-layer permissions are not assessed.
- Backup copies held on other systems cannot be verified from this host; they rely on attestation.
- Results describe the host at the time of the run. They are not continuous monitoring.
- Known-vulnerability (CVE) matching is out of scope.

Control-specific limits:

- **ACC-01:** Match blocks are evaluated for root and each declared admin user from localhost; Match rules keyed on other source addresses are not evaluated.
- **RES-01:** Off-host copies cannot be verified from inside the host; they are covered by attestation.
- **NET-01:** Cloud-provider security groups and network ACLs are invisible from inside the host; if they are the real perimeter, review them separately.
- **NET-03:** Rules in the DOCKER-USER chain are not evaluated; external probing (NET-04) is what proves the result.
- **ACC-02:** Whether each key's owner is still entitled to access is a human judgement; the key inventory is listed in the details for review.
- **PAT-03:** Image age is a proxy: a recent build of an old base image passes. CVE matching is out of scope.
- **RES-04:** Covers backups under the declared backup_paths on this host, taking parent directories into account; ACLs and access to off-host copies are not checked.
