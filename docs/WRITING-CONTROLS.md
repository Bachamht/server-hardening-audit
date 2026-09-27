# Writing controls

A control is a TOML table in `controls/*.toml`. It says what to check, how
to judge the result, why it matters and which framework clauses it gives
evidence for. It cannot contain code: parsers, collectors and assertion
operators are referenced by name.

## Example

```toml
[[control]]
id = "NET-02"
title = "Only intended services listen on non-loopback addresses"
domain = "network"                        # access | network | patching | detection | resilience | baseline
severity = "critical"                     # critical | high | medium | low
platforms = ["debian", "ubuntu", "rhel"]  # host not listed → NA
# implemented = ["debian", "ubuntu"]      # listed platform without an implementation → UNKNOWN

[[control.check]]
type = "cmd"
argv = ["ss", "-tlnpH"]
parser = "ss_listeners"
save_as = "ss-tcp.txt"                    # evidence file name; also the default check name ("ss-tcp")

[[control.check]]
type = "cmd"
argv = ["ss", "-ulnpH"]
parser = "ss_listeners"
save_as = "ss-udp.txt"

[control.assert]
op = "public_listeners_within"
source = ["ss-tcp", "ss-udp"]
ports = { param = "profile.public_ports" }
udp_ports = { param = "profile.public_udp_ports" }

[control.text]
rationale = "Why this matters, in two or three sentences."
remediation = "What to do about a FAIL, as concrete as possible."
disruptive = true                         # does the fix interrupt service?
limitations = "What this control cannot see."   # optional; shown in the report

[control.refs]
iso27001_2022 = ["A.8.20", "A.8.21"]
essential_eight = []                      # requirement IDs from frameworks/essential-eight.toml
cis = []                                  # not provided by this project
```

Unknown keys anywhere are rejected, so a typo fails loudly.

## Check types

| type | Keys | Result available to the assertion |
|---|---|---|
| `cmd` | `argv`, `parser` (default `text`), `save_as`, `name`, `ok_exit` (default `[0]`), `missing` (`unknown`\|`na`), `missing_reason` | parsed stdout; exit code |
| `file` | `path`, `parser`, `save_as`, `name`, `missing` (`fact`\|`unknown`\|`na`) | parsed content, or `null` when missing and `missing = "fact"` |
| `glob` | `pattern`, `save_as`, `name` | list of stat records; content is never read |
| `stat` | `path`, `save_as`, `name` | one stat record (`exists`, `kind`, `mode`, `owner`, `group`, `size`, `mtime`) |
| `collector` | `collector`, `params`, `name` | whatever the collector returns |
| `manual` | `instructions` | none: the verdict is MANUAL until attested |

`argv` must pass the command allowlist in `server_hardening_audit/policy.py`
and `path` must pass the read allowlist. A check that fails — command
missing, permission denied, unexpected exit code, unparseable output — makes
the control UNKNOWN (or NA where `missing = "na"` says so). The assertion
only runs when every check succeeded.

A control can end in PASS but still need a person for part of it:

```toml
[control.manual_part]
when = "profile.backup_offsite_required"
instructions = "Confirm a copy exists on another system and attest it."
```

## Assertion operators

`source` names a check (`"ss-tcp"`) or a path into a structured result
(`"fw.extra_ports"`). Any argument can be a literal or
`{ param = "profile.<field>" }`.

| op | Arguments | PASS when |
|---|---|---|
| `kv_equals` | `source`, `expect` (key → value or list of accepted values), `optional` | every expected key has an accepted value; a missing key is UNKNOWN unless optional |
| `regex_present` / `regex_absent` | `source`, `pattern`, `description` | the pattern is found / not found (multiline) |
| `exit_code` | `source`, `expect` (int or list) | the check's exit code is accepted |
| `count_at_least` / `count_at_most` | `source`, `min` / `max`, `description` | the list has at least / at most that many items |
| `value_at_least` / `value_at_most` | `source`, `min` / `max`, `description` | the number is within the bound |
| `mode_at_most` | `source`, `max` (e.g. `"0600"`) | no matching file has permission bits outside the mask |
| `owner_is` | `source`, `owner` (name or list) | every matching file has an accepted owner |
| `age_at_most` | `source`, `max_hours` | the newest matching file is recent enough; nothing found is FAIL |
| `public_listeners_within` | `source`, `ports`, `udp_ports` | every non-loopback listener is on a declared port (DHCP clients on an interface are exempt) |
| `all_of` / `any_of` | `of` (list of assertions) | all / any pass. `all_of`: any FAIL → FAIL, else any UNKNOWN → UNKNOWN. `any_of`: any PASS → PASS |

A collector can mark a single fact as undetermined with
`{"__unknown__": "reason"}`; any operator that reads it returns UNKNOWN with
that reason.

## Parsers

`text`, `lines`, `value`, `json`, `env_kv`, `sshd_kv`, `ss_listeners`,
`ufw_status`, `iptables_rules`, `nft_ruleset`, `firewalld_list`,
`apt_upgradable`, `dpkg_status`, `systemctl_show`, `unit_list`,
`fail2ban_status`, `passwd`, `group`, `systemd_ini`, `apt_conf`. They live in
`server_hardening_audit/parsers/` and raise `ParseError` on input they do not
understand — which becomes UNKNOWN, never a guess.

## Adding a collector

Use a collector when a check needs several steps or logic an assertion
cannot express. In `server_hardening_audit/collectors/`:

1. Register it with `@collector(name, plan=[...])`. The plan lists every
   operation it may perform (`run(...)`, `read(...)`, `derived(...)`,
   `stat(...)`, `listing(...)`); `list` prints it and the policy tests verify
   each command against the allowlist.
2. Do all IO through the context helpers (`ctx.cmd`, `ctx.text`,
   `ctx.derive`, `ctx.glob`, `ctx.stat`). They record evidence, make replay
   work, and raise `Undetermined` on anything but a clean result.
3. Raise `NotApplicable("reason")` or `Undetermined("reason")`; return a
   dict of facts, including a `violations` list where that is natural.
4. If a new command is needed, add the narrowest grammar to `policy.py`.
   Anything that could change host state needs the maintainer's approval.
5. If a source is sensitive, add a deriver in `derive.py` bound to its paths
   and keep only what the control needs.

## Framework references

`refs.essential_eight` takes requirement IDs from
`frameworks/essential-eight.toml` (e.g. `PO-ML1-05`); `refs.iso27001_2022`
takes Annex A numbers present in `frameworks/iso27001-2022.toml`. Loading
fails if a reference does not exist or points at a clause marked not
applicable. Whether host evidence fully or only partly covers a clause is a
property of the clause (`coverage`), set in the framework file.

## Tests every control needs

Add `tests/fixtures/controls/<ID>.toml` with at least one `PASS` and one
`FAIL` scenario (plus NA/UNKNOWN where they can occur). A scenario lists the
operations the control performs and what the host answered; the test writes
them in the evidence layout and runs the real `audit --replay`:

```toml
[[scenario]]
name = "database listening on all interfaces"
expect = "FAIL"
summary_contains = "tcp/5432"
call = [
  { op = "cmd", argv = ["ss", "-tlnpH"], stdout_file = "ss-tcp-webhost.synthetic.txt",
    replace = [["127.0.0.1:5432", "0.0.0.0:5432"]] },
  { op = "cmd", argv = ["ss", "-ulnpH"], stdout = "" },
]
```

Raw outputs go in `tests/fixtures/raw/`. Name hand-written ones
`*.synthetic.txt`; prefer output captured from a container. `make check`
must pass before a commit.
