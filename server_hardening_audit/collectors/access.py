"""Access-domain collectors: SSH, keys, accounts, sudo, MFA."""

from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import Any

from . import (
    CollectContext,
    NotApplicable,
    Undetermined,
    batched,
    collector,
    derived,
    listing,
    read,
    run,
)

SSHD_KEYS = ("passwordauthentication", "permitrootlogin", "pubkeyauthentication",
             "kbdinteractiveauthentication", "challengeresponseauthentication",
             "permitemptypasswords", "authenticationmethods", "usepam", "maxauthtries",
             "allowusers", "allowgroups", "denyusers", "authorizedkeysfile")
CONN_SPEC = "user={user},host=localhost,addr=127.0.0.1"
_MATCH = re.compile(r"^\s*Match\s", re.IGNORECASE | re.MULTILINE)
_INCLUDE = re.compile(r"^\s*Include\s+(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
NOLOGIN_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")


def _sshd_t(ctx: CollectContext, argv: list[str]) -> dict[str, str]:
    res = ctx.cmd(argv, missing="OpenSSH server (sshd) is not installed")
    return ctx.parse("sshd_kv", res.stdout, "sshd -T")


def sshd_config_files(ctx: CollectContext) -> dict[str, Any]:
    """Main config, Include patterns, drop-ins and whether each is loaded."""
    main = ctx.text("/etc/ssh/sshd_config")
    if main is None:
        raise Undetermined("/etc/ssh/sshd_config does not exist")
    patterns = []
    for m in _INCLUDE.finditer(main):
        for pat in m.group(1).split():
            patterns.append(pat if pat.startswith("/") else posixpath.join("/etc/ssh", pat))
    dropins = []
    match_blocks = bool(_MATCH.search(main))
    for entry in ctx.glob("/etc/ssh/sshd_config.d/*"):
        loaded = any(fnmatch.fnmatchcase(entry["path"], p) for p in patterns)
        dropins.append({"path": entry["path"], "loaded": loaded, "mode": entry["mode"],
                        "owner": entry["owner"]})
        if loaded and entry["kind"] == "file":
            content = ctx.text(entry["path"]) or ""
            match_blocks = match_blocks or bool(_MATCH.search(content))
    return {"include_patterns": patterns, "dropins": dropins, "match_blocks": match_blocks}


@collector("sshd_effective", plan=[
    run("sshd", "-T"),
    read("/etc/ssh/sshd_config", "for Include and Match lines"),
    listing("/etc/ssh/sshd_config.d/*"),
    read("/etc/ssh/sshd_config.d/<file>", "each drop-in matched by an Include pattern"),
    run("sshd", "-T", "-C", CONN_SPEC.format(user="<user>"),
        note="only if Match blocks exist; once for root and each profile admin_users entry"),
])
def sshd_effective(ctx: CollectContext) -> dict[str, Any]:
    base = _sshd_t(ctx, ["sshd", "-T"])
    files = sshd_config_files(ctx)
    evaluations = {"global": base}
    if files["match_blocks"]:
        for user in ["root", *ctx.profile["admin_users"]]:
            evaluations[f"user={user}"] = _sshd_t(
                ctx, ["sshd", "-T", "-C", CONN_SPEC.format(user=user)])
    effective, differences = {}, {}
    for key in SSHD_KEYS:
        values = {ctxname: ev.get(key) for ctxname, ev in evaluations.items()}
        distinct = list(dict.fromkeys(v for v in values.values() if v is not None))
        if not distinct:
            continue
        effective[key] = distinct[0] if len(distinct) == 1 else "|".join(distinct)
        if len(distinct) > 1:
            differences[key] = values
    # OpenSSH < 8.7 reports the same setting as challengeresponseauthentication.
    if "kbdinteractiveauthentication" not in effective and \
            "challengeresponseauthentication" in effective:
        effective["kbdinteractiveauthentication"] = effective["challengeresponseauthentication"]
    return {"effective": effective, "differences": differences,
            "evaluated": list(evaluations), **files}


def _login_homes(ctx: CollectContext) -> dict[str, str]:
    users = ctx.parsed("passwd", "/etc/passwd")
    if users is None:
        raise Undetermined("/etc/passwd does not exist")
    homes: dict[str, str] = {}
    for u in users:
        if (u["uid"] == 0 or u["shell"] not in NOLOGIN_SHELLS) and u["home"].startswith("/") \
                and u["home"] != "/":
            homes.setdefault(u["home"], u["name"])
    return homes


def collect_authorized_keys(ctx: CollectContext) -> list[dict[str, Any]]:
    files = []
    for home, user in sorted(_login_homes(ctx).items()):
        for entry in ctx.glob(f"{home}/.ssh/authorized_keys*"):
            if not re.search(r"/authorized_keys2?$", entry["path"]) or entry["kind"] != "file":
                continue
            value = ctx.derive("authorized_keys", entry["path"]) or {}
            files.append({"path": entry["path"], "user": user, "mode": entry["mode"],
                          "owner": entry["owner"], "keys": value.get("entries", []),
                          "invalid_lines": value.get("invalid_lines", 0)})
    return files


@collector("authorized_keys", plan=[
    read("/etc/passwd", "home directories of accounts that can log in"),
    listing("<home>/.ssh/authorized_keys*"),
    derived("authorized_keys", "<home>/.ssh/authorized_keys"),
])
def authorized_keys(ctx: CollectContext) -> dict[str, Any]:
    files = collect_authorized_keys(ctx)
    violations, review = [], []
    for f in files:
        where = f["path"]
        if f["path"].endswith("authorized_keys2"):
            violations.append(f"{where}: deprecated authorized_keys2 file present")
        if f["mode"] & 0o077:
            violations.append(f"{where}: mode {f['mode']:04o} is wider than 0600")
        if f["owner"] not in (f["user"], "root"):
            violations.append(f"{where}: owned by {f['owner']}, not {f['user']}")
        if f["invalid_lines"]:
            violations.append(f"{where}: {f['invalid_lines']} unparseable line(s)")
        for k in f["keys"]:
            label = f"{where}:{k['line']} ({k['type']} {k['comment'] or '<no comment>'})"
            if k["type"] in ("ssh-dss", "ssh-dss-cert-v01@openssh.com"):
                violations.append(f"{label}: DSA key")
            if k["type"] == "ssh-rsa" and k["bits"] is not None and k["bits"] < 3072:
                violations.append(f"{label}: RSA key of {k['bits']} bits (< 3072)")
            if not k["comment"]:
                review.append(f"{label}: no comment; owner cannot be attributed")
            opts = [o for o in k["options"] if o in ("command", "from", "permitopen",
                                                     "environment", "tunnel")]
            if opts:
                review.append(f"{label}: options {','.join(opts)}")
    inventory = [{"path": f["path"], "user": f["user"], "mode": f"{f['mode']:04o}",
                  "keys": [{"type": k["type"], "comment": k["comment"], "bits": k["bits"],
                            "options": k["options"]} for k in f["keys"]]} for f in files]
    return {"files": inventory, "key_count": sum(len(f["keys"]) for f in files),
            "violations": violations, "review": review}


PRIVILEGED_GROUPS = ("root", "sudo", "wheel", "admin", "adm", "docker", "lxd")
# Group memberships that system packages set up and that are expected.
EXPECTED_MEMBERSHIP = {("adm", "syslog")}


@collector("privileged_accounts", plan=[
    read("/etc/passwd"), read("/etc/group"),
    run("ps", "-eo", "user:32,comm", "--no-headers", note="process owners"),
    run("systemctl", "list-units", "--type=service", "--state=running", "--no-legend",
        "--plain"),
    run("systemctl", "show", "-p", "Id,User,DynamicUser", "<unit>...",
        note="running services, in batches"),
])
def privileged_accounts(ctx: CollectContext) -> dict[str, Any]:
    users = ctx.parsed("passwd", "/etc/passwd")
    groups = ctx.parsed("group", "/etc/group")
    if users is None or groups is None:
        raise Undetermined("/etc/passwd or /etc/group missing")
    by_gid = {g["gid"]: name for name, g in groups.items()}
    members: dict[str, set[str]] = {g: set(groups[g]["members"]) for g in PRIVILEGED_GROUPS
                                    if g in groups}
    for u in users:
        primary = by_gid.get(u["gid"])
        if primary in members and u["name"] != "root":
            members[primary].add(u["name"])
    members = {g: m - {"root"} for g, m in members.items()}

    ps = ctx.cmd(["ps", "-eo", "user:32,comm", "--no-headers"])
    process_owners: dict[str, set[str]] = {}
    for line in ps.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] != "root":
            process_owners.setdefault(parts[0], set()).add(parts[1].strip())

    service_users: dict[str, list[str]] = {}
    listed = ctx.try_cmd(["systemctl", "list-units", "--type=service", "--state=running",
                          "--no-legend", "--plain"])
    if listed is not None:
        units = ctx.parse("unit_list", listed.stdout, "systemctl list-units")
        for chunk in batched(units):
            shown = ctx.cmd(["systemctl", "show", "-p", "Id,User,DynamicUser", *chunk])
            for block in ctx.parse("systemctl_show", shown.stdout, "systemctl show"):
                user = block.get("User", "")
                if user and user not in ("root", "0"):  # systemd may report root as uid 0
                    service_users.setdefault(user, []).append(block.get("Id", "?"))

    admins = set(ctx.profile["admin_users"])
    declared_service = set(ctx.profile["service_users"])
    app_accounts = (declared_service | set(process_owners) | set(service_users)) - admins
    uid_of = {u["name"]: u["uid"] for u in users}
    violations = []
    for group, names in sorted(members.items()):
        for name in sorted(names):
            if name in admins or (group, name) in EXPECTED_MEMBERSHIP:
                continue
            if name in app_accounts:
                why = ("declared service account" if name in declared_service
                       else "runs processes/services")
                violations.append(f"{name} ({why}) is in privileged group '{group}'")
            elif uid_of.get(name, 0) >= 1000:
                violations.append(f"{name} is in privileged group '{group}' but is not "
                                  "declared in profile admin_users")
    return {
        "privileged_members": {g: sorted(m) for g, m in sorted(members.items())},
        "app_accounts": sorted(app_accounts),
        "service_unit_users": {u: sorted(v) for u, v in sorted(service_users.items())},
        "violations": violations,
    }


@collector("empty_passwords", plan=[
    derived("shadow_empty_passwords", "/etc/shadow"),
])
def empty_passwords(ctx: CollectContext) -> dict[str, Any]:
    value = ctx.derive("shadow_empty_passwords", "/etc/shadow")
    if value is None:
        raise Undetermined("/etc/shadow does not exist")
    return value


_ALIAS = re.compile(r"^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+(.*)$")
_INCLUDEDIR = re.compile(r"^[#@]includedir\s+(\S+)\s*$")
_INCLUDEFILE = re.compile(r"^[#@]include\s+(\S+)\s*$")


def _logical_lines(text: str) -> list[str]:
    out, buf = [], ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        out.append((buf + line).strip())
        buf = ""
    if buf:
        out.append(buf.strip())
    return out


def parse_sudoers_entries(text: str) -> tuple[list[dict[str, Any]], dict[str, list[str]],
                                               list[str], list[str]]:
    """Return (entries, user_aliases, includedirs, includefiles)."""
    entries, aliases, dirs, incs = [], {}, [], []
    for line in _logical_lines(text):
        if not line:
            continue
        m = _INCLUDEDIR.match(line)
        if m:
            dirs.append(m.group(1))
            continue
        m = _INCLUDEFILE.match(line)
        if m:
            incs.append(m.group(1))
            continue
        if line.startswith("#") or line.startswith("Defaults"):
            continue
        m = _ALIAS.match(line)
        if m:
            if m.group(1) == "User_Alias":
                for part in m.group(2).split(":"):
                    name, _, members = part.partition("=")
                    aliases[name.strip()] = [x.strip() for x in members.split(",") if x.strip()]
            continue
        parts = line.split(None, 1)
        if len(parts) != 2 or "=" not in parts[1]:
            continue
        principals_part, spec = parts
        principals = [p.strip() for p in principals_part.split(",") if p.strip()]
        _, _, cmdspec = spec.partition("=")
        cmdspec = re.sub(r"^\s*\([^)]*\)", "", cmdspec).strip()
        tags = set()
        while True:
            m = re.match(r"^([A-Z_]+):\s*", cmdspec)
            if not m:
                break
            tags.add(m.group(1))
            cmdspec = cmdspec[m.end():]
        commands = [c.strip() for c in cmdspec.split(",")]
        entries.append({"principals": principals, "nopasswd": "NOPASSWD" in tags,
                        "all_commands": "ALL" in commands, "line": line})
    return entries, aliases, dirs, incs


@collector("sudoers", plan=[
    read("/etc/sudoers"),
    listing("/etc/sudoers.d/*"),
    read("/etc/sudoers.d/<file>", "files sudo actually loads: no '.' and no trailing '~'"),
    read("/etc/group", "to expand %group principals"),
])
def sudoers(ctx: CollectContext) -> dict[str, Any]:
    main = ctx.text("/etc/sudoers")
    if main is None:
        raise NotApplicable("sudo is not configured (/etc/sudoers absent)")
    sources = [("/etc/sudoers", main)]
    _, aliases, dirs, incs = parse_sudoers_entries(main)
    ignored = []
    for d in dirs:
        if not d.startswith("/etc/sudoers"):
            ignored.append(f"{d}: includedir outside /etc/sudoers* not read")
            continue
        for f in ctx.glob(f"{d.rstrip('/')}/*"):
            base = posixpath.basename(f["path"])
            if "." in base or base.endswith("~") or f["kind"] != "file":
                ignored.append(f"{f['path']}: not loaded by sudo (name contains '.' or ends '~')")
                continue
            sources.append((f["path"], ctx.text(f["path"]) or ""))
    for inc in incs:
        if inc.startswith("/etc/sudoers"):
            sources.append((inc, ctx.text(inc) or ""))
    all_entries = []
    for path, text in sources:
        e, a, _, _ = parse_sudoers_entries(text)
        aliases.update(a)
        all_entries.extend({**x, "file": path} for x in e)
    groups = ctx.parsed("group", "/etc/group") or {}
    admins = set(ctx.profile["admin_users"])
    service = set(ctx.profile["service_users"])

    def expand(principal: str) -> list[str]:
        if principal.startswith("%"):
            g = groups.get(principal[1:])
            return sorted(g["members"]) if g else []
        if principal in aliases:
            return sorted({u for p in aliases[principal] for u in expand(p)})
        return [principal]

    nopasswd_all, violations = [], []
    for e in all_entries:
        if not (e["nopasswd"] and e["all_commands"]):
            continue
        for principal in e["principals"]:
            users = expand(principal)
            nopasswd_all.append({"file": e["file"], "principal": principal, "users": users})
            for user in users:
                if user == "root" or (user in admins and user not in service):
                    continue
                kind = "service account" if user in service else "account not in admin_users"
                violations.append(f"{e['file']}: {principal} grants NOPASSWD: ALL to "
                                  f"{user} ({kind})")
    return {"nopasswd_all": nopasswd_all, "violations": violations,
            "files_read": [p for p, _ in sources], "ignored": ignored}


@collector("ssh_mfa", plan=[
    run("sshd", "-T"),
    read("/etc/passwd"),
    listing("<home>/.ssh/authorized_keys*"),
    derived("authorized_keys", "<home>/.ssh/authorized_keys", "key types only"),
])
def ssh_mfa(ctx: CollectContext) -> dict[str, Any]:
    cfg = _sshd_t(ctx, ["sshd", "-T"])
    methods = cfg.get("authenticationmethods", "any")
    lists = [] if methods == "any" else methods.split()
    multi_factor_lists = bool(lists) and all(len(x.split(",")) >= 2 for x in lists)
    types = [k["type"] for f in collect_authorized_keys(ctx) for k in f["keys"]]
    all_fido = bool(types) and all(t.startswith("sk-") for t in types)
    if multi_factor_lists:
        how = f"sshd requires multiple methods: {methods}"
    elif all_fido:
        how = "every authorized key is a FIDO (sk-*) hardware key"
    elif cfg.get("passwordauthentication") == "no":
        how = "single factor: public key only (AuthenticationMethods any)"
    else:
        how = "single factor: password or key"
    return {"mfa_enforced": multi_factor_lists or all_fido, "how": how,
            "authenticationmethods": methods,
            "key_types": {t: types.count(t) for t in sorted(set(types))}}
