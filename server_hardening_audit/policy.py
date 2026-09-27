"""Command allowlist: the code-level read-only guarantee.

Every external command the engine runs passes through :func:`check` first.
The policy is default-deny, the same principle as a firewall: a program that
is not listed, or an argument vector that does not match one of that
program's rules exactly, is refused. Refusals are reported as UNKNOWN with
the returned reason; they never fall through to execution.

Rules describe argument grammars rather than prefixes. A rule names a fixed
leading token sequence (the subcommand), the options that may follow, and
what positional arguments look like. Anything else -- an unknown option, a
positional that starts with ``-``, a ``--`` terminator, an extra subcommand --
does not match. Adding a rule that could change host state requires the
project owner's approval (see docs/DESIGN.md).

The runner resolves ``argv[0]`` against a fixed search path, so rules key on
the bare program name and a path in ``argv[0]`` is refused.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

MAX_ARGS = 32
MAX_TOKEN_LEN = 512


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# Value shapes. None of these may begin with "-", so a value can never be
# mistaken for an option by the target program.
UNIT = _re(r"[A-Za-z0-9@_.:\\][A-Za-z0-9@_.:\\-]{0,254}")
UNIT_GLOB = _re(r"[A-Za-z0-9@_.:\\*?\[\]][A-Za-z0-9@_.:\\*?\[\]-]{0,254}")
UNIT_TYPE = _re(r"(service|socket|target|timer|mount|path|slice|scope|device|swap|automount)"
                r"(,(service|socket|target|timer|mount|path|slice|scope|device|swap|automount))*")
UNIT_STATE = _re(r"[a-z-]{1,32}(,[a-z-]{1,32})*")
PROPERTIES = _re(r"[A-Za-z][A-Za-z0-9]{0,63}(,[A-Za-z][A-Za-z0-9]{0,63})*")
NAME = _re(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
USER = _re(r"[a-z_][a-z0-9_.-]{0,31}\$?")
DOCKER_REF = _re(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}")
GO_TEMPLATE = _re(r"(?!-)[^\x00-\x08\x0a-\x1f]{1,400}")
PKG = _re(r"[a-z0-9][a-z0-9+.:*-]{0,127}")
DPKG_FORMAT = _re(r"(?!-)[^\x00]{1,400}")
TIME_SPEC = _re(r"[A-Za-z0-9][A-Za-z0-9 :+.-]{0,39}")
COUNT = _re(r"[0-9]{1,6}")
SYSLOG_ID = _re(r"[A-Za-z0-9_.@-]{1,64}")
PRIORITY = _re(r"[0-7]|emerg|alert|crit|err|warning|notice|info|debug")
JOURNAL_OUTPUT = _re(r"short|short-iso|short-iso-precise|short-precise|short-unix|cat|json|export")
JOURNAL_MATCH = _re(r"_?[A-Z][A-Z0-9_]{0,63}=[A-Za-z0-9_.@:/-]{1,128}")
IPT_TABLE = _re(r"filter|nat|mangle|raw|security")
IPT_CHAIN = _re(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,28}")
FIREWALLD_ZONE = _re(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,31}")
PS_FORMAT = _re(r"[a-z%][a-z0-9_,:=%]{0,127}")
PS_SORT = _re(r"[+-]?[a-z%]{1,16}(,[+-]?[a-z%]{1,16})*")
SSHD_CONN_SPEC = _re(r"(user|host|addr|laddr|lport|rdomain)=[A-Za-z0-9_.:%-]{1,253}"
                     r"(,(user|host|addr|laddr|lport|rdomain)=[A-Za-z0-9_.:%-]{1,253})*")
F2B_PARAM = _re(r"bantime|findtime|maxretry|logpath|backend|ignoreip|ignoreself|journalmatch"
                r"|banip|actions|maxlines|usedns|logencoding|failregex|ignoreregex")

FLAG = None  # option that takes no value


@dataclass(frozen=True)
class Rule:
    """One allowed argument grammar for a program.

    ``prefix`` must match ``argv[1:]`` literally. After it, tokens beginning
    with ``-`` must be keys of ``options`` (``FLAG`` for no value, else a
    pattern the value must fully match); other tokens are positionals and
    must fully match ``positional``.
    """

    prefix: tuple[str, ...]
    options: Mapping[str, re.Pattern[str] | None] = field(default_factory=dict)
    positional: re.Pattern[str] | None = None
    min_pos: int = 0
    max_pos: int = 0
    required: frozenset[str] = frozenset()
    require_any: frozenset[str] = frozenset()

    def match(self, args: Sequence[str]) -> str | None:
        """Return None on match, else a short reason for the mismatch."""
        n = len(self.prefix)
        if tuple(args[:n]) != self.prefix:
            return "subcommand not allowed"
        seen: set[str] = set()
        positionals = 0
        i = n
        while i < len(args):
            tok = args[i]
            if tok.startswith("-") and tok != "-":
                name, eq, inline = tok.partition("=") if tok.startswith("--") else (tok, "", "")
                if name not in self.options:
                    return f"option {name!r} not allowed"
                pattern = self.options[name]
                if pattern is FLAG:
                    if eq:
                        return f"option {name!r} takes no value"
                else:
                    if eq:
                        value = inline
                    else:
                        i += 1
                        if i >= len(args):
                            return f"option {name!r} is missing its value"
                        value = args[i]
                    if not pattern.fullmatch(value):
                        return f"value {value!r} for {name!r} not allowed"
                seen.add(name)
            else:
                if self.positional is None or not self.positional.fullmatch(tok):
                    return f"argument {tok!r} not allowed"
                positionals += 1
            i += 1
        if positionals < self.min_pos or positionals > self.max_pos:
            return "wrong number of arguments"
        missing = self.required - seen
        if missing:
            return "missing required option " + ", ".join(sorted(missing))
        if self.require_any and not (self.require_any & seen):
            return "missing one of " + ", ".join(sorted(self.require_any))
        return None


def _rules() -> dict[str, tuple[Rule, ...]]:
    many = 64
    systemctl_common = {"--no-pager": FLAG, "--no-legend": FLAG, "--plain": FLAG}
    docker_fmt = {"--format": GO_TEMPLATE, "-f": GO_TEMPLATE}
    ipt_common = {"-t": IPT_TABLE, "-w": FLAG}
    return {
        "sshd": (
            Rule(("-T",), {"-C": SSHD_CONN_SPEC}),
        ),
        "ss": (
            Rule(("-tlnpH",)),
            Rule(("-ulnpH",)),
        ),
        "systemctl": (
            Rule(("is-active",), systemctl_common, UNIT, 1, many),
            Rule(("is-enabled",), systemctl_common, UNIT, 1, many),
            Rule(("show",), {**systemctl_common, "-p": PROPERTIES, "--property": PROPERTIES,
                             "--value": FLAG, "--all": FLAG}, UNIT, 0, many),
            Rule(("cat",), systemctl_common, UNIT, 1, many),
            Rule(("list-timers",), {**systemctl_common, "--all": FLAG}, UNIT_GLOB, 0, many),
            Rule(("list-units",), {**systemctl_common, "--all": FLAG, "--type": UNIT_TYPE,
                                   "--state": UNIT_STATE}, UNIT_GLOB, 0, many),
            Rule(("list-unit-files",), {**systemctl_common, "--type": UNIT_TYPE,
                                        "--state": UNIT_STATE}, UNIT_GLOB, 0, many),
        ),
        "ufw": (
            Rule(("status",)),
            Rule(("status", "verbose")),
            Rule(("status", "numbered")),
        ),
        "fail2ban-client": (
            Rule(("ping",)),
            Rule(("status",), positional=NAME, max_pos=1),
            # `get <jail> <param>` is matched by _fail2ban_get.
        ),
        "docker": (
            Rule(("ps",), {**docker_fmt, "-a": FLAG, "--all": FLAG, "-q": FLAG, "--quiet": FLAG,
                           "--no-trunc": FLAG}),
            Rule(("inspect",), {**docker_fmt, "--type": _re(r"container|image")},
                 DOCKER_REF, 1, many),
            Rule(("port",), positional=DOCKER_REF, min_pos=1, max_pos=1),
            Rule(("version",), docker_fmt),
            Rule(("info",), docker_fmt),
            Rule(("image", "ls"), {**docker_fmt, "-a": FLAG, "--all": FLAG, "-q": FLAG,
                                   "--no-trunc": FLAG, "--digests": FLAG}),
            Rule(("image", "inspect"), docker_fmt, DOCKER_REF, 1, many),
        ),
        "journalctl": (
            Rule((), {
                "--no-pager": FLAG, "-q": FLAG, "--quiet": FLAG, "--utc": FLAG,
                "--no-hostname": FLAG, "-r": FLAG, "--reverse": FLAG, "-k": FLAG,
                "--dmesg": FLAG, "-b": FLAG, "--boot": FLAG, "--disk-usage": FLAG,
                "--list-boots": FLAG,
                "-u": UNIT, "--unit": UNIT, "-t": SYSLOG_ID, "--identifier": SYSLOG_ID,
                "-p": PRIORITY, "--priority": PRIORITY, "-S": TIME_SPEC, "--since": TIME_SPEC,
                "-U": TIME_SPEC, "--until": TIME_SPEC, "-n": COUNT, "--lines": COUNT,
                "-o": JOURNAL_OUTPUT, "--output": JOURNAL_OUTPUT,
            }, JOURNAL_MATCH, 0, 8, required=frozenset({"--no-pager"})),
        ),
        "iptables": _iptables_rules(ipt_common),
        "ip6tables": _iptables_rules(ipt_common),
        "nft": (
            Rule(("list", "ruleset")),
            Rule(("-j", "list", "ruleset")),
            Rule(("list", "tables")),
        ),
        "firewall-cmd": (
            Rule((), {"--state": FLAG, "--get-default-zone": FLAG, "--get-active-zones": FLAG,
                      "--list-all": FLAG, "--list-all-zones": FLAG, "--permanent": FLAG,
                      "--zone": FIREWALLD_ZONE},
                 require_any=frozenset({"--state", "--get-default-zone", "--get-active-zones",
                                        "--list-all", "--list-all-zones"})),
        ),
        "apt": (
            Rule(("list",), {"--upgradable": FLAG, "-qq": FLAG}, PKG, 0, many,
                 required=frozenset({"--upgradable"})),
            Rule(("list",), {"--installed": FLAG, "-qq": FLAG}, PKG, 0, many,
                 required=frozenset({"--installed"})),
        ),
        "dpkg-query": (
            Rule(("-W",), {"-f": DPKG_FORMAT, "--showformat": DPKG_FORMAT}, PKG, 0, many),
            Rule(("-l",), positional=PKG, max_pos=many),
            Rule(("-s",), positional=PKG, min_pos=1, max_pos=many),
        ),
        "sudo": (
            Rule((), {"-n": FLAG, "-l": FLAG, "-U": USER},
                 required=frozenset({"-l", "-U"})),
        ),
        "timedatectl": (
            Rule(("show",), {"-p": PROPERTIES, "--property": PROPERTIES, "--value": FLAG,
                             "--all": FLAG, "--no-pager": FLAG}),
            Rule(("status",), {"--no-pager": FLAG}),
            Rule(("show-timesync",), {"-p": PROPERTIES, "--property": PROPERTIES,
                                      "--value": FLAG, "--all": FLAG, "--no-pager": FLAG}),
        ),
        "systemd-detect-virt": (
            Rule(()),
        ),
        "ps": (
            Rule((), {"-e": FLAG, "-o": PS_FORMAT, "-eo": PS_FORMAT, "--no-headers": FLAG,
                      "--sort": PS_SORT}, require_any=frozenset({"-o", "-eo"})),
        ),
    }


def _iptables_rules(common: Mapping[str, re.Pattern[str] | None]) -> tuple[Rule, ...]:
    return (
        Rule((), {**common, "-S": FLAG}, IPT_CHAIN, 0, 1, required=frozenset({"-S"})),
        Rule((), {**common, "-L": FLAG, "-n": FLAG, "-v": FLAG, "-x": FLAG,
                  "--line-numbers": FLAG}, IPT_CHAIN, 0, 1,
             required=frozenset({"-L", "-n"})),
    )


def _fail2ban_get(args: Sequence[str]) -> str | None:
    # `fail2ban-client get <jail> <param>`: the jail is free-form, so a
    # generic Rule cannot tell a jail name from a subcommand. Match exactly.
    if len(args) == 3 and args[0] == "get" and NAME.fullmatch(args[1]) \
            and F2B_PARAM.fullmatch(args[2]):
        return None
    return "only `get <jail> <param>` with a known read-only parameter is allowed"


RULES: dict[str, tuple[Rule, ...]] = _rules()
PROGRAMS: frozenset[str] = frozenset(RULES)


def check(argv: Sequence[str]) -> Decision:
    """Decide whether ``argv`` may be executed. Default: deny."""
    if not isinstance(argv, (list, tuple)) or not argv:
        return Decision(False, "empty or malformed argv")
    if len(argv) > MAX_ARGS + 1:
        return Decision(False, "too many arguments")
    for tok in argv:
        if not isinstance(tok, str):
            return Decision(False, "argv contains a non-string token")
        if "\x00" in tok or len(tok) > MAX_TOKEN_LEN:
            return Decision(False, "argv contains a NUL byte or an oversized token")
    prog, args = argv[0], list(argv[1:])
    if "/" in prog:
        return Decision(False, f"program must be a bare name, got {prog!r}")
    rules = RULES.get(prog)
    if rules is None:
        return Decision(False, f"program {prog!r} is not on the allowlist")
    if "--" in args:
        return Decision(False, "'--' terminator is not allowed")

    if prog == "fail2ban-client" and args[:1] == ["get"]:
        reason = _fail2ban_get(args)
        return Decision(reason is None, reason or "allowed")

    reasons = []
    for rule in rules:
        reason = rule.match(args)
        if reason is None:
            return Decision(True, "allowed")
        reasons.append(reason)
    # Report the mismatch from the rule that got furthest: the first rule
    # whose prefix matched, else the generic one.
    specific = [r for r in reasons if r != "subcommand not allowed"]
    detail = specific[0] if specific else "subcommand not allowed"
    return Decision(False, f"{prog}: {detail}: {' '.join(argv)!r}")
