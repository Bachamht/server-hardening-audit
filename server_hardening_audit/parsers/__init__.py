"""Parsers: raw command output or file content -> structured data.

Parsers are pure functions of text. They raise ParseError on input they do
not understand, which the engine reports as UNKNOWN rather than guessing.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

PARSERS: dict[str, Callable[[str], Any]] = {}


class ParseError(ValueError):
    pass


def parser(name: str):
    def register(fn: Callable[[str], Any]) -> Callable[[str], Any]:
        PARSERS[name] = fn
        return fn
    return register


def parse(name: str, text: str) -> Any:
    return PARSERS[name](text)


@parser("text")
def text(raw: str) -> str:
    return raw


@parser("lines")
def lines(raw: str) -> list[str]:
    return [ln for ln in raw.splitlines() if ln.strip()]


@parser("value")
def value(raw: str) -> str:
    """A single-value file such as /proc/sys/...: stripped content."""
    return raw.strip()


@parser("env_kv")
def env_kv(raw: str) -> dict[str, str]:
    """KEY=value lines (os-release, `timedatectl show`); quotes stripped."""
    out: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        out[key.strip()] = val
    return out


@parser("sshd_kv")
def sshd_kv(raw: str) -> dict[str, str]:
    """`sshd -T` output: lowercase keyword, space, value. Repeated keywords
    (port, listenaddress, hostkey ...) are joined with ','."""
    out: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        key, _, val = line.partition(" ")
        if not key.isalnum() and not key.replace("_", "").isalnum():
            raise ParseError(f"unexpected sshd -T line: {line[:80]!r}")
        key = key.lower()
        out[key] = f"{out[key]},{val.strip()}" if key in out else val.strip()
    if not out:
        raise ParseError("empty sshd -T output")
    return out


from . import network, system  # noqa: E402,F401  (register the remaining parsers)
