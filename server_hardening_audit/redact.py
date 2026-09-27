"""Redaction gate: detect secrets in files before they are published.

``redact-check PATH`` scans every text file under PATH and reports the file,
line and kind of each hit -- never the matched secret itself. Any hit is a
failure. CI runs it over examples/.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

MAX_FILE = 16 * 1024 * 1024

# Values that look like an assignment but carry no secret.
_PLACEHOLDER = re.compile(
    r"(?i)^(<[^>]*>|\*+|x{3,}|redacted|\[redacted\]|none|null|nil|no|yes|true|false|"
    r"changeme|example|your[_-]?\w*|\$\{?\w+\}?|%\(\w+\)s|\{\{.*\}\}|\.\.\.|\"\"|'')$")

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key block", re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    ("credentials in URL", re.compile(
        r"\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@'\"]+:[^\s/@'\"]+@[^\s/'\"]+", re.I)),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe secret key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b")),
    ("Anthropic/OpenAI API key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b")),
    ("JSON Web Token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("password hash", re.compile(r"\$(?:1|2[aby]|5|6|y|gy|7)\$[./A-Za-z0-9$=]{20,}")),
]

_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|client[_-]?secret|token|auth[_-]?token|"
    r"access[_-]?token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"database[_-]?url|db[_-]?pass(?:word)?)\b[\"']?\s*[:=]\s*[\"']?([^\s\"',;]+)")


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    kind: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.kind}"


def scan_text(text: str, path: str = "<text>") -> list[Hit]:
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, pattern in PATTERNS:
            if pattern.search(line):
                hits.append(Hit(path, lineno, kind))
        for m in _ASSIGNMENT.finditer(line):
            if not _PLACEHOLDER.match(m.group(2)):
                hits.append(Hit(path, lineno, f"{m.group(1).lower()} assignment"))
    return hits


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def scan_path(root: Path) -> tuple[list[Hit], int]:
    """Return (hits, files scanned). Binary files are skipped."""
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    hits: list[Hit] = []
    scanned = 0
    for f in files:
        data = f.read_bytes()[:MAX_FILE]
        if _is_binary(data):
            continue
        scanned += 1
        hits.extend(scan_text(data.decode("utf-8", "replace"), str(f)))
    return hits, scanned
