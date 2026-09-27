"""Turn a run into a copy that can be published.

- A private map file replaces host names, domains, user names, paths and
  container names with placeholders. The same original always becomes the
  same placeholder, so the report stays internally consistent.
- IPv4 and IPv6 addresses are replaced automatically with documentation
  addresses (RFC 5737 192.0.2.0/24, RFC 3849 2001:db8::/32). Loopback and
  wildcard addresses are kept: they carry meaning ("bound to 127.0.0.1").
- Numbers are never changed.
- Controls can be dropped entirely (--drop-controls): they appear as
  "withheld" rather than silently vanishing into "not assessed".

Output is refused unless the redaction gate passes and no original value
from the map (or any replaced address) survives anywhere in it.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import frameworks, redact, report
from .loader import ConfigError, ControlSet, parse_toml

KEEP_ADDRESSES = {"0.0.0.0", "::", "::1", "*"}  # noqa: S104 -- literal values, not binds
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
DOC_V4 = ipaddress.ip_network("192.0.2.0/24")
DOC_V6 = ipaddress.ip_network("2001:db8::/32")


class ScrubRefused(Exception):
    """The scrubbed output still contains something it must not."""


@dataclass
class Scrubber:
    replacements: dict[str, str]
    addresses: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_map(cls, data: bytes, origin: str) -> Scrubber:
        doc = parse_toml(data, origin)
        extra = set(doc) - {"replace"}
        if extra:
            raise ConfigError(f"{origin}: unknown top-level key(s) {sorted(extra)}")
        repl = doc.get("replace", {})
        if not all(isinstance(k, str) and isinstance(v, str) and k and v
                   for k, v in repl.items()):
            raise ConfigError(f"{origin}: [replace] must map non-empty strings to strings")
        for k, v in repl.items():
            if k.lower() in v.lower():
                raise ConfigError(f"{origin}: placeholder for {k!r} contains the original")
        return cls(repl)

    def _address(self, match: re.Match[str]) -> str:
        text = match.group(0)
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return text
        if text in KEEP_ADDRESSES or ip.is_loopback or ip.is_unspecified \
                or ip in (DOC_V4 if ip.version == 4 else DOC_V6):
            return text
        if text not in self.addresses:
            n = sum(1 for v in self.addresses.values() if (":" in v) == (ip.version == 6))
            self.addresses[text] = (str(DOC_V4[10 + n]) if ip.version == 4
                                    else str(DOC_V6[1 + n]))
        return self.addresses[text]

    def text(self, s: str) -> str:
        for original in sorted(self.replacements, key=len, reverse=True):
            s = re.sub(re.escape(original), lambda _m, o=original: self.replacements[o], s,
                       flags=re.IGNORECASE)
        s = IPV4.sub(self._address, s)
        s = IPV6.sub(self._address, s)
        return s

    def obj(self, o: Any) -> Any:
        if isinstance(o, str):
            return self.text(o)
        if isinstance(o, list):
            return [self.obj(x) for x in o]
        if isinstance(o, dict):
            return {self.text(k): self.obj(v) for k, v in o.items()}
        return o  # numbers and booleans are never changed

    def leftovers(self, s: str) -> list[str]:
        low = s.lower()
        found = [k for k in self.replacements if k.lower() in low]
        found += [a for a in self.addresses if re.search(
            rf"(?<![\w.:]){re.escape(a)}(?![\w:]|\.\d)", s)]
        return found


def drop(doc: dict[str, Any], ids: list[str]) -> dict[str, Any]:
    known = {f["id"] for f in doc["findings"]}
    unknown = [i for i in ids if i not in known]
    if unknown:
        raise ConfigError(f"--drop-controls: unknown control id(s) {', '.join(unknown)}")
    out = dict(doc)
    out["findings"] = [f for f in doc["findings"] if f["id"] not in ids]
    out["withheld"] = sorted(set(doc.get("withheld", [])) | set(ids))
    return out


def _with_note(md: str, note: str | None) -> str:
    if not note:
        return md
    title, _, rest = md.partition("\n")
    return f"{title}\n\n> {note}\n{rest}"


def render_all(doc: dict[str, Any], run: dict[str, Any], controls: ControlSet,
               note: str | None) -> dict[str, str]:
    files = {
        "sample-report.md": _with_note(report.render_markdown(doc, run), note),
        "sample-findings.json": json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
    }
    for name in frameworks.NAMES:
        fw = frameworks.load(name, controls)
        view = frameworks.evaluate(fw, doc)
        files[f"sample-{name}.md"] = _with_note(frameworks.render_markdown(fw, view, run), note)
    return files


def scrub_run(doc: dict[str, Any], run: dict[str, Any], scrubber: Scrubber,
              controls: ControlSet, drop_ids: list[str], note: str | None) -> dict[str, str]:
    """Return {filename: content}. Raises ScrubRefused if a gate fails."""
    doc = drop(doc, drop_ids) if drop_ids else doc
    # Scrub the data first, then render, so tables and JSON agree.
    public_run = scrubber.obj({k: v for k, v in run.items() if k != "profile"})
    public_run["profile"] = {"name": scrubber.text(run["profile"]["name"])}
    public_doc = scrubber.obj(doc)
    files = render_all(public_doc, public_run, controls, note)
    files = {name: scrubber.text(content) for name, content in files.items()}
    problems = []
    for name, content in files.items():
        for hit in redact.scan_text(content, name):
            problems.append(str(hit))
        for value in scrubber.leftovers(content):
            problems.append(f"{name}: original value still present ({len(value)} chars)")
    if problems:
        raise ScrubRefused("; ".join(problems[:20]))
    return files
