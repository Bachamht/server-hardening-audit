"""Minimal TOML writer for the files this tool emits (attestations).

Supports strings, integers, floats, booleans, lists of scalars, nested
tables and arrays of tables -- nothing more is needed.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

_BARE = re.compile(r"[A-Za-z0-9_-]+")


def _key(k: str) -> str:
    return k if _BARE.fullmatch(k) else json.dumps(k)


def _scalar(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            raise ValueError("NaN/inf not supported")
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)  # JSON escapes are valid TOML basic strings
    if isinstance(v, list):
        return "[" + ", ".join(_scalar(x) for x in v) + "]"
    raise TypeError(f"cannot write {type(v).__name__} to TOML")


def _table(prefix: str, table: dict[str, Any], out: list[str]) -> None:
    subtables = []
    for k, v in table.items():
        if isinstance(v, dict):
            subtables.append((k, v))
        elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            subtables.append((k, v))
        else:
            out.append(f"{_key(k)} = {_scalar(v)}")
    for k, v in subtables:
        name = f"{prefix}.{_key(k)}" if prefix else _key(k)
        if isinstance(v, dict):
            out.append(f"\n[{name}]")
            _table(name, v, out)
        else:
            for item in v:
                out.append(f"\n[[{name}]]")
                _table(name, item, out)


def dumps(doc: dict[str, Any], header: str = "") -> str:
    out = [f"# {line}" if line else "#" for line in header.splitlines()]
    _table("", doc, out)
    return "\n".join(out).lstrip("\n") + "\n"
