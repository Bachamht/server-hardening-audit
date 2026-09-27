"""Collectors: trusted engine code for checks that need several steps.

A control file can only name a collector; it cannot supply code. Every
operation a collector performs goes through the runner, so it is
policy-checked, recorded as evidence and replayable. Each collector declares
a ``plan``: the exact operations it may perform, which ``list`` prints and
the policy tests verify.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .. import parsers
from ..runner import CmdResult, Runner


class NotApplicable(Exception):
    """The control does not apply to this host (verdict NA)."""


class Undetermined(Exception):
    """The control applies but could not be checked (verdict UNKNOWN)."""


def unknown(reason: str) -> dict[str, str]:
    """Marker for a single fact that could not be determined. Assertions that
    read it return UNKNOWN with this reason."""
    return {"__unknown__": reason}


@dataclass(frozen=True)
class PlanStep:
    op: str  # run | read | derive | stat | glob | statvfs | tls
    target: tuple[str, ...]  # argv for run; path/pattern otherwise
    note: str = ""

    def render(self) -> str:
        verb = {"run": "run ", "read": "read", "derive": "read", "stat": "stat",
                "glob": "list", "statvfs": "df  ", "tls": "tls "}[self.op]
        text = " ".join(self.target)
        if self.op == "derive":
            text = f"{self.target[1]}  [derived: {self.target[0]} -- raw content not stored]"
        return f"{verb}  {text}" + (f"   ({self.note})" if self.note else "")


def run(*argv: str, note: str = "") -> PlanStep:
    return PlanStep("run", argv, note)


def read(path: str, note: str = "") -> PlanStep:
    return PlanStep("read", (path,), note)


def derived(deriver: str, path: str, note: str = "") -> PlanStep:
    return PlanStep("derive", (deriver, path), note)


def stat(path: str, note: str = "") -> PlanStep:
    return PlanStep("stat", (path,), note)


def listing(pattern: str, note: str = "") -> PlanStep:
    return PlanStep("glob", (pattern,), note)


@dataclass
class CollectContext:
    runner: Runner
    profile: dict[str, Any]
    params: dict[str, Any] = field(default_factory=dict)
    platform: dict[str, Any] = field(default_factory=dict)

    # Helpers. They raise Undetermined on anything other than a clean result,
    # so a collector cannot silently treat a failure as "nothing found".

    def cmd(self, argv: list[str], ok: tuple[int, ...] = (0,), name: str | None = None,
            missing: str | None = None) -> CmdResult:
        res = self.runner.run(argv, name)
        if res.error_kind == "missing" and missing is not None:
            raise NotApplicable(missing)
        if res.error:
            raise Undetermined(f"`{' '.join(argv)}`: {res.error}")
        if res.returncode not in ok:
            detail = (res.stderr.strip().splitlines() or [""])[-1][:200]
            raise Undetermined(f"`{' '.join(argv)}` exited {res.returncode}: {detail}")
        return res

    def try_cmd(self, argv: list[str], ok: tuple[int, ...] = (0,),
                name: str | None = None) -> CmdResult | None:
        """Run; None if the program is not installed. Other errors raise."""
        res = self.runner.run(argv, name)
        if res.error_kind == "missing":
            return None
        if res.error:
            raise Undetermined(f"`{' '.join(argv)}`: {res.error}")
        if res.returncode not in ok:
            detail = (res.stderr.strip().splitlines() or [""])[-1][:200]
            raise Undetermined(f"`{' '.join(argv)}` exited {res.returncode}: {detail}")
        return res

    def text(self, path: str, name: str | None = None) -> str | None:
        """File content, or None if it does not exist."""
        res = self.runner.read(path, name)
        if res.error:
            raise Undetermined(f"{path}: {res.error}")
        return res.content if res.exists else None

    def parsed(self, parser: str, path: str) -> Any:
        content = self.text(path)
        if content is None:
            return None
        try:
            return parsers.parse(parser, content)
        except parsers.ParseError as exc:
            raise Undetermined(f"{path}: {exc}") from exc

    def derive(self, deriver: str, path: str) -> dict[str, Any] | None:
        res = self.runner.derive(deriver, path)
        if res.error:
            raise Undetermined(f"{path}: {res.error}")
        return res.value if res.exists else None

    def stat(self, path: str) -> dict[str, Any]:
        from dataclasses import asdict
        res = self.runner.stat(path)
        if res.error:
            raise Undetermined(f"{path}: {res.error}")
        return asdict(res)

    def glob(self, pattern: str) -> list[dict[str, Any]]:
        from dataclasses import asdict
        res = self.runner.glob(pattern)
        if res.error:
            raise Undetermined(f"{pattern}: {res.error}")
        bad = [m for m in res.matches if m.error]
        if bad:
            raise Undetermined(f"{bad[0].path}: {bad[0].error}")
        return [asdict(m) for m in res.matches]

    def parse(self, parser: str, raw: str, what: str) -> Any:
        try:
            return parsers.parse(parser, raw)
        except parsers.ParseError as exc:
            raise Undetermined(f"{what}: {exc}") from exc

    @property
    def now_ts(self) -> float:
        return self.runner.now.timestamp()

    def age_hours(self, mtime: float | None) -> float | None:
        return None if mtime is None else round((self.now_ts - mtime) / 3600, 1)


@dataclass(frozen=True)
class Collector:
    name: str
    fn: Callable[[CollectContext], dict[str, Any]]
    plan: tuple[PlanStep, ...]
    platforms: tuple[str, ...] = ("debian", "ubuntu", "rhel")


COLLECTORS: dict[str, Collector] = {}


def collector(name: str, plan: list[PlanStep]):
    def register(fn: Callable[[CollectContext], dict[str, Any]]):
        COLLECTORS[name] = Collector(name, fn, tuple(plan))
        return fn
    return register


def batched(items: list[str], size: int = 24) -> list[list[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


from . import access, baseline, detection, network, patching, resilience  # noqa: E402,F401
