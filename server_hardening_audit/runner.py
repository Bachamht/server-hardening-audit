"""The only place the engine touches the audited host.

Every operation -- running a command, reading a file, stat, glob, statvfs,
a loopback TLS handshake -- goes through a Runner. The live runner enforces
the policy, performs the operation and records the result. The replay
runner serves recorded results from an evidence directory instead, after
applying the same policy checks, so a replayed run exercises exactly the
code paths a live run does.
"""

from __future__ import annotations

import glob as _glob
import grp
import json
import os
import pwd
import shutil
import socket
import ssl
import stat as _stat
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import derive, policy

SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_ENV = {
    "PATH": SAFE_PATH,
    "LC_ALL": "C.UTF-8",
    "LANG": "C.UTF-8",
    "PAGER": "cat",
    "SYSTEMD_PAGER": "",
    "SYSTEMD_COLORS": "0",
    "NO_COLOR": "1",
    "TERM": "dumb",
}
CMD_TIMEOUT = 60
MAX_OUTPUT = 8 * 1024 * 1024
MAX_READ = 4 * 1024 * 1024
MAX_GLOB = 500


# --- Results ----------------------------------------------------------------
#
# error_kind is one of: denied, missing, permission, timeout, not_recorded,
# failed. It drives UNKNOWN / NA decisions; error is the human-readable text.


@dataclass
class CmdResult:
    argv: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None
    error_kind: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class FileResult:
    path: str
    exists: bool = False
    content: str | None = None
    error: str | None = None
    error_kind: str | None = None


@dataclass
class DerivedResult:
    path: str
    deriver: str
    exists: bool = False
    value: dict[str, Any] | None = None
    error: str | None = None
    error_kind: str | None = None


@dataclass
class StatResult:
    path: str
    exists: bool = False
    kind: str | None = None  # file | dir | link | other
    mode: int | None = None  # permission bits only
    uid: int | None = None
    gid: int | None = None
    owner: str | None = None
    group: str | None = None
    size: int | None = None
    mtime: float | None = None
    error: str | None = None
    error_kind: str | None = None


@dataclass
class GlobResult:
    pattern: str
    matches: list[StatResult] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None
    error_kind: str | None = None


@dataclass
class VfsResult:
    path: str
    blocks: int | None = None
    bavail: int | None = None
    files: int | None = None
    favail: int | None = None
    error: str | None = None
    error_kind: str | None = None


@dataclass
class TlsResult:
    host: str
    port: int
    sni: str
    verified: bool = False
    not_after: str | None = None  # ISO 8601 UTC
    subject_cn: str | None = None
    issuer_cn: str | None = None
    error: str | None = None
    error_kind: str | None = None


@dataclass
class HostResult:
    hostname: str = ""
    kernel: str = ""
    machine: str = ""
    euid: int = -1
    error: str | None = None
    error_kind: str | None = None


def _stat_from_dict(d: dict[str, Any]) -> StatResult:
    return StatResult(**d)


# --- Recording --------------------------------------------------------------


@dataclass
class Call:
    """One recorded operation. ``content`` is stored in its own file."""

    n: int
    op: str
    key: dict[str, Any]
    name: str
    result: dict[str, Any]
    content: str | None = None

    def filename(self) -> str:
        return f"{self.n:02d}-{self.name}"


def _slug(text: str, limit: int = 48) -> str:
    out = "".join(c if c.isalnum() or c in "._-" else "-" for c in text)
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-.")[:limit] or "x"


def default_name(op: str, key: dict[str, Any]) -> str:
    if op == "cmd":
        return _slug("-".join(key["argv"])) + ".txt"
    if op in ("read",):
        return _slug(key["path"].lstrip("/").replace("/", "_"))
    target = key.get("path") or key.get("pattern") or key.get("sni") or op
    return _slug(f"{op}-{str(target).lstrip('/').replace('/', '_')}") + ".json"


# --- Runners ----------------------------------------------------------------


class Runner:
    """Base: recording and dispatch. Subclasses implement ``_perform``."""

    mode = "abstract"

    def __init__(self, now: datetime):
        self.now = now
        self.calls: dict[str, list[Call]] = {}
        self.scope = "_host"

    def begin(self, scope: str) -> None:
        self.scope = scope
        self.calls.setdefault(scope, [])

    def _record(self, op: str, key: dict[str, Any], result: Any, name: str | None,
                content: str | None = None) -> None:
        calls = self.calls.setdefault(self.scope, [])
        data = asdict(result)
        data.pop("content", None)
        if op == "cmd":
            data.pop("stdout", None)
        calls.append(Call(len(calls) + 1, op, key, name or default_name(op, key), data, content))

    def evidence_files(self, scope: str) -> list[str]:
        return [c.filename() for c in self.calls.get(scope, [])]

    # Public operations. Each checks policy, performs (or replays), records.

    def run(self, argv: list[str], name: str | None = None) -> CmdResult:
        key = {"argv": list(argv)}
        decision = policy.check(argv)
        if not decision:
            res = CmdResult(list(argv), error=decision.reason, error_kind="denied")
        else:
            res = self._perform("cmd", key)
        self._record("cmd", key, res, name, res.stdout)
        return res

    def read(self, path: str, name: str | None = None) -> FileResult:
        key = {"path": path}
        decision = policy.check_read(path)
        if not decision:
            res = FileResult(path, error=decision.reason, error_kind="denied")
        else:
            res = self._perform("read", key)
        self._record("read", key, res, name, res.content)
        return res

    def derive(self, deriver: str, path: str, name: str | None = None) -> DerivedResult:
        key = {"deriver": deriver, "path": path}
        d = derive.DERIVERS.get(deriver)
        if d is None or not d.paths.fullmatch(path) or "/../" in path or "\x00" in path:
            res = DerivedResult(path, deriver, error=f"deriver {deriver!r} may not read {path}",
                                error_kind="denied")
        else:
            res = self._perform("derive", key)
        self._record("derive", key, res, name or _slug(f"derived-{deriver}-{path}") + ".json")
        return res

    def stat(self, path: str, name: str | None = None) -> StatResult:
        key = {"path": path}
        res = self._perform("stat", key)
        self._record("stat", key, res, name)
        return res

    def glob(self, pattern: str, name: str | None = None) -> GlobResult:
        key = {"pattern": pattern}
        if not pattern.startswith("/"):
            res = GlobResult(pattern, error="pattern must be absolute", error_kind="denied")
        else:
            res = self._perform("glob", key)
        self._record("glob", key, res, name)
        return res

    def statvfs(self, path: str, name: str | None = None) -> VfsResult:
        key = {"path": path}
        res = self._perform("statvfs", key)
        self._record("statvfs", key, res, name)
        return res

    def tls(self, host: str, port: int, sni: str, name: str | None = None) -> TlsResult:
        key = {"host": host, "port": port, "sni": sni}
        decision = policy.check_connect(host, port)
        if not decision:
            res = TlsResult(host, port, sni, error=decision.reason, error_kind="denied")
        else:
            res = self._perform("tls", key)
        self._record("tls", key, res, name)
        return res

    def host(self) -> HostResult:
        res = self._perform("host", {})
        self._record("host", {}, res, "host.json")
        return res

    def _perform(self, op: str, key: dict[str, Any]) -> Any:  # pragma: no cover
        raise NotImplementedError


def untrusted_executable(path: str) -> str | None:
    """Refuse to run a program that someone other than root could have
    replaced: the binary and its directory must be owned by root and not
    writable by group or others. Returns the reason, or None if trusted."""
    real = os.path.realpath(path)
    for target in (real, os.path.dirname(real)):
        try:
            st = os.stat(target)
        except OSError as exc:
            return f"cannot stat {target}: {exc}"
        if st.st_uid != 0:
            return f"{target} is not owned by root (uid {st.st_uid}); refusing to run it"
        if st.st_mode & 0o022:
            return (f"{target} is writable by group or others "
                    f"({_stat.S_IMODE(st.st_mode):04o}); refusing to run it")
    return None


class LiveRunner(Runner):
    mode = "live"

    def _perform(self, op: str, key: dict[str, Any]) -> Any:
        return getattr(self, f"_live_{op}")(**key)

    @staticmethod
    def _live_host() -> HostResult:
        u = os.uname()
        return HostResult(socket.gethostname(), f"{u.sysname} {u.release}", u.machine,
                          os.geteuid())

    @staticmethod
    def _live_cmd(argv: list[str]) -> CmdResult:
        exe = shutil.which(argv[0], path=SAFE_PATH)
        if exe is None:
            return CmdResult(argv, error=f"{argv[0]}: command not found", error_kind="missing")
        untrusted = untrusted_executable(exe)
        if untrusted:
            return CmdResult(argv, error=untrusted, error_kind="denied")
        try:
            proc = subprocess.run(  # noqa: S603 -- argv checked by policy.check
                [exe, *argv[1:]], shell=False, stdin=subprocess.DEVNULL, capture_output=True,
                timeout=CMD_TIMEOUT, env=SAFE_ENV, check=False)
        except subprocess.TimeoutExpired:
            return CmdResult(argv, error=f"timed out after {CMD_TIMEOUT}s", error_kind="timeout")
        except OSError as exc:
            return CmdResult(argv, error=str(exc), error_kind="failed")
        return CmdResult(argv, proc.returncode,
                         proc.stdout[:MAX_OUTPUT].decode("utf-8", "replace"),
                         proc.stderr[:65536].decode("utf-8", "replace"))

    @staticmethod
    def _read_bytes(path: str, limit: int) -> tuple[bytes | None, str | None, str | None]:
        try:
            # Read in small chunks: procfs/sysfs handlers reject large single
            # reads (ENOMEM on /proc/sys/*).
            chunks, total = [], 0
            with open(path, "rb") as fh:
                while total < limit:
                    chunk = fh.read(min(65536, limit - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
            return b"".join(chunks), None, None
        except FileNotFoundError:
            return None, None, None
        except PermissionError as exc:
            return None, str(exc), "permission"
        except OSError as exc:
            return None, str(exc), "failed"

    def _live_read(self, path: str) -> FileResult:
        data, err, kind = self._read_bytes(path, MAX_READ)
        if err:
            return FileResult(path, error=err, error_kind=kind)
        if data is None:
            return FileResult(path, exists=False)
        return FileResult(path, exists=True, content=data.decode("utf-8", "replace"))

    def _live_derive(self, deriver: str, path: str) -> DerivedResult:
        d = derive.DERIVERS[deriver]
        data, err, kind = self._read_bytes(path, d.max_bytes)
        if err:
            return DerivedResult(path, deriver, error=err, error_kind=kind)
        if data is None:
            return DerivedResult(path, deriver, exists=False)
        try:
            value = d.fn(data)
        except Exception as exc:  # a deriver bug must not leak raw data via a traceback
            return DerivedResult(path, deriver, exists=True,
                                 error=f"deriver failed: {type(exc).__name__}",
                                 error_kind="failed")
        finally:
            del data
        return DerivedResult(path, deriver, exists=True, value=value)

    @staticmethod
    def _live_stat(path: str) -> StatResult:
        try:
            lst = os.lstat(path)
        except FileNotFoundError:
            return StatResult(path, exists=False)
        except PermissionError as exc:
            return StatResult(path, error=str(exc), error_kind="permission")
        except OSError as exc:
            return StatResult(path, error=str(exc), error_kind="failed")
        st = lst
        kind = "link" if _stat.S_ISLNK(lst.st_mode) else None
        if kind:
            try:
                st = os.stat(path)
            except OSError:
                st = lst
        if kind is None:
            kind = ("file" if _stat.S_ISREG(st.st_mode) else
                    "dir" if _stat.S_ISDIR(st.st_mode) else "other")
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = None
        try:
            group = grp.getgrgid(st.st_gid).gr_name
        except KeyError:
            group = None
        return StatResult(path, True, kind, _stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid,
                          owner, group, st.st_size, st.st_mtime)

    def _live_glob(self, pattern: str) -> GlobResult:
        paths = sorted(_glob.glob(pattern))
        truncated = len(paths) > MAX_GLOB
        return GlobResult(pattern, [self._live_stat(p) for p in paths[:MAX_GLOB]], truncated)

    @staticmethod
    def _live_statvfs(path: str) -> VfsResult:
        try:
            v = os.statvfs(path)
        except OSError as exc:
            kind = "missing" if isinstance(exc, FileNotFoundError) else "failed"
            return VfsResult(path, error=str(exc), error_kind=kind)
        return VfsResult(path, v.f_blocks, v.f_bavail, v.f_files, v.f_favail)

    @staticmethod
    def _live_tls(host: str, port: int, sni: str) -> TlsResult:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=10) as sock, \
                    ctx.wrap_socket(sock, server_hostname=sni) as conn:
                cert = conn.getpeercert() or {}
        except ssl.SSLCertVerificationError as exc:
            return TlsResult(host, port, sni, verified=False,
                             error=f"certificate verification failed: {exc.verify_message}",
                             error_kind="verify")
        except (OSError, ssl.SSLError) as exc:
            return TlsResult(host, port, sni, error=str(exc), error_kind="failed")

        def cn(field: str) -> str | None:
            for rdn in cert.get(field, ()):
                for k, v in rdn:
                    if k == "commonName":
                        return v
            return None

        not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]),
                                           timezone.utc).isoformat()
        return TlsResult(host, port, sni, True, not_after, cn("subject"), cn("issuer"))


class ReplayRunner(Runner):
    """Serves results recorded in ``<run>/evidence/<scope>/index.json``."""

    mode = "replay"

    def __init__(self, now: datetime, evidence_dir: Path):
        super().__init__(now)
        self.evidence_dir = Path(evidence_dir)
        self._index: dict[str, list[dict[str, Any]]] = {}
        self._used: dict[str, set[int]] = {}

    def _entries(self) -> list[dict[str, Any]]:
        if self.scope not in self._index:
            path = self.evidence_dir / self.scope / "index.json"
            try:
                self._index[self.scope] = json.loads(path.read_text())["calls"]
            except FileNotFoundError:
                self._index[self.scope] = []
            self._used[self.scope] = set()
        return self._index[self.scope]

    def _perform(self, op: str, key: dict[str, Any]) -> Any:
        used = self._used.setdefault(self.scope, set())
        for entry in self._entries():
            if entry["n"] in used or entry["op"] != op:
                continue
            if all(entry.get(k) == v for k, v in key.items()):
                used.add(entry["n"])
                return self._rebuild(op, key, entry)
        return self._missing(op, key)

    def _rebuild(self, op: str, key: dict[str, Any], entry: dict[str, Any]) -> Any:
        result = dict(entry["result"])
        content = None
        if entry.get("file") and op in ("cmd", "read"):
            f = self.evidence_dir / self.scope / entry["file"]
            if f.exists():
                content = f.read_text(encoding="utf-8", errors="replace")
        if op == "cmd":
            result["stdout"] = content or ""
            return CmdResult(**result)
        if op == "read":
            result["content"] = content
            return FileResult(**result)
        if op == "derive":
            return DerivedResult(**result)
        if op == "stat":
            return _stat_from_dict(result)
        if op == "glob":
            result["matches"] = [_stat_from_dict(m) for m in result.get("matches", [])]
            return GlobResult(**result)
        if op == "statvfs":
            return VfsResult(**result)
        if op == "tls":
            return TlsResult(**result)
        if op == "host":
            return HostResult(**result)
        raise ValueError(f"unknown op {op!r}")

    @staticmethod
    def _missing(op: str, key: dict[str, Any]) -> Any:
        msg = f"no recorded result for {op} {json.dumps(key)}"
        kind = "not_recorded"
        if op == "cmd":
            return CmdResult(key["argv"], error=msg, error_kind=kind)
        if op == "read":
            return FileResult(key["path"], error=msg, error_kind=kind)
        if op == "derive":
            return DerivedResult(key["path"], key["deriver"], error=msg, error_kind=kind)
        if op == "stat":
            return StatResult(key["path"], error=msg, error_kind=kind)
        if op == "glob":
            return GlobResult(key["pattern"], error=msg, error_kind=kind)
        if op == "statvfs":
            return VfsResult(key["path"], error=msg, error_kind=kind)
        if op == "host":
            return HostResult(error=msg, error_kind=kind)
        return TlsResult(key["host"], key["port"], key["sni"], error=msg, error_kind=kind)
