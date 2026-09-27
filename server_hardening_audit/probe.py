"""External probe: what the audited host exposes, seen from outside.

Run on the operator's machine, never on the audited host. Only probe hosts
you are authorised to test.

- Ports: a plain TCP connect per port, per address family. Connected =
  open, refused = closed, timed out = filtered. No raw packets, no nmap.
- SSH: one unauthenticated connection per user, offering no credentials,
  to read which authentication methods the server advertises
  ("Authentications that can continue: ..."). No password or key is ever
  tried, so no authentication failure is logged against the operator.
- TLS: a handshake per domain with SNI, verified against the local CA store.

Writes probe.json (raw results) and probe-attestation.toml (attestations
for NET-04, NET-05 and an external check of ACC-01, ready for
``report --attest``).
"""

from __future__ import annotations

import datetime as dt
import json
import re
import shutil
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import __version__, tomlw

SSH_METHODS = re.compile(r"Authentications that can continue: ([A-Za-z0-9,@._-]+)")


def resolve(host: str) -> dict[str, str]:
    """First IPv4 and first IPv6 address of host."""
    out: dict[str, str] = {}
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OSError(f"cannot resolve {host}: {exc}") from exc
    for family, _, _, _, sockaddr in infos:
        key = "ipv4" if family == socket.AF_INET else "ipv6" if family == socket.AF_INET6 else None
        if key and key not in out:
            out[key] = sockaddr[0]
    return out


def tcp_state(addr: str, port: int, timeout: float) -> str:
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((addr, port))
            return "open"
        except ConnectionRefusedError:
            return "closed"
        except TimeoutError:
            return "filtered"
        except OSError as exc:
            return f"error: {exc.strerror or exc}"


def scan(addrs: dict[str, str], ports: list[int], timeout: float) -> dict[str, dict[str, str]]:
    jobs = [(fam, addr, port) for fam, addr in addrs.items() for port in ports]
    with ThreadPoolExecutor(max_workers=32) as pool:
        states = list(pool.map(lambda j: tcp_state(j[1], j[2], timeout), jobs))
    out: dict[str, dict[str, str]] = {fam: {} for fam in addrs}
    for (fam, _, port), state in zip(jobs, states, strict=True):
        out[fam][str(port)] = state
    return out


def ssh_argv(host: str, port: int, user: str, timeout: int = 10) -> list[str]:
    """The only command the probe runs. Every authentication method is off,
    the user's ssh config, agent and known_hosts files are not used."""
    return ["ssh", "-F", "/dev/null", "-v", "-p", str(port), "-l", user,
            "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentityAgent=none",
            "-o", "IdentitiesOnly=yes", "-o", "PubkeyAuthentication=no",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "GSSAPIAuthentication=no", "-o", "HostbasedAuthentication=no",
            host, "exit"]


def parse_ssh_methods(stderr: str) -> list[str] | None:
    m = SSH_METHODS.findall(stderr)
    return sorted(set(m[0].split(","))) if m else None


def ssh_methods(host: str, port: int, user: str) -> dict[str, Any]:
    if shutil.which("ssh") is None:
        return {"user": user, "error": "ssh client not installed"}
    argv = ssh_argv(host, port, user)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30,  # noqa: S603
                              stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired:
        return {"user": user, "error": "ssh timed out"}
    methods = parse_ssh_methods(proc.stderr)
    banner = next((ln.split("remote software version", 1)[1].strip()
                   for ln in proc.stderr.splitlines() if "remote software version" in ln), None)
    result: dict[str, Any] = {"user": user, "methods": methods, "server_version": banner}
    if methods is None:
        tail = [ln for ln in proc.stderr.splitlines() if not ln.startswith("debug")][-2:]
        result["error"] = " ".join(tail) or f"ssh exited {proc.returncode}"
    return result


def tls_check(host: str, domain: str, timeout: float) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=domain) as conn:
            cert = conn.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        return {"domain": domain, "verified": False, "error": exc.verify_message}
    except (OSError, ssl.SSLError) as exc:
        return {"domain": domain, "verified": False, "error": str(exc)}
    not_after = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]),
                                          dt.timezone.utc)
    days = (not_after - dt.datetime.now(dt.timezone.utc)).total_seconds() / 86400
    return {"domain": domain, "verified": True, "not_after": not_after.isoformat(),
            "days_left": round(days, 1)}


def attestations(result: dict[str, Any], public_ports: list[int] | None,
                 tls_min_days: int) -> list[dict[str, Any]]:
    now = result["finished_at"]
    by = f"server-hardening-audit {__version__} probe"
    out = []
    scanned = result["ports"]
    open_by_family = {fam: sorted(int(p) for p, s in states.items() if s == "open")
                      for fam, states in scanned.items()}
    if public_ports is not None:
        unexpected = sorted({p for ports in open_by_family.values() for p in ports}
                            - set(public_ports))
        families = ", ".join(f"{fam} {result['addresses'][fam]}" for fam in scanned)
        out.append({
            "control": "NET-04", "verdict": "FAIL" if unexpected else "PASS",
            "method": (f"TCP connect probe of {len(result['ports_requested'])} ports on "
                       f"{families} from the operator's network"),
            "performed_at": now, "performed_by": by, "source": "probe",
            "evidence": ["probe.json"],
            "measurements": {
                "declared_public_ports": public_ports,
                "unexpected_open_ports": unexpected,
                **{f"open_{fam}": ports for fam, ports in open_by_family.items()},
                **{f"filtered_{fam}": sorted(int(p) for p, s in st.items() if s == "filtered")
                   for fam, st in scanned.items()},
            },
        })
    ssh = [s for s in result["ssh"] if s.get("methods") is not None]
    if ssh:
        weak = sorted({m for s in ssh for m in s["methods"]
                       if m in ("password", "keyboard-interactive")})
        out.append({
            "control": "ACC-01", "verdict": "FAIL" if weak else "PASS",
            "method": ("Unauthenticated SSH connection offering no credentials; methods "
                       "advertised by the server were read from the handshake"),
            "performed_at": now, "performed_by": by, "source": "probe",
            "evidence": ["probe.json"],
            "measurements": {f"methods_{s['user']}": s["methods"] for s in ssh},
        })
    if result["tls"]:
        bad = [t["domain"] for t in result["tls"]
               if not t["verified"] or t.get("days_left", 0) < tls_min_days]
        out.append({
            "control": "NET-05", "verdict": "FAIL" if bad else "PASS",
            "method": "TLS handshake with SNI from outside, verified against the local CA store",
            "performed_at": now, "performed_by": by, "source": "probe",
            "evidence": ["probe.json"],
            "measurements": {"domains_failing": bad, **{
                f"days_left_{i + 1}": t.get("days_left", -1) for i, t in enumerate(result["tls"])
            }},
        })
    return out


def run_probe(host: str, ports: list[int], ssh_users: list[str], ssh_port: int,
              tls_domains: list[str], timeout: float) -> dict[str, Any]:
    started = dt.datetime.now(dt.timezone.utc)
    addrs = resolve(host)
    result: dict[str, Any] = {
        "tool": {"name": "server-hardening-audit", "version": __version__},
        "target": host, "addresses": addrs, "ports_requested": ports,
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ports": scan(addrs, ports, timeout),
        "ssh": [ssh_methods(host, ssh_port, u) for u in ssh_users],
        "tls": [tls_check(host, d, timeout) for d in tls_domains],
    }
    result["finished_at"] = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return result


def write(out_dir: Path, result: dict[str, Any], atts: list[dict[str, Any]]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "probe.json").write_text(json.dumps(result, indent=2) + "\n")
    header = (f"Generated by server-hardening-audit {__version__} probe at "
              f"{result['finished_at']}.\nPass to: server-hardening-audit report RUN_DIR "
              "--attest probe-attestation.toml")
    (out_dir / "probe-attestation.toml").write_text(tomlw.dumps({"attestation": atts}, header))
