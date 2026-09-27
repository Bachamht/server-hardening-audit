"""Network-domain collectors: host firewall, container ports, TLS."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ..assertions import is_loopback
from . import (
    CollectContext,
    NotApplicable,
    PlanStep,
    Undetermined,
    batched,
    collector,
    read,
    run,
    unknown,
)

# --- Firewall -----------------------------------------------------------------

FIREWALLD_SERVICES = {"ssh": [22], "http": [80], "https": [443], "http3": [443]}
FIREWALLD_CLIENT_SERVICES = {"dhcpv6-client", "dhcp"}


def _port_spec(spec: str) -> list[int] | None:
    """'22', '22/tcp', '80,443/tcp', '6000:6007/tcp' -> ports; None if not numeric."""
    spec = spec.split("/")[0].strip()
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if re.fullmatch(r"\d+", part):
            ports.append(int(part))
        elif re.fullmatch(r"\d+[:-]\d+", part):
            lo, hi = map(int, re.split(r"[:-]", part))
            if hi - lo > 1000:
                return None
            ports.extend(range(lo, hi + 1))
        else:
            return None
    return ports


def _ipv6_enabled(ctx: CollectContext) -> bool:
    value = ctx.text("/proc/sys/net/ipv6/conf/all/disable_ipv6")
    return value is not None and value.strip() == "0"


def _from_ufw(ctx: CollectContext, raw: str) -> dict[str, Any] | None:
    st = ctx.parse("ufw_status", raw, "ufw status verbose")
    if not st["active"]:
        return None
    defaults = ctx.parsed("env_kv", "/etc/default/ufw") or {}
    deny = st["default_incoming"] in ("deny", "reject")
    v6_managed = defaults.get("IPV6", "yes").lower() == "yes"
    open_ports, unresolved = set(), []
    for r in st["rules"]:
        if r["action"] not in ("ALLOW", "LIMIT") or r["direction"] != "IN":
            continue
        if r["from"] != "Anywhere":
            continue  # source-restricted: not open to the internet
        ports = _port_spec(r["to"])
        if ports is None:
            unresolved.append(f"{r['to']} {r['action']} from {r['from']}")
        else:
            open_ports.update(ports)
    return {"frontend": "ufw", "default_deny_v4": deny, "default_deny_v6": deny and v6_managed,
            "open_ports": sorted(open_ports), "unresolved_rules": unresolved,
            "notes": [] if v6_managed else ["ufw IPV6=no: IPv6 traffic is not filtered by ufw"]}


def _from_firewalld(ctx: CollectContext) -> dict[str, Any]:
    res = ctx.cmd(["firewall-cmd", "--list-all"])
    zone = ctx.parse("firewalld_list", res.stdout, "firewall-cmd --list-all")
    deny = zone.get("target", "default").lower() in ("default", "drop", "reject", "%%reject%%")
    open_ports, unresolved = set(), []
    for svc in zone.get("services", "").split():
        if svc in FIREWALLD_SERVICES:
            open_ports.update(FIREWALLD_SERVICES[svc])
        elif svc not in FIREWALLD_CLIENT_SERVICES:
            unresolved.append(f"service {svc}")
    for spec in zone.get("ports", "").split():
        ports = _port_spec(spec)
        if ports is None:
            unresolved.append(f"port {spec}")
        else:
            open_ports.update(ports)
    return {"frontend": f"firewalld (zone {zone['zone']})", "default_deny_v4": deny,
            "default_deny_v6": deny, "open_ports": sorted(open_ports),
            "unresolved_rules": unresolved, "notes": []}


_NFT_DPORT = re.compile(r"\b(?:tcp|udp|th) dport (\{[^}]*\}|\S+)")


def _from_nft(ctx: CollectContext, raw: str) -> dict[str, Any] | None:
    chains = ctx.parse("nft_ruleset", raw, "nft list ruleset")["chains"]
    inputs = [c for c in chains if c["hook"] == "input" and c["type"] == "filter"]
    if not inputs:
        return None
    deny_v4 = any(c["policy"] == "drop" and c["family"] in ("ip", "inet") for c in inputs)
    deny_v6 = any(c["policy"] == "drop" and c["family"] in ("ip6", "inet") for c in inputs)
    open_ports, unresolved = set(), []
    for c in inputs:
        for rule in c["rules"]:
            if not rule.rstrip().endswith("accept") or "saddr" in rule or "iif" in rule:
                continue
            m = _NFT_DPORT.search(rule)
            if not m:
                continue
            ports = _port_spec(m.group(1).strip("{} ").replace(" ", "").replace("-", ":"))
            if ports is None:
                unresolved.append(rule)
            else:
                open_ports.update(ports)
    return {"frontend": "nftables", "default_deny_v4": deny_v4, "default_deny_v6": deny_v6,
            "open_ports": sorted(open_ports), "unresolved_rules": unresolved, "notes": []}


_IPT_DPORT = re.compile(r"--dports? (\S+)")


def _from_iptables(ctx: CollectContext) -> dict[str, Any] | None:
    v4 = ctx.try_cmd(["iptables", "-S"])
    if v4 is None:
        return None
    r4 = ctx.parse("iptables_rules", v4.stdout, "iptables -S")
    v6 = ctx.try_cmd(["ip6tables", "-S"])
    r6 = ctx.parse("iptables_rules", v6.stdout, "ip6tables -S") if v6 else None
    open_ports, unresolved = set(), []
    for rules in (r4, r6):
        for rule in (rules or {}).get("rules", []):
            if not rule.startswith("-A INPUT ") or not rule.endswith("-j ACCEPT"):
                continue
            if " -s " in rule or " -i lo" in rule:
                continue
            m = _IPT_DPORT.search(rule)
            if m:
                ports = _port_spec(m.group(1))
                if ports is None:
                    unresolved.append(rule)
                else:
                    open_ports.update(ports)
    return {"frontend": "iptables",
            "default_deny_v4": r4["policies"].get("INPUT") == "DROP",
            "default_deny_v6": bool(r6) and r6["policies"].get("INPUT") == "DROP",
            "open_ports": sorted(open_ports), "unresolved_rules": unresolved, "notes": []}


@collector("firewall", plan=[
    run("ufw", "status", "verbose", note="if installed"),
    read("/etc/default/ufw", "IPV6 setting"),
    run("firewall-cmd", "--state", note="if installed"),
    run("firewall-cmd", "--list-all", note="if firewalld is running"),
    run("nft", "list", "ruleset", note="if installed"),
    run("iptables", "-S", note="fallback"),
    run("ip6tables", "-S", note="fallback"),
    read("/proc/sys/net/ipv6/conf/all/disable_ipv6"),
])
def firewall(ctx: CollectContext) -> dict[str, Any]:
    result = None
    ufw = ctx.try_cmd(["ufw", "status", "verbose"])
    if ufw is not None:
        result = _from_ufw(ctx, ufw.stdout)
    if result is None:
        state = ctx.runner.run(["firewall-cmd", "--state"])
        if state.error is None and state.stdout.strip() == "running":
            result = _from_firewalld(ctx)
    if result is None:
        nft = ctx.try_cmd(["nft", "list", "ruleset"])
        if nft is not None:
            result = _from_nft(ctx, nft.stdout)
    if result is None:
        result = _from_iptables(ctx)
    if result is None:
        raise Undetermined("no firewall front-end or ruleset tool found (ufw, firewalld, nft, "
                           "iptables); the kernel ruleset could not be read")
    v6 = _ipv6_enabled(ctx)
    if not v6:
        result["default_deny_v6"] = True
        result["notes"].append("IPv6 is disabled on this host")
    public = set(ctx.profile["public_ports"])
    result["ipv6_enabled"] = v6
    result["extra_ports"] = [p for p in result["open_ports"] if p not in public]
    if result["unresolved_rules"] and not result["extra_ports"]:
        result["extra_ports"] = unknown(
            "rules that could not be resolved to port numbers: "
            + "; ".join(result["unresolved_rules"][:5]))
    return result


# --- Docker -------------------------------------------------------------------


def running_containers(ctx: CollectContext) -> list[dict[str, Any]]:
    """`docker inspect` documents for running containers. NA without docker."""
    res = ctx.runner.run(["docker", "ps", "-q", "--no-trunc"])
    if res.error_kind == "missing":
        raise NotApplicable("Docker is not installed")
    if res.error:
        raise Undetermined(f"docker ps: {res.error}")
    if res.returncode != 0:
        if "Cannot connect to the Docker daemon" in res.stderr:
            raise NotApplicable("Docker is installed but its daemon is not running")
        raise Undetermined(f"docker ps exited {res.returncode}: {res.stderr.strip()[:200]}")
    ids = res.stdout.split()
    docs: list[dict[str, Any]] = []
    for chunk in batched(ids):
        out = ctx.cmd(["docker", "inspect", "--type", "container", *chunk])
        docs.extend(ctx.parse("json", out.stdout, "docker inspect") or [])
    return docs


@collector("docker_ports", plan=[
    run("docker", "ps", "-q", "--no-trunc"),
    run("docker", "inspect", "--type", "container", "<container-id>..."),
])
def docker_ports(ctx: CollectContext) -> dict[str, Any]:
    docs = running_containers(ctx)
    public = set(ctx.profile["public_ports"])
    published, violations, host_net = [], [], []
    for d in docs:
        name = d.get("Name", "?").lstrip("/")
        if (d.get("HostConfig") or {}).get("NetworkMode") == "host":
            host_net.append(name)
        for cport, binds in ((d.get("NetworkSettings") or {}).get("Ports") or {}).items():
            for b in binds or []:
                host_ip = b.get("HostIp") or "0.0.0.0"  # noqa: S104 -- docker default
                host_port = int(b.get("HostPort") or 0)
                entry = f"{name}: {host_ip}:{host_port} -> {cport}"
                published.append(entry)
                if not is_loopback(host_ip) and host_port not in public:
                    violations.append(entry)
    return {"containers": len(docs), "published": published, "violations": violations,
            "host_network": host_net}


# --- TLS ----------------------------------------------------------------------


@collector("tls_certs", plan=[
    PlanStep("tls", ("127.0.0.1:443", "SNI=<each profile tls_domains entry>"),
             "certificate verified against the system CA store"),
])
def tls_certs(ctx: CollectContext) -> dict[str, Any]:
    domains = ctx.profile["tls_domains"]
    if not domains:
        raise NotApplicable("profile declares no tls_domains")
    certs, violations = [], []
    for domain in domains:
        res = ctx.runner.tls("127.0.0.1", 443, domain)
        if res.error and res.error_kind != "verify":
            raise Undetermined(f"{domain}: {res.error}")
        days = None
        if res.not_after:
            days = round((datetime.fromisoformat(res.not_after).timestamp() - ctx.now_ts)
                         / 86400, 1)
        certs.append({"domain": domain, "verified": res.verified, "not_after": res.not_after,
                      "days_left": days, "issuer": res.issuer_cn, "error": res.error})
        if not res.verified:
            violations.append(f"{domain}: {res.error}")
        elif days is not None and days < ctx.profile["tls_min_days"]:
            violations.append(f"{domain}: expires in {days} days")
    return {"certs": certs, "violations": violations}
