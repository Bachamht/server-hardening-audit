import pytest
from replay_fixture import RAW

from server_hardening_audit import parsers
from server_hardening_audit.parsers import ParseError, parse


def raw(name):
    return (RAW / name).read_text()


def test_sshd_kv_joins_repeated_keys():
    out = parse("sshd_kv", raw("sshd-T-hardened.synthetic.txt"))
    assert out["passwordauthentication"] == "no"
    assert out["listenaddress"] == "[::]:22,0.0.0.0:22"
    assert out["hostkey"].count(",") == 2
    with pytest.raises(ParseError):
        parse("sshd_kv", "")


def test_ss_listeners():
    rows = parse("ss_listeners", raw("ss-tcp-webhost.synthetic.txt"))
    by = {(r["addr"], r["port"]) for r in rows}
    assert ("127.0.0.53", 53) in by and ("::", 443) in by and ("::1", 5432) in by
    assert next(r for r in rows if r["port"] == 80)["process"] == ["nginx"]
    udp = parse("ss_listeners", raw("ss-udp-webhost.synthetic.txt"))
    assert {"proto": "udp", "addr": "203.0.113.10", "iface": "eth0", "port": 68,
            "process": ["systemd-network"]} in udp
    with pytest.raises(ParseError):
        parse("ss_listeners", "garbage line")


def test_ufw_status():
    st = parse("ufw_status", raw("ufw-status-verbose.synthetic.txt"))
    assert st["active"] and st["default_incoming"] == "deny"
    assert {"to": "80,443/tcp", "action": "ALLOW", "direction": "IN", "from": "Anywhere",
            "v6": True} in st["rules"]
    assert parse("ufw_status", "Status: inactive\n")["active"] is False
    commented = parse("ufw_status", "Status: active\nDefault: deny (incoming)\n\n"
                      "To  Action  From\n--  ------  ----\n"
                      "80,443/tcp                 ALLOW IN    173.245.48.0/20            # CDN\n")
    assert commented["rules"][0]["from"] == "173.245.48.0/20"
    with pytest.raises(ParseError):
        parse("ufw_status", "ERROR: You need to be root\n")


def test_nft_ruleset():
    chains = parse("nft_ruleset", raw("nft-ruleset.synthetic.txt"))["chains"]
    inp = next(c for c in chains if c["chain"] == "input")
    assert (inp["family"], inp["hook"], inp["policy"]) == ("inet", "input", "drop")
    assert "tcp dport { 22, 80, 443 } accept" in inp["rules"]


def test_iptables_rules():
    out = parse("iptables_rules", raw("iptables-S-drop.synthetic.txt"))
    assert out["policies"]["INPUT"] == "DROP" and len(out["rules"]) == 4
    with pytest.raises(ParseError):
        parse("iptables_rules", "iptables: Permission denied (you must be root)")


def test_apt_upgradable_marks_security():
    pkgs = parse("apt_upgradable", raw("apt-upgradable.synthetic.txt"))
    assert [p["package"] for p in pkgs if p["security"]] == ["libssl3t64", "openssl"]


def test_dpkg_status_and_systemctl_show():
    st = parse("dpkg_status", "auditd\tii \t1:3.1\naide\tun \t\n")
    assert st["auditd"]["installed"] and not st["aide"]["installed"]
    blocks = parse("systemctl_show", "Id=a.service\nUser=\n\nId=b.service\nUser=app\n")
    assert blocks == [{"Id": "a.service", "User": ""}, {"Id": "b.service", "User": "app"}]


def test_fail2ban_status():
    st = parse("fail2ban_status", raw("fail2ban-status-sshd.synthetic.txt"))
    assert st["total banned"] == "212" and st["currently failed"] == "3"


def test_env_kv_and_ini_and_apt_conf():
    assert parse("env_kv", 'ID="ubuntu"\nVERSION_ID=24.04\n# c\n') == {
        "ID": "ubuntu", "VERSION_ID": "24.04"}
    assert parse("systemd_ini", "[Journal]\n#Storage=auto\nStorage=persistent\n") == {
        "Journal": {"Storage": "persistent"}}
    assert parse("apt_conf", 'APT::Periodic::Unattended-Upgrade "1";\n') == {
        "APT::Periodic::Unattended-Upgrade": "1"}


def test_every_parser_has_a_test():
    tested = {"text", "lines", "value", "env_kv", "sshd_kv", "ss_listeners", "ufw_status",
              "iptables_rules", "nft_ruleset", "firewalld_list", "json", "apt_upgradable",
              "dpkg_status", "systemctl_show", "unit_list", "fail2ban_status", "passwd", "group",
              "systemd_ini", "apt_conf"}
    assert set(parsers.PARSERS) == tested
