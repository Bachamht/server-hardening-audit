from datetime import datetime, timezone

import pytest

from server_hardening_audit.assertions import OPS, Context, evaluate

NOW = datetime(2026, 9, 20, 12, tzinfo=timezone.utc)


def ctx(facts=None, profile=None, exit_codes=None):
    return Context(facts or {}, exit_codes or {}, profile or {}, NOW)


def v(raw, c):
    return evaluate(raw, c).verdict


def test_kv_equals():
    c = ctx({"s": {"a": "No", "b": True, "u": {"__unknown__": "why"}}})
    assert v({"op": "kv_equals", "source": "s", "expect": {"a": "no"}}, c) == "PASS"
    assert v({"op": "kv_equals", "source": "s", "expect": {"a": ["yes", "no"]}}, c) == "PASS"
    assert v({"op": "kv_equals", "source": "s", "expect": {"b": False}}, c) == "FAIL"
    assert v({"op": "kv_equals", "source": "s", "expect": {"zz": "1"}}, c) == "UNKNOWN"
    assert v({"op": "kv_equals", "source": "s", "expect": {"zz": "1"}, "optional": ["zz"]},
             c) == "PASS"
    out = evaluate({"op": "kv_equals", "source": "s", "expect": {"u": True}}, c)
    assert out.verdict == "UNKNOWN" and "why" in out.summary
    assert v({"op": "kv_equals", "source": "missing", "expect": {"a": 1}}, c) == "UNKNOWN"


def test_regex_and_exit_code():
    c = ctx({"t": "hello\nworld"}, exit_codes={"t": 3})
    assert v({"op": "regex_present", "source": "t", "pattern": "^world$"}, c) == "PASS"
    assert v({"op": "regex_absent", "source": "t", "pattern": "^world$"}, c) == "FAIL"
    assert v({"op": "exit_code", "source": "t", "expect": [0, 3]}, c) == "PASS"
    assert v({"op": "exit_code", "source": "t", "expect": 0}, c) == "FAIL"


def test_counts_and_values_with_params():
    c = ctx({"x": {"items": [1, 2], "n": 5, "u": {"__unknown__": "stale"}}},
            profile={"limit": 4})
    assert v({"op": "count_at_most", "source": "x.items", "max": 2}, c) == "PASS"
    assert v({"op": "count_at_most", "source": "x.items", "max": 1}, c) == "FAIL"
    assert v({"op": "count_at_least", "source": "x.items", "min": 3}, c) == "FAIL"
    assert v({"op": "value_at_most", "source": "x.n", "max": {"param": "profile.limit"}},
             c) == "FAIL"
    assert v({"op": "value_at_least", "source": "x.n", "min": {"param": "profile.limit"}},
             c) == "PASS"
    assert v({"op": "count_at_most", "source": "x.u", "max": 0}, c) == "UNKNOWN"
    assert v({"op": "value_at_most", "source": "x.n", "max": {"param": "profile.nope"}},
             c) == "UNKNOWN"


def _st(path, mode=0o600, owner="root", age_h=1.0, exists=True):
    return {"path": path, "exists": exists, "mode": mode, "owner": owner, "uid": 0,
            "mtime": NOW.timestamp() - age_h * 3600}


def test_file_metadata_ops():
    c = ctx({"f": [_st("/a"), _st("/b", 0o644, "app", 30)]})
    assert v({"op": "mode_at_most", "source": "f", "max": "0644"}, c) == "PASS"
    assert v({"op": "mode_at_most", "source": "f", "max": "0600"}, c) == "FAIL"
    assert v({"op": "owner_is", "source": "f", "owner": "root"}, c) == "FAIL"
    assert v({"op": "age_at_most", "source": "f", "max_hours": 2}, c) == "PASS"
    assert v({"op": "age_at_most", "source": "f", "max_hours": 0.5}, c) == "FAIL"
    assert v({"op": "age_at_most", "source": "g", "max_hours": 2},
             ctx({"g": [_st("/x", exists=False)]})) == "FAIL"


def test_public_listeners_within():
    rows = [{"proto": "tcp", "addr": "0.0.0.0", "iface": None, "port": 22, "process": []},
            {"proto": "tcp", "addr": "127.0.0.1", "iface": None, "port": 5432, "process": []},
            {"proto": "udp", "addr": "203.0.113.1", "iface": "eth0", "port": 68, "process": []}]
    c = ctx({"l": rows})
    assert v({"op": "public_listeners_within", "source": "l", "ports": [22]}, c) == "PASS"
    assert v({"op": "public_listeners_within", "source": "l", "ports": []}, c) == "FAIL"
    rows.append({"proto": "tcp", "addr": "::", "iface": None, "port": 6379, "process": ["redis"]})
    assert v({"op": "public_listeners_within", "source": "l", "ports": [22]}, c) == "FAIL"


@pytest.mark.parametrize("verdicts,all_of,any_of", [
    (["PASS", "PASS"], "PASS", "PASS"),
    (["PASS", "FAIL"], "FAIL", "PASS"),
    (["FAIL", "UNKNOWN"], "FAIL", "UNKNOWN"),
    (["PASS", "UNKNOWN"], "UNKNOWN", "PASS"),
    (["FAIL", "FAIL"], "FAIL", "FAIL"),
])
def test_combinators(verdicts, all_of, any_of):
    facts = {"s": {"p": 1, "f": 2}}
    sub = {"PASS": {"op": "kv_equals", "source": "s", "expect": {"p": 1}},
           "FAIL": {"op": "kv_equals", "source": "s", "expect": {"p": 9}},
           "UNKNOWN": {"op": "kv_equals", "source": "nope", "expect": {"p": 1}}}
    of = [sub[x] for x in verdicts]
    assert v({"op": "all_of", "of": of}, ctx(facts)) == all_of
    assert v({"op": "any_of", "of": of}, ctx(facts)) == any_of


def test_minimum_operator_set_from_spec():
    required = {"kv_equals", "regex_absent", "regex_present", "exit_code", "count_at_least",
                "mode_at_most", "owner_is", "age_at_most", "public_listeners_within",
                "all_of", "any_of"}
    assert required <= set(OPS)
