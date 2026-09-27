#!/usr/bin/env bash
# Runs inside ubuntu:22.04 / ubuntu:24.04 in CI with the repo mounted
# read-only at /src and dist/server-hardening-audit.pyz already built.
set -euo pipefail
trap 'echo "::error title=container.sh::line $LINENO: $BASH_COMMAND"' ERR
export DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1
PYZ=/src/dist/server-hardening-audit.pyz
CHECK="python3 /src/tests/integration/check_run.py"
PROFILE=/src/profiles/single-vps-webhost.toml

apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 >/dev/null
python3 "$PYZ" list >/dev/null

audit() {  # audit OUT_DIR [runuser args...]
  local out=$1; shift
  set +e
  "$@" python3 "$PYZ" audit --profile "$PROFILE" --out "$out"
  rc=$?
  set -e
}

echo "== 1. bare container: no sshd, no ss, no firewall, no docker, no systemd"
audit /tmp/runs-bare
$CHECK /tmp/runs-bare "$rc" "ACC-01=NA" "NET-03=NA" "PAT-03=NA" "NET-02=UNKNOWN" \
  "NET-04=MANUAL" "RES-02=MANUAL" "BAS-03=UNKNOWN"

echo "== 2. with openssh-server and iproute2"
apt-get install -y -qq --no-install-recommends openssh-server iproute2 sudo >/dev/null
mkdir -p /run/sshd
audit /tmp/runs-sshd
$CHECK /tmp/runs-sshd "$rc" "ACC-01=PASS|FAIL" "NET-02=PASS|FAIL" "ACC-04=PASS|FAIL" \
  "ACC-05=PASS|FAIL" "BAS-02=PASS|FAIL"

echo "== 3. same host, not root"
chmod 1777 /tmp
audit /tmp/runs-nobody runuser -u nobody --
$CHECK /tmp/runs-nobody "$rc" "ACC-04=UNKNOWN" "ACC-01=UNKNOWN"

echo "== 4. probe against the container's own sshd (SPEC M3 acceptance)"
/usr/sbin/sshd
sleep 1
python3 "$PYZ" probe 127.0.0.1 --ports 22,2222 --ssh-user root --public-ports 22 \
  --out /tmp/probe-stock
python3 - <<'PY'
import json
r = json.load(open("/tmp/probe-stock/probe.json"))
methods = r["ssh"][0]["methods"]
assert r["ports"]["ipv4"]["22"] == "open" and r["ports"]["ipv4"]["2222"] == "closed", r["ports"]
assert "password" in methods and "publickey" in methods, methods   # stock config
print("stock sshd advertises:", methods)
PY
printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
  > /etc/ssh/sshd_config.d/00-keys-only.conf
kill -HUP "$(cat /run/sshd.pid)"
sleep 1
python3 "$PYZ" probe 127.0.0.1 --ports 22 --ssh-user root --public-ports 22 --out /tmp/probe-hard
python3 - <<'PY'
import json, sys
sys.path.insert(0, "/src")
from server_hardening_audit.loader import parse_toml
r = json.load(open("/tmp/probe-hard/probe.json"))
assert r["ssh"][0]["methods"] == ["publickey"], r["ssh"]
doc = parse_toml(open("/tmp/probe-hard/probe-attestation.toml", "rb").read(), "probe")
atts = {a["control"]: a for a in doc["attestation"]}
assert atts["ACC-01"]["verdict"] == "PASS" and atts["NET-04"]["verdict"] == "PASS", atts
print("hardened sshd advertises:", r["ssh"][0]["methods"])
PY
echo "integration: OK"
