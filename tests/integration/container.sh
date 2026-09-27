#!/usr/bin/env bash
# Runs inside ubuntu:22.04 / ubuntu:24.04 in CI with the repo mounted
# read-only at /src and dist/server-hardening-audit.pyz already built.
set -euo pipefail
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
apt-get install -y -qq --no-install-recommends openssh-server iproute2 >/dev/null
mkdir -p /run/sshd
audit /tmp/runs-sshd
$CHECK /tmp/runs-sshd "$rc" "ACC-01=PASS|FAIL" "NET-02=PASS|FAIL" "ACC-04=PASS|FAIL" \
  "ACC-05=PASS|FAIL" "BAS-02=PASS|FAIL"

echo "== 3. same host, not root"
chmod 1777 /tmp
audit /tmp/runs-nobody runuser -u nobody --
$CHECK /tmp/runs-nobody "$rc" "ACC-04=UNKNOWN" "ACC-01=UNKNOWN"
