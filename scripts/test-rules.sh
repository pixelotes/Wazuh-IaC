#!/usr/bin/env bash
# Runs every tests/events/<rule-id>-*.json through the live manager and checks that
# the expected custom rule fires. Needs the rules to be loaded (Argo CD sync).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
fail=0
# *.json events are AWS/GitHub integration events; *.log are raw container log lines read by the node agent
NODE_LOG=/host/var/log/pods/kube-system_kube-apiserver-wazuh-control-plane_0123abcd/kube-apiserver/0.log
for f in "$ROOT"/tests/events/*.json "$ROOT"/tests/events/*.log; do
  expected=$(basename "$f" | cut -d- -f1)
  case "$f" in
    *.log) got=$("$ROOT/scripts/logtest.sh" "$f" "$NODE_LOG" syslog 2>/dev/null | awk '/^rule/{print $3}') ;;
    *)     got=$("$ROOT/scripts/logtest.sh" "$f" 2>/dev/null | awk '/^rule/{print $3}') ;;
  esac
  if [ "$got" = "$expected" ]; then echo "PASS $(basename "$f") -> $got"; else echo "FAIL $(basename "$f"): expected $expected, got ${got:-none}"; fail=1; fi
done
exit $fail
