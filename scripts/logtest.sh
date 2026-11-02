#!/usr/bin/env bash
# Runs an event through the manager's ruleset (wazuh-logtest via the API) and prints the decoded
# fields and the rule that fired.
# Usage: scripts/logtest.sh <event-file> [location] [log_format]   (defaults: aws-s3, json)
set -euo pipefail

CTX=${CTX:-kind-wazuh}
POD=wazuh-manager-master-0
K="kubectl --context $CTX -n wazuh"
FILE=${1:?usage: logtest.sh <event-file> [location]}
LOCATION=${2:-aws-s3}
LOG_FORMAT=${3:-json}

U=$($K get secret wazuh-api-cred -o jsonpath='{.data.API_USERNAME}' | base64 -d)
P=$($K get secret wazuh-api-cred -o jsonpath='{.data.API_PASSWORD}' | base64 -d)

exec_api() { $K exec -i "$POD" -c wazuh-manager -- "$@"; }
TOKEN=$(exec_api curl -sk -u "$U:$P" -X POST "https://localhost:55000/security/user/authenticate?raw=true")

python3 - "$FILE" "$LOCATION" "$LOG_FORMAT" <<'PY' |
import json, sys
event = open(sys.argv[1]).read().strip()
print(json.dumps({"log_format": sys.argv[3], "location": sys.argv[2], "event": event}))
PY
exec_api curl -sk -X PUT "https://localhost:55000/logtest" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @- |
python3 -c '
import json, sys
d = json.load(sys.stdin)
out = d.get("data", {}).get("output")
if not out:
    print(json.dumps(d, indent=1)); sys.exit(1)
print("decoder :", out.get("decoder", {}).get("name"))
print("rule    :", out.get("rule", {}).get("id"), "L%s" % out.get("rule", {}).get("level"), out.get("rule", {}).get("description"))
print("fields  :", json.dumps(out.get("data", {}), indent=1))
'
