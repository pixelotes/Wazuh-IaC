#!/usr/bin/env bash
# Logs in through Dex with the OIDC authorization code flow (no browser) and prints who the Wazuh dashboard
# thinks you are. Needs Dex on http://dex.localhost:5556 (kind port mapping or `kubectl -n dex port-forward svc/dex 5556:5556`).
# Usage: scripts/test-sso.sh [admin|analyst]
set -euo pipefail

CTX=${CTX:-kind-wazuh}
USER_NAME=${1:-admin}
PW=$(kubectl --context "$CTX" -n dex get secret dex-demo-passwords -o jsonpath="{.data.$USER_NAME}" | base64 -d)
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
redirect() { curl -s -o /dev/null -w '%{redirect_url}' -c "$JAR" -b "$JAR" "$@"; }

# 1. dashboard -> Dex /auth -> Dex local connector -> login form URL
AUTH=$(redirect http://localhost:8443/auth/openid/login)
LOCAL=$(redirect "$AUTH")
FORM=$(redirect "$LOCAL")
# 2. submit the credentials and follow every redirect back to the dashboard callback, which sets its session
FINAL=$(curl -s -o /dev/null -w '%{url_effective}' -L -c "$JAR" -b "$JAR" \
  --data-urlencode "login=$USER_NAME@wazuh.local" --data-urlencode "password=$PW" "$FORM")
echo "landed on: ${FINAL%%\?*}"
# 3. ask the dashboard who we are
curl -s -b "$JAR" http://localhost:8443/api/v1/auth/authinfo | python3 -c '
import sys, json
d = json.load(sys.stdin)
if "user_name" not in d:
    sys.exit("login failed: " + json.dumps(d)[:300])
print("user_name    :", d["user_name"])
print("backend_roles:", d.get("backend_roles"))
print("roles        :", d.get("roles"))'
