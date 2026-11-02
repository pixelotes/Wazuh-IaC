#!/usr/bin/env bash
# Backup round trip: snapshot the alerts indices to S3, restore them under another name and compare
# document counts. Leaves nothing behind.
set -euo pipefail

CTX=${CTX:-kind-wazuh}
K="kubectl --context $CTX -n wazuh"
PW=$($K get secret wazuh-indexer-cred -o jsonpath='{.data.INDEXER_PASSWORD}' | base64 -d)
api() { $K exec wazuh-indexer-0 -c wazuh-indexer -- curl -sk -u "admin:$PW" -H 'Content-Type: application/json' "$@"; }
count() { api "https://localhost:9200/$1/_count" | python3 -c 'import sys,json;print(json.load(sys.stdin)["count"])'; }

SNAP=test-$(date -u +%Y%m%d%H%M%S)
echo "alerts before: $(count 'wazuh-alerts-4.x-*')"

echo "snapshot $SNAP"
api -X PUT "https://localhost:9200/_snapshot/s3-backups/$SNAP?wait_for_completion=true" \
  -d '{"indices":"wazuh-alerts-4.x-*","include_global_state":false}' |
  python3 -c 'import sys,json;s=json.load(sys.stdin)["snapshot"];print(" ",s["state"],len(s["indices"]),"indices,",s["shards"]["successful"],"shards")'

echo "restore as restored-*"
api -X POST "https://localhost:9200/_snapshot/s3-backups/$SNAP/_restore?wait_for_completion=true" \
  -d '{"indices":"wazuh-alerts-4.x-*","rename_pattern":"wazuh-alerts-(.+)","rename_replacement":"restored-wazuh-alerts-$1","include_global_state":false}' |
  python3 -c 'import sys,json;print(" ",json.load(sys.stdin)["snapshot"]["shards"])'

ORIG=$(count 'wazuh-alerts-4.x-*') RESTORED=$(count 'restored-wazuh-alerts-*')
echo "alerts now: $ORIG, restored: $RESTORED"

api -X DELETE "https://localhost:9200/restored-wazuh-alerts-*" >/dev/null
api -X DELETE "https://localhost:9200/_snapshot/s3-backups/$SNAP" >/dev/null
# the live index keeps receiving alerts while the snapshot runs, so the restored copy may be slightly behind
if [ "$RESTORED" -gt 0 ] && [ "$RESTORED" -le "$ORIG" ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
