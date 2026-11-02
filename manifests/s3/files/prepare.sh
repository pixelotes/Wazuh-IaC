set -eu
ACCOUNT=123456789012
REGION=eu-west-1
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RUN=$(date -u +%s)

sed -e "s/__NOW__/$NOW/g" -e "s/__RUN__/$RUN/g" /seed/cloudtrail-events.json | gzip >/work/events.json.gz
echo "AWSLogs/$ACCOUNT/CloudTrail/$REGION/$(date -u +%Y/%m/%d)/${ACCOUNT}_CloudTrail_${REGION}_$(date -u +%Y%m%dT%H%MZ)_$RUN.json.gz" >/work/key
