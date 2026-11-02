set -eu
EP=http://s3:8333
BUCKET=wazuh-cloudtrail
KEY=$(cat /work/key)

for b in "$BUCKET" wazuh-snapshots; do
  aws --endpoint-url "$EP" s3api head-bucket --bucket "$b" 2>/dev/null ||
    aws --endpoint-url "$EP" s3api create-bucket --bucket "$b"
done
aws --endpoint-url "$EP" s3 cp /work/events.json.gz "s3://$BUCKET/$KEY"
echo "uploaded s3://$BUCKET/$KEY"
