# Init container of the indexer. The Wazuh indexer image is OpenSearch 2.19.6 without repository-s3, so
# this installs it into an emptyDir mounted over plugins/repository-s3, and builds a keystore that holds the
# S3 credentials (they are secure settings: they cannot come from environment variables or opensearch.yml).
# In production, bake the plugin into the image instead and use IAM roles for the credentials.
set -eu
V=2.19.6   # must match the OpenSearch version inside wazuh-indexer 4.14.9
URL=https://artifacts.opensearch.org/releases/plugins/repository-s3/$V/repository-s3-$V.zip

cd /tmp
curl -fsSL -o "repository-s3-$V.zip" "$URL"
curl -fsSL -o "repository-s3-$V.zip.sha512" "$URL.sha512"
sha512sum -c "repository-s3-$V.zip.sha512"
(cd /s3-plugin && /usr/share/wazuh-indexer/jdk/bin/jar xf "/tmp/repository-s3-$V.zip")

export OPENSEARCH_PATH_CONF=/s3-keystore
KS=/usr/share/wazuh-indexer/bin/opensearch-keystore
rm -f "$OPENSEARCH_PATH_CONF/opensearch.keystore"
$KS create
printf %s "$AWS_ACCESS_KEY_ID" | $KS add -x s3.client.default.access_key
printf %s "$AWS_SECRET_ACCESS_KEY" | $KS add -x s3.client.default.secret_key
echo "repository-s3 $V installed, keystore ready"
