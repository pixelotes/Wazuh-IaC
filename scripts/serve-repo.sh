#!/usr/bin/env bash
# Serves this repo read-only over git:// so Argo CD in kind can clone it
# (git://host.docker.internal:9418/wazuh-kubernetes). Local-only substitute for a remote.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
exec git daemon --reuseaddr --listen=0.0.0.0 --port=9418 \
  --base-path="$(dirname "$ROOT")" --export-all "$ROOT"
