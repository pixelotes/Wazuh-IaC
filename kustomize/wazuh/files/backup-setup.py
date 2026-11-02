"""Applies the indexer's backup and lifecycle configuration (indexer/*.json) through its REST API:

  snapshot repository s3-backups   PUT  _snapshot/s3-backups         (then verified)
  SLM policy wazuh-daily           POST/PUT _plugins/_sm/policies/wazuh-daily
  ISM policy wazuh-alerts          PUT  _plugins/_ism/policies/wazuh-alerts (+ attach to existing indices)

Idempotent: safe to run after every sync.
"""
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

URL = os.environ.get("INDEXER_URL", "https://wazuh-indexer:9200")
AUTH = "Basic " + base64.b64encode(f"admin:{os.environ['INDEXER_PASSWORD']}".encode()).decode()
CTX = ssl._create_unverified_context()  # in-cluster, certificate issued by the cluster's own CA
DIR = "/config"


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, method=method)
    req.add_header("Authorization", AUTH)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"error": raw.decode()[:300]}
    except OSError as e:
        return 0, {"error": str(e)}


def load(name):
    return json.load(open(f"{DIR}/{name}"))


def must(status, body, what, ok=(200, 201)):
    if status not in ok:
        sys.exit(f"{what} failed: {status} {json.dumps(body)[:600]}")
    print(f"ok: {what}")


def upsert(kind, path, body, cas_path):
    """Create, or update with the optimistic-concurrency parameters the plugin requires."""
    status, res = call("GET", path)
    if status == 404:
        method = "PUT" if kind == "ism" else "POST"
        return call(method, path, body)
    return call("PUT", f"{path}?if_seq_no={res['_seq_no']}&if_primary_term={res['_primary_term']}", body)


def main():
    for _ in range(60):
        status, res = call("GET", "/_cluster/health")
        if status == 200 and res.get("status") in ("green", "yellow"):
            break
        time.sleep(5)
    else:
        sys.exit("indexer not healthy")

    status, plugins = call("GET", "/_cat/plugins?format=json")
    if not any(p.get("component") == "repository-s3" for p in plugins if isinstance(plugins, list)):
        sys.exit("repository-s3 plugin is not installed in the indexer")

    must(*call("PUT", "/_snapshot/s3-backups", load("snapshot-repository.json")), "snapshot repository s3-backups")
    must(*call("POST", "/_snapshot/s3-backups/_verify"), "snapshot repository verified")

    must(*upsert("slm", "/_plugins/_sm/policies/wazuh-daily", load("slm-wazuh-daily.json"), None), "SLM policy wazuh-daily")
    must(*upsert("ism", "/_plugins/_ism/policies/wazuh-alerts", load("ism-wazuh-alerts.json"), None), "ISM policy wazuh-alerts")

    # ism_template only applies to indices created from now on: attach the policy to the existing ones
    status, res = call("POST", "/_plugins/_ism/add/wazuh-alerts-*", {"policy_id": "wazuh-alerts"})
    must(status, res, f"ISM policy attached to existing indices ({res.get('updated_indices', 0)} updated)")


main()
