"""Makes the Wazuh manager's custom rule and decoder files match the repo through the API.

rules/iac-*.xml -> etc/rules, decoders/iac-*.xml -> etc/decoders. Managed files are named iac-*.xml:
uploaded when missing or different, deleted when no longer in the repo. Decoders go first (rules refer to
them). The manager is restarted once, and only if something changed.
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("WAZUH_API", "https://wazuh:55000")
# (API collection, mounted directory, directory on the manager)
KINDS = [("decoders", "/decoders", "etc/decoders"), ("rules", "/rules", "etc/rules")]
PREFIX = "iac-"
CTX = ssl._create_unverified_context()  # the API certificate is self-signed


def call(method, path, token=None, data=None, basic=None):
    req = urllib.request.Request(API + path, data=data, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if basic:
        req.add_header("Authorization", "Basic " + basic)
    if data is not None:
        req.add_header("Content-Type", "application/octet-stream")
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def wait_for_api():
    import base64
    basic = base64.b64encode(f"{os.environ['API_USERNAME']}:{os.environ['API_PASSWORD']}".encode()).decode()
    for _ in range(60):
        try:
            status, body = call("POST", "/security/user/authenticate?raw=true", basic=basic)
            if status == 200:
                return body.decode()
        except OSError:
            pass
        time.sleep(5)
    sys.exit("Wazuh API not reachable")


def check(status, body, what):
    ok = status == 200 and json.loads(body).get("error", 0) == 0
    if not ok:
        sys.exit(f"{what} failed: {status} {body.decode()[:500]}")


def sync(token, kind, local_dir, remote_dir):
    wanted = {f: open(os.path.join(local_dir, f), "rb").read()
              for f in sorted(os.listdir(local_dir)) if f.startswith(PREFIX) and f.endswith(".xml")}

    status, body = call("GET", f"/{kind}/files?relative_dirname={remote_dir}&limit=500", token)
    check(status, body, f"list {kind} files")
    existing = {i["filename"] for i in json.loads(body)["data"]["affected_items"]}

    changed = False
    for name, content in wanted.items():
        current = None
        if name in existing:
            status, body = call("GET", f"/{kind}/files/{name}?raw=true&relative_dirname={remote_dir}", token)
            current = body if status == 200 else None
        if current is not None and current.strip() == content.strip():
            print(f"unchanged {kind}/{name}")
            continue
        q = urllib.parse.urlencode({"overwrite": "true", "relative_dirname": remote_dir})
        status, body = call("PUT", f"/{kind}/files/{name}?{q}", token, content)
        check(status, body, f"upload {kind}/{name}")
        print(f"uploaded  {kind}/{name}")
        changed = True

    for name in sorted(f for f in existing if f.startswith(PREFIX) and f not in wanted):
        status, body = call("DELETE", f"/{kind}/files/{name}?relative_dirname={remote_dir}", token)
        check(status, body, f"delete {kind}/{name}")
        print(f"deleted   {kind}/{name}")
        changed = True
    return changed


def main():
    token = wait_for_api()
    changed = False
    for kind, local_dir, remote_dir in KINDS:
        changed = sync(token, kind, local_dir, remote_dir) or changed

    if changed:
        status, body = call("PUT", "/manager/restart", token)
        check(status, body, "restart manager")
        print("manager restart requested")


main()
