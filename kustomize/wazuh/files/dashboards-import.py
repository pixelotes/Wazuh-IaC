"""Imports the saved objects in /dashboards/*.ndjson into the Wazuh dashboard (overwriting by id)."""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

URL = os.environ.get("DASHBOARD_URL", "http://wazuh-dashboard:5601")
AUTH = "Basic " + base64.b64encode(f"admin:{os.environ['INDEXER_PASSWORD']}".encode()).decode()
DIR = "/dashboards"


def request(path, data=None, ctype=None):
    req = urllib.request.Request(URL + path, data=data)
    req.add_header("Authorization", AUTH)
    req.add_header("osd-xsrf", "true")
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:500]}
    except OSError as e:
        return 0, {"error": str(e)}


def main():
    for _ in range(60):
        status, _body = request("/api/status")
        if status == 200:
            break
        time.sleep(5)
    else:
        sys.exit("dashboard not reachable")

    for name in sorted(f for f in os.listdir(DIR) if f.endswith(".ndjson")):
        boundary = uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                f"Content-Type: application/ndjson\r\n\r\n").encode() + open(f"{DIR}/{name}", "rb").read() + \
               f"\r\n--{boundary}--\r\n".encode()
        status, res = request("/api/saved_objects/_import?overwrite=true", body, f"multipart/form-data; boundary={boundary}")
        if status != 200 or not res.get("success"):
            sys.exit(f"import {name} failed: {status} {json.dumps(res)[:600]}")
        print(f"imported {name}: {res.get('successCount')} objects")


main()
