"""Wazuh integration: creates an Opsgenie / JSM Operations alert from a Wazuh alert.

Both products take the same request (POST <hook_url> with "Authorization: GenieKey <key>"), so only
hook_url differs: https://api.opsgenie.com/v2/alerts (or api.eu.opsgenie.com) for Opsgenie, and the same
endpoint for JSM Operations integrations. The key comes from OPSGENIE_API_KEY (a Secret), not from ossec.conf.
"""
import json
import os
import sys
import urllib.error
import urllib.request

LOG = "/var/ossec/logs/integrations.log"


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"custom-opsgenie: {msg}\n")


def flatten(d, prefix=""):
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            yield from flatten(v, key + ".")
        else:
            yield key, v


def priority(level):
    return "P1" if level >= 14 else "P2" if level >= 12 else "P3" if level >= 10 else "P4" if level >= 7 else "P5"


def build(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    level = int(rule.get("level", 0))
    details = {"rule.id": rule.get("id"), "rule.level": level, "agent": agent.get("name"),
               "location": alert.get("location"), "timestamp": alert.get("timestamp")}
    for k, v in flatten(alert.get("data", {}), "data."):
        if len(details) >= 40:
            break
        details[k] = v
    return {
        "message": f'Wazuh: {rule.get("description", "alert")}'[:130],
        "alias": f'wazuh-{rule.get("id")}-{agent.get("id", "000")}',  # same rule + agent updates one alert
        "description": f'Rule {rule.get("id")} (level {level}) on {agent.get("name", "manager")}',
        "priority": priority(level),
        "source": "wazuh",
        "tags": list(rule.get("groups", [])) + list(rule.get("mitre", {}).get("id", [])),
        "details": {k: str(v)[:8000] for k, v in details.items() if v is not None},
    }


def main():
    args = sys.argv[1:]
    alert_file = args[0]
    url = next((a for a in args[1:] if a.startswith("http")), "https://api.opsgenie.com/v2/alerts")
    key = os.environ.get("OPSGENIE_API_KEY") or next((a for a in args[1:] if a and not a.startswith("http") and a != "debug"), "")
    alert = json.load(open(alert_file))
    payload = build(alert)
    req = urllib.request.Request(url, json.dumps(payload).encode(), {
        "Content-Type": "application/json", "Authorization": "GenieKey " + key})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            log(f'rule {alert["rule"]["id"]} -> {r.status}')
    except urllib.error.HTTPError as e:
        log(f'rule {alert["rule"]["id"]} -> HTTP {e.code} {e.read()[:200]!r}')
        sys.exit(1)
    except OSError as e:
        log(f'rule {alert["rule"]["id"]} -> {e}')
        sys.exit(1)


main()
