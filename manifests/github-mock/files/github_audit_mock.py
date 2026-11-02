"""Generates random GitHub organization audit-log events and sends them to Wazuh over syslog.

Entries follow the GitHub audit-log API schema (GET /orgs/{org}/audit-log). They are wrapped as
{"integration": "github", "github": <entry>}, which is what the Wazuh github module emits, so the
native ruleset (0750-github_rules.xml) handles them. Stdlib only.
"""
import json
import os
import random
import socket
import time
import uuid

HOST = os.environ.get("SYSLOG_HOST", "wazuh-syslog.wazuh.svc.cluster.local")
PORT = int(os.environ.get("SYSLOG_PORT", "514"))
ORG = os.environ.get("GITHUB_ORG", "acme-corp")
PER_MINUTE = float(os.environ.get("EVENTS_PER_MINUTE", "6"))
BURST_EVERY = int(os.environ.get("BURST_EVERY_MINUTES", "15"))  # 0 disables the incident burst

ACTORS = {"alice": ("ES", 1001), "bob": ("DE", 1002), "carol": ("US", 1003), "dave": ("FR", 1004),
          "eve-contractor": ("RU", 1666), "dependabot[bot]": ("US", 49699333)}
REPOS = ["api-gateway", "billing-service", "web-frontend", "infra-terraform", "docs", "wazuh-demo"]
AGENTS = ["Mozilla/5.0 (X11; Linux x86_64)", "git/2.43.0", "GitHub-Hookshot/abc123", "curl/8.5.0"]

# (action, operation_type, scope, weight); scope: repo | org | user
CATALOG = [
    # routine, native level 3
    ("git.clone", "access", "repo", 30), ("git.fetch", "access", "repo", 25), ("git.push", "modify", "repo", 20),
    ("dependabot_alerts.enable", "modify", "org", 2),
    # level 5
    ("org.invite_member", "create", "user", 4), ("org.add_member", "create", "user", 3),
    ("hook.create", "create", "repo", 3), ("oauth_application.create", "create", "org", 2),
    # level 7
    ("org.remove_member", "remove", "user", 2), ("hook.destroy", "remove", "repo", 2),
    ("org.update_actions_secret", "modify", "org", 2),
    # level 9
    ("repo.archived", "modify", "repo", 1), ("org.block_user", "create", "user", 1),
    ("repository_secret_scanning.disable", "modify", "repo", 1),
    # level 12
    ("org.disable_two_factor_requirement", "modify", "org", 1), ("dependabot_alerts.disable", "modify", "org", 1),
    ("repo.advanced_security_disabled", "modify", "repo", 1),
]
ACTIONS, WEIGHTS = [c[:3] for c in CATALOG], [c[3] for c in CATALOG]


def entry(action, op, scope, actor=None, repo=None):
    actor = actor or random.choice(list(ACTORS))
    country, actor_id = ACTORS[actor]
    now = int(time.time() * 1000)
    e = {
        "@timestamp": now, "created_at": now, "_document_id": uuid.uuid4().hex[:22],
        "action": action, "operation_type": op, "actor": actor, "actor_id": actor_id,
        "actor_is_bot": actor.endswith("[bot]"), "actor_location": {"country_code": country},
        "org": ORG, "org_id": 4711, "user_agent": random.choice(AGENTS),
        "transport_protocol_name": random.choice(["http", "ssh"]) if action.startswith("git.") else "http",
        "programmatic_access_type": "OAuth access token" if random.random() < 0.3 else "unknown",
    }
    if scope == "repo":
        name = repo or random.choice(REPOS)
        e.update({"repo": f"{ORG}/{name}", "repo_id": 9000 + REPOS.index(name) if name in REPOS else 9999,
                  "repository_public": random.random() < 0.2})
    elif scope == "user":
        e["user"] = random.choice([a for a in ACTORS if a != actor and not a.endswith("[bot]")])
    return {"integration": "github", "github": e}


def send(ev):
    """One short-lived connection per event: a long-lived one silently breaks when the manager restarts."""
    line = (json.dumps(ev, separators=(",", ":")) + "\n").encode()
    while True:
        try:
            with socket.create_connection((HOST, PORT), timeout=10) as sock:
                sock.sendall(line)
            print("sent", ev["github"]["action"], ev["github"]["actor"], flush=True)
            return
        except OSError as err:
            print("syslog send failed, retrying:", err, flush=True)
            time.sleep(5)


def main():
    next_burst = time.time() + BURST_EVERY * 60
    while True:
        if BURST_EVERY and time.time() >= next_burst:
            # incident: one actor deletes several repositories in a row
            for name in random.sample(REPOS, 4):
                send(entry("repo.destroy", "remove", "repo", actor="eve-contractor", repo=name))
                time.sleep(1)
            next_burst = time.time() + BURST_EVERY * 60
        action, op, scope = random.choices(ACTIONS, WEIGHTS)[0]
        send(entry(action, op, scope))
        time.sleep(random.expovariate(PER_MINUTE / 60))


main()
