"""Receiver that stands in for Slack and Opsgenie / JSM Operations.

POST /slack/...            Slack incoming webhook      -> 200 "ok"
POST /opsgenie/v2/alerts   Opsgenie create-alert API   -> 202, requires "Authorization: GenieKey <key>"
GET  /                     HTML list of what was received (auto-refresh)
GET  /messages             the same as JSON
Stdlib only.
"""
import html
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MESSAGES = []  # newest first
LOCK = threading.Lock()
KEEP = 200


def summary(kind, body):
    if not isinstance(body, dict):
        return str(body)[:200]
    if kind == "slack":
        att = (body.get("attachments") or [{}])[0]
        return att.get("title") or att.get("text") or body.get("text") or ""
    return f'[{body.get("priority", "?")}] {body.get("message", "")}'


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw.decode(errors="replace")
        if self.path.startswith("/slack/"):
            kind = "slack"
        elif self.path.startswith("/opsgenie/v2/alerts"):
            kind = "opsgenie"
            if not self.headers.get("Authorization", "").startswith("GenieKey "):
                return self.reply(401, {"message": "Could not authenticate", "took": 0.0})
        else:
            return self.reply(404, {"message": "unknown endpoint"})
        with LOCK:
            MESSAGES.insert(0, {"time": time.strftime("%H:%M:%S"), "channel": kind, "path": self.path,
                                "summary": summary(kind, body), "body": body})
            del MESSAGES[KEEP:]
        print(kind, summary(kind, body), flush=True)
        if kind == "slack":
            return self.reply(200, b"ok", "text/plain")
        self.reply(202, {"result": "Request will be processed", "took": 0.0, "requestId": str(uuid.uuid4())})

    def do_GET(self):
        with LOCK:
            msgs = list(MESSAGES)
        if self.path.startswith("/messages"):
            return self.reply(200, msgs)
        rows = "".join(
            f'<tr><td>{m["time"]}</td><td class="{m["channel"]}">{m["channel"]}</td>'
            f'<td>{html.escape(m["summary"])}<details><pre>{html.escape(json.dumps(m["body"], indent=1))}</pre></details></td></tr>'
            for m in msgs)
        page = ("<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=10>"
                "<title>Webhook mock</title><style>body{font:14px system-ui;margin:2rem}td{padding:.3rem .8rem;vertical-align:top}"
                ".slack{color:#4a154b;font-weight:600}.opsgenie{color:#0052cc;font-weight:600}pre{font-size:12px}</style>"
                f"<h2>Webhook mock: {len(msgs)} messages</h2><table>{rows}</table>")
        self.reply(200, page.encode(), "text/html; charset=utf-8")

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
