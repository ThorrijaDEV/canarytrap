from __future__ import annotations

import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Optional

from canarytrap.store import TokenStore, bait_content

HitCallback = Callable[[dict], None]


class TrapServer(ThreadingHTTPServer):
    def __init__(self, host: str, port: int, store: TokenStore,
                 hits_path: Path, webhook: Optional[str] = None):
        self.store = store
        self.hits_path = Path(hits_path)
        self.webhook = webhook
        self.on_hit: Optional[HitCallback] = None
        super().__init__((host, port), TrapHandler)


class TrapHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = [p for p in self.path.split("/") if p]
        token_id = None
        # accepted shapes: /bait/<id>, /bait/<id>.zip|key|env, /<id>
        for p in parts:
            stem = p.rsplit(".", 1)[0]
            if len(stem) == 16 and all(c.isalnum() and c.islower() or c.isdigit() for c in stem):
                token_id = stem
                break

        hit = {
            "ts": time.time(),
            "ip": self.client_address[0],
            "path": self.path,
            "ua": self.headers.get("User-Agent", ""),
            "token": token_id or "",
            "known": False,
        }

        if token_id and self.server.store.get(token_id):
            hit["known"] = True
            content_type, body = bait_content(self.server.store.tokens[token_id].kind, token_id)
            self.server.store.record_hit(token_id)
        else:
            content_type, body = "text/plain", "not found\n"

        self._record(hit)
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # discourage caching so every fetch counts
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _record(self, hit: dict) -> None:
        line = json.dumps(hit)
        with open(self.server.hits_path, "a") as fh:
            fh.write(line + "\n")
        on_hit = self.server.on_hit
        if on_hit:
            on_hit(hit)
        webhook = self.server.webhook
        if webhook:
            threading.Thread(target=self._fire_webhook, args=(hit,), daemon=True).start()

    def _fire_webhook(self, hit: dict) -> None:
        try:
            req = urllib.request.Request(
                self.server.webhook,
                data=json.dumps({"event": "canarytrip", **hit}).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=5).close()
        except Exception as exc:  # never let alerting kill the trap
            print(f"[webhook] fallo: {exc}")

    def log_message(self, *args):  # quiet by default; hits go to JSONL
        pass


def read_hits(path: Path, limit: int = 50) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    return [json.loads(l) for l in lines[-limit:] if l.strip()]
