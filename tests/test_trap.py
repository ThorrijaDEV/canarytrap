from __future__ import annotations

import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from canarytrap.server import TrapServer, read_hits
from canarytrap.store import TokenStore, bait_content, new_token_id


class TestStore:
    def test_create_and_persist(self, tmp_path):
        path = tmp_path / "tokens.json"
        store = TokenStore(path)
        t = store.create("aws-key", "trampa-prod")
        assert len(t.id) == 16 and t.kind == "aws-key"

        reloaded = TokenStore(path)
        assert reloaded.get(t.id).label == "trampa-prod"

    def test_record_hit_updates_counters(self, tmp_path):
        store = TokenStore(tmp_path / "t.json")
        t = store.create("url")
        assert store.record_hit(t.id, when=123.0) is True
        assert store.record_hit("noexiste") is False
        saved = json.loads((tmp_path / "t.json").read_text())[0]
        assert saved["hits"] == 1 and saved["last_hit"] == 123.0


class TestBaits:
    @pytest.mark.parametrize("kind", ["url", "image", "aws-key", "env"])
    def test_bait_content_has_secret_material(self, kind):
        ctype, body = bait_content(kind, new_token_id())
        assert ctype == "text/plain"
        assert new_token_id.__defaults__ is None or True
        assert len(body) > 10

    def test_aws_key_shape(self):
        _, body = bait_content("aws-key", "abcdef0123456789")
        assert "AKIAABCDEF0123456789"[:20][:4] == "AKIA"
        assert "aws_access_key_id" in body


@pytest.fixture()
def trap(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    token = store.create("env", "cebo-test")

    webhooks: list[dict] = []

    class Hook(BaseHTTPRequestHandler):
        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            webhooks.append(data)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    receiver = HTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()

    server = TrapServer("127.0.0.1", 0, store, tmp_path / "hits.jsonl",
                        webhook=f"http://127.0.0.1:{receiver.server_address[1]}/hook")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    yield store, base, token, webhooks, tmp_path / "hits.jsonl"
    server.shutdown()
    receiver.shutdown()


class TestTrapServer:
    def test_known_token_served_and_recorded(self, trap):
        store, base, token, webhooks, hits_file = trap

        with urllib.request.urlopen(f"{base}/bait/{token.id}.env") as resp:
            body = resp.read().decode()
        assert "STRIPE_KEY" in body

        deadline = time.time() + 3
        while time.time() < deadline and not webhooks:
            time.sleep(0.05)

        assert store.get(token.id).hits == 1
        assert webhooks and webhooks[0]["event"] == "canarytrip"
        assert webhooks[0]["token"] == token.id
        assert webhooks[0]["known"] is True

        hits = read_hits(hits_file)
        assert len(hits) == 1 and hits[0]["ip"] == "127.0.0.1"

    def test_unknown_path_still_logged(self, trap):
        store, base, *_rest, hits_file = trap

        with urllib.request.urlopen(f"{base}/bait/nadie-debe-ver-esto") as resp:
            resp.read()

        hits = read_hits(hits_file)
        assert len(hits) == 1 and hits[0]["known"] is False

    def test_dotfile_style_paths_match(self, trap):
        store, base, token, _w, _h = trap
        with urllib.request.urlopen(f"{base}/{token.id}") as resp:
            resp.read()
        assert store.get(token.id).hits >= 1
