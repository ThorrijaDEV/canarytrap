from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

from canarytrap.server import TrapServer, read_hits
from canarytrap.store import TokenStore, bait_content

DEFAULT_DIR = Path.home() / ".local" / "state" / "canarytrap"

KINDS = ("url", "image", "aws-key", "env")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="canarytrap",
        description="Canary tokens autoalojados: cebos que avisan cuando alguien los toca.",
    )
    parser.add_argument("--state", type=Path, default=DEFAULT_DIR,
                        help="directorio de estado (tokens.json, hits.jsonl)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_new = sub.add_parser("new", help="genera un token nuevo")
    p_new.add_argument("kind", choices=KINDS)
    p_new.add_argument("--label", default="")
    p_new.add_argument("--host", default="localhost",
                       help="host público donde correrá el servidor (para la URL del cebo)")
    p_new.add_argument("--port", type=int, default=8420,
                       help="puerto público del servidor (para la URL del cebo)")

    p_serve = sub.add_parser("serve", help="arranca el servidor trampa")
    p_serve.add_argument("--bind", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8420)
    p_serve.add_argument("--webhook", default=None,
                         help="URL que recibirá un POST JSON por cada toque")

    p_hits = sub.add_parser("hits", help="muestra los últimos toques registrados")
    p_hits.add_argument("-n", type=int, default=20)

    return parser


def cmd_new(args) -> int:
    store = TokenStore(args.state / "tokens.json")
    token = store.create(args.kind, args.label)
    print(f"Token {token.id} ({token.kind}) · etiqueta: {token.label}")
    if args.kind in ("url", "image"):
        ext = ".png" if args.kind == "image" else ".zip"
        print(f"  Cebo:   http://{args.host}:{args.port}/bait/{token.id}{ext}")
    else:
        _, body = bait_content(token.kind, token.id)
        print("  Contenido a colocar (p. ej. ~/.aws/credentials falso, .env señuelo):")
        for line in body.splitlines():
            print(f"    {line}")
    print("  Cada descarga queda registrada en hits.jsonl y dispara tu webhook.")
    return 0


def cmd_serve(args) -> int:
    store = TokenStore(args.state / "tokens.json")
    server = TrapServer(args.bind, args.port, store,
                        args.state / "hits.jsonl", webhook=args.webhook)
    def announce(hit: dict):
        tok = hit["token"] or "?"
        label = store.get(tok).label if tok in store.tokens else "?"
        print(f"[!] CEBO PISADO  {label:<16} desde {hit['ip']:<15} {hit['ua']}")
    server.on_hit = announce
    print(f"canarytrap escuchando en {args.bind}:{args.port} "
          f"({len(store.tokens)} tokens armados)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nhasta pronto")
    return 0


def cmd_hits(args) -> int:
    hits = read_hits(args.state / "hits.jsonl", limit=args.n)
    if not hits:
        print("Nadie ha tocado los cebos todavía.")
        return 0
    store = TokenStore(args.state / "tokens.json")
    for h in reversed(hits):
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["ts"]))
        label = store.get(h["token"]).label if h["token"] in store.tokens else h["token"] or "?"
        flag = "★" if h.get("known") else "·"
        print(f"{flag} {when}  {h['ip']:<16} {label:<18} {h['ua']}  {h['path']}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.state.mkdir(parents=True, exist_ok=True)
    if args.command == "new":
        return cmd_new(args)
    if args.command == "serve":
        return cmd_serve(args)
    return cmd_hits(args)


if __name__ == "__main__":
    sys.exit(main())
