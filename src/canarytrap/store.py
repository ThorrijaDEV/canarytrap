from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

TOKEN_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"


def new_token_id(length: int = 16) -> str:
    return "".join(secrets.choice(TOKEN_CHARS) for _ in range(length))


@dataclass
class Token:
    id: str
    kind: str          # "url" | "aws-key" | "env" | "image"
    label: str
    created: float
    hits: int = 0
    last_hit: float = 0.0


class TokenStore:
    """JSON-file backed registry of tokens and their hit counters."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.tokens: dict[str, Token] = {}
        if self.path.exists():
            for raw in json.loads(self.path.read_text()):
                self.tokens[raw["id"]] = Token(**raw)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [asdict(t) for t in sorted(self.tokens.values(), key=lambda t: t.created)]
        self.path.write_text(json.dumps(payload, indent=2))

    def create(self, kind: str, label: str = "") -> Token:
        token = Token(
            id=new_token_id(),
            kind=kind,
            label=label or f"{kind}-{new_token_id(4)}",
            created=time.time(),
        )
        self.tokens[token.id] = token
        self.save()
        return token

    def record_hit(self, token_id: str, when: Optional[float] = None) -> bool:
        token = self.tokens.get(token_id)
        if token is None:
            return False
        token.hits += 1
        token.last_hit = when if when is not None else time.time()
        self.save()
        return True

    def get(self, token_id: str) -> Optional[Token]:
        return self.tokens.get(token_id)


# ------------------------------------------------------------------ baits

AWS_KEY_TEMPLATE = """[default]
aws_access_key_id = {key_id}
aws_secret_access_key = {secret}
region = eu-west-1
"""

ENV_TEMPLATE = (
    "# Production environment — DO NOT COMMIT\n"
    "DATABASE_URL=postgres://admin:{secret}@db.internal:5432/prod\n"
    "STRIPE_KEY=sk_live_{token}\n"
    "JWT_SECRET={secret}\n"
)


def bait_content(kind: str, token_id: str) -> tuple[str, str]:
    """Return (content_type, body) served for this token kind."""
    secret = f"{token_id}{secrets.token_hex(12)}"
    if kind == "aws-key":
        key_id = "AKIA" + token_id.upper()[:16]
        return ("text/plain", AWS_KEY_TEMPLATE.format(key_id=key_id, secret=secret))
    if kind == "env":
        return ("text/plain", ENV_TEMPLATE.format(secret=secret, token=token_id))
    # plain url / image beacon default
    return ("text/plain", f"canary {token_id}\n")
