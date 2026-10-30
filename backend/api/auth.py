"""Dashboard token: one random secret in the data directory, required by the REST API and the WebSocket."""
import os
import secrets
from pathlib import Path

TOKEN_FILE = "api-token"
SUBPROTOCOL = "sentinelstream"


def load_or_create_token(data_dir: Path) -> str:
    """Reuse the token across restarts; delete the file to rotate it."""
    path = data_dir / TOKEN_FILE
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and (token := path.read_text().strip()):
        return token
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    return token


def matches(expected: str, presented: str | None) -> bool:
    return presented is not None and secrets.compare_digest(expected.encode(), presented.encode())


def from_bearer(header: str | None) -> str | None:
    return header[len("Bearer "):] if header and header.startswith("Bearer ") else None


def from_subprotocols(header: str | None) -> str | None:
    """Browsers can't set WebSocket headers, so the client offers ["sentinelstream", <token>] as subprotocols."""
    parts = [p.strip() for p in (header or "").split(",")]
    return parts[1] if len(parts) == 2 and parts[0] == SUBPROTOCOL else None
