"""Bounded, fixed-route HTTP client; no credential submission methods."""

import json
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout

from .const import MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_SECONDS
from .models import Status, parse_status


def normalize_backend_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or any(c.isspace() for c in value)
        or parsed.port == 0
    ):
        raise ValueError("Invalid backend origin")
    return value.rstrip("/")


class FileVaultClient:
    def __init__(self, session: ClientSession, origin: str, token: str) -> None:
        self._session = session
        self._origin = normalize_backend_url(origin)
        self._token = token

    async def status(self) -> Status:
        async with self._session.get(
            self._origin + "/v1/status",
            headers={"Authorization": "Bearer " + self._token},
            timeout=ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
            allow_redirects=False,
        ) as response:
            if response.status != 200:
                raise ValueError("Status service unavailable")
            body = bytearray()
            async for chunk in response.content.iter_chunked(1024):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Status response too large")
            return parse_status(json.loads(body))
