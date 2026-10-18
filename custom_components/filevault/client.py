"""Bounded, fixed-route HTTP client; no credential submission methods."""

import json
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout

from .const import MAX_RESPONSE_BYTES, REQUEST_TIMEOUT_SECONDS
from .models import Status, parse_status


class InvalidBackendURL(ValueError):
    """An origin that cannot receive a credential."""


class InvalidAuth(ValueError):
    """Read-only service credential rejected."""


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
        raise InvalidBackendURL("Invalid backend origin")
    return value.rstrip("/")


class FileVaultClient:
    def __init__(self, session: ClientSession, origin: str, token: str) -> None:
        self._session = session
        self._origin = normalize_backend_url(origin)
        self._token = token

    async def status(self) -> Status:
        return parse_status(await self._get_json("/v1/status"))

    async def system(self) -> dict[str, object]:
        return await self._get_json("/v1/system")

    async def _get_json(self, path: str) -> dict[str, object]:
        async with self._session.get(
            self._origin + path,
            headers={"Authorization": "Bearer " + self._token},
            timeout=ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
            allow_redirects=False,
        ) as response:
            if response.status in {401, 403}:
                raise InvalidAuth("Status credential rejected")
            if response.status != 200:
                raise ValueError("Status service unavailable")
            body = bytearray()
            async for chunk in response.content.iter_chunked(1024):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError("Status response too large")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("Invalid service response")
            return data
