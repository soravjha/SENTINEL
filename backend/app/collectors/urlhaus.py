"""URLhaus (abuse.ch) collector.

Uses the documented "recent URLs" endpoint. abuse.ch requires a free Auth-Key sent
in the `Auth-Key` header: https://auth.abuse.ch/ . Respect abuse.ch's terms and do
not poll more often than needed (a few times per day is plenty for a recent feed).
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.collectors.base import (
    BaseCollector,
    CollectorConfigError,
    CollectorError,
    RawObservation,
)
from app.services.normalizer import IndicatorType

logger = logging.getLogger(__name__)

API_BASE = "https://urlhaus-api.abuse.ch/v1"
_DETAIL_KEYS = ("url_status", "reporter", "urlhaus_reference")


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _entry_to_observations(entry: dict[str, Any]) -> list[RawObservation]:
    url = entry.get("url")
    if not isinstance(url, str) or not url:
        return []
    ref = str(entry.get("id") or url)[:240]
    observed_at = _parse_timestamp(entry.get("date_added"))
    threat = entry.get("threat")
    raw_tags = entry.get("tags")
    if isinstance(raw_tags, str):
        raw_tags = [raw_tags]
    tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []
    details = {k: entry[k] for k in _DETAIL_KEYS if entry.get(k) is not None}

    observations = [
        RawObservation(IndicatorType.URL, url, observed_at, ref, threat, tags, details)
    ]
    host = entry.get("host")
    if host:
        # The serving host is a derived indicator. It can be a legitimate shared host,
        # so Phase 2 scoring must weigh it; the tag keeps that provenance visible.
        host_type = IndicatorType.IP if _is_ip(str(host)) else IndicatorType.DOMAIN
        observations.append(
            RawObservation(
                host_type,
                str(host),
                observed_at,
                f"{ref}:host",
                threat,
                [*tags, "derived-from-url"],
                {**details, "source_url_id": ref},
            )
        )
    return observations


def parse_recent_urls(payload: Any) -> list[RawObservation]:
    """Turn a URLhaus 'recent URLs' JSON response into raw observations."""
    if not isinstance(payload, dict):
        raise CollectorError("unexpected URLhaus response: not a JSON object")
    status = payload.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise CollectorError(f"unexpected URLhaus response (query_status={status!r})")

    observations: list[RawObservation] = []
    for entry in payload.get("urls") or []:
        if isinstance(entry, dict):
            observations.extend(_entry_to_observations(entry))
    return observations


class URLhausCollector(BaseCollector):
    source_name = "urlhaus"
    feed_url = f"{API_BASE}/urls/recent/"

    def __init__(
        self,
        auth_key: str | None,
        *,
        limit: int = 1000,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not auth_key:
            raise CollectorConfigError(
                "URLHAUS_AUTH_KEY is not set. Get a free key at https://auth.abuse.ch/"
            )
        self._auth_key = auth_key
        self.limit = max(1, min(limit, 1000))
        self._timeout = timeout
        self._client = client

    def collect(self) -> list[RawObservation]:
        url = f"{API_BASE}/urls/recent/limit/{self.limit}/"
        owns_client = self._client is None
        client = self._client or httpx.Client()
        try:
            response = client.get(url, headers={"Auth-Key": self._auth_key}, timeout=self._timeout)
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise CollectorError(f"URLhaus request failed: {exc}") from exc
        finally:
            if owns_client:
                client.close()

        observations = parse_recent_urls(payload)
        logger.info("URLhaus returned %d observations", len(observations))
        return observations
