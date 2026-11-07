"""Glue between collectors and ingestion; used by the CLI and the API."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.collectors.base import BaseCollector, CollectorConfigError
from app.collectors.urlhaus import URLhausCollector
from app.config import Settings
from app.services.ingestion import (
    IngestResult,
    acquire_ingest_lock,
    get_or_create_source,
    ingest,
)

SUPPORTED_COLLECTORS = ("urlhaus",)


def build_collector(name: str, settings: Settings) -> BaseCollector:
    if name == "urlhaus":
        return URLhausCollector(
            settings.urlhaus_auth_key,
            limit=settings.urlhaus_fetch_limit,
            timeout=settings.http_timeout_seconds,
        )
    raise CollectorConfigError(f"unknown collector: {name!r}")


def run_collector(session: Session, collector: BaseCollector) -> IngestResult:
    observations = collector.collect()  # network I/O happens before taking the lock
    acquire_ingest_lock(session)
    source = get_or_create_source(
        session, collector.source_name, collector.feed_url, collector.default_reliability
    )
    return ingest(session, source, observations)
