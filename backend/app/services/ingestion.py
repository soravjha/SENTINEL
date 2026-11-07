"""Turns raw collector output into deduplicated indicators and observations."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.collectors.base import RawObservation
from app.models import Indicator, Observation, ThreatSource
from app.services.normalizer import InvalidIndicator, normalize

logger = logging.getLogger(__name__)


# Arbitrary application-wide key for the PostgreSQL advisory lock.
INGEST_LOCK_KEY = 7_300_100_001


def acquire_ingest_lock(session: Session) -> None:
    """Serialize ingestion across processes (PostgreSQL only; a no-op elsewhere).

    A transaction-scoped advisory lock: concurrent collectors queue instead of racing
    to create the same indicator, and it is released automatically on commit or
    rollback. One global lock is deliberate: ingestion is a batch job, and a single
    writer avoids the lock-ordering deadlocks that row-level conflicts can cause.
    Call it *after* fetching feed data so the lock is never held during network I/O.
    """
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": INGEST_LOCK_KEY}).close()


@dataclass
class IngestResult:
    received: int = 0
    new_indicators: int = 0
    updated_indicators: int = 0
    new_observations: int = 0
    duplicate_observations: int = 0
    rejected: int = 0


def _as_utc(value: datetime) -> datetime:
    """SQLite returns naive datetimes; treat them as UTC so comparisons are safe."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def get_or_create_source(
    session: Session, name: str, feed_url: str | None, reliability: float
) -> ThreatSource:
    source = session.scalar(select(ThreatSource).where(ThreatSource.name == name))
    if source is None:
        source = ThreatSource(name=name, feed_url=feed_url, reliability=reliability)
        session.add(source)
        session.flush()
    return source


def ingest(
    session: Session, source: ThreatSource, observations: Iterable[RawObservation]
) -> IngestResult:
    """Normalize and store observations.

    Deduplication happens at two levels:
      * indicators are unique per (type, sha256 of normalized value);
      * observations are unique per (indicator, source, source_ref), so running the
        same collector twice never creates duplicates.
    """
    result = IngestResult()
    created_ids: set[int] = set()
    touched_ids: set[int] = set()
    now = datetime.now(timezone.utc)

    try:
        acquire_ingest_lock(session)
        for raw in observations:
            result.received += 1
            try:
                norm = normalize(raw.indicator_type, raw.raw_value)
            except InvalidIndicator as exc:
                result.rejected += 1
                logger.debug("rejected indicator: %s", exc)
                continue

            observed_at = _as_utc(raw.observed_at or now)
            indicator = session.scalar(
                select(Indicator).where(
                    Indicator.indicator_type == norm.indicator_type.value,
                    Indicator.value_hash == norm.value_hash,
                )
            )
            if indicator is None:
                indicator = Indicator(
                    indicator_type=norm.indicator_type.value,
                    value=norm.value,
                    value_hash=norm.value_hash,
                    first_seen=observed_at,
                    last_seen=observed_at,
                    observation_count=0,
                )
                session.add(indicator)
                session.flush()
                created_ids.add(indicator.id)

            # Feeds without their own ids fall back to one observation per day.
            source_ref = (raw.source_ref or observed_at.strftime("%Y-%m-%d"))[:255]
            already_seen = session.scalar(
                select(Observation.id)
                .where(
                    Observation.indicator_id == indicator.id,
                    Observation.source_id == source.id,
                    Observation.source_ref == source_ref,
                )
                .limit(1)
            )
            if already_seen is not None:
                result.duplicate_observations += 1
                continue

            session.add(
                Observation(
                    indicator_id=indicator.id,
                    source_id=source.id,
                    source_ref=source_ref,
                    observed_at=observed_at,
                    threat_type=raw.threat_type,
                    tags=list(raw.tags),
                    details=dict(raw.details),
                )
            )
            indicator.observation_count += 1
            if observed_at < _as_utc(indicator.first_seen):
                indicator.first_seen = observed_at
            if observed_at > _as_utc(indicator.last_seen):
                indicator.last_seen = observed_at
            result.new_observations += 1
            touched_ids.add(indicator.id)

        session.commit()
    except Exception:
        session.rollback()
        raise

    result.new_indicators = len(created_ids)
    result.updated_indicators = len(touched_ids - created_ids)
    return result
