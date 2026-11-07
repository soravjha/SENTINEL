"""Verification tests against a real PostgreSQL. Skipped unless TEST_DATABASE_URL is set.

WARNING: drops and recreates all SENTINEL tables. The database name must contain "test".
"""

import os
import threading
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.collectors.base import RawObservation
from app.models import Base, Indicator, Observation, ThreatSource
from app.services.ingestion import (
    INGEST_LOCK_KEY,
    acquire_ingest_lock,
    get_or_create_source,
    ingest,
)
from app.services.normalizer import IndicatorType

URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set TEST_DATABASE_URL to a disposable PostgreSQL database")


@pytest.fixture()
def pg_engine():
    assert "test" in (make_url(URL).database or ""), "refusing to drop tables in a non-test database"
    engine = create_engine(URL)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


def _count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def _try_lock(session) -> bool:
    return session.scalar(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": INGEST_LOCK_KEY})


def test_advisory_lock_excludes_other_sessions_and_is_released_on_rollback(pg_engine):
    with Session(pg_engine) as holder, Session(pg_engine) as other:
        acquire_ingest_lock(holder)
        assert _try_lock(other) is False, "a second session must not get the lock while it is held"
        other.rollback()
        holder.rollback()
        assert _try_lock(other) is True, "the lock must be released when the holder rolls back"
        other.rollback()


def test_failed_batch_rolls_back_completely_and_releases_the_lock(pg_engine):
    def feed():
        yield RawObservation(IndicatorType.URL, "http://evil.example.com/a", None, "1")
        raise RuntimeError("feed broke")

    with Session(pg_engine, expire_on_commit=False) as s:
        acquire_ingest_lock(s)
        source = get_or_create_source(s, "rollback-test", None, 0.5)
        with pytest.raises(RuntimeError):
            ingest(s, source, feed())

    with Session(pg_engine) as check:
        assert _count(check, Indicator) == 0
        assert _count(check, Observation) == 0
        assert _count(check, ThreatSource) == 0
        assert _try_lock(check) is True, "the lock must be free after a failed batch"
        check.rollback()


def test_reingestion_is_idempotent_with_timezone_aware_timestamps(pg_engine):
    when = datetime(2026, 11, 6, 10, 0, tzinfo=timezone.utc)
    batch = [
        RawObservation(IndicatorType.URL, "http://evil.example.com/a", when, "1", "malware_download", ["x"]),
        RawObservation(IndicatorType.DOMAIN, "evil.example.com", when, "1:host", "malware_download"),
    ]
    results = []
    for _ in range(2):
        with Session(pg_engine, expire_on_commit=False) as s:
            acquire_ingest_lock(s)
            source = get_or_create_source(s, "idempotence-test", None, 0.5)
            results.append(ingest(s, source, batch))

    assert (results[0].new_indicators, results[0].new_observations) == (2, 2)
    assert (results[1].new_indicators, results[1].new_observations, results[1].duplicate_observations) == (0, 0, 2)
    with Session(pg_engine) as s:
        assert _count(s, Indicator) == 2
        assert _count(s, Observation) == 2
        indicator = s.scalar(select(Indicator).where(Indicator.indicator_type == "url"))
        assert indicator.first_seen == when and indicator.last_seen == when


def test_parallel_ingestion_of_overlapping_batches_does_not_fail_or_duplicate(pg_engine):
    values = [f"http://host{i}.example.com/a" for i in range(150)]
    workers = 4
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        # Opposite orderings are what would deadlock a row-level approach.
        ordered = values if n % 2 == 0 else list(reversed(values))
        batch = [RawObservation(IndicatorType.URL, v, None, f"w{n}-{i}") for i, v in enumerate(ordered)]
        try:
            with Session(pg_engine, expire_on_commit=False) as s:
                acquire_ingest_lock(s)
                source = get_or_create_source(s, "concurrency-test", None, 0.5)
                ingest(s, source, batch)
        except BaseException as exc:  # noqa: BLE001 - surfaced in the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)

    assert not errors, errors
    with Session(pg_engine) as s:
        assert _count(s, Indicator) == len(values)
        assert _count(s, Observation) == len(values) * workers
        assert s.scalar(select(func.sum(Indicator.observation_count))) == len(values) * workers
