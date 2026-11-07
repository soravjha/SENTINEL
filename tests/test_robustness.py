import httpx
import pytest
from sqlalchemy import func, select

from app.collectors.base import CollectorError, RawObservation
from app.collectors.urlhaus import URLhausCollector, parse_recent_urls
from app.models import Indicator, Observation
from app.services.ingestion import acquire_ingest_lock, get_or_create_source, ingest
from app.services.normalizer import IndicatorType


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def test_exception_mid_batch_rolls_everything_back(session):
    source = get_or_create_source(session, "t", None, 0.5)

    def feed():
        yield RawObservation(IndicatorType.URL, "http://evil.example.com/a", None, "1")
        raise RuntimeError("feed broke")

    with pytest.raises(RuntimeError):
        ingest(session, source, feed())

    assert count(session, Indicator) == 0
    assert count(session, Observation) == 0


def test_non_string_indicator_values_are_rejected_not_crashed(session):
    source = get_or_create_source(session, "t", None, 0.5)
    result = ingest(session, source, [RawObservation(IndicatorType.URL, 12345, None, "1")])
    assert result.rejected == 1
    assert result.new_indicators == 0


def test_advisory_lock_is_a_noop_on_sqlite(session):
    acquire_ingest_lock(session)  # must not raise on non-PostgreSQL databases


def test_malformed_feed_entries_are_tolerated():
    payload = {
        "query_status": "ok",
        "urls": [
            None,
            "text",
            42,
            {"url": None},
            {"url": 12345},
            {"url": "http://evil.example.com/", "tags": "elf", "id": 7, "date_added": "garbage"},
        ],
    }
    observations = parse_recent_urls(payload)
    assert len(observations) == 1
    only = observations[0]
    assert only.tags == ["elf"]
    assert only.observed_at is None
    assert only.source_ref == "7"


def test_urls_field_of_the_wrong_type_yields_nothing():
    assert parse_recent_urls({"query_status": "ok", "urls": "oops"}) == []
    assert parse_recent_urls({"query_status": "ok", "urls": None}) == []


def test_timeout_becomes_a_collector_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(CollectorError):
        URLhausCollector("k", client=client).collect()
