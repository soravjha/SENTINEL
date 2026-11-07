from datetime import datetime, timezone

from sqlalchemy import func, select

from app.collectors.base import RawObservation
from app.models import Indicator, Observation
from app.services.ingestion import get_or_create_source, ingest
from app.services.normalizer import IndicatorType


def obs(value, ref, when=None, kind=IndicatorType.URL, tags=None):
    return RawObservation(kind, value, when, ref, "malware_download", tags or [], {})


def count(session, model):
    return session.scalar(select(func.count()).select_from(model))


def test_ingest_creates_and_deduplicates(session):
    source = get_or_create_source(session, "test", None, 0.5)
    batch = [
        obs("http://Evil.example.com/a.exe#frag", "1"),
        obs("http://evil.example.com/a.exe", "2"),  # same indicator, different sighting
    ]
    result = ingest(session, source, batch)

    assert result.received == 2
    assert result.new_indicators == 1
    assert result.new_observations == 2
    assert count(session, Indicator) == 1
    assert session.scalar(select(Indicator.observation_count)) == 2


def test_reingesting_the_same_feed_is_idempotent(session):
    source = get_or_create_source(session, "test", None, 0.5)
    batch = [obs("http://evil.example.com/a.exe", "1"), obs("evil.example.com", "1:host", kind=IndicatorType.DOMAIN)]
    ingest(session, source, batch)
    again = ingest(session, source, batch)

    assert again.new_indicators == 0
    assert again.new_observations == 0
    assert again.duplicate_observations == 2
    assert count(session, Indicator) == 2
    assert count(session, Observation) == 2


def test_invalid_and_private_indicators_are_rejected(session):
    source = get_or_create_source(session, "test", None, 0.5)
    result = ingest(
        session,
        source,
        [
            obs("not a url", "1"),
            obs("10.0.0.1", "2", kind=IndicatorType.IP),
            obs("8.8.8.8", "3", kind=IndicatorType.IP),
        ],
    )
    assert result.rejected == 2
    assert result.new_indicators == 1


def test_first_and_last_seen_track_the_observation_window(session):
    source = get_or_create_source(session, "test", None, 0.5)
    feb = datetime(2026, 2, 1, tzinfo=timezone.utc)
    jan = datetime(2026, 1, 1, tzinfo=timezone.utc)
    ingest(session, source, [obs("http://evil.example.com/x", "a", feb)])
    result = ingest(session, source, [obs("http://evil.example.com/x", "b", jan)])

    assert result.updated_indicators == 1
    indicator = session.scalar(select(Indicator))
    assert indicator.first_seen.replace(tzinfo=timezone.utc) == jan
    assert indicator.last_seen.replace(tzinfo=timezone.utc) == feb


def test_two_sources_share_one_indicator(session):
    a = get_or_create_source(session, "feed-a", None, 0.5)
    b = get_or_create_source(session, "feed-b", None, 0.5)
    ingest(session, a, [obs("8.8.4.4", "1", kind=IndicatorType.IP)])
    result = ingest(session, b, [obs("8.8.4.4", "1", kind=IndicatorType.IP)])

    assert result.new_indicators == 0
    assert result.updated_indicators == 1
    assert count(session, Indicator) == 1
    assert count(session, Observation) == 2
