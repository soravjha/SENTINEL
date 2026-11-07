from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.collectors.base import BaseCollector, CollectorError, RawObservation
from app.config import Settings, get_settings
from app.database.session import get_db
from app.main import app
from app.services.ingestion import get_or_create_source, ingest
from app.services.normalizer import IndicatorType

ADMIN = {"X-API-Key": "admin-secret"}


@pytest.fixture()
def client(engine):
    maker = sessionmaker(bind=engine, expire_on_commit=False)

    def override_db():
        with maker() as s:
            yield s

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_settings] = lambda: Settings(
        admin_api_key="admin-secret", urlhaus_auth_key="k"
    )
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def seeded(engine):
    when = datetime(2026, 11, 6, tzinfo=timezone.utc)
    with Session(engine, expire_on_commit=False) as s:
        source = get_or_create_source(s, "urlhaus", "https://example.test", 0.5)
        ingest(
            s,
            source,
            [
                RawObservation(IndicatorType.URL, "http://evil.example.com/a.exe", when, "1", "malware_download"),
                RawObservation(IndicatorType.DOMAIN, "evil.example.com", when, "1:host", "malware_download"),
                RawObservation(IndicatorType.IP, "8.8.8.8", when, "2:host", "malware_download"),
            ],
        )


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"


def test_list_filter_and_search(client, seeded):
    page = client.get("/api/v1/indicators").json()
    assert page["total"] == 3

    only_ips = client.get("/api/v1/indicators", params={"type": "ip"}).json()
    assert [i["value"] for i in only_ips["items"]] == ["8.8.8.8"]

    found = client.get("/api/v1/indicators", params={"q": "EVIL"}).json()
    assert found["total"] == 2

    assert client.get("/api/v1/indicators", params={"type": "bogus"}).status_code == 422
    assert client.get("/api/v1/indicators", params={"limit": 0}).status_code == 422


def test_lookup_normalizes_input(client, seeded):
    resp = client.get("/api/v1/indicators/lookup", params={"type": "domain", "value": "EVIL[.]example[.]com."})
    assert resp.status_code == 200
    body = resp.json()
    assert body["value"] == "evil.example.com"
    assert body["observations"][0]["source"]["name"] == "urlhaus"

    assert client.get("/api/v1/indicators/lookup", params={"type": "domain", "value": "other.example"}).status_code == 404
    assert client.get("/api/v1/indicators/lookup", params={"type": "ip", "value": "10.0.0.1"}).status_code == 422


def test_get_indicator_by_id(client, seeded):
    first = client.get("/api/v1/indicators").json()["items"][0]
    assert client.get(f"/api/v1/indicators/{first['id']}").status_code == 200
    assert client.get("/api/v1/indicators/99999").status_code == 404


def test_sources_and_stats(client, seeded):
    assert [s["name"] for s in client.get("/api/v1/sources").json()] == ["urlhaus"]
    stats = client.get("/api/v1/stats").json()
    assert stats["total_indicators"] == 3
    assert stats["indicators_by_type"] == {"url": 1, "domain": 1, "ip": 1}
    assert stats["total_observations"] == 3


class FakeCollector(BaseCollector):
    source_name = "urlhaus"
    feed_url = "https://example.test"

    def collect(self):
        return [RawObservation(IndicatorType.IP, "1.1.1.1", None, "x1")]


def test_collector_endpoint_requires_the_admin_key(client):
    assert client.post("/api/v1/collectors/urlhaus/run").status_code == 401
    assert client.post("/api/v1/collectors/urlhaus/run", headers={"X-API-Key": "wrong"}).status_code == 401


def test_collector_endpoint_is_disabled_without_a_configured_key(client):
    app.dependency_overrides[get_settings] = lambda: Settings(admin_api_key=None)
    assert client.post("/api/v1/collectors/urlhaus/run", headers=ADMIN).status_code == 503


def test_collector_endpoint_runs_and_reports(client, monkeypatch):
    monkeypatch.setattr("app.api.routes.build_collector", lambda name, settings: FakeCollector())
    resp = client.post("/api/v1/collectors/urlhaus/run", headers=ADMIN)
    assert resp.status_code == 200
    assert resp.json()["new_indicators"] == 1
    assert client.get("/api/v1/stats").json()["total_indicators"] == 1


def test_collector_endpoint_error_mapping(client, monkeypatch):
    assert client.post("/api/v1/collectors/nope/run", headers=ADMIN).status_code == 404

    def boom(name, settings):
        raise CollectorError("feed down")

    monkeypatch.setattr("app.api.routes.build_collector", boom)
    assert client.post("/api/v1/collectors/urlhaus/run", headers=ADMIN).status_code == 502
