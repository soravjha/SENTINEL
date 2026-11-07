from datetime import datetime, timezone

import httpx
import pytest

from app.collectors.base import CollectorConfigError, CollectorError
from app.collectors.urlhaus import URLhausCollector, parse_recent_urls
from app.services.normalizer import IndicatorType

PAYLOAD = {
    "query_status": "ok",
    "urls": [
        {
            "id": "3001",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/3001/",
            "url": "http://Evil.example.com/bad.exe",
            "url_status": "online",
            "host": "evil.example.com",
            "date_added": "2026-11-06 10:15:00 UTC",
            "threat": "malware_download",
            "tags": ["elf", "mirai"],
            "reporter": "someone",
        },
        {
            "id": "3002",
            "url": "http://8.8.8.8/x.sh",
            "url_status": "offline",
            "host": "8.8.8.8",
            "date_added": "2026-11-06 11:00:00 UTC",
            "threat": "malware_download",
            "tags": None,
        },
        {"id": "3003"},  # no url: skipped
    ],
}


def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_parse_produces_url_and_host_observations():
    obs = parse_recent_urls(PAYLOAD)
    assert [o.indicator_type for o in obs] == [
        IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.URL, IndicatorType.IP,
    ]
    url_obs, host_obs = obs[0], obs[1]
    assert url_obs.source_ref == "3001"
    assert host_obs.source_ref == "3001:host"
    assert url_obs.observed_at == datetime(2026, 11, 6, 10, 15, tzinfo=timezone.utc)
    assert url_obs.tags == ["elf", "mirai"]
    assert "derived-from-url" in host_obs.tags
    assert url_obs.details["url_status"] == "online"
    assert obs[2].tags == []


def test_no_results_is_empty_and_unknown_status_is_an_error():
    assert parse_recent_urls({"query_status": "no_results"}) == []
    with pytest.raises(CollectorError):
        parse_recent_urls({"query_status": "http_post_expected"})
    with pytest.raises(CollectorError):
        parse_recent_urls([])


def test_collect_sends_auth_key_and_limit():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Auth-Key")
        seen["path"] = request.url.path
        return httpx.Response(200, json=PAYLOAD)

    collector = URLhausCollector("secret-key", limit=2, client=client_for(handler))
    observations = collector.collect()

    assert seen == {"auth": "secret-key", "path": "/v1/urls/recent/limit/2/"}
    assert len(observations) == 4


def test_http_errors_become_collector_errors():
    collector = URLhausCollector("k", client=client_for(lambda r: httpx.Response(401, json={})))
    with pytest.raises(CollectorError):
        collector.collect()


def test_non_json_body_becomes_collector_error():
    collector = URLhausCollector("k", client=client_for(lambda r: httpx.Response(200, text="<html>")))
    with pytest.raises(CollectorError):
        collector.collect()


@pytest.mark.parametrize("key", [None, ""])
def test_missing_key_is_a_config_error(key):
    with pytest.raises(CollectorConfigError):
        URLhausCollector(key)
