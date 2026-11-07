import pytest

from app.services.normalizer import (
    IndicatorType,
    InvalidIndicator,
    normalize,
    normalize_domain,
    normalize_hash,
    normalize_ip,
    normalize_url,
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("8.8.8.8", "8.8.8.8"),
        (" 8.8.8[.]8 ", "8.8.8.8"),
        ("2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888"),
        ("[2001:4860:4860::8888]", "2001:4860:4860::8888"),
        ("::ffff:8.8.8.8", "8.8.8.8"),
    ],
)
def test_normalize_ip(raw, expected):
    assert normalize_ip(raw) == expected


@pytest.mark.parametrize("raw", ["10.0.0.1", "127.0.0.1", "192.168.1.5", "169.254.1.1", "0.0.0.0", "nope", "999.1.1.1", "",
                                 "192.0.2.1", "198.51.100.7", "203.0.113.9"])
def test_normalize_ip_rejects_non_public_or_invalid(raw):
    with pytest.raises(InvalidIndicator):
        normalize_ip(raw)


def test_normalize_ip_can_allow_private():
    assert normalize_ip("10.0.0.1", allow_non_global=True) == "10.0.0.1"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Evil.Example.COM", "evil.example.com"),
        ("evil.example.com.", "evil.example.com"),
        ("evil[.]example[.]com", "evil.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "localhost", "1.2.3.4", "a..b.com", "-bad.example.com", "bad-.example.com",
     "has space.com", "http://x.com", "x.com/path", "a.123", ("a" * 64) + ".com"],
)
def test_normalize_domain_rejects_invalid(raw):
    with pytest.raises(InvalidIndicator):
        normalize_domain(raw)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("http://Evil.Example.com/a.exe", "http://evil.example.com/a.exe"),
        ("http://evil.example.com", "http://evil.example.com/"),
        ("http://evil.example.com:80/x", "http://evil.example.com/x"),
        ("https://evil.example.com:443/x", "https://evil.example.com/x"),
        ("http://evil.example.com:8080/x", "http://evil.example.com:8080/x"),
        ("http://evil.example.com/a?b=1#frag", "http://evil.example.com/a?b=1"),
        ("hxxps://evil[.]example[.]com/a", "https://evil.example.com/a"),
        ("http://user:pw@evil.example.com/a", "http://evil.example.com/a"),
        ("http://1.2.3.4/bin.sh", "http://1.2.3.4/bin.sh"),
        ("http://10.0.0.1:81/x", "http://10.0.0.1:81/x"),
        ("http://[2001:db8::1]:8080/x", "http://[2001:db8::1]:8080/x"),
    ],
)
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["", "evil.example.com/a", "javascript:alert(1)", "file:///etc/passwd",
     "http://", "http://bad host/x", "http://evil.example.com:99999/x"],
)
def test_normalize_url_rejects_invalid(raw):
    with pytest.raises(InvalidIndicator):
        normalize_url(raw)


def test_normalize_hash():
    sha256 = "A" * 64
    assert normalize_hash(f" {sha256} ") == "a" * 64
    with pytest.raises(InvalidIndicator):
        normalize_hash("xyz")
    with pytest.raises(InvalidIndicator):
        normalize_hash("g" * 32)


def test_equivalent_inputs_share_a_hash():
    a = normalize(IndicatorType.URL, "HTTP://Evil.Example.com:80/x#a")
    b = normalize(IndicatorType.URL, "hxxp://evil[.]example[.]com/x")
    assert a.value == b.value
    assert a.value_hash == b.value_hash


def test_same_value_different_type_has_distinct_identity():
    assert normalize(IndicatorType.DOMAIN, "a.example").indicator_type is IndicatorType.DOMAIN
