"""Indicator normalization. Standard library only, so it is easy to test and reuse.

Every indicator is reduced to a canonical form so the same threat arriving from
different feeds maps to one database row.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class InvalidIndicator(ValueError):
    """Raised when a raw value cannot be normalized into a valid indicator."""


@dataclass(frozen=True)
class NormalizedIndicator:
    indicator_type: IndicatorType
    value: str
    value_hash: str


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = {32, 40, 64}  # md5, sha1, sha256
_ALLOWED_SCHEMES = {"http", "https", "ftp"}
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}


def refang(value: str) -> str:
    """Undo common analyst 'defanging' such as hxxp://evil[.]com."""
    v = value.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)
    v = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", v, flags=re.IGNORECASE)
    return v.replace("[://]", "://").replace("[:]", ":")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _canonical_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def normalize_ip(raw: str, *, allow_non_global: bool = False) -> str:
    candidate = refang(raw).strip("[]")
    try:
        ip = _canonical_ip(candidate)
    except ValueError as exc:
        raise InvalidIndicator(f"not an IP address: {raw!r}") from exc
    if not allow_non_global and not ip.is_global:
        raise InvalidIndicator(f"not a public IP address: {raw!r}")
    return str(ip)


def normalize_domain(raw: str) -> str:
    candidate = refang(raw).strip().rstrip(".").lower()
    if not candidate or any(ch in candidate for ch in "/:@?# \t\r\n"):
        raise InvalidIndicator(f"not a domain name: {raw!r}")
    if _is_ip(candidate):
        raise InvalidIndicator(f"IP address, not a domain: {raw!r}")
    try:
        ascii_name = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidIndicator(f"invalid domain name: {raw!r}") from exc
    labels = ascii_name.split(".")
    if (
        len(ascii_name) > 253
        or len(labels) < 2
        or not all(_LABEL_RE.match(label) for label in labels)
        or labels[-1].isdigit()
    ):
        raise InvalidIndicator(f"invalid domain name: {raw!r}")
    return ascii_name


def normalize_url(raw: str) -> str:
    """Canonical URL: lowercase scheme/host, no fragment, no userinfo, no default port."""
    candidate = refang(raw)
    if not candidate or any(ch.isspace() for ch in candidate):
        raise InvalidIndicator(f"not a URL: {raw!r}")
    try:
        parts = urlsplit(candidate)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidIndicator(f"invalid URL: {raw!r}") from exc

    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES or not host:
        raise InvalidIndicator(f"unsupported or incomplete URL: {raw!r}")

    host_norm = str(_canonical_ip(host)) if _is_ip(host) else normalize_domain(host)
    netloc = f"[{host_norm}]" if ":" in host_norm else host_norm
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"

    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def normalize_hash(raw: str) -> str:
    candidate = raw.strip().lower()
    if len(candidate) not in _HASH_LENGTHS or not _HEX_RE.match(candidate):
        raise InvalidIndicator(f"not an MD5/SHA-1/SHA-256 hash: {raw!r}")
    return candidate


def normalize(indicator_type: IndicatorType, raw: str) -> NormalizedIndicator:
    if not isinstance(raw, str):
        raise InvalidIndicator(f"indicator must be a string, got {type(raw).__name__}")
    if indicator_type is IndicatorType.IP:
        value = normalize_ip(raw)
    elif indicator_type is IndicatorType.DOMAIN:
        value = normalize_domain(raw)
    elif indicator_type is IndicatorType.URL:
        value = normalize_url(raw)
    elif indicator_type is IndicatorType.HASH:
        value = normalize_hash(raw)
    else:  # pragma: no cover
        raise InvalidIndicator(f"unsupported indicator type: {indicator_type!r}")
    return NormalizedIndicator(
        indicator_type=indicator_type,
        value=value,
        value_hash=hashlib.sha256(value.encode("utf-8")).hexdigest(),
    )
