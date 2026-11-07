from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from app.services.normalizer import IndicatorType


class CollectorError(RuntimeError):
    """A feed could not be fetched or its response was not understood."""


class CollectorConfigError(CollectorError):
    """A collector is missing required configuration (for example an API key)."""


@dataclass
class RawObservation:
    """A feed record before normalization. Collectors produce these; ingestion stores them."""

    indicator_type: IndicatorType
    raw_value: str
    observed_at: datetime | None = None
    source_ref: str | None = None
    threat_type: str | None = None
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


class BaseCollector(ABC):
    """Subclass this to add a feed: set the class attributes and implement collect()."""

    source_name: ClassVar[str]
    feed_url: ClassVar[str]
    default_reliability: ClassVar[float] = 0.5

    @abstractmethod
    def collect(self) -> list[RawObservation]:
        """Fetch the feed and return raw observations. Must not touch the database."""
