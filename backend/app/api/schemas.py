from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    feed_url: str | None
    reliability: float
    enabled: bool


class ObservationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: SourceOut
    source_ref: str
    observed_at: datetime
    threat_type: str | None
    tags: list[str]
    details: dict


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    indicator_type: str
    value: str
    first_seen: datetime
    last_seen: datetime
    observation_count: int


class IndicatorDetail(IndicatorOut):
    observations: list[ObservationOut]


class IndicatorPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IndicatorOut]


class StatsOut(BaseModel):
    total_indicators: int
    indicators_by_type: dict[str, int]
    total_observations: int
    sources: int


class CollectorRunOut(BaseModel):
    source: str
    received: int
    new_indicators: int
    updated_indicators: int
    new_observations: int
    duplicate_observations: int
    rejected: int
