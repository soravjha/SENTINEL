from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, BigIntPK, JSONType, utcnow


class ThreatSource(Base):
    """An intelligence feed (URLhaus, AbuseIPDB, ...)."""

    __tablename__ = "threat_sources"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    feed_url: Mapped[str | None] = mapped_column(Text)
    # 0..1. A placeholder until the Phase 2 source reliability model.
    reliability: Mapped[float] = mapped_column(Float, default=0.5)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Indicator(Base):
    """A unique, normalized indicator (IP, domain, URL or file hash)."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("indicator_type", "value_hash", name="uq_indicator_type_hash"),
        Index("ix_indicators_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(Text)
    # sha256 of the normalized value; keeps the unique index small even for long URLs.
    value_hash: Mapped[str] = mapped_column(String(64))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    observations: Mapped[list[Observation]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan"
    )


class Observation(Base):
    """One sighting of an indicator in one source."""

    __tablename__ = "observations"
    __table_args__ = (
        UniqueConstraint("indicator_id", "source_id", "source_ref", name="uq_observation_ref"),
        Index("ix_observations_source_time", "source_id", "observed_at"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), index=True
    )
    source_id: Mapped[int] = mapped_column(ForeignKey("threat_sources.id"))
    # The feed's own identifier for the sighting; makes re-ingestion idempotent.
    source_ref: Mapped[str] = mapped_column(String(255))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    threat_type: Mapped[str | None] = mapped_column(String(64))
    tags: Mapped[list] = mapped_column(JSONType, default=list)
    details: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    indicator: Mapped[Indicator] = relationship(back_populates="observations")
    source: Mapped[ThreatSource] = relationship()
