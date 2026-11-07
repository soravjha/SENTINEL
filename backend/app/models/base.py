from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase

# BIGINT on PostgreSQL, INTEGER on SQLite (needed for autoincrement in tests).
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")
# JSONB on PostgreSQL, plain JSON elsewhere.
JSONType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
