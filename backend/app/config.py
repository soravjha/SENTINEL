from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from environment variables or a .env file."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel"
    # Create tables from the ORM models at startup. Docker uses database/schema.sql instead.
    auto_create_tables: bool = False
    log_level: str = "INFO"

    # Protects the collector-trigger endpoint. If unset, that endpoint is disabled.
    admin_api_key: str | None = None

    # URLhaus (abuse.ch) requires a free Auth-Key: https://auth.abuse.ch/
    urlhaus_auth_key: str | None = None
    urlhaus_fetch_limit: int = Field(default=1000, ge=1, le=1000)
    http_timeout_seconds: float = 30.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
