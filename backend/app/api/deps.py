import secrets

from fastapi import Depends, Header, HTTPException

from app.config import Settings, get_settings


def require_admin(
    x_api_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    """Guards state-changing endpoints. Disabled entirely when ADMIN_API_KEY is unset."""
    if not settings.admin_api_key:
        raise HTTPException(status_code=503, detail="ADMIN_API_KEY is not configured")
    if not x_api_key or not secrets.compare_digest(
        x_api_key.encode("utf-8"), settings.admin_api_key.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")
