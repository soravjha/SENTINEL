import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.api.routes import router
from app.config import get_settings
from app.database.session import get_db, get_engine
from app.models import Base


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    if settings.auto_create_tables:
        Base.metadata.create_all(get_engine())
    yield


app = FastAPI(
    title="SENTINEL",
    version=__version__,
    description="Open-source threat intelligence engine: collect, normalize and query indicators.",
    lifespan=lifespan,
)
app.include_router(router)


@app.get("/health", tags=["system"])
def health(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail="database unavailable") from exc
    return {"status": "ok", "version": __version__}
