from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.api.schemas import (
    CollectorRunOut,
    IndicatorDetail,
    IndicatorOut,
    IndicatorPage,
    ObservationOut,
    SourceOut,
    StatsOut,
)
from app.collectors.base import CollectorConfigError, CollectorError
from app.config import Settings, get_settings
from app.database.session import get_db
from app.models import Indicator, Observation, ThreatSource
from app.services.normalizer import IndicatorType, InvalidIndicator, normalize
from app.services.runner import SUPPORTED_COLLECTORS, build_collector, run_collector

router = APIRouter(prefix="/api/v1")

MAX_OBSERVATIONS_IN_DETAIL = 100


def _detail(db: Session, indicator: Indicator) -> IndicatorDetail:
    observations = db.scalars(
        select(Observation)
        .where(Observation.indicator_id == indicator.id)
        .order_by(Observation.observed_at.desc(), Observation.id.desc())
        .limit(MAX_OBSERVATIONS_IN_DETAIL)
    ).all()
    return IndicatorDetail(
        **IndicatorOut.model_validate(indicator).model_dump(),
        observations=[ObservationOut.model_validate(o) for o in observations],
    )


@router.get("/indicators", response_model=IndicatorPage)
def list_indicators(
    indicator_type: IndicatorType | None = Query(default=None, alias="type"),
    q: str | None = Query(default=None, min_length=1, max_length=255),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> IndicatorPage:
    stmt = select(Indicator)
    if indicator_type is not None:
        stmt = stmt.where(Indicator.indicator_type == indicator_type.value)
    if q:
        stmt = stmt.where(func.lower(Indicator.value).contains(q.lower(), autoescape=True))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(
        stmt.order_by(Indicator.last_seen.desc(), Indicator.id.desc()).limit(limit).offset(offset)
    ).all()
    return IndicatorPage(
        total=total,
        limit=limit,
        offset=offset,
        items=[IndicatorOut.model_validate(i) for i in items],
    )


# Declared before /indicators/{indicator_id} so "lookup" is not parsed as an id.
@router.get("/indicators/lookup", response_model=IndicatorDetail)
def lookup_indicator(
    indicator_type: IndicatorType = Query(..., alias="type"),
    value: str = Query(..., min_length=1, max_length=2048),
    db: Session = Depends(get_db),
) -> IndicatorDetail:
    """Find an indicator by value. The value is normalized first, so defanged or
    differently-cased input (hxxp://Evil[.]com) still matches."""
    try:
        norm = normalize(indicator_type, value)
    except InvalidIndicator as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    indicator = db.scalar(
        select(Indicator).where(
            Indicator.indicator_type == norm.indicator_type.value,
            Indicator.value_hash == norm.value_hash,
        )
    )
    if indicator is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    return _detail(db, indicator)


@router.get("/indicators/{indicator_id}", response_model=IndicatorDetail)
def get_indicator(indicator_id: int, db: Session = Depends(get_db)) -> IndicatorDetail:
    indicator = db.get(Indicator, indicator_id)
    if indicator is None:
        raise HTTPException(status_code=404, detail="indicator not found")
    return _detail(db, indicator)


@router.get("/sources", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db)) -> list[SourceOut]:
    sources = db.scalars(select(ThreatSource).order_by(ThreatSource.name)).all()
    return [SourceOut.model_validate(s) for s in sources]


@router.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)) -> StatsOut:
    by_type = {
        kind: count
        for kind, count in db.execute(
            select(Indicator.indicator_type, func.count()).group_by(Indicator.indicator_type)
        ).all()
    }
    return StatsOut(
        total_indicators=sum(by_type.values()),
        indicators_by_type=by_type,
        total_observations=db.scalar(select(func.count()).select_from(Observation)) or 0,
        sources=db.scalar(select(func.count()).select_from(ThreatSource)) or 0,
    )


@router.post(
    "/collectors/{name}/run",
    response_model=CollectorRunOut,
    dependencies=[Depends(require_admin)],
)
def run_collector_endpoint(
    name: str,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> CollectorRunOut:
    """Run one collector now. Requires the X-API-Key header (ADMIN_API_KEY)."""
    if name not in SUPPORTED_COLLECTORS:
        raise HTTPException(status_code=404, detail=f"unknown collector: {name}")
    try:
        collector = build_collector(name, settings)
        result = run_collector(db, collector)
    except CollectorConfigError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except CollectorError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return CollectorRunOut(source=name, **vars(result))
