from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.event import EventBatch, EventIn, EventOut, IngestResult
from app.services import event_ingestion
from app.utils.sample_data import generate_scenario

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("", response_model=IngestResult, status_code=201)
def ingest_event(event: EventIn, db: Session = Depends(get_db)):
    """Ingest one event, run detection, create incidents."""
    return event_ingestion.ingest_events(db, [event])


@router.post("/batch", response_model=IngestResult, status_code=201)
def ingest_batch(payload: EventBatch, db: Session = Depends(get_db)):
    """Ingest up to 5000 events atomically. One invalid event rejects the whole batch (HTTP 422)."""
    return event_ingestion.ingest_events(db, payload.events)


@router.post("/sample", response_model=IngestResult, status_code=201)
def ingest_sample(seed: int = Query(42), db: Session = Depends(get_db)):
    """Generate and ingest a synthetic scenario (benign traffic plus six simulated attack patterns)."""
    return event_ingestion.ingest_events(db, generate_scenario(seed=seed).events)


@router.get("", response_model=list[EventOut])
def list_events(
    source_ip: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    return event_ingestion.list_events(db, source_ip, limit, offset)
