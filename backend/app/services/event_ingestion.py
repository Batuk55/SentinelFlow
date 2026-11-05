"""Event ingestion: validate -> store -> run detection -> create incidents (one transaction)."""
from __future__ import annotations

from datetime import timedelta
from functools import lru_cache
from time import perf_counter

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import NetworkEvent
from app.schemas.event import EventIn, IngestResult
from app.services import incident_service
from app.services.detection_engine import DetectionEngine, EventRecord, load_rules
from app.utils.time import utcnow


@lru_cache
def get_engine() -> DetectionEngine:
    path = get_settings().detection_rules_path or None
    return DetectionEngine(load_rules(path))


def _to_record(row: NetworkEvent) -> EventRecord:
    return EventRecord(
        id=row.id, source_ip=row.source_ip, destination_ip=row.destination_ip,
        destination_port=row.destination_port, protocol=row.protocol, event_type=row.event_type,
        connection_status=row.connection_status, connection_attempts=row.connection_attempts,
        timestamp=row.event_timestamp,
    )


def ingest_events(db: Session, events: list[EventIn]) -> IngestResult:
    started = perf_counter()
    engine = get_engine()

    rows = [
        NetworkEvent(
            source_ip=e.source_ip, destination_ip=e.destination_ip, source_port=e.source_port,
            destination_port=e.destination_port, protocol=e.protocol, event_type=e.event_type,
            connection_status=e.connection_status, connection_attempts=e.connection_attempts,
            event_timestamp=e.timestamp,
        )
        for e in events
    ]
    db.add_all(rows)
    db.flush()  # assigns primary keys
    new_ids = {r.id for r in rows}

    # Pull stored history for the affected sources so windows can span earlier batches.
    sources = {r.source_ip for r in rows}
    cutoff = min(e.timestamp for e in events) - timedelta(seconds=engine.max_window_seconds)
    history = db.scalars(
        select(NetworkEvent).where(
            NetworkEvent.source_ip.in_(sources), NetworkEvent.event_timestamp >= cutoff
        )
    )
    detections = engine.analyze([_to_record(r) for r in history], now=utcnow())
    # Only act on detections that involve at least one event from this batch, so that
    # resolving an incident does not cause the same old events to re-open it on the next ingest.
    detections = [d for d in detections if new_ids.intersection(d.event_ids)]

    created_ids, deduplicated = incident_service.create_incidents_from_detections(db, detections)
    incident_service.write_audit(
        db, "events_ingested", "api", None,
        {"events": len(rows), "detections": len(detections), "incidents_created": len(created_ids)},
    )
    db.commit()
    return IngestResult(
        events_ingested=len(rows), detections=len(detections), incidents_created=len(created_ids),
        incidents_deduplicated=deduplicated, incident_ids=created_ids,
        processing_ms=round((perf_counter() - started) * 1000, 2),
    )


def list_events(db: Session, source_ip: str | None, limit: int, offset: int) -> list[NetworkEvent]:
    stmt = select(NetworkEvent)
    if source_ip:
        stmt = stmt.where(NetworkEvent.source_ip == source_ip)
    stmt = stmt.order_by(NetworkEvent.event_timestamp.desc(), NetworkEvent.id.desc()).limit(limit).offset(offset)
    return list(db.scalars(stmt))
