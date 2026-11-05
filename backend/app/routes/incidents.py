from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.incident import (
    AuditLogOut, IncidentDetail, IncidentOut, NoteCreate, NoteOut, Severity, Status, StatusUpdate,
)
from app.services import incident_service

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _get_or_404(db: Session, incident_id: int):
    incident = incident_service.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    severity: Severity | None = None,
    status: Status | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    return incident_service.list_incidents(db, severity, status, limit, offset)


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = _get_or_404(db, incident_id)
    detail = IncidentDetail.model_validate(incident)
    detail.audit_logs = [
        AuditLogOut.model_validate(entry) for entry in incident_service.get_audit_logs(db, incident_id)
    ]
    return detail


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_status(incident_id: int, body: StatusUpdate, db: Session = Depends(get_db)):
    incident = _get_or_404(db, incident_id)
    return incident_service.update_status(db, incident, body.status, body.actor)


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=201)
def add_note(incident_id: int, body: NoteCreate, db: Session = Depends(get_db)):
    incident = _get_or_404(db, incident_id)
    return incident_service.add_note(db, incident, body.note, body.author)
