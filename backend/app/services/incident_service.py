"""Incident lifecycle: creation from detections, queries, status changes, notes, audit logs."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditLog, Incident, InvestigationNote, NetworkEvent
from app.schemas.incident import Severity, Status
from app.services.detection_engine import Detection

OPEN_STATES = ("Open", "Investigating")
ALL_SEVERITIES = ["Low", "Medium", "High", "Critical"]
ALL_STATUSES = ["Open", "Investigating", "Resolved", "False Positive"]


def write_audit(db: Session, action: str, actor: str, incident_id: int | None = None,
                details: dict | None = None) -> AuditLog:
    entry = AuditLog(incident_id=incident_id, action=action, actor=actor, details=details or {})
    db.add(entry)
    return entry


def create_incidents_from_detections(db: Session, detections: list[Detection]) -> tuple[list[int], int]:
    """Persist detections as incidents. Skips a detection when an Open/Investigating incident with the
    same rule and source IP already exists. Returns (new_incident_ids, deduplicated_count)."""
    created_ids: list[int] = []
    deduplicated = 0
    for det in detections:
        existing = db.scalar(
            select(Incident.id).where(
                Incident.detection_rule == det.rule,
                Incident.source_ip == det.source_ip,
                Incident.status.in_(OPEN_STATES),
            ).limit(1)
        )
        if existing is not None:
            deduplicated += 1
            continue
        incident = Incident(
            threat_category=det.category, detection_rule=det.rule, source_ip=det.source_ip,
            severity=det.severity, description=det.description, evidence=det.evidence,
            status="Open", detected_at=det.detected_at,
        )
        db.add(incident)
        db.flush()
        write_audit(db, "incident_created", "detection_engine", incident.id,
                    {"rule": det.rule, "severity": det.severity, "source_ip": det.source_ip})
        created_ids.append(incident.id)
    return created_ids, deduplicated


def list_incidents(db: Session, severity: Severity | None = None, status: Status | None = None,
                   limit: int = 100, offset: int = 0) -> list[Incident]:
    stmt = select(Incident)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if status:
        stmt = stmt.where(Incident.status == status)
    stmt = stmt.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(limit).offset(offset)
    return list(db.scalars(stmt))


def get_incident(db: Session, incident_id: int) -> Incident | None:
    return db.get(Incident, incident_id)


def get_audit_logs(db: Session, incident_id: int) -> list[AuditLog]:
    return list(db.scalars(
        select(AuditLog).where(AuditLog.incident_id == incident_id).order_by(AuditLog.id)
    ))


def update_status(db: Session, incident: Incident, new_status: Status, actor: str) -> Incident:
    old_status = incident.status
    if old_status != new_status:
        incident.status = new_status
        write_audit(db, "status_changed", actor, incident.id, {"from": old_status, "to": new_status})
    db.commit()
    db.refresh(incident)
    return incident


def add_note(db: Session, incident: Incident, note: str, author: str) -> InvestigationNote:
    entry = InvestigationNote(incident_id=incident.id, note=note, author=author)
    db.add(entry)
    # Touch the incident so updated_at reflects analyst activity.
    incident.updated_at = func.now()
    write_audit(db, "note_added", author, incident.id, {"note_length": len(note)})
    db.commit()
    db.refresh(entry)
    return entry


def dashboard_stats(db: Session) -> dict:
    sev_rows = dict(db.execute(select(Incident.severity, func.count()).group_by(Incident.severity)).all())
    status_rows = dict(db.execute(select(Incident.status, func.count()).group_by(Incident.status)).all())
    severity = {s: sev_rows.get(s, 0) for s in ALL_SEVERITIES}
    status = {s: status_rows.get(s, 0) for s in ALL_STATUSES}
    recent = list(db.scalars(
        select(NetworkEvent).order_by(NetworkEvent.event_timestamp.desc(), NetworkEvent.id.desc()).limit(10)
    ))
    return {
        "total_events": db.scalar(select(func.count()).select_from(NetworkEvent)) or 0,
        "total_incidents": sum(severity.values()),
        "critical_incidents": severity["Critical"],
        "high_incidents": severity["High"],
        "open_incidents": status["Open"],
        "resolved_incidents": status["Resolved"],
        "severity_distribution": severity,
        "status_distribution": status,
        "recent_events": recent,
    }
