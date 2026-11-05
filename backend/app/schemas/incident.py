from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["Low", "Medium", "High", "Critical"]
Status = Literal["Open", "Investigating", "Resolved", "False Positive"]


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    threat_category: str
    detection_rule: str
    source_ip: str
    severity: Severity
    description: str
    evidence: dict[str, Any]
    status: Status
    detected_at: datetime
    created_at: datetime
    updated_at: datetime


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    author: str
    note: str
    created_at: datetime


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int | None
    action: str
    actor: str
    details: dict[str, Any]
    created_at: datetime


class IncidentDetail(IncidentOut):
    notes: list[NoteOut] = []
    audit_logs: list[AuditLogOut] = []


class StatusUpdate(BaseModel):
    status: Status
    actor: str = Field(default="analyst", min_length=1, max_length=100)


class NoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=5000)
    author: str = Field(default="analyst", min_length=1, max_length=100)

    @field_validator("note", "author")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be blank")
        return value


class DashboardStats(BaseModel):
    total_events: int
    total_incidents: int
    critical_incidents: int
    high_incidents: int
    open_incidents: int
    resolved_incidents: int
    severity_distribution: dict[str, int]
    status_distribution: dict[str, int]
    recent_events: list["EventOutRef"]


from app.schemas.event import EventOut as EventOutRef  # noqa: E402

DashboardStats.model_rebuild()
