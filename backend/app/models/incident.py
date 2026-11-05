from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("severity IN ('Low','Medium','High','Critical')", name="ck_incidents_severity"),
        CheckConstraint(
            "status IN ('Open','Investigating','Resolved','False Positive')", name="ck_incidents_status"
        ),
        Index("ix_incidents_severity", "severity"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_source_rule", "source_ip", "detection_rule"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    threat_category: Mapped[str] = mapped_column(String(100), nullable=False)
    detection_rule: Mapped[str] = mapped_column(String(100), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="Open")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    notes: Mapped[list["InvestigationNote"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="InvestigationNote.created_at"
    )


class InvestigationNote(Base):
    __tablename__ = "investigation_notes"
    __table_args__ = (Index("ix_notes_incident", "incident_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    author: Mapped[str] = mapped_column(String(100), nullable=False, server_default="analyst")
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    incident: Mapped[Incident] = relationship(back_populates="notes")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_incident", "incident_id"),
        Index("ix_audit_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
