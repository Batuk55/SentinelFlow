from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class NetworkEvent(Base):
    __tablename__ = "network_events"
    __table_args__ = (
        CheckConstraint("destination_port BETWEEN 0 AND 65535", name="ck_events_dst_port"),
        CheckConstraint("source_port BETWEEN 0 AND 65535", name="ck_events_src_port"),
        CheckConstraint("connection_attempts >= 1", name="ck_events_attempts"),
        Index("ix_events_source_ip", "source_ip"),
        Index("ix_events_timestamp", "event_timestamp"),
        Index("ix_events_source_ts", "source_ip", "event_timestamp"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    event_type: Mapped[str] = mapped_column(String(30), nullable=False)
    connection_status: Mapped[str] = mapped_column(String(20), nullable=False)
    connection_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
