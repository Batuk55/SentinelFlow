import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.utils.time import ensure_utc, utcnow

Protocol = Literal["TCP", "UDP", "ICMP"]
EventType = Literal["connection", "login_attempt"]
ConnectionStatus = Literal["success", "failed", "blocked", "reset"]


class EventIn(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    protocol: Protocol
    timestamp: datetime = Field(default_factory=utcnow)
    event_type: EventType
    connection_status: ConnectionStatus
    connection_attempts: int = Field(default=1, ge=1, le=100000)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise ValueError(f"'{value}' is not a valid IPv4/IPv6 address") from exc

    @field_validator("protocol", "event_type", "connection_status", mode="before")
    @classmethod
    def _normalise_case(cls, value):
        if not isinstance(value, str):
            return value
        value = value.strip()
        return value.upper() if value.lower() in {"tcp", "udp", "icmp"} else value.lower()

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)


class EventBatch(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=5000)


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: int
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int
    protocol: str
    event_type: str
    connection_status: str
    connection_attempts: int
    timestamp: datetime = Field(validation_alias="event_timestamp")


class IngestResult(BaseModel):
    events_ingested: int
    detections: int
    incidents_created: int
    incidents_deduplicated: int
    incident_ids: list[int]
    processing_ms: float
