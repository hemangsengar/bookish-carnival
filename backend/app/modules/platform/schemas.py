from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IngestionRequest(BaseModel):
    source: str = Field(min_length=1, max_length=255)
    payload_type: str = Field(min_length=1, max_length=100)
    severity: Severity = Severity.low
    records_count: int = Field(default=1, ge=1, le=1_000_000)


class IngestionJob(BaseModel):
    id: str
    source: str
    payload_type: str
    severity: Severity
    records_count: int
    status: str
    policy_violations_count: int
    alerts_generated_count: int
    created_at: datetime


class IngestionListResponse(BaseModel):
    items: list[IngestionJob]


class PolicyViolation(BaseModel):
    id: str
    job_id: str
    rule_name: str
    severity: Severity
    status: str
    description: str
    created_at: datetime
    resolved_at: datetime | None = None


class PolicyViolationListResponse(BaseModel):
    items: list[PolicyViolation]


class Alert(BaseModel):
    id: str
    violation_id: str
    title: str
    priority: Severity
    status: str
    created_at: datetime
    acknowledged_at: datetime | None = None
    resolved_at: datetime | None = None


class AlertListResponse(BaseModel):
    items: list[Alert]


class AuditEvent(BaseModel):
    id: str
    event_type: str
    actor_role: str
    entity_type: str
    entity_id: str
    message: str
    created_at: datetime


class AuditEventListResponse(BaseModel):
    items: list[AuditEvent]


class AnalyticsKpis(BaseModel):
    active_alerts: int
    ingestion_jobs_today: int
    policy_violations: int
    processed_records: int
