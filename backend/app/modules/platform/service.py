from fastapi import HTTPException, status

from app.modules.platform.schemas import (
    Alert,
    AnalyticsKpis,
    AuditEvent,
    IngestionJob,
    IngestionRequest,
    PolicyViolation,
)
from app.modules.platform.store import PlatformStore


class PlatformService:
    def __init__(self, store: PlatformStore) -> None:
        self.store = store

    def create_ingestion_job(self, request: IngestionRequest, actor_role: str) -> IngestionJob:
        return self.store.create_ingestion_job(request=request, actor_role=actor_role)

    def list_ingestion_jobs(self) -> list[IngestionJob]:
        return self.store.list_ingestion_jobs()

    def list_policy_violations(self, status_filter: str | None = None) -> list[PolicyViolation]:
        return self.store.list_policy_violations(status_filter=status_filter)

    def resolve_policy_violation(self, violation_id: str, actor_role: str) -> PolicyViolation:
        violation = self.store.resolve_policy_violation(violation_id=violation_id, actor_role=actor_role)
        if not violation:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy violation not found")
        return violation

    def list_alerts(self, status_filter: str | None = None) -> list[Alert]:
        return self.store.list_alerts(status_filter=status_filter)

    def acknowledge_alert(self, alert_id: str, actor_role: str) -> Alert:
        alert = self.store.acknowledge_alert(alert_id=alert_id, actor_role=actor_role)
        if not alert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        return alert

    def resolve_alert(self, alert_id: str, actor_role: str) -> Alert:
        alert = self.store.resolve_alert(alert_id=alert_id, actor_role=actor_role)
        if not alert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        return alert

    def get_kpis(self) -> AnalyticsKpis:
        return AnalyticsKpis(**self.store.get_kpis())

    def list_audit_events(self, limit: int = 100) -> list[AuditEvent]:
        return self.store.list_audit_events(limit=limit)

    def reset_state(self) -> None:
        self.store.reset_state()
