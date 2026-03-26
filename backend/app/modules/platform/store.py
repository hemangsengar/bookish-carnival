from datetime import UTC, date, datetime
from threading import Lock
from uuid import uuid4

from app.core.config import settings
from app.modules.platform.schemas import (
    Alert,
    AuditEvent,
    IngestionJob,
    IngestionRequest,
    PolicyViolation,
    Severity,
)


class PlatformStore:
    def __init__(self) -> None:
        self._jobs: list[IngestionJob] = []
        self._violations: list[PolicyViolation] = []
        self._alerts: list[Alert] = []
        self._audit_events: list[AuditEvent] = []
        self._lock = Lock()

    def create_ingestion_job(self, request: IngestionRequest, actor_role: str) -> IngestionJob:
        with self._lock:
            job = IngestionJob(
                id=str(uuid4()),
                source=request.source,
                payload_type=request.payload_type,
                severity=request.severity,
                records_count=request.records_count,
                status="processed",
                policy_violations_count=0,
                alerts_generated_count=0,
                created_at=datetime.now(UTC),
            )
            self._jobs.append(job)

            violations = self._evaluate_policy(job)
            job.policy_violations_count = len(violations)

            generated_alerts = self._generate_alerts(violations)
            job.alerts_generated_count = len(generated_alerts)

            self._audit_events.append(
                AuditEvent(
                    id=str(uuid4()),
                    event_type="ingestion.job.created",
                    actor_role=actor_role,
                    entity_type="ingestion_job",
                    entity_id=job.id,
                    message=f"Ingestion job created for source={job.source}",
                    created_at=datetime.now(UTC),
                )
            )

            return job

    def list_ingestion_jobs(self) -> list[IngestionJob]:
        with self._lock:
            return list(self._jobs)

    def list_policy_violations(self, status_filter: str | None = None) -> list[PolicyViolation]:
        with self._lock:
            if not status_filter:
                return list(self._violations)
            return [item for item in self._violations if item.status == status_filter]

    def resolve_policy_violation(self, violation_id: str, actor_role: str) -> PolicyViolation | None:
        with self._lock:
            for violation in self._violations:
                if violation.id == violation_id:
                    violation.status = "resolved"
                    violation.resolved_at = datetime.now(UTC)
                    self._audit_events.append(
                        AuditEvent(
                            id=str(uuid4()),
                            event_type="policy.violation.resolved",
                            actor_role=actor_role,
                            entity_type="policy_violation",
                            entity_id=violation.id,
                            message="Policy violation resolved",
                            created_at=datetime.now(UTC),
                        )
                    )
                    return violation
            return None

    def list_alerts(self, status_filter: str | None = None) -> list[Alert]:
        with self._lock:
            if not status_filter:
                return list(self._alerts)
            return [item for item in self._alerts if item.status == status_filter]

    def acknowledge_alert(self, alert_id: str, actor_role: str) -> Alert | None:
        with self._lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    alert.status = "acknowledged"
                    alert.acknowledged_at = datetime.now(UTC)
                    self._audit_events.append(
                        AuditEvent(
                            id=str(uuid4()),
                            event_type="alert.acknowledged",
                            actor_role=actor_role,
                            entity_type="alert",
                            entity_id=alert.id,
                            message="Alert acknowledged",
                            created_at=datetime.now(UTC),
                        )
                    )
                    return alert
            return None

    def resolve_alert(self, alert_id: str, actor_role: str) -> Alert | None:
        with self._lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    alert.status = "resolved"
                    alert.resolved_at = datetime.now(UTC)
                    self._audit_events.append(
                        AuditEvent(
                            id=str(uuid4()),
                            event_type="alert.resolved",
                            actor_role=actor_role,
                            entity_type="alert",
                            entity_id=alert.id,
                            message="Alert resolved",
                            created_at=datetime.now(UTC),
                        )
                    )
                    return alert
            return None

    def list_audit_events(self, limit: int = 100) -> list[AuditEvent]:
        with self._lock:
            return list(self._audit_events[-limit:])

    def get_kpis(self) -> dict[str, int]:
        with self._lock:
            active_alerts = sum(1 for alert in self._alerts if alert.status != "resolved")
            jobs_today = sum(1 for job in self._jobs if job.created_at.date() == date.today())
            violations = len(self._violations)
            processed_records = sum(job.records_count for job in self._jobs)

            return {
                "active_alerts": active_alerts,
                "ingestion_jobs_today": jobs_today,
                "policy_violations": violations,
                "processed_records": processed_records,
            }

    def reset_state(self) -> None:
        with self._lock:
            self._jobs.clear()
            self._violations.clear()
            self._alerts.clear()
            self._audit_events.clear()

    def _evaluate_policy(self, job: IngestionJob) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []

        if job.severity in {Severity.high, Severity.critical}:
            violations.append(
                PolicyViolation(
                    id=str(uuid4()),
                    job_id=job.id,
                    rule_name="high_severity_ingestion",
                    severity=job.severity,
                    status="open",
                    description="High severity payload requires compliance review.",
                    created_at=datetime.now(UTC),
                )
            )

        if job.records_count >= settings.policy_records_threshold:
            violations.append(
                PolicyViolation(
                    id=str(uuid4()),
                    job_id=job.id,
                    rule_name="large_batch_ingestion",
                    severity=Severity.medium,
                    status="open",
                    description="Large record volume requires manual verification.",
                    created_at=datetime.now(UTC),
                )
            )

        self._violations.extend(violations)
        return violations

    def _generate_alerts(self, violations: list[PolicyViolation]) -> list[Alert]:
        alerts: list[Alert] = []

        for violation in violations:
            if violation.severity in {Severity.high, Severity.critical}:
                alerts.append(
                    Alert(
                        id=str(uuid4()),
                        violation_id=violation.id,
                        title=f"Policy violation: {violation.rule_name}",
                        priority=violation.severity,
                        status="open",
                        created_at=datetime.now(UTC),
                    )
                )

        self._alerts.extend(alerts)
        return alerts
