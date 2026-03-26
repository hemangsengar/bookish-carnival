from fastapi.testclient import TestClient

from app.main import app
from app.modules.platform.dependencies import get_platform_service

ENGINEER_HEADERS = {"x-api-key": "local-dev-api-key", "x-user-role": "engineer"}
ANALYST_HEADERS = {"x-api-key": "local-dev-api-key", "x-user-role": "analyst"}
COMPLIANCE_HEADERS = {"x-api-key": "local-dev-api-key", "x-user-role": "compliance"}
BUSINESS_HEADERS = {"x-api-key": "local-dev-api-key", "x-user-role": "business"}


def test_pipeline_creates_violation_alert_and_updates_states() -> None:
    service = get_platform_service()
    service.reset_state()
    client = TestClient(app)

    create_response = client.post(
        "/ingestion/jobs",
        headers=ENGINEER_HEADERS,
        json={
            "source": "siem",
            "payload_type": "json",
            "severity": "critical",
            "records_count": 12000,
        },
    )

    assert create_response.status_code == 201
    created = create_response.json()
    assert created["policy_violations_count"] == 2
    assert created["alerts_generated_count"] == 1

    violations_response = client.get("/policy/violations", headers=COMPLIANCE_HEADERS)
    assert violations_response.status_code == 200
    violations = violations_response.json()["items"]
    assert len(violations) == 2

    alerts_response = client.get("/alerts", headers=ANALYST_HEADERS)
    assert alerts_response.status_code == 200
    alerts = alerts_response.json()["items"]
    assert len(alerts) == 1
    alert_id = alerts[0]["id"]

    ack_response = client.patch(f"/alerts/{alert_id}/acknowledge", headers=ANALYST_HEADERS)
    assert ack_response.status_code == 200
    assert ack_response.json()["status"] == "acknowledged"

    resolve_response = client.patch(f"/alerts/{alert_id}/resolve", headers=ANALYST_HEADERS)
    assert resolve_response.status_code == 200
    assert resolve_response.json()["status"] == "resolved"

    violation_id = violations[0]["id"]
    resolve_violation_response = client.patch(
        f"/policy/violations/{violation_id}/resolve",
        headers=COMPLIANCE_HEADERS,
    )
    assert resolve_violation_response.status_code == 200
    assert resolve_violation_response.json()["status"] == "resolved"

    kpis_response = client.get("/analytics/kpis", headers=BUSINESS_HEADERS)
    assert kpis_response.status_code == 200
    kpis = kpis_response.json()
    assert kpis["ingestion_jobs_today"] == 1
    assert kpis["policy_violations"] == 2
    assert kpis["processed_records"] == 12000
    assert kpis["active_alerts"] == 0

    audit_response = client.get("/audit/events", headers=COMPLIANCE_HEADERS)
    assert audit_response.status_code == 200
    assert len(audit_response.json()["items"]) >= 4
