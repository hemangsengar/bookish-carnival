from fastapi.testclient import TestClient

from app.main import app
from app.modules.ingestion.dependencies import get_ingestion_service

API_KEY_HEADER = {"x-api-key": "local-dev-api-key"}
ENGINEER_HEADERS = {"x-api-key": "local-dev-api-key", "x-user-role": "engineer"}
ANALYST_HEADERS = {"x-api-key": "local-dev-api-key", "x-user-role": "analyst"}


def test_ingestion_requires_api_key() -> None:
    client = TestClient(app)
    response = client.get("/ingestion/jobs")

    assert response.status_code == 401


def test_ingestion_forbidden_without_valid_role() -> None:
    client = TestClient(app)
    response = client.get(
        "/ingestion/jobs",
        headers={"x-api-key": "local-dev-api-key", "x-user-role": "guest"},
    )

    assert response.status_code == 403


def test_create_and_list_ingestion_jobs() -> None:
    service = get_ingestion_service()
    service.reset_state()

    client = TestClient(app)

    create_response = client.post(
        "/ingestion/jobs",
        headers=ENGINEER_HEADERS,
        json={"source": "firewall", "payload_type": "json", "severity": "high", "records_count": 25},
    )

    assert create_response.status_code == 201
    created = create_response.json()

    assert created["source"] == "firewall"
    assert created["payload_type"] == "json"
    assert created["severity"] == "high"
    assert created["records_count"] == 25
    assert created["status"] == "processed"
    assert created["policy_violations_count"] == 1
    assert created["alerts_generated_count"] == 1
    assert created["id"]
    assert created["created_at"]

    list_response = client.get("/ingestion/jobs", headers=ANALYST_HEADERS)

    assert list_response.status_code == 200
    payload = list_response.json()
    assert len(payload["items"]) == 1
    assert payload["items"][0]["id"] == created["id"]
