from fastapi.testclient import TestClient
from io import BytesIO
from zipfile import ZipFile

from app.main import app


def test_analyze_json_detects_sensitive_log_findings() -> None:
    client = TestClient(app)
    payload = {
        "input_type": "log",
        "content": "2026-03-10 login email=admin@company.com password=admin123 api_key=sk-prod-xyz ERROR stack trace: NullPointerException",
        "options": {"mask": True, "block_high_risk": True, "log_analysis": True},
    }

    response = client.post("/analyze", json=payload)

    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in {"high", "critical"}
    assert data["action"] == "blocked"
    assert len(data["findings"]) >= 4
    finding_types = {item["type"] for item in data["findings"]}
    assert {"email", "password", "api_key", "stack_trace"}.issubset(finding_types)
    assert len(data["insight_cards"]) >= 1
    assert any("Credential" in card["title"] or "secret" in card["title"].lower() for card in data["insight_cards"])
    assert len(data["recommended_actions"]) >= 1


def test_analyze_file_upload() -> None:
    client = TestClient(app)
    file_content = "INFO user=test@example.com token=abc123456789 failed login from 10.0.0.5"

    response = client.post(
        "/analyze/file",
        files={"file": ("app.log", file_content.encode("utf-8"), "text/plain")},
        data={"input_type": "log", "mask": "true", "block_high_risk": "false", "log_analysis": "true"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["content_type"] == "log"
    assert data["action"] in {"masked", "allowed", "blocked"}
    assert len(data["findings"]) >= 1
    assert len(data["insight_cards"]) >= 1


def test_analyze_docx_upload() -> None:
    client = TestClient(app)

    xml = """
        <w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">
            <w:body>
                <w:p><w:r><w:t>email=security@company.com password=secret123</w:t></w:r></w:p>
            </w:body>
        </w:document>
    """.strip()

    buffer = BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", xml)

    response = client.post(
        "/analyze/file",
        files={"file": ("report.docx", buffer.getvalue(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
        data={"input_type": "file", "mask": "true", "block_high_risk": "true", "log_analysis": "true"},
    )

    assert response.status_code == 200
    data = response.json()
    finding_types = {item["type"] for item in data["findings"]}
    assert "email" in finding_types
    assert "password" in finding_types
    assert any(card["severity"] in {"high", "critical"} for card in data["insight_cards"])
