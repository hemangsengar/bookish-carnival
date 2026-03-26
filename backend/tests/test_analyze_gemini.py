from app.modules.analyze.schemas import AnalyzeOptions
from app.modules.analyze.service import AnalyzeService


class FakeGeminiClient:
    def generate_contextual_analysis(self, payload: dict) -> dict:
        return {
            "summary": "Potential credential compromise with immediate lateral movement risk.",
            "insight_cards": [
                {
                    "title": "Credential leak likely enables privileged account abuse",
                    "severity": "critical",
                    "impact": "Leaked password and key artifacts can be weaponized quickly across integrated services.",
                    "evidence": ["password findings: 1", "api_key findings: 1", "line hotspots: [1]"],
                    "recommendation": "Rotate secrets and force re-authentication across affected systems now.",
                }
            ],
            "recommended_actions": [
                "Block distribution of this payload until remediation is complete.",
                "Trigger emergency secret rotation workflow.",
            ],
        }


class MalformedGeminiClient:
    def generate_contextual_analysis(self, payload: dict) -> dict:
        return {"summary": "", "insight_cards": "not-a-list", "recommended_actions": {"a": 1}}


def test_gemini_enhances_contextual_insights() -> None:
    service = AnalyzeService(gemini_client=FakeGeminiClient())

    result = service.analyze(
        input_type="log",
        content="email=admin@company.com password=admin123 api_key=sk-prod-xyz",
        options=AnalyzeOptions(mask=True, block_high_risk=True, log_analysis=True),
    )

    assert "credential compromise" in result.summary.lower()
    assert len(result.insight_cards) >= 1
    assert result.insight_cards[0].severity.value in {"high", "critical"}
    assert len(result.recommended_actions) >= 1


def test_gemini_malformed_response_falls_back_to_deterministic() -> None:
    service = AnalyzeService(gemini_client=MalformedGeminiClient())

    result = service.analyze(
        input_type="log",
        content="password=admin123",
        options=AnalyzeOptions(mask=True, block_high_risk=True, log_analysis=True),
    )

    assert len(result.insight_cards) >= 1
    assert any("secret" in card.title.lower() or "credential" in card.title.lower() for card in result.insight_cards)
    assert len(result.recommended_actions) >= 1
