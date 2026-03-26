import json
from typing import Any

import httpx


class GeminiInsightClient:
    def __init__(self, api_key: str, model: str, timeout_seconds: int = 12) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def generate_contextual_analysis(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        prompt = self._build_prompt(payload)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

        body = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                response = client.post(url, params={"key": self.api_key}, json=body)
                response.raise_for_status()
        except Exception:
            return None

        try:
            data = response.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            return self._extract_json(text)
        except Exception:
            return None

    def _extract_json(self, text: str) -> dict[str, Any] | None:
        text = text.strip()

        if text.startswith("```"):
            text = text.strip("`")
            if text.startswith("json"):
                text = text[4:].strip()

        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1 or end <= start:
                return None
            try:
                parsed = json.loads(text[start : end + 1])
                return parsed if isinstance(parsed, dict) else None
            except Exception:
                return None

    def _build_prompt(self, payload: dict[str, Any]) -> str:
        return (
            "You are a senior security incident analyst.\n"
            "Given the JSON payload, produce concise high-impact security intelligence.\n"
            "Return STRICT JSON with this exact shape:\n"
            "{\n"
            '  "summary": "...",\n'
            '  "insight_cards": [\n'
            "    {\n"
            '      "title": "...",\n'
            '      "severity": "low|medium|high|critical",\n'
            '      "impact": "...",\n'
            '      "evidence": ["..."],\n'
            '      "recommendation": "..."\n'
            "    }\n"
            "  ],\n"
            '  "recommended_actions": ["..."]\n'
            "}\n"
            "Constraints: no markdown, no extra keys, max 4 insight cards, max 6 actions.\n"
            f"Payload:\n{json.dumps(payload, ensure_ascii=False)}"
        )
