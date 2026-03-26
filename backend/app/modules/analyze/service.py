import re
from collections import Counter

from app.modules.analyze.schemas import AnalyzeOptions, AnalyzeResponse, Finding, RiskLevel

RISK_SCORES: dict[RiskLevel, int] = {
    RiskLevel.low: 1,
    RiskLevel.medium: 3,
    RiskLevel.high: 5,
    RiskLevel.critical: 8,
}

PATTERNS: list[tuple[str, RiskLevel, re.Pattern[str]]] = [
    ("email", RiskLevel.low, re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("phone", RiskLevel.low, re.compile(r"\b(?:\+\d{1,3}[\s-]?)?(?:\d{10}|\d{3}[\s-]\d{3}[\s-]\d{4})\b")),
    (
        "api_key",
        RiskLevel.high,
        re.compile(r"(?:api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{8,}|\bsk-[A-Za-z0-9_\-]{8,}\b)", re.IGNORECASE),
    ),
    (
        "password",
        RiskLevel.critical,
        re.compile(r"password\s*[:=]\s*[^\s,;]+", re.IGNORECASE),
    ),
    (
        "token",
        RiskLevel.high,
        re.compile(r"(?:token|bearer)\s*[:=]?\s*[A-Za-z0-9_\-\.]{8,}", re.IGNORECASE),
    ),
    (
        "stack_trace",
        RiskLevel.medium,
        re.compile(r"(?:traceback|exception|\sat\s.+:\d+)", re.IGNORECASE),
    ),
    (
        "failed_login",
        RiskLevel.medium,
        re.compile(r"failed login|authentication failed|invalid credentials", re.IGNORECASE),
    ),
]

INSIGHT_TEMPLATES: dict[str, str] = {
    "api_key": "API key exposed in logs/content",
    "password": "Sensitive credentials exposed",
    "email": "Personally identifiable information (email) detected",
    "phone": "Potential personal contact data detected",
    "token": "Access token leakage risk detected",
    "stack_trace": "Stack trace reveals internal system details",
    "failed_login": "Multiple failed authentication indicators detected",
}


class AnalyzeService:
    def analyze(self, input_type: str, content: str, options: AnalyzeOptions) -> AnalyzeResponse:
        findings = self._detect_findings(content=content, input_type=input_type, log_analysis=options.log_analysis)
        risk_score = sum(RISK_SCORES[finding.risk] for finding in findings)
        risk_level = self._risk_level_from_score(risk_score)
        insights = self._build_insights(findings)

        action = "allowed"
        if options.block_high_risk and risk_level in {RiskLevel.high, RiskLevel.critical}:
            action = "blocked"
        elif options.mask and findings:
            action = "masked"

        summary = self._build_summary(input_type=input_type, findings=findings, risk_level=risk_level)
        sanitized_preview = self._sanitize_content(content, findings) if options.mask and findings else content[:1200]

        return AnalyzeResponse(
            summary=summary,
            content_type=input_type,
            findings=findings,
            risk_score=risk_score,
            risk_level=risk_level,
            action=action,
            insights=insights,
            sanitized_preview=sanitized_preview,
        )

    def _detect_findings(self, content: str, input_type: str, log_analysis: bool) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines() or [content]

        for index, line in enumerate(lines, start=1):
            for finding_type, risk, pattern in PATTERNS:
                if not log_analysis and finding_type in {"stack_trace", "failed_login"}:
                    continue
                if input_type != "log" and finding_type in {"stack_trace", "failed_login"} and not log_analysis:
                    continue
                for match in pattern.finditer(line):
                    findings.append(
                        Finding(
                            type=finding_type,
                            risk=risk,
                            line=index,
                            value=match.group(0),
                        )
                    )

        return findings

    def _risk_level_from_score(self, score: int) -> RiskLevel:
        if score >= 15:
            return RiskLevel.critical
        if score >= 10:
            return RiskLevel.high
        if score >= 5:
            return RiskLevel.medium
        return RiskLevel.low

    def _build_insights(self, findings: list[Finding]) -> list[str]:
        if not findings:
            return ["No significant security risks detected"]

        counts = Counter(finding.type for finding in findings)
        insights: list[str] = []
        for finding_type in sorted(counts.keys()):
            base = INSIGHT_TEMPLATES.get(finding_type, f"{finding_type} detected")
            insights.append(f"{base} ({counts[finding_type]} occurrence(s))")
        return insights

    def _build_summary(self, input_type: str, findings: list[Finding], risk_level: RiskLevel) -> str:
        if not findings:
            return f"{input_type.upper()} content appears clean with no critical findings"

        finding_types = sorted({finding.type for finding in findings})
        joined = ", ".join(finding_types)
        return f"{input_type.upper()} content contains {len(findings)} findings: {joined}. Overall risk: {risk_level.value}."

    def _sanitize_content(self, content: str, findings: list[Finding]) -> str:
        sanitized = content
        for finding in findings:
            if finding.value:
                sanitized = sanitized.replace(finding.value, "[REDACTED]")
        return sanitized[:1200]
