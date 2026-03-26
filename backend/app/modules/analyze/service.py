import re
from collections import Counter, defaultdict
from typing import Any

from app.modules.analyze.schemas import AnalyzeOptions, AnalyzeResponse, Finding, InsightCard, RiskLevel

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
    def __init__(self, gemini_client: Any | None = None) -> None:
        self.gemini_client = gemini_client

    def analyze(self, input_type: str, content: str, options: AnalyzeOptions) -> AnalyzeResponse:
        findings = self._detect_findings(content=content, input_type=input_type, log_analysis=options.log_analysis)
        risk_score = sum(RISK_SCORES[finding.risk] for finding in findings)
        risk_level = self._risk_level_from_score(risk_score)
        insight_cards = self._build_insight_cards(findings=findings, risk_level=risk_level)
        insights = [card.title for card in insight_cards]

        action = "allowed"
        if options.block_high_risk and risk_level in {RiskLevel.high, RiskLevel.critical}:
            action = "blocked"
        elif options.mask and findings:
            action = "masked"

        summary = self._build_summary(input_type=input_type, findings=findings, risk_level=risk_level)
        sanitized_preview = self._sanitize_content(content, findings) if options.mask and findings else content[:1200]
        recommended_actions = self._build_recommended_actions(insight_cards=insight_cards, action=action)

        summary, insight_cards, recommended_actions = self._try_gemini_enhancement(
            input_type=input_type,
            content=content,
            findings=findings,
            risk_level=risk_level,
            deterministic_summary=summary,
            deterministic_cards=insight_cards,
            deterministic_actions=recommended_actions,
        )
        insights = [card.title for card in insight_cards]

        return AnalyzeResponse(
            summary=summary,
            content_type=input_type,
            findings=findings,
            risk_score=risk_score,
            risk_level=risk_level,
            action=action,
            insights=insights,
            insight_cards=insight_cards,
            recommended_actions=recommended_actions,
            sanitized_preview=sanitized_preview,
        )

    def _try_gemini_enhancement(
        self,
        input_type: str,
        content: str,
        findings: list[Finding],
        risk_level: RiskLevel,
        deterministic_summary: str,
        deterministic_cards: list[InsightCard],
        deterministic_actions: list[str],
    ) -> tuple[str, list[InsightCard], list[str]]:
        if self.gemini_client is None:
            return deterministic_summary, deterministic_cards, deterministic_actions

        payload = {
            "input_type": input_type,
            "risk_level": risk_level.value,
            "findings": [
                {"type": f.type, "risk": f.risk.value, "line": f.line, "value": f.value} for f in findings[:80]
            ],
            "preview": content[:1500],
        }

        result = self.gemini_client.generate_contextual_analysis(payload)
        if not result:
            return deterministic_summary, deterministic_cards, deterministic_actions

        summary = result.get("summary")
        cards_payload = result.get("insight_cards")
        actions_payload = result.get("recommended_actions")

        if not isinstance(summary, str) or not summary.strip():
            summary = deterministic_summary

        parsed_cards = self._parse_gemini_cards(cards_payload)
        if not parsed_cards:
            parsed_cards = deterministic_cards

        parsed_actions = self._parse_gemini_actions(actions_payload)
        if not parsed_actions:
            parsed_actions = deterministic_actions

        return summary, parsed_cards[:4], parsed_actions[:6]

    def _parse_gemini_cards(self, cards_payload: Any) -> list[InsightCard]:
        if not isinstance(cards_payload, list):
            return []

        parsed: list[InsightCard] = []
        for item in cards_payload:
            if not isinstance(item, dict):
                continue

            severity_raw = str(item.get("severity", "medium")).lower()
            if severity_raw not in {"low", "medium", "high", "critical"}:
                severity_raw = "medium"

            evidence = item.get("evidence")
            if not isinstance(evidence, list):
                evidence = []

            title = str(item.get("title", "Security signal detected")).strip()
            impact = str(item.get("impact", "Potential security impact identified.")).strip()
            recommendation = str(item.get("recommendation", "Review and remediate this risk.")).strip()

            parsed.append(
                InsightCard(
                    title=title[:160],
                    severity=RiskLevel(severity_raw),
                    impact=impact[:500],
                    evidence=[str(entry)[:200] for entry in evidence[:5]],
                    recommendation=recommendation[:300],
                )
            )

        return parsed

    def _parse_gemini_actions(self, actions_payload: Any) -> list[str]:
        if not isinstance(actions_payload, list):
            return []
        actions: list[str] = []
        for action in actions_payload[:8]:
            if not isinstance(action, str):
                continue
            action = action.strip()
            if action and action not in actions:
                actions.append(action[:220])
        return actions

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

    def _build_insight_cards(self, findings: list[Finding], risk_level: RiskLevel) -> list[InsightCard]:
        if not findings:
            return [
                InsightCard(
                    title="No immediate exposure signals detected",
                    severity=RiskLevel.low,
                    impact="No high-confidence secrets, credentials, or abuse patterns were found in the submitted data.",
                    evidence=["No findings generated by detection engine"],
                    recommendation="Keep monitoring with periodic scans and enforce log redaction at source.",
                )
            ]

        cards: list[InsightCard] = []
        counts = Counter(finding.type for finding in findings)

        type_to_lines: dict[str, list[int]] = defaultdict(list)
        findings_per_line: Counter[int] = Counter()
        for finding in findings:
            if finding.line is not None:
                type_to_lines[finding.type].append(finding.line)
                findings_per_line[finding.line] += 1

        hotspot_lines = [line for line, _ in findings_per_line.most_common(3)]

        secret_types = [t for t in ("password", "api_key", "token") if counts.get(t, 0) > 0]
        secret_count = sum(counts.get(t, 0) for t in secret_types)
        if secret_count:
            severity = RiskLevel.critical if counts.get("password", 0) > 0 else RiskLevel.high
            cards.append(
                InsightCard(
                    title="Credential and secret leakage creates immediate takeover risk",
                    severity=severity,
                    impact=(
                        f"Detected {secret_count} secret-like artifact(s) across {len(set(hotspot_lines)) or 1} hotspot line(s), "
                        "which can enable unauthorized API or account access."
                    ),
                    evidence=[
                        f"password findings: {counts.get('password', 0)}",
                        f"api_key findings: {counts.get('api_key', 0)}",
                        f"token findings: {counts.get('token', 0)}",
                        f"hotspot lines: {hotspot_lines or ['n/a']}",
                    ],
                    recommendation="Rotate exposed secrets immediately, invalidate active sessions/tokens, and purge sensitive values from logs.",
                )
            )

        if counts.get("failed_login", 0) >= 3:
            cards.append(
                InsightCard(
                    title="Repeated authentication failures suggest brute-force pressure",
                    severity=RiskLevel.high,
                    impact=(
                        f"Observed {counts['failed_login']} failed-auth pattern(s), indicating sustained credential probing activity "
                        "or a misconfigured authentication workflow."
                    ),
                    evidence=[
                        f"failed_login findings: {counts['failed_login']}",
                        f"lines: {sorted(set(type_to_lines.get('failed_login', [])))[:5]}",
                    ],
                    recommendation="Enable account lockout/rate limiting and investigate source IP/account concentration for abuse.",
                )
            )

        pii_count = counts.get("email", 0) + counts.get("phone", 0)
        if pii_count > 0:
            pii_severity = RiskLevel.medium if pii_count < 3 else RiskLevel.high
            cards.append(
                InsightCard(
                    title="PII exposure may trigger compliance and privacy obligations",
                    severity=pii_severity,
                    impact=(
                        f"Detected {pii_count} personally identifiable data point(s). "
                        "Unmasked storage/transmission can increase regulatory and reputational risk."
                    ),
                    evidence=[
                        f"email findings: {counts.get('email', 0)}",
                        f"phone findings: {counts.get('phone', 0)}",
                    ],
                    recommendation="Apply structured redaction for PII fields and limit access to raw diagnostic logs.",
                )
            )

        if counts.get("stack_trace", 0) > 0:
            stack_severity = RiskLevel.high if secret_count else RiskLevel.medium
            cards.append(
                InsightCard(
                    title="Debug and stack trace leakage increases exploitability",
                    severity=stack_severity,
                    impact=(
                        f"Detected {counts['stack_trace']} stack-trace/error detail(s). "
                        "This can reveal internals (service names, code paths, file locations) useful for targeted exploitation."
                    ),
                    evidence=[f"stack_trace findings: {counts['stack_trace']}"],
                    recommendation="Disable verbose debug output in production and map exceptions to sanitized error codes.",
                )
            )

        if len(findings) >= 10 or risk_level in {RiskLevel.high, RiskLevel.critical}:
            cards.append(
                InsightCard(
                    title="Concentrated multi-signal risk indicates elevated incident probability",
                    severity=risk_level,
                    impact=(
                        f"Total findings: {len(findings)} spanning {len(counts)} risk signal type(s). "
                        "Signal clustering raises confidence that this is actionable security noise, not random artifacts."
                    ),
                    evidence=[
                        f"risk level: {risk_level.value}",
                        f"top signal counts: {dict(counts.most_common(4))}",
                        f"hotspot lines: {hotspot_lines or ['n/a']}",
                    ],
                    recommendation="Escalate to security triage, preserve forensic context, and track remediation with an incident ticket.",
                )
            )

        if not cards:
            for finding_type, count in counts.most_common(3):
                base = INSIGHT_TEMPLATES.get(finding_type, f"{finding_type} detected")
                cards.append(
                    InsightCard(
                        title=base,
                        severity=next((f.risk for f in findings if f.type == finding_type), RiskLevel.low),
                        impact=f"Detected {count} occurrence(s) of {finding_type}.",
                        evidence=[f"{finding_type} findings: {count}"],
                        recommendation="Review affected lines and apply targeted masking/remediation.",
                    )
                )

        return cards

    def _build_summary(self, input_type: str, findings: list[Finding], risk_level: RiskLevel) -> str:
        if not findings:
            return f"{input_type.upper()} content appears clean with no critical findings"

        finding_types = sorted({finding.type for finding in findings})
        line_counter = Counter(f.line for f in findings if f.line is not None)
        hottest_line = line_counter.most_common(1)[0][0] if line_counter else None
        joined = ", ".join(finding_types)
        hotspot_message = f" Hotspot line: {hottest_line}." if hottest_line is not None else ""
        return (
            f"{input_type.upper()} content contains {len(findings)} findings across {len(finding_types)} signal types: {joined}. "
            f"Overall risk: {risk_level.value}.{hotspot_message}"
        )

    def _build_recommended_actions(self, insight_cards: list[InsightCard], action: str) -> list[str]:
        recommendations: list[str] = []
        for card in insight_cards:
            if card.recommendation not in recommendations:
                recommendations.append(card.recommendation)

        if action == "blocked":
            recommendations.insert(0, "Keep payload blocked until containment actions are completed and verified.")
        elif action == "masked":
            recommendations.insert(0, "Use masked output for downstream workflows and prevent raw artifact propagation.")

        return recommendations[:6]

    def _sanitize_content(self, content: str, findings: list[Finding]) -> str:
        sanitized = content
        for finding in findings:
            if finding.value:
                sanitized = sanitized.replace(finding.value, "[REDACTED]")
        return sanitized[:1200]
