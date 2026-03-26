from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AnalyzeOptions(BaseModel):
    mask: bool = True
    block_high_risk: bool = True
    log_analysis: bool = True


class AnalyzeRequest(BaseModel):
    input_type: Literal["text", "file", "sql", "chat", "log"]
    content: str = Field(default="", min_length=1)
    options: AnalyzeOptions = AnalyzeOptions()


class Finding(BaseModel):
    type: str
    risk: RiskLevel
    line: int | None = None
    value: str | None = None


class AnalyzeResponse(BaseModel):
    summary: str
    content_type: str
    findings: list[Finding]
    risk_score: int
    risk_level: RiskLevel
    action: str
    insights: list[str]
    sanitized_preview: str | None = None
