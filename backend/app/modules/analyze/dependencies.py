from functools import lru_cache

from app.core.config import settings
from app.modules.analyze.gemini_client import GeminiInsightClient
from app.modules.analyze.service import AnalyzeService


@lru_cache
def get_analyze_service() -> AnalyzeService:
    gemini_client = None
    if settings.gemini_enabled and settings.gemini_api_key.strip():
        gemini_client = GeminiInsightClient(
            api_key=settings.gemini_api_key,
            model=settings.gemini_model,
            timeout_seconds=settings.gemini_timeout_seconds,
        )
    return AnalyzeService(gemini_client=gemini_client)
