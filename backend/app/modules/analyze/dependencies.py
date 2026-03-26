from functools import lru_cache

from app.modules.analyze.service import AnalyzeService


@lru_cache
def get_analyze_service() -> AnalyzeService:
    return AnalyzeService()
