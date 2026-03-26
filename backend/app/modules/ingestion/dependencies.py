from functools import lru_cache

from app.modules.ingestion.service import IngestionService
from app.modules.platform.dependencies import get_platform_service


@lru_cache
def get_ingestion_service() -> IngestionService:
    return IngestionService(platform_service=get_platform_service())
