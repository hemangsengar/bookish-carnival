from app.modules.ingestion.schemas import IngestionJob, IngestionRequest
from app.modules.platform.service import PlatformService


class IngestionService:
    def __init__(self, platform_service: PlatformService) -> None:
        self.platform_service = platform_service

    def create_job(self, request: IngestionRequest, actor_role: str) -> IngestionJob:
        return self.platform_service.create_ingestion_job(request=request, actor_role=actor_role)

    def list_jobs(self) -> list[IngestionJob]:
        return self.platform_service.list_ingestion_jobs()

    def reset_state(self) -> None:
        self.platform_service.reset_state()
