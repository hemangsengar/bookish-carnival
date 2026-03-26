from fastapi import APIRouter, Depends, status

from app.core.security import require_roles, require_service_api_key
from app.modules.ingestion.dependencies import get_ingestion_service
from app.modules.ingestion.schemas import IngestionListResponse, IngestionJob, IngestionRequest
from app.modules.ingestion.service import IngestionService

router = APIRouter(
    prefix="/ingestion",
    tags=["ingestion"],
    dependencies=[Depends(require_service_api_key)],
)


@router.post(
    "/jobs",
    summary="Create ingestion job",
    status_code=status.HTTP_201_CREATED,
    response_model=IngestionJob,
)
def create_ingestion_job(
    request: IngestionRequest,
    actor_role: str = Depends(require_roles("engineer", "analyst")),
    service: IngestionService = Depends(get_ingestion_service),
) -> IngestionJob:
    return service.create_job(request=request, actor_role=actor_role)


@router.get("/jobs", summary="List ingestion jobs", response_model=IngestionListResponse)
def list_ingestion_jobs(
    _: str = Depends(require_roles("engineer", "analyst", "compliance", "business")),
    service: IngestionService = Depends(get_ingestion_service),
) -> IngestionListResponse:
    return IngestionListResponse(items=service.list_jobs())
