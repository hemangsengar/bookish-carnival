from fastapi import APIRouter, Depends, Query

from app.core.security import require_roles, require_service_api_key
from app.modules.platform.dependencies import get_platform_service
from app.modules.platform.schemas import AuditEventListResponse
from app.modules.platform.service import PlatformService

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    dependencies=[Depends(require_service_api_key)],
)


@router.get("/events", response_model=AuditEventListResponse)
def list_audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    _: str = Depends(require_roles("compliance", "business")),
    service: PlatformService = Depends(get_platform_service),
) -> AuditEventListResponse:
    return AuditEventListResponse(items=service.list_audit_events(limit=limit))
