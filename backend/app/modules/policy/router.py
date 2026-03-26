from fastapi import APIRouter, Depends

from app.core.security import require_roles, require_service_api_key
from app.modules.platform.dependencies import get_platform_service
from app.modules.platform.schemas import PolicyViolation, PolicyViolationListResponse
from app.modules.platform.service import PlatformService

router = APIRouter(
    prefix="/policy",
    tags=["policy"],
    dependencies=[Depends(require_service_api_key)],
)


@router.get("/status", summary="Policy engine status")
def policy_status() -> dict[str, str]:
    return {"status": "ready"}


@router.get("/violations", response_model=PolicyViolationListResponse)
def list_policy_violations(
    status: str | None = None,
    _: str = Depends(require_roles("analyst", "compliance")),
    service: PlatformService = Depends(get_platform_service),
) -> PolicyViolationListResponse:
    return PolicyViolationListResponse(items=service.list_policy_violations(status_filter=status))


@router.patch("/violations/{violation_id}/resolve", response_model=PolicyViolation)
def resolve_policy_violation(
    violation_id: str,
    actor_role: str = Depends(require_roles("compliance")),
    service: PlatformService = Depends(get_platform_service),
) -> PolicyViolation:
    return service.resolve_policy_violation(violation_id=violation_id, actor_role=actor_role)
