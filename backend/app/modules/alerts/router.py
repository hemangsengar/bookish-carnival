from fastapi import APIRouter, Depends

from app.core.security import require_roles, require_service_api_key
from app.modules.platform.dependencies import get_platform_service
from app.modules.platform.schemas import Alert, AlertListResponse
from app.modules.platform.service import PlatformService

router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_service_api_key)],
)


@router.get("", summary="List alerts", response_model=AlertListResponse)
def list_alerts(
    status: str | None = None,
    _: str = Depends(require_roles("analyst", "compliance", "business")),
    service: PlatformService = Depends(get_platform_service),
) -> AlertListResponse:
    return AlertListResponse(items=service.list_alerts(status_filter=status))


@router.patch("/{alert_id}/acknowledge", response_model=Alert)
def acknowledge_alert(
    alert_id: str,
    actor_role: str = Depends(require_roles("analyst", "compliance")),
    service: PlatformService = Depends(get_platform_service),
) -> Alert:
    return service.acknowledge_alert(alert_id=alert_id, actor_role=actor_role)


@router.patch("/{alert_id}/resolve", response_model=Alert)
def resolve_alert(
    alert_id: str,
    actor_role: str = Depends(require_roles("analyst", "compliance")),
    service: PlatformService = Depends(get_platform_service),
) -> Alert:
    return service.resolve_alert(alert_id=alert_id, actor_role=actor_role)
