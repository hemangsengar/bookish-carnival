from fastapi import APIRouter, Depends

from app.core.security import require_roles, require_service_api_key
from app.modules.platform.dependencies import get_platform_service
from app.modules.platform.schemas import AnalyticsKpis
from app.modules.platform.service import PlatformService

router = APIRouter(
    prefix="/analytics",
    tags=["analytics"],
    dependencies=[Depends(require_service_api_key)],
)


@router.get("/kpis", summary="Fetch dashboard KPIs")
def get_kpis(
    _: str = Depends(require_roles("analyst", "business", "compliance")),
    service: PlatformService = Depends(get_platform_service),
) -> AnalyticsKpis:
    return service.get_kpis()
