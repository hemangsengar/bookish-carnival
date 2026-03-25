from fastapi import APIRouter

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", summary="List alerts")
def list_alerts() -> dict[str, list[dict[str, str]]]:
    return {"items": []}
