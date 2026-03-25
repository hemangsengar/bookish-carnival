from fastapi import APIRouter

router = APIRouter(prefix="/policy", tags=["policy"])


@router.get("/status", summary="Policy engine status")
def policy_status() -> dict[str, str]:
    return {"status": "ready"}
