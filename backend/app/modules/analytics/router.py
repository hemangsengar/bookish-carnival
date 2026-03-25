from fastapi import APIRouter

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/kpis", summary="Fetch dashboard KPIs")
def get_kpis() -> dict[str, int]:
    return {
        "active_alerts": 0,
        "ingestion_jobs_today": 0,
        "policy_violations": 0,
    }
