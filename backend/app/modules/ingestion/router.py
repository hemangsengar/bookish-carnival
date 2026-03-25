from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/ingestion", tags=["ingestion"])


class IngestionRequest(BaseModel):
    source: str
    payload_type: str


@router.post("/jobs", summary="Create ingestion job")
def create_ingestion_job(request: IngestionRequest) -> dict[str, str]:
    return {
        "message": "Ingestion job accepted",
        "source": request.source,
        "payload_type": request.payload_type,
    }
