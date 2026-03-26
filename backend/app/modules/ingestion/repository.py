from datetime import UTC, datetime
from threading import Lock
from uuid import uuid4

from app.modules.ingestion.schemas import IngestionJob, IngestionRequest


class InMemoryIngestionRepository:
    def __init__(self) -> None:
        self._jobs: list[IngestionJob] = []
        self._lock = Lock()

    def create_job(self, request: IngestionRequest) -> IngestionJob:
        job = IngestionJob(
            id=str(uuid4()),
            source=request.source,
            payload_type=request.payload_type,
            status="queued",
            created_at=datetime.now(UTC),
        )

        with self._lock:
            self._jobs.append(job)

        return job

    def list_jobs(self) -> list[IngestionJob]:
        with self._lock:
            return list(self._jobs)

    def clear(self) -> None:
        with self._lock:
            self._jobs.clear()
