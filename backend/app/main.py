from fastapi import FastAPI

from app.modules.alerts.router import router as alerts_router
from app.modules.analytics.router import router as analytics_router
from app.modules.health.router import router as health_router
from app.modules.ingestion.router import router as ingestion_router
from app.modules.policy.router import router as policy_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AI Secure Data Intelligence Platform",
        version="0.1.0",
        description="On-prem secure data intelligence API built with FastAPI.",
    )

    app.include_router(health_router)
    app.include_router(ingestion_router)
    app.include_router(analytics_router)
    app.include_router(policy_router)
    app.include_router(alerts_router)

    return app


app = create_app()
