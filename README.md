# AI Secure Data Intelligence Platform

Security-first, on-prem/private-cloud data intelligence platform with a FastAPI backend.

## Current implementation status

This repository now contains a **Phase 1 bootstrap**:

- Modular FastAPI service scaffold
- Domain routers for:
	- health
	- ingestion
	- analytics
	- policy
	- alerts
- Environment-based settings
- Docker + docker-compose for local/private-cloud style deployment
- Basic health-check test

## Repository structure

- `backend/app/main.py` — FastAPI entrypoint and router wiring
- `backend/app/core/config.py` — environment-driven application settings
- `backend/app/modules/*` — domain modules
- `backend/tests/` — API tests
- `docker-compose.yml` — local stack (API + PostgreSQL + Redis)

## Quick start

1. Create your environment values using `.env` (already scaffolded).
2. Start with Docker Compose.
3. Open API docs at `http://localhost:8000/docs`.

## Next implementation milestones

1. Add authentication/authorization integration (OIDC/SAML + RBAC)
2. Build ingestion worker pipeline and schema validation
3. Add persistence layer + repository pattern
4. Implement audit logging and immutable event trails
5. Add observability (structured logs, metrics, traces)
