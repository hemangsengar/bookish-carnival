# AI Secure Data Intelligence Platform

Security-first, on-prem/private-cloud data intelligence platform with a FastAPI backend.

## Current implementation status

This repository now contains a **functional MVP backend**:

- Modular FastAPI service with domain-level APIs
- End-to-end ingestion pipeline:
  - ingestion job creation
  - policy evaluation
  - alert generation
  - analytics KPI updates
  - audit trail emission
- Role-based authorization using request headers
- Environment-based settings and policy thresholds
- Docker + docker-compose for local/private-cloud style deployment
- Automated tests covering health, auth, ingestion workflow, alerts, policy, analytics, and audit events

## Repository structure

- `backend/app/main.py` — FastAPI entrypoint and router wiring
- `backend/app/core/config.py` — environment-driven application settings
- `backend/app/core/security.py` — API key and role-based guards
- `backend/app/modules/*` — domain modules
- `backend/tests/` — API tests
- `docker-compose.yml` — local stack (API + PostgreSQL + Redis)

## Quick start

1. Create your environment values using `.env` (already scaffolded).
2. Start with Docker Compose.
3. Open API docs at `http://localhost:8000/docs`.

### Local test run

Use the project virtual environment to run tests:

1. Create environment: `python3 -m venv .venv`
2. Install dependencies: `./.venv/bin/python -m pip install -r backend/requirements.txt`
3. Run tests: `cd backend && ../.venv/bin/python -m pytest`

### Auth for protected endpoints

Protected endpoints use:

- Header: `x-api-key`
- Value: `SERVICE_API_KEY` from `.env`
- Header: `x-user-role`
- Supported roles: `engineer`, `analyst`, `compliance`, `business`

### Implemented API surface

- `GET /health`
- `POST /ingestion/jobs`
- `GET /ingestion/jobs`
- `GET /policy/status`
- `GET /policy/violations`
- `PATCH /policy/violations/{violation_id}/resolve`
- `GET /alerts`
- `PATCH /alerts/{alert_id}/acknowledge`
- `PATCH /alerts/{alert_id}/resolve`
- `GET /analytics/kpis`
- `GET /audit/events`

### Policy behavior

- `severity in {high, critical}` => policy violation generated
- `records_count >= POLICY_RECORDS_THRESHOLD` => policy violation generated
- high/critical violations automatically create open alerts

## Next implementation milestones

1. Replace in-memory state with persistent storage (PostgreSQL + migrations)
2. Replace header-based roles with OIDC/SAML and enterprise RBAC
3. Add asynchronous processing workers and queue-backed ingestion
4. Add observability stack (metrics/tracing/log shipping)
5. Add compliance exports and reporting views
