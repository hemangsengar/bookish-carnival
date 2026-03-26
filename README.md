# AI Secure Data Intelligence Platform

End-to-end AI Gateway + Scanner + Log Analyzer + Risk Engine with FastAPI APIs and a Vercel-ready web UI.

## Current implementation status

This repository now contains a **functional end-to-end MVP**:

- FastAPI service with security, policy, alerting, analytics, and audit modules
- Unified `/analyze` API for multi-input analysis:
  - text
  - sql
  - chat
  - logs
  - file upload (`.log`, `.txt`, and general text extraction)
- Detection engine for:
  - emails
  - phone numbers
  - API keys
  - passwords
  - tokens
  - stack traces
  - failed-login patterns
- Risk engine with risk score/level + policy actions (`allowed`, `masked`, `blocked`)
- Hybrid insights generation: deterministic rules + optional Gemini contextual intelligence
- Frontend web app for upload, findings table, sanitized preview, and log visualization
- Vercel deployment config for static frontend + Python API runtime
- Automated tests for analyze endpoints and incident workflow

## Repository structure

- `backend/app/main.py` — FastAPI entrypoint and router wiring
- `backend/app/core/config.py` — environment-driven application settings
- `backend/app/core/security.py` — API key and role-based guards
- `backend/app/modules/*` — domain modules including analyze/log intelligence
- `backend/tests/` — API tests
- `public/` — Vercel-served frontend UI
- `api/index.py` — Vercel Python entrypoint
- `vercel.json` — Vercel routing and build configuration
- `docker-compose.yml` — local stack (API + PostgreSQL + Redis)

## Quick start

1. Create your environment values using `.env`.
2. Create environment: `python3 -m venv .venv`
3. Install dependencies: `./.venv/bin/python -m pip install -r backend/requirements.txt`
4. Run API locally: `cd backend && ../.venv/bin/python -m uvicorn app.main:app --reload`
5. Open API docs at `http://localhost:8000/docs`
6. Open UI at `http://localhost:8000` (if serving static separately) or use Vercel preview.

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

`/analyze` endpoints are intentionally open for hackathon-style evaluation unless you add gateway-level auth.

### Implemented API surface

- `POST /analyze`
- `POST /analyze/file`
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

### `/analyze` request format

```json
{
  "input_type": "text | file | sql | chat | log",
  "content": "...",
  "options": {
    "mask": true,
    "block_high_risk": true,
    "log_analysis": true
  }
}
```

### `/analyze` response shape

- `summary`
- `content_type`
- `findings[]` (type, risk, line, value)
- `risk_score`
- `risk_level`
- `action`
- `insights[]`
- `insight_cards[]` (title, severity, impact, evidence, recommendation)
- `recommended_actions[]`
- `sanitized_preview`

## Gemini-powered analysis (optional)

The analyzer supports Gemini for richer, more actionable security insights.

If Gemini is enabled and reachable, it can enhance:

- executive-quality risk summary
- impact framing with evidence-based context
- prioritized remediation recommendations

If Gemini fails or returns malformed output, the deterministic engine remains active and responses still succeed.

### Gemini environment variables

- `GEMINI_ENABLED=true`
- `GEMINI_API_KEY=your-gemini-api-key`
- `GEMINI_MODEL=gemini-1.5-flash`
- `GEMINI_TIMEOUT_SECONDS=12`

## Deploy on Vercel

This repository is configured for Vercel:

- `public/*` serves frontend
- `/api/*` routes to `api/index.py` (FastAPI ASGI app)

### Vercel setup

1. Import this repository in Vercel.
2. Configure environment variables if needed (`POLICY_RECORDS_THRESHOLD`, etc.).
3. Deploy.

After deploy:

- Web UI: `/`
- API docs: `/api/docs`
- Analyze endpoint: `/api/analyze`

## Next recommended hardening steps

1. Persist platform store into PostgreSQL with migrations
2. Replace header-based roles with OIDC/SAML + JWT verification
3. Add rate limiting and request size limits for large file uploads
4. Add model-backed anomaly scoring for advanced insights
5. Add OpenTelemetry traces, metrics, and SIEM-forward audit export
