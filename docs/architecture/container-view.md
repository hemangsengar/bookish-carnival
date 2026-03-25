# Container View

## Runtime containers
- API Container (`FastAPI`): public/internal API endpoints
- Worker Container (future): async enrichment and heavy processing
- PostgreSQL: operational metadata and transactional records
- Redis: queue/cache coordination
- Object Store (future): raw and curated data zones
- Search Index (future): investigation and dashboard acceleration

## Core flows
1. Source -> API `/ingestion/jobs` -> async queue -> worker pipeline
2. Processed events -> policy checks -> alert generation
3. Dashboard/API -> analytics read model -> KPI views
