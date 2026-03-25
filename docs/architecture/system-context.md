# System Context

## Objective
Deliver secure data ingestion and intelligence dashboards for on-prem/private-cloud environments.

## Primary users
- Security Analysts
- Data Engineers
- Compliance Officers
- Business Stakeholders

## External systems
- Enterprise Identity Provider (OIDC/SAML)
- Data source systems (files, APIs/webhooks, DB CDC)
- Notification channels (email/chat/ITSM)

## Trust boundaries
1. Ingress boundary (external systems to ingestion APIs)
2. Application boundary (internal service communication)
3. Data boundary (restricted storage tiers)
4. Admin boundary (management endpoints and control plane)
