# Security Architecture

## Identity & Access
- Integrate enterprise IdP via OIDC/SAML
- Enforce RBAC for user personas
- Add ABAC for data classification controls in later phase

## Data Protection
- TLS for in-transit communications
- Encryption at rest for all data stores
- Secrets from vault/HSM in production

## Auditability
- Record security-relevant actions (login, policy changes, alert actions)
- Persist immutable audit trails with retention controls

## Immediate implementation backlog
- Add auth middleware and token validation
- Introduce role checks on domain endpoints
- Add security event logging for all write operations
