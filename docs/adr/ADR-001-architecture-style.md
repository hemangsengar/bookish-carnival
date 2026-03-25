# ADR-001: Architecture Style

## Status
Accepted

## Context
The project needs fast MVP delivery for secure ingestion and analytics while preserving long-term scalability.

## Decision
Adopt a **modular monolith** with FastAPI domain modules and explicit boundaries that can be extracted into services later.

## Consequences
- Faster development and simpler operations for MVP
- Lower distributed-system overhead in early stages
- Requires discipline in module boundaries to avoid tight coupling
