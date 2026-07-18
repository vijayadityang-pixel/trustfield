# TrustField

**Multi-cloud IAM trust graph and privilege escalation detection platform**

TrustField ingests IAM data from AWS, Azure, GCP, and Kubernetes, builds a unified trust graph in Neo4j, and detects privilege escalation paths using Cypher-backed detectors and machine learning. Built as a capstone project at Ghousia College of Engineering (2025–2026).

## What it does

Cloud IAM misconfigurations — over-permissive trust policies, wildcard principals, role chaining, cross-account trust — are a leading cause of privilege escalation in real-world breaches. TrustField models these relationships as a graph and runs structural + ML-based detection to surface escalation paths before attackers find them.

- **Collects** IAM identities, roles, and trust relationships from AWS, Azure, GCP, and Kubernetes RBAC
- **Builds** a unified trust graph in Neo4j (`CAN_ASSUME`, `HAS_ROLE`, `BOUND_TO` relationships)
- **Detects** privilege escalation paths via Cypher-backed pattern matching, mapped to MITRE ATT&CK
- **Scores** risk and flags anomalous access patterns using ML (Isolation Forest)
- **Visualizes** the trust graph and escalation paths through a React dashboard

## Architecture

Cloud APIs (AWS/Azure/GCP/K8s)
│
Collectors
│
Trust Graph Builder ──▶ Neo4j (graph store)
│
Escalation Detectors (Cypher) + ML Anomaly Detection
│
FastAPI ──▶ React Dashboard

**Stack:** FastAPI · Neo4j · PostgreSQL · React (Vite) · scikit-learn · PyTorch Geometric

## Detectors

| Detector | Description | MITRE ATT&CK |
|---|---|---|
| `privilege_escalation` | Generic low→high privilege trust path | T1078 |
| `wildcard_trust` | Trust policies with `"*"` principals | T1078.004 |
| `role_chaining` | Multi-hop AssumeRole chains | T1548.005 |
| `cross_account` | Trust to external AWS account roots | T1199 |

## Status

Built as an 8-week capstone project. Currently through Week 4:

- ✅ **Weeks 1–3:** Core platform, AWS ingestion, all 4 escalation detectors — live-proven end-to-end against real AWS test accounts
- ✅ **Week 4:** Azure and GCP collectors — both live-proven end-to-end; `privilege_escalation` fires on all three clouds (`wildcard_trust`/`cross_account` are AWS-specific trust-policy patterns without direct structural equivalents in Azure RBAC/GCP IAM bindings)
- 🔜 **Week 5:** ML anomaly detection (Isolation Forest)
- 🔜 **Week 6:** Kubernetes RBAC collection, containment actions
- 🔜 **Week 7:** Cross-provider integration testing
- 🔜 **Week 8:** Polish, demo prep, limitations writeup

## Setup

See [`docs/setup_guide.md`](docs/setup_guide.md) for full local setup instructions (Neo4j, PostgreSQL, backend, frontend, cloud credentials).

## API Reference

See [`docs/api_reference.md`](docs/api_reference.md).

## Architecture Deep Dive

See [`docs/architecture.md`](docs/architecture.md).

## Team
Vijaya Aditya N G, Venkatesh S, Yashas Gowda R S, Nemath Miyan

