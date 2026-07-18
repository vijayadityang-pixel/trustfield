# TrustField Architecture

## Overview

TrustField ingests identity and access management (IAM) configuration from four cloud surfaces — AWS, Azure, GCP, and Kubernetes — and assembles it into a single trust graph in Neo4j. Rule-based detectors and machine learning models analyze that graph to surface privilege escalation paths, misconfigurations, and anomalous access patterns, and an automated containment engine can act on findings without waiting for a human in the loop.

## System diagram

```
 ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
 │  AWS        │   │  Azure      │   │  GCP        │   │  Kubernetes │
 │  collector  │   │  collector  │   │  collector  │   │  collector  │
 └─────┬───────┘   └─────┬───────┘   └─────┬───────┘   └─────┬───────┘
       │                 │                 │                 │
       └────────────────────────┬──────────────────────────┘
                                 ▼
                       ┌───────────────────┐
                       │   graph builder    │
                       │  (schema + Cypher) │
                       └─────────┬──────────┘
                                 ▼
                       ┌───────────────────┐
                       │      Neo4j         │
                       │   trust graph DB   │
                       └─────────┬──────────┘
                 ┌───────────────┼───────────────┐
                 ▼                               ▼
       ┌───────────────────┐           ┌───────────────────--┐
       │  detection engine   │         │     ML layer        │
       │  (pattern matching, │         │  (Isolation Forest, │
       │   path finding,      │        │   GAT/GNN scaffold  │
       │   risk scoring)      │        |, not yet trained)   |
       └─────────┬───────────┘         └─────────┬───────────┘                       │
                 └───────────────┬───────────────┘
                                 ▼
                       ┌───────────────────┐
                       │   FastAPI backend   │
                       │  (graph, alerts,     │
                       │   scan, containment) │
                       └─────────┬──────────┘
                       ┌─────────┴──────────┐
                       ▼                    ▼
             ┌───────────────────┐ ┌───────────────────┐
             │  containment        │ │  React frontend     │
             │  engine (auto IR)    │ │  (graph view,        │
             └───────────────────┘ │   alerts, heatmap)    │
                                    └───────────────────┘
```

## Component responsibilities

**Collectors** (`collectors/`) poll each cloud provider's IAM APIs on a schedule — boto3 for AWS, azure-identity and azure-mgmt-resource for Azure, google-cloud-iam (v2) for GCP, and the official Kubernetes Python client for cluster RBAC. Each collector normalizes provider-specific shapes (roles, policies, service accounts, bindings) into a common intermediate representation before handing off to the graph builder.

**Graph builder** (`graph/`) takes normalized IAM objects and writes them into Neo4j as nodes (Identity, Role, Policy, Resource, ServiceAccount) and relationships (ASSUMES, ATTACHED_TO, GRANTS, TRUSTS, BINDS). The schema is provider-agnostic at the relationship level, which lets path-finding queries traverse across AWS, Azure, GCP, and Kubernetes boundaries in a single Cypher query — for example, a cross-cloud chain where a GCP service account's exported key is used to assume an AWS role.

**Detection engine** (`detection/`) runs two complementary strategies. Pattern matching checks the graph against the rule definitions in `data/escalation_patterns.json` (confused-deputy trust policies, PassRole-plus-Lambda escalation, wildcard trust principals, and similar known-bad shapes, each tagged with a MITRE ATT&CK technique). Path finding walks the trust graph to enumerate every viable route from a low-privilege identity to a high-privilege one, ranking paths by hop count and the sensitivity of resources along the way. Risk scoring combines pattern hits, path findings, and node centrality into a single 0–100 score per identity and per path.

**ML layer** (`ml/`) adds an unsupervised anomaly detection layer on top of the rule engine. As implemented (Week 5), an Isolation Forest scores each *identity node* — not individual access events — using a feature vector built from privilege level, activity status, wildcard-trust exposure, cross-account exposure, graph topology (in/out-degree, neighbor average risk, betweenness centrality), and provider/node-type one-hot encoding. Betweenness centrality in particular proved effective at surfacing intermediary nodes in multi-hop escalation chains that raw privilege level alone would miss. A Graph Attention Network (`gnn_model.py`) is scaffolded for future structural learning directly on trust-graph edges but is not part of the current detection pipeline — it requires labeled incident data this capstone's synthetic/live test environment doesn't produce at volume, and is documented as future work rather than built out for Week 5.

**Containment engine** (`containment/`) executes response actions once a finding crosses a configured severity threshold, or on manual trigger from the frontend: quarantining a role by attaching a deny-all policy, revoking active sessions, disabling access keys, patching an over-permissive Kubernetes RoleBinding, or removing a stale cross-account trust statement. Every action is logged with a before/after snapshot so it can be reversed.

**API layer** (`api/`) exposes the above through FastAPI route groups: graph queries and visualization data, alert listing and triage, on-demand scan triggering, and containment action execution and history.

**Frontend** (`frontend/`) is the operator-facing surface: an interactive trust graph, a risk heatmap across accounts and resource types, an alert queue with path-level detail, and containment controls with a confirmation step before any destructive action runs.

## Data flow for a single detection cycle

1. A scan is triggered (scheduled or via `POST /scan/run`).
2. Collectors pull current-state IAM configuration from each connected cloud.
3. The graph builder diffs the new state against the existing Neo4j graph and applies updates.
4. The detection engine re-evaluates pattern matches and re-runs path finding against the updated graph; risk scores are recalculated for affected nodes.
5. The ML layer scores current identity nodes for anomalies in parallel with detection engine re-evaluation (via `POST /ml/train` / `GET /ml/anomalies`).
6. Findings above the configured severity threshold are written as alerts and, where auto-containment is enabled for that severity, the containment engine executes the mapped response action.
7. The frontend polls or subscribes to the alerts and graph endpoints to reflect the updated state.
## ML layer implementation notes (Week 5)

The Isolation Forest pipeline runs as two endpoints: `POST /ml/train` fits the model against the full current graph state (all `:Identity` nodes and their relationships, pulled via `Neo4jClient.get_all_nodes_and_edges()`), and `GET /ml/anomalies` scores the graph and returns per-node results, including the top contributing features per flagged node. `GET /ml/anomalies/{node_id:path}` returns a single node's result.

Two implementation bugs were found and fixed during live end-to-end testing (same pattern as Weeks 1–4 — verified through the real API, not standalone scripts):

- **Fixed-range score normalization.** The original scaffold normalized raw IsolationForest scores against an assumed fixed range of `[-0.5, 0.5]`, which sklearn does not guarantee. Real scores fell outside that range, compressing the entire 964-node test graph toward an anomaly score near 1.0 and flagging 100% of nodes instead of the configured 5% contamination rate. Fixed by normalizing against the batch's actual `min()`/`max()` raw score range.
- **`numpy.bool_` not JSON-serializable.** `is_anomaly` was computed from a numpy boolean comparison and passed directly into the response model, crashing `GET /ml/anomalies` with a 500 (FastAPI's `jsonable_encoder` can't serialize numpy scalar types). Fixed with an explicit `bool()` cast.

The original feature scaffold (`feature_extractor.py`) also included several fields — `mfa_enabled`, `access_key_age_days`, `attached_policy_count`, `inline_policy_count`, `group_count`, `admin_role_count` — that no collector across any of the four providers actually populates as a graph property. These were silently zero-filling roughly half of every feature vector. Trimmed to the ~21 features with real signal; richer per-identity attributes would require extending all four collectors and are noted as future work rather than built out here.

**Live validation result:** on the combined Week 1–4 test graph (964 nodes across AWS/Azure/GCP), the trained model's top anomalies included four of the deliberately-planted vulnerable test scenarios from Weeks 2–4 — `trustfield-intermediate-role` (role-chaining test, score 1.0), `trustfield-admin-role` (score 0.91), `trustfield-cross-account-role` (score 0.89), and the GCP `trustfield-target-gcp`/`trustfield-victim-gcp` impersonation pair (scores 0.95/0.88) — surfaced independently, without labels. A known limitation: AWS-managed service roles (e.g. `AWSServiceRoleForSupport`) are structurally indistinguishable from user-created roles in the current feature set and get flagged alongside genuine escalation paths; an `is_aws_managed` feature would filter this false-positive class.

## Why Neo4j

Privilege escalation in IAM is fundamentally a graph traversal problem — "can identity A reach privilege level B through any sequence of trust relationships" — which maps far more naturally onto Cypher path queries than onto relational joins. Neo4j also makes the cross-cloud case tractable: a single `MATCH` clause can walk an edge that represents "AWS role trusts GCP-issued OIDC token" without provider-specific join logic.
