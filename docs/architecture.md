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
       ┌───────────────────┐           ┌───────────────────┐
       │  detection engine   │           │     ML layer        │
       │  (pattern matching, │           │  (Isolation Forest,  │
       │   path finding,      │           │   GAT/GNN)           │
       │   risk scoring)      │           └─────────┬───────────┘
       └─────────┬───────────┘                       │
                 └───────────────┬───────────────────┘
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

**ML layer** (`ml/`) adds a statistical and structural detection layer on top of the rule engine. An Isolation Forest model flags individual access events (sourced from CloudTrail-equivalent logs) that deviate from an identity's historical behavior — unusual source IP, off-hours activity, first-time API calls. A Graph Attention Network (GAT) operates directly on the trust graph's structure to learn which node and edge patterns correlate with confirmed incidents, catching novel escalation shapes that the rule engine hasn't been taught to recognize yet.

**Containment engine** (`containment/`) executes response actions once a finding crosses a configured severity threshold, or on manual trigger from the frontend: quarantining a role by attaching a deny-all policy, revoking active sessions, disabling access keys, patching an over-permissive Kubernetes RoleBinding, or removing a stale cross-account trust statement. Every action is logged with a before/after snapshot so it can be reversed.

**API layer** (`api/`) exposes the above through FastAPI route groups: graph queries and visualization data, alert listing and triage, on-demand scan triggering, and containment action execution and history.

**Frontend** (`frontend/`) is the operator-facing surface: an interactive trust graph, a risk heatmap across accounts and resource types, an alert queue with path-level detail, and containment controls with a confirmation step before any destructive action runs.

## Data flow for a single detection cycle

1. A scan is triggered (scheduled or via `POST /scan/run`).
2. Collectors pull current-state IAM configuration from each connected cloud.
3. The graph builder diffs the new state against the existing Neo4j graph and applies updates.
4. The detection engine re-evaluates pattern matches and re-runs path finding against the updated graph; risk scores are recalculated for affected nodes.
5. The ML layer scores recent access events and flags structural anomalies in parallel.
6. Findings above the configured severity threshold are written as alerts and, where auto-containment is enabled for that severity, the containment engine executes the mapped response action.
7. The frontend polls or subscribes to the alerts and graph endpoints to reflect the updated state.

## Why Neo4j

Privilege escalation in IAM is fundamentally a graph traversal problem — "can identity A reach privilege level B through any sequence of trust relationships" — which maps far more naturally onto Cypher path queries than onto relational joins. Neo4j also makes the cross-cloud case tractable: a single `MATCH` clause can walk an edge that represents "AWS role trusts GCP-issued OIDC token" without provider-specific join logic.
