# TrustField API Reference

> Documents the actual endpoints implemented in `api/routes_*.py`, verified against the live route handlers (not the frontend's assumed contract). Base path and auth flow confirmed via live testing during Week 6.

Base URL: `http://localhost:8000/api/v1` (all routes below are relative to this prefix)

All endpoints require a JWT bearer token, obtained via `POST /auth/login`. Send it as `Authorization: Bearer <token>` on every subsequent request. Tokens expire per `ACCESS_TOKEN_EXPIRE_MINUTES` in config — expect to re-login periodically during a long working session.

---

## Auth

### `POST /auth/login`
Body:
```json
{ "email": "admin@trustfield.com", "password": "..." }
```
Returns:
```json
{ "access_token": "eyJ...", "token_type": "bearer" }
```

---

## Trust Graph — `routes_graph.py` (prefix `/graph`)

### `GET /graph/`
Returns the full trust graph or a filtered slice.

Query params: `cloud_provider` (aws | azure | gcp | k8s), `account_id`, `depth` (1–6, default 3), `min_trust_score` (0.0–1.0, default 0.0)

Response (`GraphResponse`): `{ "nodes": [...], "edges": [...], "total_nodes": int, "total_edges": int }`

### `GET /graph/stats`
Query params: `cloud_provider` (optional)

Returns high-level graph statistics (node/edge counts, avg trust score, high-risk node count). Note: `escalation_path_count` is currently hardcoded to `0` in `TrustGraphBuilder.compute_stats()` — not yet wired to a real count.

### `GET /graph/nodes/search`
Query params: `q` (required, min length 2), `cloud_provider`, `node_type`, `limit` (1–100, default 20)

Full-text search across graph nodes.

### `GET /graph/nodes/{node_id:path}`
Full detail for a single node — metadata, risk score, connected neighbor IDs. `node_id` uses a `:path` converter since real node IDs are ARNs/resource paths containing slashes.

### `GET /graph/escalation-paths`
Query params: `cloud_provider`, `min_risk_score` (0.0–1.0, default 0.5), `limit` (1–100, default 20)

Runs live detection via `PrivilegeEscalationPathFinder` and returns matching paths. **Not persisted** — this is an on-demand query, not a stored alert. See the note under Alerts below.

### `GET /graph/escalation-paths/{source_node}/{target_node}`
Shortest trust path between two specific nodes.

### `POST /graph/refresh`
⚠️ **Known bug, unfixed as of Week 6**: calls `trigger_scan()` with the wrong arguments (`cloud_provider=`, `current_user=`) against `trigger_scan`'s real signature (`request: ScanRequest, background_tasks, db, current_user`). Will raise a `TypeError` at runtime if called. Use `POST /scan/` directly instead until this is fixed.

### `GET /graph/subgraph/{node_id:path}`
Query params: `depth` (1–4, default 2), `direction` (`inbound` | `outbound` | `both`, default `both`)

Subgraph centered on one node, for investigating a single identity's trust relationships.

### `GET /graph/risk-scores`
Query params: `cloud_provider`, `threshold` (0.0–1.0, default 0.7), `limit` (1–200, default 50)

Nodes above the given risk threshold, descending.

---

## Alerts — `routes_alerts.py` (prefix `/alerts`)

⚠️ **Architectural note**: as of Week 6, nothing in the codebase ever creates `Alert` rows from detection results. `PatternMatcher` is never instantiated; `PrivilegeEscalationPathFinder` is only wired into `GET /graph/escalation-paths` as an on-demand query. This means the endpoints below currently only operate on whatever `Alert` rows exist by other means (e.g. manual insertion) — detection and alerting are disconnected. See Week 8 limitations.

### `GET /alerts/`
Query params: `severity` (critical | high | medium | low), `status` (open | in_progress | resolved | dismissed), `cloud_provider`, `start_date`, `end_date`, `skip` (default 0), `limit` (1–200, default 50)

### `GET /alerts/summary`
Dashboard counts: total, by severity, by status, and alerts created in the last 24h.

### `GET /alerts/{alert_id}`
Single alert by integer ID.

### `PATCH /alerts/{alert_id}`
Body: `{ "status": "...", "analyst_notes": "...", "assigned_to": ... }` (all optional; only provided fields are updated). Setting `status` to `resolved` auto-stamps `resolved_at`/`resolved_by`.

### `DELETE /alerts/{alert_id}`
Soft-delete for non-admins (sets status to `dismissed`); hard-delete for `admin` role. Returns `204`.

### `POST /alerts/{alert_id}/escalate`
Bumps severity one level: `low → medium → high → critical` (no-op at `critical`).

---

## Scan — `routes_scan.py` (prefix `/scan`)

### `POST /scan/`
Body: `{ "providers": ["aws", "azure", "gcp", "k8s"] }` (optional — omitting `providers` scans all four)

Returns `202` with `{ "job_id": "...", "status": "pending", "providers": [...], "message": "..." }`. Runs asynchronously via its own fresh DB session (`_run_scan` opens `SessionLocal()` directly, since the request-scoped session closes before the background task runs).

### `GET /scan/`
Query params: `status`, `skip` (default 0), `limit` (1–?, default 20)

List scan jobs.

### `GET /scan/latest`
Query params: `cloud_provider` (optional)

Most recently completed scan job.

### `GET /scan/{job_id}`
Full detail of one scan job.

### `DELETE /scan/{job_id}`
Admin only. Cancels a `pending`/`running` job. Returns `204`.

### `GET /scan/{job_id}/results`
Summary for a completed job: node/edge counts, providers scanned, duration.

---

## Containment — `routes_containment.py` (prefix `/containment`)

### `POST /containment/trigger`
Requires `analyst` or `admin` role.

Body:
```json
{
  "alert_id": null,
  "action_type": "REVOKE_CREDENTIALS | DISABLE_ACCOUNT | ISOLATE_RESOURCE | REMOVE_ROLE_ASSIGNMENT | DISABLE_SERVICE_PRINCIPAL | REMOVE_ROLE_BINDING",
  "cloud_provider": "aws | azure | k8s",
  "target_resource": "..."
}
```
Returns `202` with `{ "action_id": int, "status": "pending", "message": "..." }`. Runs asynchronously via its own fresh DB session (`_execute_containment` re-fetches the `ContainmentAction` row by id inside a new `SessionLocal()`, for the same reason as `_run_scan` above).

⚠️ **Real per-provider support, as of Week 6** (the generic action-type list above is aspirational — not every action is implemented for every provider):
- **AWS**: `REVOKE_CREDENTIALS`, `DISABLE_ACCOUNT`, `ISOLATE_RESOURCE` (EC2 only), plus `ATTACH_DENY_ALL_POLICY` (not exposed in any frontend catalog yet). `ROTATE_KEYS` and `BLOCK_IP` are **not implemented anywhere** in the AWS engine.
- **Azure**: `DISABLE_ACCOUNT`, `REVOKE_CREDENTIALS`, `REMOVE_ROLE_ASSIGNMENT`, `DISABLE_SERVICE_PRINCIPAL`. `ISOLATE_RESOURCE`, `BLOCK_IP`, `ROTATE_KEYS` are **not implemented**.
- **K8s**: `REMOVE_ROLE_BINDING` only — deletes the `RoleBinding`/`ClusterRoleBinding` identified by `target_resource` (format: `k8s:rolebinding:<namespace>:<name>` or `k8s:clusterrolebinding:<name>`), after capturing the manifest for potential future rollback.
- **GCP**: no containment engine exists yet.

### `GET /containment/actions`
Query params: `alert_id`, `cloud_provider`, `action_status`, `skip` (default 0), `limit` (1–?, default 50)

Lists **past executed** containment actions (not "available action types," despite what an older draft of this doc said).

### `GET /containment/actions/{action_id}`
Full detail of one containment action, including its `result` (JSON string) or `error_message`.

### `POST /containment/actions/{action_id}/rollback`
Admin only. Creates a new `ROLLBACK_<original_type>` action against the same target. ⚠️ Rollback is **not actually implemented** in any provider engine's dispatch — no engine handles a `ROLLBACK_*` action type yet, so this will currently fail at execution.

### `GET /containment/playbooks`
Lists available playbooks.

### `POST /containment/playbooks/{playbook_id}/run`
Query/body: `alert_id` (required). Requires `analyst` or `admin` role. Chains multiple containment actions per the playbook definition.

---

## Error shape

FastAPI's default validation/HTTP error shape:
```json
{ "detail": "human-readable message" }
```
or, for `422` validation errors, FastAPI's standard field-level error list under `detail`.