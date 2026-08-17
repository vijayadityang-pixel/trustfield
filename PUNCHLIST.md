# TrustField Punch List

Tracks confirmed bugs, deferred work, and known limitations for the Week 8
push and beyond. Anything confirmed in a debugging session gets written
here immediately, not left to session memory.

Status values: `open`, `in progress`, `resolved`, `deferred (documented limitation)`

---

## Open

### `build_subgraph()` frontend/backend field mismatch (dormant, unused)
**Status:** open (documented, not fixed — no urgency)
`build_subgraph()` (backs `GET /graph/subgraph/{node_id}`) has the same
kind of field mismatch `build_graph()` had before this session's fix —
its Cypher returns `id`/`provider`/`source`/`target`/`type` instead of
`node_id`/`cloud_provider`/`source_id`/`target_id`/`relationship_type`,
which `NodeDetail`/`EdgeDetail` require. Currently harmless because
`fetchSubgraph()` is exported from `api.js` but never called anywhere in
the frontend — but it will 500 with a Pydantic validation error the
moment something calls it. Fix when that endpoint gets wired up.

---

## Resolved this session (2026-08-17)

### `trustfield_demo_script.md` — demo script for College Review-1 panel
**Status:** resolved (drafted fresh — no prior skeleton existed on disk;
earlier session had deferred this to "after Week 8" and it was never
saved)
Full script written covering: pre-demo golden-snapshot restore
checklist (`neo4j_golden.dump` + `trustfield_golden.dump`), opening
framing (cross-cloud graph correlation as the core value prop vs.
single-cloud native tools), UI walkthrough (Dashboard → gravity-well
graph view → heatmap → alert detail → containment modal, narrated
against alert 126 as a simple example), centerpiece live walkthrough
of the Azure role-chaining chain (alerts 141/142/143,
`trustfield-victim-azure → trustfield-chain-identity →
Owner/Contributor/UAA`, MITRE T1548.005), and a close on the
`is_aws_managed` IsolationForest limitation as the honest research
insight. Includes anticipated panel Q&A prep notes and a flexible
timing cheat sheet (built for a longer/flexible slot, with guidance on
what to cut if time is short).
File: `trustfield_demo_script.md` (repo root).

## Resolved earlier (2026-08-16)

### `ContainmentModal.jsx` test suite — mock missing `fetchAlert`/`fetchContainmentAction`/`resolveK8sBinding`/`resolveGcpBinding`
**Status:** resolved
**Verified:** `npx vitest run` — 15/15 passing, both test files (was
12/15 with 3 pre-existing `Containmentmodal.test.jsx` failures)
Root cause: the test file's `vi.mock('../../services/api')` block only
stubbed `triggerContainment`. The component had since grown to also
call `fetchAlert` (to resolve the full alert regardless of what the
caller passed in), `resolveK8sBinding`/`resolveGcpBinding` (to resolve
a concrete binding target for k8s/gcp before showing the action
catalog), and `fetchContainmentAction` (to poll a triggered action
until it reaches `completed`/`failed`, since `/containment/trigger`
only queues a background job and returns immediately). None of these
were stubbed, so any test exercising a k8s or gcp alert, or the
execute-action flow, threw as soon as the component called an
undefined mock function.
Fix went beyond adding stubs — two tests' premises were stale and
needed rewriting to match current component behavior:
- The k8s test previously asserted the catalog rendered synchronously;
  the component now gates it behind an async resolution step, so the
  test now mocks `fetchAlert`/`resolveK8sBinding` and uses `waitFor`.
- The gcp test previously asserted "no actions available for
  unrecognized provider" — no longer true, since gcp now has a real
  action catalog (`Remove IAM binding`). Replaced with a test of the
  actual current edge case: the blocked-message state shown when
  `source_node_id`/`target_node_id` are missing and resolution can't
  proceed.
- The "shows done state" test's `triggerContainment` mock now resolves
  `{ action_id }` instead of `{}`, and `fetchContainmentAction` is
  mocked to return `{ status: 'completed' }` immediately so the poll
  resolves without hitting the real 15s timeout.
File: `frontend/src/components/__tests__/Containmentmodal.test.jsx`.
Commit: `15cf5f6`.

### AWS Console cleanup — `trustfield-rotate-test` IAM user + NACL rule on `acl-0629ecd6db413837c`
**Status:** resolved (found already resolved — logging for the record)
**Verified:** live in AWS Console — IAM Users page shows only 2 users
(`trustfield-collector`, `trustfield-victim`), no `trustfield-rotate-test`;
`acl-0629ecd6db413837c` inbound rules show only the two default rules
(100/allow-all, */deny-all) with no leftover custom rule
Both items were previously flagged as pending manual cleanup because
`trustfield-collector`'s IAM role lacks delete permissions for IAM
users and NACL rules. On checking the console directly this session,
both were already gone — either cleaned up manually in an earlier
session and never logged here, or the rule/user in question never
actually persisted. No action was needed; closing the item as
resolved rather than leaving it open against a false premise.

---

## Resolved earlier (2026-08-14)

### Frontend design-system layer was entirely missing
**Status:** resolved
**Verified:** `npm run build` clean (vite 5.4.21, 2121 modules, no
errors); `npx vitest run` — same pass/fail counts as before the CSS
change; live-verified in browser against a running backend/Neo4j
Root cause: `index.css` only ever defined the app shell (sidebar,
login screen) — roughly 15 CSS custom properties referenced across
`TrustGraph.jsx`, `AlertPanel.jsx`, `RiskHeatmap.jsx`, `PathDetail.jsx`,
`ContainmentModal.jsx`, and all four `pages/*.jsx` files
(`--bg-elevated`, `--bg-hover`, `--border`, `--border-bright`,
`--accent-trust(-dim)`, `--risk-critical/high/medium/low`,
`--text-faint`, `--radius-md`, `--shadow-elevated`, `--font-display`,
`--font-mono`) were never defined, and ~15 component classes
(`.card`, `.card-header/-title`, `.btn` + variants, `.badge` +
severity variants, `.select`, `.skeleton`, `.empty-state`,
`.stat-grid/-tile`, `.mono`, `.page-header/-title/-subtitle`) had zero
rules anywhere in the codebase. Every content surface outside the
sidebar/login screen had been rendering with browser-default styling
since whenever those components were written — this, not a "needs
polish" issue, was the actual reason the app looked unfinished.
Fixed by extending `index.css` with the full token set and the full
component stylesheet. Added Space Grotesk (display / stat numbers) and
JetBrains Mono (`.mono` — IDs, ARNs) via Google Fonts link in
`index.html`, alongside existing Inter.
Files: `index.html`, `src/index.css`, `src/components/AlertPanel.jsx`
(see field-name fix below, same commit).

### `AlertPanel.jsx` field-name mismatch (cosmetic bug, previously deferred)
**Status:** resolved
**Verified:** confirmed against `backend/schemas/alert_schemas.py` and
`backend/detection/alert_generator.py` (`raw_evidence` dict
construction) before editing — not guessed
`AlertPanel.jsx` read `alert.pattern_id`, `alert.detected_at`, and
`alert.mitre_technique` as top-level fields. Real `AlertResponse`
fields are `alert_type` and `created_at`; `mitre_technique` is nested
inside `raw_evidence`, not top-level. All three previously rendered
`undefined`. Fixed to `alert.alert_type`, `alert.created_at`,
`alert.raw_evidence?.mitre_technique`, and risk score now goes through
the shared `riskPercent()` util (see below) instead of printing the
raw 0-1 float.
File: `src/components/AlertPanel.jsx`.

### Frontend↔backend graph contract mismatch (graph view + heatmap rendered empty)
**Status:** resolved
**Verified:** `vite build` clean; `npx vitest run` — same 3 pre-existing
`ContainmentModal` failures, nothing new broken; `py_compile` clean on
all touched backend files; live-verified — Dashboard now renders real
nodes/edges in the trust graph, heatmap cells populate with real
percentages, "Providers connected" shows a real count (4)
Root cause, three separate mismatches stacked on top of each other:
1. `GraphResponse`'s Cypher output (`build_graph()` in
   `graph_builder.py`) correctly matches the backend's own
   `NodeDetail`/`EdgeDetail` schema (`node_id`, `node_type`, `name`,
   `cloud_provider`; edges `source_id`, `target_id`,
   `relationship_type`) — the backend was internally consistent, but
   `TrustGraph.jsx` and `RiskHeatmap.jsx` were written against a
   simpler, never-matching shape (`id`, `type`, `label`, `provider`).
2. Real ingested `node_type` values are provider-specific
   (`aws_role`, `azure_service_principal`, `k8s_cluster_role`, etc.),
   not the generic `Identity/Role/Policy/Resource/ServiceAccount`
   categories the graph/heatmap group by. **`Policy` and `Resource`
   are not populated by any collector currently** — only identities,
   roles, and service-account-like principals are ingested today, so
   those two categories will legitimately stay empty until
   policy/resource nodes are modeled (not a bug, a scope gap, see
   Known Limitations).
3. `RiskHeatmap.jsx`'s provider list used `'kubernetes'`; the actual
   stored value is `'k8s'` (see `graph_builder.py` — `"provider":
   "k8s"` throughout the k8s ingestion pass), so the Kubernetes row
   could never match any node.
An earlier attempt at this fix (normalizing field names inside
`fetchGraph()` in `api.js`, aliasing the real fields to the shape
components expected) was written, then superseded and reverted in
favor of fixing the shape mismatch at its actual source: components
now read the real backend fields directly (`node_id`, `node_type`,
`name`, `cloud_provider`), and a single shared
`src/utils/nodeTypes.js` (`NODE_TYPE_CATEGORY` map + `PROVIDERS` list)
is the one place the ~14 real `node_type` strings get bucketed into
the 5 display categories, rather than duplicating that map in `api.js`
and each component separately. `api.js`'s `fetchGraph()` is back to a
plain passthrough.
Files: `src/utils/nodeTypes.js` (new),
`src/components/TrustGraph.jsx`, `src/components/RiskHeatmap.jsx`,
`src/pages/Dashboard.jsx`.

### `GraphStatsResponse` missing `providers_connected`; `build_graph()` had an unordered flat `LIMIT 500`
**Status:** resolved
**Verified:** live — Azure `Role` heatmap cell shows 149/150 nodes,
confirming the new per-provider cap is actually engaging (not just
coincidentally under the old flat limit); "Providers connected" tile
shows a real `4`
Two related backend gaps found while fixing the contract mismatch
above:
1. `compute_stats()` never computed which providers actually have
   ingested data — the frontend's "Providers connected" stat had
   nothing real to bind to. Added
   `neo4j_client.get_connected_providers()` (`MATCH (n:Identity) ...
   RETURN DISTINCT n.provider`), wired through `compute_stats()`, and
   added `providers_connected: List[str] = []` to
   `GraphStatsResponse`.
2. `build_graph()`'s Cypher capped the whole result set at a flat
   `LIMIT 500` with no `ORDER BY` — on a multi-provider graph this
   meant one provider with a lot of nodes could silently starve
   another provider's nodes out of the response entirely, and there
   was no guarantee the *highest-risk* nodes were the ones that
   survived the cap. Rewrote to cap 150 nodes per provider, ordered by
   `risk_score DESC`, so every connected provider always gets
   representation and the nodes that make the cut are the ones that
   matter most for a risk-focused view.
Files: `backend/graph/neo4j_client.py`, `backend/graph/graph_builder.py`,
`backend/schemas/graph_schemas.py`.

### Risk score displayed as raw 0.0-1.0 float instead of a percent (graph, heatmap, alerts, node detail)
**Status:** resolved
**Verified:** live — node detail panel shows "Risk score: 18", not
"0.18"; heatmap cells show real percentages instead of near-zero
rounding artifacts
`risk_score` is stored as a 0.0-1.0 float everywhere in the backend
(`backend/detection/risk_scorer.py`), but `TrustGraph.jsx` and
`RiskHeatmap.jsx` treated it as already being 0-100 (progress-bar
`width: ${risk_score}%`, severity thresholds checked against
`>=80/55/30`) — every risk bar rendered essentially empty and every
severity bucket resolved to "low." Centralized the conversion in a new
`src/utils/risk.js` (`riskPercent()`, `riskBucket()`, `riskColor()`)
so every display surface converts through one place instead of each
component reimplementing (and mismatching) the scale independently.
Thresholds (85/70/55/low) match `alert_generator.py`'s
`_severity_for_risk` cuts exactly.
Files: `src/utils/risk.js` (new), `src/components/TrustGraph.jsx`,
`src/components/RiskHeatmap.jsx`, `src/components/AlertPanel.jsx`,
`src/pages/Dashboard.jsx`.

### `TrustGraph.jsx` layout: radial layout collapsed to a single point; dagre replacement then collapsed to a single column; `fitView` never refit after async load
**Status:** resolved
**Verified:** live — graph renders as a browsable multi-column grid
(isolated nodes) with dagre-laid-out chains (connected nodes); zoom
controls and minimap visible; no manual pan/zoom needed to find the
bulk of the ~1041 nodes on load
Three layered bugs, found in sequence while live-verifying the graph
contract fix above:
1. Before this session, `radialLayout()` positioned nodes keyed by
   `positions[n.id]` — but `n.id` was always `undefined` (the real
   field is `node_id`, see contract fix above), so every node looked
   up the same `positions[undefined]` entry and rendered stacked
   exactly on top of each other. Fixed as part of the contract fix.
2. Replacing `radialLayout()` with a `dagre`-based `rankdir: LR`
   layout fixed the single-point collapse, but introduced a new
   problem: dagre assigns rank purely from edges, so any node with
   zero edges to other nodes in view (the common case — most
   identities/roles/service-accounts don't link to each other
   directly) defaults to rank 0, and hundreds of them stacked into one
   very tall column instead of spreading out. Fixed by splitting nodes
   into connected vs. isolated sets: connected nodes still get a
   normal dagre `LR` layout; isolated nodes are packed into a roughly
   square grid below it instead of one column, keeping the graph
   browsable at any node count.
3. `fitView` on `<ReactFlow>` is a boolean prop that only fits the
   viewport once, at first mount — but graph data loads asynchronously
   after that render, so the initial fit locked onto an empty/near-
   empty canvas and never re-fit once the real node set arrived,
   requiring manual pan/zoom to find anything. Fixed by capturing the
   ReactFlow instance via `onInit` and calling `fitView()` again in a
   `useEffect` keyed off the node array actually changing.
Also added `dagre` to `package.json`.
Files: `src/components/TrustGraph.jsx`, `frontend/package.json`.

### New: "Gravity well" alternate graph layout
**Status:** shipped (enhancement, not a bug fix)
A second layout mode, toggled alongside the default grid view. Nodes
are sorted by `risk_score` descending and placed on a golden-angle
phyllotaxis spiral (radius grows with sort-rank via `sqrt(index)`,
angle increments by the golden angle each step) — an even,
non-overlapping spiral at any node count, where the highest-risk node
in the whole graph always lands at the center and density falls off
outward. Real trust edges still draw between wherever nodes land in
the spiral. `fitView` refit logic (above) re-triggers on layout-mode
switch as well as on data load.
File: `src/components/TrustGraph.jsx`.

---

## Resolved earlier (2026-08-09)

### Five-singleton Neo4j architecture
**Status:** resolved
**Verified:** live — `GET /graph/stats`, `/scan/latest`, `/ml/anomalies`,
and `/containment/actions` all returned `200` in the same running
uvicorn process, with no restarts between calls, confirming all 5
modules share one working connection
All 5 backend modules (`main.py`, `routes_scan.py`, `routes_graph.py`,
`routes_ml.py`, `routes_containment.py`) previously instantiated their
own `Neo4jClient()` at module level, with only `main.py`'s instance
having a managed `connect()`/`close()` lifecycle via `lifespan()`. The
other 4 relied on lazy `.connect()` bootstrapping inside `session()`
and were never explicitly closed. Fixed by adding
`graph/neo4j_singleton.py` holding one shared instance; all 5 files
now import it instead of constructing their own. `main.py`'s
`lifespan()` still owns `connect()`/`close()`/`apply_indexes()` for
the single shared instance; route modules only read from it. No route
handler signatures or logic changed — diff limited to swapping the
import line and removing the now-redundant local instantiation in
each file.

Root cause (or contributing factor) behind: the `upsert_node()`
MERGE-on-full-label-set duplicate-node bug's wider blast radius, the
"Unable to retrieve routing information after restart" bug, and
async-fixture test-isolation crashes.

Commit: `f104eac`.

### `is_aws_managed` ML feature
**Status:** resolved
**Verified:** live scan + Neo4j query — all 3 real AWS-managed roles
(`AWSServiceRoleForResourceExplorer`, `AWSServiceRoleForSupport`,
`AWSServiceRoleForTrustedAdvisor`) correctly flagged
`is_aws_managed: true`; all test/admin roles (`trustfield-admin-role`,
`trustfield-cross-account-role`, `trustfield-intermediate-role`,
`trustfield-containment-role`) correctly `false`
Added `is_aws_managed` to `feature_extractor.py` (index 25, appended
rather than inserted, to avoid shifting `PROVIDER_MAP`/`NODE_TYPE_MAP`
indices) and to `graph_builder.py`'s `_ingest_aws` via a new
`_is_aws_managed_role` helper (checks `Path` for the
`/aws-service-role/` prefix, with a `RoleName` prefix fallback —
`AWSServiceRoleFor*` / `AWSReservedSSO_*` — in case `Path` isn't
populated). Retrained model, 26 features confirmed in training
response.

**Finding (documented for the Week 8 limitations writeup, not a
further-fix item):** `is_aws_managed` became the single largest
`feature_contribution` (0.299) for all 3 managed roles, and
`anomaly_score` dropped from the Week 5 baseline of ~0.89–0.95 to 0.82
— directionally correct, but did not clear the anomaly threshold.
Root cause: IsolationForest flags points that are rare in feature
space, not points matching a specific "safe" pattern. With only 3 of
1041 nodes carrying `is_aws_managed=true`, the flag's own rarity
becomes a new isolation signal, partially offsetting its intended
exculpatory effect. This is a genuine structural limit of unsupervised
anomaly detection on a domain-derived exculpatory feature — a
supervised label or a post-hoc override rule (force
`is_anomaly = False` when `is_aws_managed` is true) would fully
suppress it, but was deliberately not implemented this session to
avoid scope creep this late in Week 8.

Commit: `4a93310`.

---

## Resolved (2026-08-06 to 2026-08-08)

### `job_id` / `id` field naming drift
**Status:** resolved
**Verified:** live — `POST /scan/` and `GET /scan/{job_id}` both returned
`job_id` for the same scan (`9f1d063a-092b-4b1a-8520-a87c0fb677d9`)
`ScanJobResponse` (returned by `POST /scan/`) and `ScanResultSummary`
(returned by `GET /scan/{job_id}/results`) both used `job_id`, but
`ScanJobDetail` (returned by `GET /scan/{job_id}`, `GET /scan/latest`,
and `GET /scan/`) used `id` directly from the ORM column via
`from_attributes=True` — so the same scan job's identifier appeared
under two different field names depending on which endpoint was hit.
Same field-naming-drift bug class as the Week 2–3 Cypher/Pydantic
issues and the `cloud_provider` filter bug, this time at the
response-schema-vs-ORM-column layer. Fixed by changing the field to
`job_id: str = Field(validation_alias="id")` in `ScanJobDetail`,
keeping the DB column named `id` untouched while aliasing it for a
consistent API surface.

Commit: `c2b9ee9`.

### Azure `role_chaining` / identity-chaining detection
**Status:** resolved
**Verified:** live scan, alerts 138/139/140, path
`trustfield-victim-azure → trustfield-chain-identity → {Owner,
Contributor, User Access Administrator}`, MITRE T1548.005
Chain of five bugs found and fixed in sequence:
1. `upsert_node()` MERGE-on-full-label-set — same id under two label
   combinations created a duplicate node. Fixed to MERGE on
   `(primary_label, id)`, then `SET` additional labels.
2. `resourcegroups` vs `resourceGroups` casing mismatch between role
   assignment scopes and ARM resource listings. Fixed by lowercasing
   both sides of the `managed_identity_by_resource` lookup.
3. `MANAGED_IDENTITY_ASSIGN_ACTIONS` exact-set-intersection never
   matched Azure's real "Managed Identity Operator" action string
   (`.../userAssignedIdentities/*/assign/action` — the `*` is a fixed
   canonical path segment, not a glob to strip). Replaced with an
   fnmatch-based coverage check.
4. Target constant itself was missing the `*/` segment — corrected to
   match Azure's real action string.
5. Stray `DEBUG hop1 check` logger line removed after root-causing.

Commits: `5dc7ce9` (fix), `ab4ada8` (push).

### Systemic action-matching audit
**Status:** resolved
**Verified:** live rescan post-fix — same 3 alerts (138/139/140), no
regressions; same node/edge counts (1129/163)
Same exact-set-intersection blind spot found in
`_role_grants_self_escalation`, `DANGEROUS_AZURE_ACTIONS` usage, and
`SELF_ESCALATION_ONLY_ACTIONS` exclusion logic in
`_role_definition_privilege`. A role granting e.g.
`Microsoft.Authorization/roleAssignments/*` would cover
`roleAssignments/write` but never equal any literal string in either
set, so self-escalation went undetected and privilege scoring was
skipped incorrectly. Fixed with a shared `_action_covered(target,
granted_actions)` / `_any_action_covered(targets, granted_actions)`
helper pair using `fnmatch.fnmatch` with target as the "name" side and
each granted action as the "pattern" side. Applied consistently across
all three call sites, including unifying `_grants_managed_identity_assign`
onto the same helper.

Commit: `97d5537`.

### `POST /scan/` `cloud_provider` filter ignored
**Status:** resolved
**Verified:** live scan job `065d8bea-09e6-4df5-ba8b-7403cab9066b` —
`{"providers":["azure"]}` correctly returned `providers_requested:
["azure"]` and, on completion, `providers_scanned: ["azure"]` only
(965 nodes, 14 edges — matches standalone Azure ingest counts from
earlier in the session)
Root cause: `ScanRequest` had no `extra="forbid"` config, so Pydantic
silently dropped any unrecognized field instead of rejecting it. The
original bug report's field name — `cloud_provider` — was never a real
field on `ScanRequest` (the actual field is `providers`, a list), so a
request sending `cloud_provider` had it silently dropped, leaving
`request.providers` as `None`, which `trigger_scan`'s `providers =
request.providers or list(COLLECTOR_MAP.keys())` interpreted as "scan
everything." Same field-naming-drift bug class as the Week 2–3
Cypher/Pydantic issues, surfacing at the request-schema layer this
time. Fixed by adding `model_config = ConfigDict(extra="forbid")` to
`ScanRequest`, so future field-name mismatches return a 422 instead of
silently scanning everything.

Commit: `bd7e292`.

### `role_chaining` alerts had empty `path_edges`
**Status:** resolved
**Verified:** live scan, alerts 141/142/143 — `raw_evidence.path_edges`
now `["CAN_ASSUME","CAN_ASSUME"]`, matching the two-hop `path_nodes`
chain (stale alerts 138/139/140 deleted and regenerated fresh to see
the fix, since `generate_alerts` dedup skips creation when an OPEN
alert already exists for the same source/target pair)
Root cause: `_record_to_path()` reads `path_edges` from
`record.get("rel_types", [])`. `QUERY_PRIVILEGE_ESCALATION` explicitly
computes and returns `rel_types`, but `QUERY_ROLE_CHAINING` never
selected it at all — its `WITH` clause only carried `chain` and `depth`
forward, dropping the `path` variable before any relationship-type
extraction, so `rel_types` always fell back to the empty-list default.
Same field-not-projected bug class as the rest of the project. Fixed
by adding `[r IN relationships(path) | type(r)] AS rel_types` to both
the `WITH` and `RETURN` clauses of `QUERY_ROLE_CHAINING`. No other
code changes needed — `_record_to_path()` already read the field
generically.

Commit: `338f6d2`.

### `extra="forbid"` schema audit
**Status:** resolved
**Verified:** live — `POST /containment/trigger` with a deliberately
misspelled field (`alertId` instead of `alert_id`) returned `422
extra_forbidden`, confirming the guard actually rejects bad fields
rather than silently dropping them
Audited all 5 files in `schemas/` for the same gap that caused the
`cloud_provider`/`ScanRequest` bug (`bd7e292`) — that fix only covered
`ScanRequest` itself. Added `ConfigDict(extra="forbid")` to the 3
other real request-body models: `AlertUpdate` (`alert_schemas.py`,
PATCH `/alerts/{id}` body), `LoginRequest` (`auth_schemas.py`, POST
`/auth/login` body), `ContainmentRequest` (`containment_schemas.py`,
POST `/containment/trigger` body). `graph_schemas.py` has no
request-body models (response-only) — nothing to fix. `AlertFilter`
intentionally excluded — used as a query-param grouping, not bound as
a request body.

Commit: `70b9782`.

---

## Deferred / documented as limitations (not gaps)

These are known and intentional, documented for the Week 8 "Known
Limitations and Future Work" writeup rather than left as invisible gaps:

- `wildcard_trust` and `cross_account` detectors are AWS-specific; no
  direct structural equivalent modeled in Azure/GCP yet.
- `escalation_patterns.json` query-pattern externalization deliberately
  not done.
- GCP containment engine not yet live-verified end-to-end from the
  frontend (backend verified).
- K8s multi-hop chain alerts correctly show "no single binding to
  remove" — permanent structural limitation, not a bug.
- Azure cross-tenant guest-user scenario not built — stretch goal only.
- `str(dict)`-as-condition edge storage pattern (not valid JSON) in
  `_ingest_aws`, `_ingest_azure`, `_ingest_gcp` — latent bug when
  condition fields are read back as dicts elsewhere; already hit and
  fixed once in the GCP resolver with `ast.literal_eval`.
- `POST /ml/train` overwrites the demo model pkl — running tests
  clobbers demo state.
- `clear_provider_data` wipes real demo data on every scan, including
  test runs.
- `is_aws_managed` feature moves anomaly scores in the correct
  direction (0.89–0.95 → 0.82 for real AWS-managed roles) but does not
  clear the anomaly threshold, because IsolationForest reads the
  flag's own rarity (3/1041 nodes) as an isolation signal rather than
  as exculpatory context. A supervised label or post-hoc override rule
  would fully resolve this; deliberately not implemented. See resolved
  entry above for full detail.

---

## Still-open loose threads

*(none — schema audit completed 2026-08-09, ContainmentModal test fix
and AWS Console cleanup verification completed 2026-08-16, demo script
completed 2026-08-17)*