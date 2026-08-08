# TrustField Punch List

Tracks confirmed bugs, deferred work, and known limitations for the Week 8
push and beyond. Anything confirmed in a debugging session gets written
here immediately, not left to session memory.

Status values: `open`, `in progress`, `resolved`, `deferred (documented limitation)`

---

## Open

### 1. Five-singleton Neo4j architecture
**Status:** open
No shared lifecycle management across the five places the codebase
instantiates a Neo4j client/driver. Root cause (or contributing factor)
behind at least two separate bugs hit this project:
- `upsert_node()` MERGE-on-full-label-set duplicate-node bug (fixed
  2026-08-06, but the underlying singleton sprawl that made it easy to
  miss remains)
- Neo4j driver binding to the wrong event loop across test isolation
  boundaries (async fixture chaining issue)
Needs a proper refactor to a single shared client with defined lifecycle,
not a patch.

### 2. `is_aws_managed` ML feature missing
**Status:** open
AWS managed service roles (`AWSServiceRole*`) are structurally
indistinguishable from user-created roles in the current feature set,
causing false positives in the anomaly detector. Needs a boolean feature
flag derived from role naming/path convention, threaded into the
Isolation Forest training data.

---

## Resolved this session (2026-08-06 to 2026-08-08)

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
- `AlertPanel.jsx` reads `alert.pattern_id`, `alert.detected_at`,
  `alert.mitre_technique` — none exist in `AlertResponse`. Cosmetic,
  deferred.
- `POST /ml/train` overwrites the demo model pkl — running tests
  clobbers demo state.
- `clear_provider_data` wipes real demo data on every scan, including
  test runs.
- `role_chaining` alerts' `path_edges` field is empty (`[]`) while
  `privilege_escalation` alerts populate it (`["CAN_ASSUME"]`) —
  observed 2026-08-08, not yet investigated. Possibly intentional given
  multi-hop paths, possibly another schema-drift instance. Flagged, not
  chased.
- `job_id` vs `id` field naming inconsistency between `POST /scan/`'s
  response and `GET /scan/{id}`'s response — same dominant bug class as
  the Week 2–3 Cypher/Pydantic drift, just at the route-response level
  this time. Observed 2026-08-08, not yet fixed.