# TrustField: Known Limitations and Future Work

*Last updated: August 16, 2026*

This document catalogs the architectural, algorithmic, and coverage
limitations discovered over the course of building TrustField, along
with the reasoning behind each and what a production version would
need to address it. Nothing here is a hidden gap — every item was
found, root-caused, and deliberately scoped out or deferred rather
than left undiscovered. Several of these limitations are themselves
useful findings about the domain, not just unfinished checkboxes.

---

## 1. Detection Coverage

### 1.1 `wildcard_trust` and `cross_account` detectors are AWS-specific
These two detectors rely on AWS-specific trust policy constructs
(principal wildcards in an IAM trust document, cross-account role
assumption) that don't have a direct structural equivalent modeled in
Azure or GCP yet. Azure's closest analogue would be guest-user/
cross-tenant access; GCP's would be cross-project service account
impersonation. Both are architecturally different enough from AWS
trust policies that porting the detectors isn't a simple copy — they'd
need their own Cypher patterns built against how Azure/GCP actually
represent that trust relationship in the graph.

### 1.2 GCP/Azure privilege escalation detection requires project-level `HAS_ROLE` on the target
The privilege escalation detector's risk score is driven by the target
node's `privilege_level`, which is only populated when the target has
a project-level (GCP) or subscription-level (Azure) role binding. A
target with escalation-path access but no direct role binding never
reaches the `privilege_level >= 4` threshold the detector requires,
even though the escalation path itself is real. This surfaced
independently in both the Azure and GCP detectors, which points to it
being a structural property of how privilege scoring is currently
computed rather than a one-off bug in either provider's collector.

### 1.3 K8s built-in controller false positives
Roughly 25 of 40 `k8s_escalation_primitive` alerts fire against
Kubernetes' own built-in controller service accounts, which
legitimately hold bind/escalate-style verbs as part of normal cluster
operation. The detector currently has no allowlist for
well-known system service accounts, so it can't distinguish "a
controller doing its job" from "an attacker-controlled identity with
the same verb." A production version would need a curated allowlist
(or a trust baseline learned from cluster metadata) to suppress these.

### 1.4 K8s multi-hop chain alerts have no single binding to remove
This is a structural limitation, not a bug: some k8s escalation
findings span a chain of multiple RoleBindings/ClusterRoleBindings,
and there's no single binding whose removal fully closes the path.
`ContainmentModal.jsx` correctly detects this case and shows a
"contain the source identity through another workflow" message rather
than offering a containment action that would silently fail.

### 1.5 Row multiplicity in `QUERY_PRIVILEGE_ESCALATION` and `QUERY_ROLE_CHAINING`
`QUERY_PRIVILEGE_ESCALATION` fires once per qualifying low-privilege
source node, and `QUERY_ROLE_CHAINING`'s `*2..4` variable-length
pattern matches every sub-chain within a longer chain, not just the
maximal one. Both produce multiple alerts for what a human reviewer
would likely see as one underlying issue. Deduplicating by "longest
chain per source/target pair" would reduce alert noise but wasn't
implemented, since the current alert dedup (skip creation if an OPEN
alert already exists for the same source/target path) already
prevents the worst of it across rescans.

---

## 2. Machine Learning

### 2.1 IsolationForest can't fully separate AWS-managed roles from user-created ones
An `is_aws_managed` feature was added specifically to give the
unsupervised model exculpatory context for AWS service-linked roles.
It moved anomaly scores in the correct direction (0.89–0.95 down to
0.82 for the 3 real AWS-managed roles in the dataset) but didn't clear
the anomaly threshold. The root cause is structural: IsolationForest
flags points that are *rare* in feature space, not points matching a
specific "known-safe" pattern. With only 3 of 1,041 nodes carrying
`is_aws_managed=true`, the flag's own rarity becomes a new isolation
signal, partially cancelling out its intended effect. A supervised
label or a post-hoc override rule (force `is_anomaly=False` when
`is_aws_managed` is true) would fully resolve this, but wasn't
implemented in order to keep the ML pipeline honestly unsupervised
rather than special-casing the demo dataset. This is arguably the most
interesting finding in the whole project for a capstone writeup: it's
a real, general limitation of unsupervised anomaly detection on rare
exculpatory features, not a project-specific bug.

### 2.2 `POST /ml/train` overwrites the demo model binary
The trained model is a single file
(`backend/ml/models/isolation_forest.pkl`) written by a module-level
singleton. Any test run or exploratory retrain during a demo session
overwrites the model that's been tuned against the demo dataset. The
golden-snapshot restore strategy (see Section 4) works around this for
demo day but doesn't fix the underlying single-binary design; a
production version would need versioned model artifacts.

---

## 3. Data Model and Storage

### 3.1 `str(dict)` condition storage across non-K8s providers
AWS, Azure, and GCP collectors all store `CAN_ASSUME` edge `condition`
fields as Python's `str(dict)` repr (single-quoted, not valid JSON)
rather than as actual JSON. Neo4j stores it as a plain string
regardless. Reading it back requires `ast.literal_eval()` rather than
a JSON parser — already discovered and fixed once, in the GCP
resolver. Nothing currently reads these fields back as structured data
for AWS or Azure, so the bug is latent rather than active, but it will
throw `AttributeError` the moment any future route tries `.get()`
directly on a condition value for those two providers. A production
fix would standardize condition storage as real JSON across all four
collectors.

### 3.2 `Policy` and `Resource` node categories are unpopulated
No current collector ingests standalone Policy or Resource nodes —
only identities, roles, and service-account-like principals are
modeled. The frontend's node-type categorization
(`src/utils/nodeTypes.js`) includes Policy/Resource as display
categories in anticipation of this, but they'll legitimately stay
empty in the heatmap and graph view until policy/resource ingestion is
built. This is a deliberate scope boundary for the capstone, not an
oversight — modeling policies and resources as first-class graph nodes
(rather than attributes on the identities that hold them) would
roughly double the ingestion surface area for each provider.

### 3.3 `build_subgraph()` field mismatch (dormant)
`build_subgraph()`, which backs `GET /graph/subgraph/{node_id}`,
returns Cypher output in the pre-refactor shape (`id`/`provider`/
`source`/`target`/`type`) rather than the current schema contract
(`node_id`/`cloud_provider`/`source_id`/`target_id`/
`relationship_type`) that the rest of the graph API now uses. It's
currently harmless because `fetchSubgraph()` is exported from the
frontend API client but never called anywhere in the UI — but it will
fail a Pydantic validation check with a 500 the moment something calls
it. Flagged here rather than fixed silently, since fixing it properly
means either wiring up a UI feature that uses it or deciding to remove
the dead code path.

---

## 4. Demo and Operational Constraints

### 4.1 Snapshot-only IAM analysis, not continuous monitoring
TrustField currently operates as a point-in-time scanner: a scan is
triggered, IAM state is ingested, and the graph reflects that single
moment. There's no continuous/streaming ingestion, drift detection
between scans, or webhook-based reaction to IAM changes as they
happen. A production deployment would need scheduled or
event-triggered scanning and a way to diff graph state across scans to
surface newly introduced risk rather than requiring a manual rescan.

### 4.2 `clear_provider_data()` runs on every scan, including test runs
Each provider's scan clears that provider's existing graph data before
re-ingesting, with no distinction between a real scan and a test/CI
run. This makes the system unsafe to test against live demo data
without a restore step afterward. Resolved operationally for demo day
via a golden-snapshot backup/restore strategy
(`neo4j_golden.dump` + `trustfield_golden.dump`), but the underlying
behavior — tests and demos sharing one mutable data store — remains a
structural constraint a production system would need to design around
(e.g., separate scan targets per environment).

### 4.3 Five-singleton Neo4j architecture (resolved this project, noted for context)
Earlier in the project, all five backend route modules independently
instantiated their own `Neo4jClient()`, with only one having a managed
connection lifecycle. This was root-caused as a contributing factor
behind several downstream bugs (routing errors after restart,
async-fixture test isolation crashes) and was refactored to a single
shared singleton. Included here for completeness since it shaped
several other bugs in this document's earlier drafts, even though the
architectural issue itself is now resolved.

---

## 5. Summary Table

| Area | Item | Status |
|---|---|---|
| Detection | AWS-only wildcard_trust/cross_account detectors | Documented limitation |
| Detection | GCP/Azure escalation requires project-level HAS_ROLE | Documented limitation |
| Detection | K8s built-in controller false positives | Documented limitation |
| Detection | K8s multi-hop chains have no single binding | Structural, by design |
| Detection | Alert row multiplicity (privilege_escalation, role_chaining) | Documented limitation |
| ML | is_aws_managed doesn't clear anomaly threshold | Documented limitation (informative finding) |
| ML | /ml/train overwrites demo model binary | Mitigated via golden snapshot |
| Data model | str(dict) condition storage (AWS/Azure latent) | Documented limitation |
| Data model | Policy/Resource nodes unmodeled | Deliberate scope boundary |
| Data model | build_subgraph() field mismatch (dormant, unused) | Open, low priority |
| Operations | Snapshot-only, no continuous monitoring | Documented limitation |
| Operations | clear_provider_data() wipes data on every scan | Mitigated via golden snapshot |

---

## 6. What a Production Version Would Prioritize

If TrustField continued past this capstone, the highest-value next
steps, roughly in order of impact:

1. **Continuous scanning with drift detection** — turn the snapshot
   model into a scheduled or event-driven pipeline that surfaces what
   *changed* between scans, not just current state.
2. **Policy/Resource node modeling** — extends the graph beyond
   identities to the actual permissions and resources they touch,
   which is where a large share of real-world IAM risk lives.
3. **A supervised or hybrid ML layer** — the unsupervised
   IsolationForest approach has a clear, well-understood ceiling (see
   2.1); a small set of labeled known-safe/known-risky examples would
   likely outperform feature engineering alone.
4. **Cross-provider detector parity** — bringing wildcard_trust/
   cross_account-equivalent detection to Azure and GCP, closing the
   biggest cross-cloud coverage gap.
5. **JSON-native condition storage** — a small, mechanical fix
   (Section 3.1) that removes a whole latent bug class in one pass
   across all four collectors.