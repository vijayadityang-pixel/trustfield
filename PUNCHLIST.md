\# TrustField Punch List



Tracks confirmed bugs, deferred work, and known limitations for the Week 8

push and beyond. Anything confirmed in a debugging session gets written

here immediately, not left to session memory.



Status values: `open`, `in progress`, `resolved`, `deferred (documented limitation)`



\---



\## Open



\### 1. `POST /scan/` `cloud\_provider` filter ignored

\*\*Status:\*\* open

\*\*Found:\*\* Week 8

Requesting a scan with a `providers` filter (e.g. `\["azure"]`) still scans

all four providers (aws, azure, gcp, k8s) every time. Confirmed via live

API call — `providers\_requested` and `providers\_scanned` always match the

full set regardless of what was requested. Root cause not yet

investigated; likely the filter value isn't being threaded through from

`routes\_scan.py` into the actual collector dispatch loop.



\### 2. Five-singleton Neo4j architecture

\*\*Status:\*\* open

No shared lifecycle management across the five places the codebase

instantiates a Neo4j client/driver. Root cause (or contributing factor)

behind at least two separate bugs hit this project:

\- `upsert\_node()` MERGE-on-full-label-set duplicate-node bug (fixed

&#x20; 2026-08-06, but the underlying singleton sprawl that made it easy to

&#x20; miss remains)

\- Neo4j driver binding to the wrong event loop across test isolation

&#x20; boundaries (async fixture chaining issue)

Needs a proper refactor to a single shared client with defined lifecycle,

not a patch.



\### 3. `is\_aws\_managed` ML feature missing

\*\*Status:\*\* open

AWS managed service roles (`AWSServiceRole\*`) are structurally

indistinguishable from user-created roles in the current feature set,

causing false positives in the anomaly detector. Needs a boolean feature

flag derived from role naming/path convention, threaded into the

Isolation Forest training data.



\---



\## Resolved this session (2026-08-06 to 2026-08-08)



\### Azure `role\_chaining` / identity-chaining detection

\*\*Status:\*\* resolved

\*\*Verified:\*\* live scan, alerts 138/139/140, path

`trustfield-victim-azure → trustfield-chain-identity → {Owner,

Contributor, User Access Administrator}`, MITRE T1548.005

Chain of five bugs found and fixed in sequence:

1\. `upsert\_node()` MERGE-on-full-label-set — same id under two label

&#x20;  combinations created a duplicate node. Fixed to MERGE on

&#x20;  `(primary\_label, id)`, then `SET` additional labels.

2\. `resourcegroups` vs `resourceGroups` casing mismatch between role

&#x20;  assignment scopes and ARM resource listings. Fixed by lowercasing

&#x20;  both sides of the `managed\_identity\_by\_resource` lookup.

3\. `MANAGED\_IDENTITY\_ASSIGN\_ACTIONS` exact-set-intersection never

&#x20;  matched Azure's real "Managed Identity Operator" action string

&#x20;  (`.../userAssignedIdentities/\*/assign/action` — the `\*` is a fixed

&#x20;  canonical path segment, not a glob to strip). Replaced with an

&#x20;  fnmatch-based coverage check.

4\. Target constant itself was missing the `\*/` segment — corrected to

&#x20;  match Azure's real action string.

5\. Stray `DEBUG hop1 check` logger line removed after root-causing.



Commits: `5dc7ce9` (fix), `ab4ada8` (push).



\### Systemic action-matching audit

\*\*Status:\*\* resolved

\*\*Verified:\*\* live rescan post-fix — same 3 alerts (138/139/140), no

regressions; same node/edge counts (1129/163)

Same exact-set-intersection blind spot found in

`\_role\_grants\_self\_escalation`, `DANGEROUS\_AZURE\_ACTIONS` usage, and

`SELF\_ESCALATION\_ONLY\_ACTIONS` exclusion logic in

`\_role\_definition\_privilege`. A role granting e.g.

`Microsoft.Authorization/roleAssignments/\*` would cover

`roleAssignments/write` but never equal any literal string in either

set, so self-escalation went undetected and privilege scoring was

skipped incorrectly. Fixed with a shared `\_action\_covered(target,

granted\_actions)` / `\_any\_action\_covered(targets, granted\_actions)`

helper pair using `fnmatch.fnmatch` with target as the "name" side and

each granted action as the "pattern" side. Applied consistently across

all three call sites, including unifying `\_grants\_managed\_identity\_assign`

onto the same helper.



Commit: `97d5537`.



\---



\## Deferred / documented as limitations (not gaps)



These are known and intentional, documented for the Week 8 "Known

Limitations and Future Work" writeup rather than left as invisible gaps:



\- `wildcard\_trust` and `cross\_account` detectors are AWS-specific; no

&#x20; direct structural equivalent modeled in Azure/GCP yet.

\- `escalation\_patterns.json` query-pattern externalization deliberately

&#x20; not done.

\- GCP containment engine not yet live-verified end-to-end from the

&#x20; frontend (backend verified).

\- K8s multi-hop chain alerts correctly show "no single binding to

&#x20; remove" — permanent structural limitation, not a bug.

\- Azure cross-tenant guest-user scenario not built — stretch goal only.

\- `str(dict)`-as-condition edge storage pattern (not valid JSON) in

&#x20; `\_ingest\_aws`, `\_ingest\_azure`, `\_ingest\_gcp` — latent bug when

&#x20; condition fields are read back as dicts elsewhere; already hit and

&#x20; fixed once in the GCP resolver with `ast.literal\_eval`.

\- `AlertPanel.jsx` reads `alert.pattern\_id`, `alert.detected\_at`,

&#x20; `alert.mitre\_technique` — none exist in `AlertResponse`. Cosmetic,

&#x20; deferred.

\- `POST /ml/train` overwrites the demo model pkl — running tests

&#x20; clobbers demo state.

\- `clear\_provider\_data` wipes real demo data on every scan, including

&#x20; test runs.

\- `role\_chaining` alerts' `path\_edges` field is empty (`\[]`) while

&#x20; `privilege\_escalation` alerts populate it (`\["CAN\_ASSUME"]`) —

&#x20; observed 2026-08-08, not yet investigated. Possibly intentional given

&#x20; multi-hop paths, possibly another schema-drift instance. Flagged, not

&#x20; chased.

\- `job\_id` vs `id` field naming inconsistency between `POST /scan/`'s

&#x20; response and `GET /scan/{id}`'s response — same dominant bug class as

&#x20; the Week 2–3 Cypher/Pydantic drift, just at the route-response level

&#x20; this time. Observed 2026-08-08, not yet fixed.

