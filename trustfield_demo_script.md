# TrustField — Demo Script
**Audience:** College Review-1 Panel
**Format:** Flexible / longer slot (build for ~15–20 min core walkthrough + open Q&A buffer)
**Presenters:** Vijay Aditya N G, Venkatesh S, Yashas Gowda R S, Nemath Miyan

---

## 0. Pre-Demo Setup (do this BEFORE the panel walks in)

**Goal:** Guarantee a deterministic, repeatable demo state. Do not rely on live cloud/K8s scans — those introduce network, quota, and timing risk on presentation day.

1. Restore the golden Neo4j snapshot:
   ```
   neo4j-admin database load --from-path=C:\Users\91741\TrustField\backups neo4j --overwrite-destination=true
   ```
   (using `neo4j_golden.dump`)
2. Restore the golden PostgreSQL snapshot (`trustfield_golden.dump`) from the same backups folder.
3. Start backend manually (not `--reload`) and confirm health:
   ```
   curl http://localhost:8000/health
   ```
4. Log in and cache a fresh token (30 min expiry — re-login if the panel runs long):
   ```
   POST /api/v1/auth/login
   {"email": "admin@trustfield.com", "password": "Admin123!"}
   ```
5. Start frontend (`npm run dev` in `frontend/`), open in browser, confirm Dashboard loads with alert counts populated.
6. **Sanity check the centerpiece alert exists:** confirm alerts 141/142/143 are visible and the Azure chain (`trustfield-victim-azure → trustfield-chain-identity → Owner/Contributor/UAA`) renders correctly in the graph view.
7. Close any terminal windows showing scan/ingestion logs — keep the screen clean, only the UI visible when the panel arrives.
8. Have a **backup**: a screen-recorded video of the full walkthrough, in case of live-demo failure (projector issues, crash, etc.). Mention this only if something breaks — don't lead with "in case this fails."

---

## 1. Opening — What Is TrustField (~2 min)

**Say something like:**

> "Cloud environments today aren't single-cloud — most organizations run AWS, Azure, GCP, and Kubernetes side by side. Each has its own identity and access model: IAM roles, RBAC, service accounts, managed identities. The problem is that privilege escalation paths often *cross* these boundaries, and no single cloud provider's native tooling can see across all of them.
>
> TrustField is a multi-cloud IAM privilege escalation detection and automated containment platform. It models identities, roles, policies, and resources from all four platforms as a single unified graph in Neo4j, then finds dangerous trust relationships two ways: structural path analysis using Cypher-based detectors that encode known escalation techniques, and unsupervised anomaly detection using IsolationForest to catch things that don't match a known pattern.
>
> When it finds something dangerous, it doesn't just alert — it can walk an analyst through the exact path, and trigger containment."

**Anticipate:** panel may ask "why not just use AWS Access Analyzer / Azure PIM / etc." — answer: those are single-cloud. The value proposition is the **cross-cloud graph correlation**, which is what none of the native tools do.

---

## 2. UI Walkthrough (~5–6 min)

Narrate as you click — don't just click silently.

### 2a. Dashboard
- Point out alert counts, severity breakdown, provider breakdown (AWS/Azure/GCP/K8s).
- "This is the analyst's landing page — triage starts here."

### 2b. Graph View (gravity-well layout)
- Open the graph view.
- Explain the gravity-well layout choice: high-privilege / high-risk nodes gravitate toward the center, low-risk nodes toward the periphery — so an analyst's eye is drawn to what matters without reading labels first.
- Point out node types: identities, roles, policies, resources — and that edges represent trust relationships (`CAN_ASSUME`, `CAN_BIND`, etc.) collected from all four providers into one schema.

### 2c. Heatmap
- Switch to heatmap view.
- Explain this is a different lens on the same graph data — density of risky relationships, useful for spotting clusters an analyst might miss in the node-link view.

### 2d. Alert Detail
- Click into a representative alert (not yet the centerpiece — pick a simpler one, e.g. the K8s escalation-primitive alert 126: `default:trustfield-victim-sa → admin-role`).
- Show the alert detail panel: severity, MITRE technique mapping, path explanation.

### 2e. Containment Modal
- Open the containment modal from that alert.
- Explain: this is where TrustField moves from *detection* to *action* — proposed containment steps (e.g., revoke binding, disable identity), with human-in-the-loop confirmation before anything executes.
- **Do not actually execute containment during the demo** unless you've specifically prepared a safe, reversible target — narrate the flow instead.

---

## 3. Centerpiece — Live Escalation Path Walkthrough (~5–6 min)

This is the section to slow down on. It's the strongest, most concrete evidence that the system works end-to-end on real cloud data (not synthetic/toy data).

**Setup context first:**

> "Rather than describe escalation abstractly, let me show you a real chain we set up and detected against a live Azure subscription."

**Walk the graph for alerts 141 / 142 / 143:**

- Identity: `trustfield-victim-azure` (a service principal) — start here.
- Edge 1 (`CAN_ASSUME`): victim SP can assume/act through `trustfield-chain-identity`, a user-assigned managed identity.
- Edge 2 (`CAN_ASSUME`): that managed identity in turn holds — or can assign — a highly privileged role: **Owner**, **Contributor**, or **User Access Administrator (UAA)**.
- So: a low-looking identity, through one hop, reaches Owner-level control of the subscription.

**Explain the technique in MITRE terms:**

> "This maps to MITRE ATT&CK T1548.005 — Abuse Elevation Control Mechanism via Temporary Elevated Cloud Access. It's a two-hop chain, and this is exactly the kind of path that's invisible if you're only looking at one identity's *direct* permissions — you have to walk the graph to see it."

**Show the detector, not just the result:**
- Briefly show the Cypher pattern (or describe it) that finds `(:Identity)-[:CAN_ASSUME]->(:Identity)-[:CAN_ASSUME]->(:Role {privilege_level: 'high'})` style two-hop chains — this demonstrates the structural detection is explainable, not a black box.

**Anticipate questions here — be ready to answer:**
- "How did you create this test condition?" → Answer honestly: it's a deliberately provisioned test environment (`trustfield-victim-azure`, `trustfield-chain-identity`, custom role `TrustField-SelfEscalation-Test`) built to validate the detector against a known-true escalation path, not found in production data.
- "Does this generalize beyond Azure?" → Yes — the same two-hop chain detector pattern is applied across AWS `CAN_ASSUME` (role chaining via `sts:AssumeRole`), GCP service account impersonation, and K8s RoleBinding escalation (alert 126 is the K8s analog).

---

## 4. Close — The Honest Research Insight (~2–3 min)

This is your strongest differentiator: showing a *limitation* you understand deeply, rather than only showing successes, signals genuine research maturity to a review panel.

**Say something like:**

> "I want to end on something we found while building the ML side, because I think it's the most interesting result in the project — even though it's a limitation, not a success.
>
> We use IsolationForest, an unsupervised anomaly detector, to catch escalation patterns that don't match our hand-written structural rules. One of the features we engineered is `is_aws_managed` — whether a policy is an AWS-managed policy rather than a customer-authored one. The intuition is that AWS-managed policies are lower-risk by construction — they're vetted, standard, widely reused — so this feature should *reduce* the anomaly score for otherwise-suspicious identities.
>
> What we found is the opposite effect, partially. Because `is_aws_managed` is a *rare* boolean feature — most policies in our dataset are customer-managed — IsolationForest, which works by isolating points that are 'few and different,' partially reads the *rarity* of this feature as an anomaly signal in itself. So instead of cleanly suppressing false positives, it partially cancels its own intended effect. We measured this directly: anomaly scores dropped, but not enough to cross the detection threshold — from a range of roughly 0.89–0.95 down to about 0.82, when the threshold needed to clear was lower still.
>
> We made a deliberate decision not to patch this with a post-hoc override — for example, hard-coding 'if is_aws_managed, subtract a fixed amount from the score.' That would fix the demo case but wouldn't be honest about what unsupervised anomaly detection actually does on imbalanced boolean features. We documented it instead as a structural limitation, in `known_limitations_and_future_work.md`, along with what a real fix would look like — likely feature weighting, or moving this specific check into the structural rule layer instead of the ML layer, since it's really a *known* mitigating factor, not something that should be *learned*.
>
> We think this is a more honest and more interesting result than if everything had worked cleanly."

**This is your best interview/Q&A moment — let the panel ask about it. Don't rush past it.**

---

## 5. Anticipated Panel Q&A — Prep Notes

- **"What's novel here vs. existing tools?"** → Cross-cloud graph correlation in one schema; explainable structural detectors + ML in combination, not ML alone.
- **"How do you validate detection accuracy?"** → Deliberately provisioned known-true escalation paths (Azure 141/142/143, K8s 126) used as ground truth against detectors.
- **"Why Neo4j specifically?"** → Privilege escalation is fundamentally a graph reachability problem — multi-hop `CAN_ASSUME`/`CAN_BIND` chains are natural Cypher path queries, awkward in relational SQL.
- **"Why IsolationForest over supervised methods?"** → No large labeled dataset of real-world multi-cloud escalation incidents exists publicly; unsupervised fits the actual data availability constraint.
- **"What's left to do / what's the honest completion state?"** → ~95–97% of the engineering (Weeks 1–8) is complete and tested (31/31 backend, 15/15 frontend). Remaining work is academic deliverables: literature survey finalization, design diagrams, research paper writeup.
- **"Is this production-ready?"** → No — it's a capstone research prototype. Be upfront: real production deployment would need multi-tenant hardening, credential lifecycle management, and containment-action safety guarantees beyond what's built here.

---

## 6. Timing Cheat Sheet (flexible slot — adjust live)

| Section | Target time |
|---|---|
| Opening | 2 min |
| UI walkthrough | 5–6 min |
| Centerpiece (Azure chain) | 5–6 min |
| Honest limitation close | 2–3 min |
| **Core total** | **~15–17 min** |
| Buffer for panel questions during sections | flexible |
| Open Q&A at end | remainder of slot |

If time is cut short: **keep sections 1, 3, and 4 — cut section 2 to just the graph view.** The centerpiece and the honest-limitation close are what make this presentation distinct; the generic UI tour is the most compressible part.