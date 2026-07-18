# TrustField Setup Guide

This guide covers getting the full stack running locally on Windows: Neo4j, the FastAPI backend, and the React frontend.

## Prerequisites

- Python 3.10+
- Node.js 18 or 20 LTS
- Neo4j 5.x (Desktop app or Docker)
- A shared virtual environment per the team convention (excluded from git via `.gitignore`)

## 1. Neo4j

1. Install Neo4j Desktop, or run it via Docker:
   ```
   docker run -d --name trustfield-neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/trustfield123 neo4j:5
   ```
2. Confirm the browser console loads at `http://localhost:7474` and you can log in with the credentials above.
3. Note the bolt URI (`bolt://localhost:7687`) — the backend's `config.py` reads this from environment variables.

## 2. Backend

1. Activate the shared venv:
   ```
   .venv\Scripts\activate
   ```
2. Install PyTorch first, then PyTorch Geometric from its dedicated wheel index, then the rest of `requirements.txt` with the PyG lines commented out — installing in any other order causes wheel resolution failures on Windows:
   ```
   pip install torch==2.3.0
   pip install torch-geometric -f https://data.pyg.org/whl/torch-2.3.0+cpu.html
   pip install -r requirements.txt
   ```
3. Set environment variables (a `.env` file at the project root, loaded by `config.py`):
   ```
   NEO4J_URI=bolt://localhost:7687
   NEO4J_USER=neo4j
   NEO4J_PASSWORD=trustfield123
   AWS_PROFILE=trustfield-readonly
   AZURE_TENANT_ID=...
   GCP_PROJECT_ID=...
   KUBE_CONFIG_PATH=~/.kube/config
   ```
4. Run the API:
   ```
   uvicorn main:app --reload --port 8000
   ```
5. Confirm `http://localhost:8000/docs` loads the FastAPI Swagger UI.

## 3. Frontend

1. From `frontend/`:
   ```
   npm install
   ```
2. Create `frontend/.env`:
   ```
   VITE_API_BASE_URL=http://localhost:8000/api
   ```
3. Run the dev server:
   ```
   npm run dev
   ```
4. Open `http://localhost:5173`. The dashboard will show empty/placeholder state until the backend has run at least one scan.

## 4. Seeding sample data

Before connecting real cloud credentials, you can exercise the full pipeline with the fixtures in `data/`:

- `sample_iam_policies.json` — multi-cloud IAM policies, including several with intentional misconfigurations (missing `ExternalId`, wildcard trust principals, over-broad PassRole grants) for exercising the detection engine.
- `synthetic_cloudtrail.json` — synthetic access log events labeled `benign` or `anomalous`, useful for validating both the rule engine and the Isolation Forest model without needing live CloudTrail access.
- `escalation_patterns.json` — the rule definitions the pattern-matching detector evaluates against; each entry maps to a MITRE ATT&CK technique and a recommended containment action.

A loader script (to be added under `scripts/` or invoked from `main.py` in dev mode) can ingest these directly into Neo4j to populate a working graph for frontend development without any cloud credentials configured.

## 5. Common Windows issues

- **npm/Node not found from a Python subprocess**: subprocess calls into npm or node need `shell=True` on Windows or PATH resolution fails silently.
- **protobuf version conflicts**: `google-cloud-logging` and `google-api-core` can pin incompatible protobuf versions; pin a mutually compatible version explicitly in `requirements.txt` if you hit a `TypeError` on import.
- **GCP IAM import errors**: `google-cloud-iam` v2.23.0+ exposes `google.cloud.iam_v2`, not `iam_v1` — double check this if a collector import fails after a fresh install.

## 6. Verifying the full loop

1. Trigger a scan from the frontend Settings page, or directly via `POST /api/scan/run`.
2. Watch the Dashboard's trust graph populate as the scan completes.
3. Confirm at least one seeded misconfiguration (e.g. the `vendor-billing-integration` role) surfaces as a critical alert on the Alerts page.
4. Open the alert's path detail and trigger the recommended containment action against the sample data to confirm the end-to-end flow works before pointing it at real cloud accounts.
