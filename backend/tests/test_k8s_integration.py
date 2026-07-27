"""
Week 7 Day 2 AM - K8s integration test (LIVE against kind cluster).

Not mocked - reuses the kind-trustfield-test cluster and Week 6's
bind-escalation-fixture.yaml. Applies real RBAC objects, runs a real
scan, checks the real escalation-primitive detection + the via_role
resolver endpoint built in Week 6 session 3, then tears everything down.

Fixture recap (fixtures/bind-escalation-fixture.yaml):
  - ServiceAccount default/trustfield-victim-sa
  - Role default/admin-role (wildcard */*/* - the escalation TARGET)
  - Role default/bind-granter-role (bind verb on admin-role by resourceName -
    this is the DANGEROUS role; its binding is what containment must remove)
  - RoleBinding default/bind-granter-binding (victim-sa -> bind-granter-role)

Expected primitive: CAN_ESCALATE_VIA(trustfield-victim-sa -> admin-role)
  with via_role = "default:bind-granter-role", verb = "bind"
  (via_role is the GRANTING role, not the target - that's the whole point
  of the Week 6 session 3 fix, so the resolver can find the real binding
  to delete rather than something touching admin-role itself).

Node ID conventions (confirmed Week 7 Day 2 AM prep):
  - ServiceAccount / namespaced Role id = "namespace:name"
  - ClusterRole id = bare name
  - Subject id for ServiceAccount = "namespace:name"
"""
import subprocess
import pytest
from pathlib import Path
from httpx import AsyncClient, ASGITransport

from main import app
from graph.neo4j_client import Neo4jClient

K8S_CONTEXT = "kind-trustfield-test"
FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "bind-escalation-fixture.yaml"

VICTIM_SA_ID = "default:trustfield-victim-sa"
ADMIN_ROLE_ID = "default:admin-role"
BIND_GRANTER_ROLE_ID = "default:bind-granter-role"


def _kubectl(*args):
    cmd = ["kubectl", "--context", K8S_CONTEXT, *args]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result


@pytest.fixture
def apply_bind_escalation_fixture():
    assert FIXTURE_PATH.exists(), f"Fixture not found at {FIXTURE_PATH}"
    apply_result = _kubectl("apply", "-f", str(FIXTURE_PATH))
    assert apply_result.returncode == 0, (
        f"kubectl apply failed: {apply_result.stderr}"
    )
    yield
    # Teardown: always attempt delete, even if the test failed mid-way
    delete_result = _kubectl("delete", "-f", str(FIXTURE_PATH), "--ignore-not-found=true")
    if delete_result.returncode != 0:
        print(f"WARNING: kubectl delete cleanup failed: {delete_result.stderr}")


@pytest.mark.asyncio
async def test_k8s_bind_escalation_primitive_detected_and_resolved(
    auth_headers, apply_bind_escalation_fixture
):
    """
    Full pipeline against a REAL kind cluster:
    kubectl apply -> real K8sCollector -> TrustGraphBuilder (Pass 5
    escalation primitives) -> Neo4j -> POST /scan/ -> GET
    /graph/escalation-paths -> GET /containment/resolve/k8s-binding.
    """
    transport = ASGITransport(app=app)
    job_id = None
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/scan/",
            json={"providers": ["k8s"]},
            headers=auth_headers,
        )
        assert resp.status_code == 202, resp.text
        job_id = resp.json()["job_id"]

        status_resp = await client.get(
            f"/api/v1/scan/{job_id}", headers=auth_headers
        )
        assert status_resp.status_code == 200
        assert status_resp.json()["status"] == "completed", status_resp.text

        paths_resp = await client.get(
            "/api/v1/graph/escalation-paths",
            params={"cloud_provider": "k8s"},
            headers=auth_headers,
        )
        assert paths_resp.status_code == 200, paths_resp.text
        paths = paths_resp.json()

        # Find the bind-escalation primitive finding for our fixture identities
        match = None
        for p in paths:
            path_str = str(p)
            if "trustfield-victim-sa" in path_str and "admin-role" in path_str:
                match = p
                break
        assert match is not None, (
            f"Expected a bind-escalation primitive for trustfield-victim-sa "
            f"-> admin-role, not found in: {paths}"
        )

        metadata = match.get("metadata", {})
        assert metadata.get("verb") == "bind", (
            f"Expected verb='bind' in metadata, got: {metadata}"
        )
        via_role = metadata.get("via_role")
        assert via_role is not None and "bind-granter-role" in via_role, (
            f"Expected via_role to reference bind-granter-role (the GRANTING "
            f"role, not admin-role which is just the target), got: {via_role}"
        )

        # Now exercise the resolver: given identity + via_role, it should
        # find the real BOUND_TO edge and return the correct target_resource
        # for containment (the binding to bind-granter-role, NOT admin-role).
        resolve_resp = await client.get(
            "/api/v1/containment/resolve/k8s-binding",
            params={"identity_id": VICTIM_SA_ID, "via_role": via_role},
            headers=auth_headers,
        )
        assert resolve_resp.status_code == 200, resolve_resp.text
        resolved = resolve_resp.json()
        target_resource = resolved.get("target_resource")
        assert target_resource == "k8s:rolebinding:default:bind-granter-binding", (
            f"Expected resolver to return the bind-granter-binding "
            f"(the dangerous RoleBinding), got: {target_resource}"
        )

    # Cleanup: own self-contained Neo4jClient instance (never chain async
    # fixtures for Neo4j - Day 1 lesson)
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await neo4j.run_query(
            "MATCH (n) WHERE n.id IN $ids DETACH DELETE n",
            {"ids": [VICTIM_SA_ID, ADMIN_ROLE_ID, BIND_GRANTER_ROLE_ID]},
        )
    finally:
        await neo4j.close()

    # Cleanup: ScanJob row (background task opens its own SessionLocal,
    # bypasses any FastAPI dependency override)
    from db.database import SessionLocal
    from db import models
    db = SessionLocal()
    try:
        job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if job:
            db.delete(job)
            db.commit()
    finally:
        db.close()