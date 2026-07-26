"""
AWS integration test - reconstructs the Week 3 live escalation scenario
(trustfield-victim -> trustfield-admin-role) inside moto's fake AWS instead
of hitting the real account (403959680247), then drives it through the
real API: POST /scan/ -> background _run_scan() -> AWSCollector ->
TrustGraphBuilder -> Neo4j -> GET /graph/escalation-paths.

Cleanup is scoped by moto's fixed sandbox account id (123456789012), which
never collides with real AWS/Azure/GCP/K8s data sitting in the same local
Neo4j instance - see conftest.py's wipe_nodes_matching().
"""

import json

import boto3
import pytest
import pytest_asyncio

from db.database import SessionLocal
from db.models import ScanJob

MOTO_ACCOUNT_ID = "123456789012"
VICTIM_USER = "trustfield-victim-test"
ADMIN_ROLE = "trustfield-admin-role-test"


def _seed_moto_scenario() -> tuple[str, str]:
    """
    Builds the same victim -> admin-role trust escalation as the real
    Week 3 AWS scenario, but inside moto's in-memory fake AWS.
    Returns the real ARNs moto assigns (needed to assert against later,
    since moto's ARN format must match exactly for the graph lookup).
    """
    iam = boto3.client("iam", region_name="us-east-1")

    victim = iam.create_user(UserName=VICTIM_USER)["User"]
    victim_arn = victim["Arn"]

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": victim_arn},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=ADMIN_ROLE,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
    )["Role"]
    role_arn = role["Arn"]

    iam.attach_role_policy(
        RoleName=ADMIN_ROLE,
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
    )

    return victim_arn, role_arn


@pytest_asyncio.fixture(autouse=True)
async def clean_moto_aws_graph_data():
    """
    Wipes only moto-sandbox-account nodes, before and after each test.

    Deliberately self-contained: does NOT depend on conftest.py's shared
    neo4j_client fixture. Chaining async fixtures (this fixture requesting
    neo4j_client as an argument) reliably triggered
    "Future attached to a different loop" under pytest-asyncio 0.23.6 on
    Windows, regardless of decorator consistency or the anyio plugin (both
    ruled out). Giving this fixture its own driver instance, connected and
    closed entirely within its own setup/teardown, sidesteps the issue.
    """
    from graph.neo4j_client import Neo4jClient
    from conftest import wipe_nodes_matching

    client = Neo4jClient()
    await client.connect()
    await wipe_nodes_matching(client, MOTO_ACCOUNT_ID)
    yield
    await wipe_nodes_matching(client, MOTO_ACCOUNT_ID)
    await client.close()


async def test_aws_privilege_escalation_detected(api_client, auth_headers, moto_aws):
    """
    End-to-end: seed a vulnerable scenario in moto, trigger a real scan via
    the API, and confirm the escalation path is actually found - the same
    assertion your manual curl checks made live in Week 3, now automated.
    """
    victim_arn, role_arn = _seed_moto_scenario()

    scan_resp = await api_client.post(
        "/api/v1/scan/",
        json={"providers": ["aws"]},
        headers=auth_headers,
    )
    assert scan_resp.status_code == 202, scan_resp.text
    job_id = scan_resp.json()["job_id"]

    try:
        # Starlette runs BackgroundTasks as part of the same ASGI call before
        # the response is returned to the client, so under httpx's
        # ASGITransport this should already be COMPLETED by the time we get here.
        job_resp = await api_client.get(f"/api/v1/scan/{job_id}", headers=auth_headers)
        assert job_resp.status_code == 200, job_resp.text
        job_body = job_resp.json()
        # ADJUST if this fails: confirm the exact ScanStatus string your
        # schema serializes (e.g. "completed" vs "COMPLETED").
        assert job_body["status"].lower() == "completed", job_body

        paths_resp = await api_client.get(
            "/api/v1/graph/escalation-paths",
            params={"cloud_provider": "aws", "limit": 100},
            headers=auth_headers,
        )
        assert paths_resp.status_code == 200, paths_resp.text
        paths = paths_resp.json()

        match = next(
            (
                p
                for p in paths
                if p["source_node_id"] == victim_arn and p["target_node_id"] == role_arn
            ),
            None,
        )
        assert match is not None, (
            f"Expected escalation path {victim_arn} -> {role_arn} "
            f"not found. Got: {paths}"
        )
        assert match["risk_score"] > 0.5, match

    finally:
        # _run_scan() opens its OWN SessionLocal() (bypassing any FastAPI
        # dependency override), so this ScanJob row landed in your real
        # local Postgres and has to be cleaned up directly, not through
        # the test client.
        db = SessionLocal()
        try:
            db.query(ScanJob).filter(ScanJob.id == job_id).delete()
            db.commit()
        finally:
            db.close()