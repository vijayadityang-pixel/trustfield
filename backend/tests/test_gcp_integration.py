"""
Week 7 Day 2 AM - GCP integration test (mocked).

Mocks collectors.gcp_collector.discovery.build (function call, dispatched by
serviceName/version) and collectors.gcp_collector.google.auth.default.
Patches settings.GCP_PROJECT_ID to a fake truthy value so
_resolve_project() short-circuits before any real network call
(same falsy-settings-fallback gotcha as Azure).

Scenario reconstructed: a member (user or SA) is granted
roles/iam.serviceAccountTokenCreator on a TARGET SA's own IAM policy
(via serviceAccounts().getIamPolicy(resource=target_sa)). This is the
real GCP impersonation trust mechanism - project-level bindings only
produce HAS_ROLE, never CAN_ASSUME. _build_trust_relationships() should
synthesize CAN_ASSUME(member -> target_sa).
"""
import pytest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport

from main import app
from config import settings
from graph.neo4j_client import Neo4jClient

FAKE_PROJECT_ID = "trustfield-gcp-test-fake"

MEMBER_EMAIL = "attacker-user@trustfield-gcp-test-fake.iam.gserviceaccount.com"
TARGET_SA_EMAIL = "target-privileged-sa@trustfield-gcp-test-fake.iam.gserviceaccount.com"
TARGET_SA_NAME = f"projects/{FAKE_PROJECT_ID}/serviceAccounts/{TARGET_SA_EMAIL}"
ATTACKER_SA_NAME = f"projects/{FAKE_PROJECT_ID}/serviceAccounts/{MEMBER_EMAIL}"


def _make_execute(return_value):
    """Helper: build a MagicMock whose .execute() returns return_value."""
    m = MagicMock()
    m.execute.return_value = return_value
    return m


def _build_iam_service_mock():
    """
    Mocks the 'iam'/'v1' service used by _get_iam_service():
      - service.projects().serviceAccounts().list(name=...).execute()
      - service.projects().serviceAccounts().keys().list(name=...).execute()
      - service.projects().serviceAccounts().getIamPolicy(resource=...).execute()
      - service.projects().roles().list(parent=...).execute()
    """
    iam_service = MagicMock()

    sa_list_response = {
        "accounts": [
            {
                "name": ATTACKER_SA_NAME,
                "email": MEMBER_EMAIL,
                "uniqueId": "100000000000000000001",
                "displayName": "attacker-user",
                "disabled": False,
            },
            {
                "name": TARGET_SA_NAME,
                "email": TARGET_SA_EMAIL,
                "uniqueId": "100000000000000000002",
                "displayName": "target-privileged-sa",
                "disabled": False,
            },
        ]
    }

    def get_iam_policy_side_effect(resource, **kwargs):
        if resource == TARGET_SA_NAME:
            policy = {
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": [f"serviceAccount:{MEMBER_EMAIL}"],
                    }
                ]
            }
        else:
            policy = {"bindings": []}
        return _make_execute(policy)

    sa_mock = MagicMock()
    sa_mock.list.return_value = _make_execute(sa_list_response)
    sa_mock.keys.return_value.list.return_value = _make_execute({"keys": []})
    sa_mock.getIamPolicy.side_effect = get_iam_policy_side_effect

    roles_mock = MagicMock()
    roles_mock.list.return_value = _make_execute({"roles": []})

    iam_service.projects.return_value.serviceAccounts.return_value = sa_mock
    iam_service.projects.return_value.roles.return_value = roles_mock

    return iam_service


def _build_crm_service_mock():
    """
    Mocks the 'cloudresourcemanager'/'v3' service used by _collect_iam_policy():
      - service.projects().getIamPolicy(resource=..., body={}).execute()

    NOT empty: the target SA needs a real project-level role binding
    (roles/owner) so graph_builder's principal_max_privilege-from-HAS_ROLE
    pattern sets its privilege_level to 5. Without this the target node
    stays at default privilege and the privilege_escalation detector's
    risk score never crosses min_risk=0.5, even though the CAN_ASSUME
    impersonation edge exists (same gap class as the Azure session's
    HAS_ROLE fix).
    """
    crm_service = MagicMock()
    project_policy = {
        "bindings": [
            {
                "role": "roles/owner",
                "members": [f"serviceAccount:{TARGET_SA_EMAIL}"],
            }
        ]
    }
    crm_service.projects.return_value.getIamPolicy.return_value = _make_execute(
        project_policy
    )
    return crm_service


def _discovery_build_side_effect(serviceName, version, **kwargs):
    if serviceName == "iam":
        return _build_iam_service_mock()
    elif serviceName == "cloudresourcemanager":
        return _build_crm_service_mock()
    raise ValueError(f"Unexpected discovery.build call: {serviceName}/{version}")


@pytest.mark.asyncio
async def test_gcp_scan_detects_sa_impersonation_escalation(auth_headers):
    """
    Full pipeline: mocked GCP collector -> TrustGraphBuilder -> Neo4j
    -> real POST /scan/ -> GET /graph/escalation-paths.
    Asserts CAN_ASSUME(attacker-user -> target-privileged-sa) is created
    and a privilege_escalation finding surfaces on it.
    """
    with patch.object(settings, "GCP_PROJECT_ID", FAKE_PROJECT_ID), \
         patch("collectors.gcp_collector.discovery.build",
               side_effect=_discovery_build_side_effect), \
         patch("collectors.gcp_collector.google.auth.default",
               return_value=(MagicMock(), FAKE_PROJECT_ID)):

        transport = ASGITransport(app=app)
        job_id = None
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/scan/",
                json={"providers": ["gcp"]},
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
                params={"cloud_provider": "gcp"},
                headers=auth_headers,
            )
            assert paths_resp.status_code == 200, paths_resp.text
            paths = paths_resp.json()

            found = False
            for p in paths:
                path_str = str(p)
                if MEMBER_EMAIL in path_str and TARGET_SA_EMAIL in path_str:
                    found = True
                    break
            assert found, (
                f"Expected escalation path {MEMBER_EMAIL} -> {TARGET_SA_EMAIL} "
                f"not found in: {paths}"
            )

        # cleanup: own self-contained Neo4jClient instance (per Day 1 lesson -
        # never chain async fixtures for Neo4j)
        neo4j = Neo4jClient()
        try:
            await neo4j.connect()
            await neo4j.run_query(
                "MATCH (n:Identity) WHERE n.cloud_provider = 'gcp' "
                "AND n.id CONTAINS $marker DETACH DELETE n",
                {"marker": "trustfield-gcp-test-fake"},
            )
        finally:
            await neo4j.close()

        # cleanup: ScanJob row (background task opens its own SessionLocal,
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