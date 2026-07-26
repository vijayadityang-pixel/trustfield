"""
Azure integration test - no moto-equivalent exists for Azure, so this mocks
the SDK client classes directly (GraphServiceClient, AuthorizationManagementClient)
at the point AzureCollector imports them, feeding in fake response objects
shaped like the real SDK's (attribute access, not dicts - matches how
azure_collector.py actually reads them, e.g. u.display_name not u["displayName"]).

Reconstructs the Week 4 trustfield-victim-azure scenario: a service principal
holding a custom role that grants Microsoft.Authorization/roleAssignments/write
(the dangerous self-escalation action). AzureCollector's own
_build_trust_relationships() should synthesize this into a CAN_ASSUME edge
toward a high-privilege built-in role (Owner), the same mechanism live-verified
against the real trustfield-victim-azure account in Week 4.

Uses real settings.AZURE_* values for constructing the collector (since
_run_scan() in routes_scan.py wires those in from config, not test-overridable)
but since the SDK client CLASSES are mocked entirely, no real network calls or
real Azure credentials are ever exercised.
"""

import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from config import settings
from db.database import SessionLocal
from db.models import ScanJob

# Embedded in every synthetic node id so cleanup can find exactly (and only)
# what this test created, regardless of which real Azure subscription/tenant
# is configured in settings.
AZURE_TEST_MARKER = "trustfield-azure-test"


def _ns(**kwargs):
    """Builds a fake SDK response object with attribute access (u.display_name),
    matching how azure_collector.py reads real msgraph/azure-mgmt objects -
    NOT dict access, which is why plain dicts won't work as mocks here."""
    return types.SimpleNamespace(**kwargs)


def _build_azure_scenario():
    """
    Builds fake Graph/ARM SDK objects for a service principal that can grant
    itself any role (Microsoft.Authorization/roleAssignments/write), plus a
    built-in high-privilege Owner role it should get a synthetic CAN_ASSUME
    edge to. Returns (sp_id, owner_role_id, mock objects needed for patching).
    """
    sp_id = f"{AZURE_TEST_MARKER}-sp-victim"
    owner_role_id = f"{AZURE_TEST_MARKER}-role-owner"
    writer_role_id = f"{AZURE_TEST_MARKER}-role-writer"
    scope = "/subscriptions/11111111-1111-1111-1111-111111111111"

    sp = _ns(
        id=sp_id,
        display_name=f"{AZURE_TEST_MARKER}-victim-sp",
        app_id=f"{AZURE_TEST_MARKER}-app-id",
        service_principal_type="Application",
        account_enabled=True,
    )

    owner_role_def = _ns(
        id=owner_role_id,
        role_name="Owner",
        description="Full access to all resources",
        role_type="BuiltInRole",
        permissions=[_ns(actions=["*"], not_actions=[], data_actions=[])],
    )

    writer_role_def = _ns(
        id=writer_role_id,
        role_name=f"{AZURE_TEST_MARKER}-role-assignment-writer",
        description="Custom role granting self-escalation",
        role_type="CustomRole",
        permissions=[
            _ns(
                actions=["Microsoft.Authorization/roleAssignments/write"],
                not_actions=[],
                data_actions=[],
            )
        ],
    )

    role_assignment = _ns(
        id=f"{scope}/providers/Microsoft.Authorization/roleAssignments/{AZURE_TEST_MARKER}-assignment",
        name=f"{AZURE_TEST_MARKER}-assignment",
        principal_id=sp_id,
        principal_type="ServicePrincipal",
        role_definition_id=writer_role_id,
        scope=scope,
    )

    return sp_id, owner_role_id, sp, [owner_role_def, writer_role_def], [role_assignment]


@pytest_asyncio.fixture(autouse=True)
async def clean_azure_test_graph_data():
    """Self-contained Neo4j client, scoped by AZURE_TEST_MARKER - see Day 1 AM
    notes: never chain this as a dependency of another async fixture, it
    reliably breaks under pytest-asyncio 0.23.6 on Windows."""
    from graph.neo4j_client import Neo4jClient
    from conftest import wipe_nodes_matching

    client = Neo4jClient()
    await client.connect()
    await wipe_nodes_matching(client, AZURE_TEST_MARKER)
    yield
    await wipe_nodes_matching(client, AZURE_TEST_MARKER)
    await client.close()


async def test_azure_self_escalation_detected(api_client, auth_headers):
    """
    End-to-end: mock the Azure SDK to return a service-principal-can-grant-
    itself-any-role scenario, trigger a real scan, and confirm the synthetic
    CAN_ASSUME edge (sp -> Owner role) is found via the real escalation-paths API.
    """
    sp_id, owner_role_id, sp, role_defs, role_assignments = _build_azure_scenario()

    with patch("collectors.azure_collector.GraphServiceClient") as MockGraphCls, \
         patch("collectors.azure_collector.AuthorizationManagementClient") as MockAuthCls, \
         patch.object(settings, "AZURE_SUBSCRIPTION_ID", f"{AZURE_TEST_MARKER}-subscription"):

        mock_graph = MockGraphCls.return_value
        mock_graph.users.get = AsyncMock(return_value=_ns(value=[]))
        mock_graph.service_principals.get = AsyncMock(return_value=_ns(value=[sp]))

        mock_auth = MockAuthCls.return_value
        mock_auth.role_assignments.list_for_subscription = MagicMock(return_value=role_assignments)
        mock_auth.role_definitions.list = MagicMock(return_value=role_defs)

        scan_resp = await api_client.post(
            "/api/v1/scan/",
            json={"providers": ["azure"]},
            headers=auth_headers,
        )
        assert scan_resp.status_code == 202, scan_resp.text
        job_id = scan_resp.json()["job_id"]

    try:
        job_resp = await api_client.get(f"/api/v1/scan/{job_id}", headers=auth_headers)
        assert job_resp.status_code == 200, job_resp.text
        job_body = job_resp.json()
        # ADJUST if this fails: confirm exact ScanStatus string serialization
        assert job_body["status"].lower() == "completed", job_body

        paths_resp = await api_client.get(
            "/api/v1/graph/escalation-paths",
            params={"cloud_provider": "azure", "limit": 100},
            headers=auth_headers,
        )
        assert paths_resp.status_code == 200, paths_resp.text
        paths = paths_resp.json()

        match = next(
            (
                p
                for p in paths
                if p["source_node_id"] == sp_id and p["target_node_id"] == owner_role_id
            ),
            None,
        )
        assert match is not None, (
            f"Expected escalation path {sp_id} -> {owner_role_id} "
            f"not found. Got: {paths}"
        )

    finally:
        # _run_scan() opens its own SessionLocal(), same as the AWS test -
        # this ScanJob row landed in the real local Postgres.
        db = SessionLocal()
        try:
            db.query(ScanJob).filter(ScanJob.id == job_id).delete()
            db.commit()
        finally:
            db.close()