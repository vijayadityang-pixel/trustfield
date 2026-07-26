"""
TrustField backend test harness.

Shared fixtures for Week 7 integration tests:
- api_client: async HTTP client wrapping the real FastAPI app (in-process, no server needed)
- auth_headers: real JWT from the seed admin login, ready to drop into request headers
- neo4j_client / cleanup: talks to your existing local Neo4j instance, tags and
  wipes only test-created nodes before/after each test (does not touch real data)
- moto_aws: wraps a test in a fully mocked in-memory AWS (iam/sts/ec2) via moto
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from main import app
from graph.neo4j_client import Neo4jClient

SEED_ADMIN_EMAIL = "admin@trustfield.com"
SEED_ADMIN_PASSWORD = "Admin123!"


@pytest_asyncio.fixture
async def api_client():
    """Async client hitting the real FastAPI app in-process (no uvicorn needed)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def auth_headers(api_client):
    """Logs in as the seed admin and returns a ready-to-use Authorization header."""
    resp = await api_client.post(
        "/api/v1/auth/login",
        json={"email": SEED_ADMIN_EMAIL, "password": SEED_ADMIN_PASSWORD},
    )
    assert resp.status_code == 200, f"Seed admin login failed: {resp.status_code} {resp.text}"
    body = resp.json()
    # ADJUST if wrong: confirm the JWT field name in your LoginResponse schema
    token = body.get("access_token") or body.get("token")
    assert token, f"Could not find JWT in login response: {body}"
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(autouse=True)
async def reset_production_neo4j_singleton():
    """
    Five separate modules each construct their own module-level
    `neo4j_client = Neo4jClient()` at import time (routes_scan, routes_graph,
    routes_ml, routes_containment, main) - found via
    `findstr /m /s /c:"Neo4jClient()" backend\\*.py`. Each one's async driver
    lazily connects on first real query and binds its sockets to whichever
    event loop is active at that moment.

    Since pytest-asyncio (asyncio_mode=auto) gives each test function its own
    fresh event loop, whichever of these singletons gets used first in a test
    connects fine - but is never disconnected afterward (they're production
    objects, not test fixtures). Any LATER test that touches the same
    singleton reuses a driver whose sockets are bound to an already-closed
    loop, crashing with "'NoneType' object has no attribute 'send'".

    Found via running AWS+Azure tests together: first hit this in
    routes_scan's singleton (the scan itself), fixed that, then hit the
    identical bug in whatever singleton detection/path_finder.py uses for
    GET /graph/escalation-paths. Resetting all 5 known singletons up front
    avoids finding the rest of them one crash at a time.
    """
    singleton_locations = [
        ("api.routes_scan", "neo4j_client"),
        ("api.routes_graph", "neo4j_client"),
        ("api.routes_ml", "neo4j_client"),
        ("api.routes_containment", "neo4j_client"),
        ("main", "neo4j_client"),
    ]

    for module_path, attr_name in singleton_locations:
        try:
            import importlib

            module = importlib.import_module(module_path)
            prod_client = getattr(module, attr_name, None)
        except ImportError:
            prod_client = None

        if prod_client is not None and getattr(prod_client, "_driver", None) is not None:
            try:
                await prod_client.close()
            except Exception:
                pass
            prod_client._driver = None

    yield


@pytest_asyncio.fixture
async def neo4j_client():
    """
    Function-scoped connection to your existing local Neo4j instance.
    MUST be function-scoped, not session-scoped: pytest-asyncio's default
    event_loop fixture is function-scoped (a fresh loop per test), and the
    Neo4j async driver's socket gets bound to whichever loop was active
    during connect(). A session-scoped client would try to reuse that
    socket from a later test's different event loop and fail with
    "Future attached to a different loop".
    Constructor defaults to settings.NEO4J_URI/USERNAME/PASSWORD when no
    args are passed (same pattern main.py's neo4j_client = Neo4jClient() uses).
    """
    client = Neo4jClient()
    await client.connect()
    yield client
    await client.close()


async def wipe_nodes_matching(client: Neo4jClient, id_substring: str):
    """
    Deletes nodes whose id contains the given substring.
    NOT autouse - the real scan pipeline never tags nodes with a generic
    test marker, so cleanup has to be scoped per test-file to something
    that actually appears in the data it creates (e.g. moto's fixed AWS
    sandbox account id, which is guaranteed different from your real
    test accounts 403959680247 / 203413544400).
    """
    await client.run_query(
        "MATCH (n) WHERE n.id CONTAINS $substring DETACH DELETE n",
        {"substring": id_substring},
    )


@pytest.fixture
def moto_aws():
    """
    Wraps a test in a fully mocked in-memory AWS.
    boto3 calls inside the test hit moto's fake AWS instead of account 403959680247 -
    no real API calls, no cleanup, no rate limits.

    MOTO_IAM_LOAD_MANAGED_POLICIES must be set before mock_aws() starts:
    moto 5.x doesn't pre-load real AWS managed policies (AdministratorAccess,
    ReadOnlyAccess, etc.) by default, since loading the full ~750-policy
    catalog is slow - attach_role_policy on a real managed-policy ARN fails
    with NoSuchEntityException without this.
    """
    import os
    from moto import mock_aws

    os.environ.setdefault("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    with mock_aws():
        yield