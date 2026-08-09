"""
TrustField - Shared Neo4j Client Singleton
Single Neo4jClient instance shared across the whole app. Import this
instead of constructing `Neo4jClient()` directly in route modules —
five independent instances with no shared lifecycle was the root cause
behind the upsert_node duplicate-node bug's blast radius, the "Unable
to retrieve routing information after restart" bug, and async-fixture
test-isolation crashes (see PUNCHLIST.md).

main.py's lifespan() owns connect()/close() for this instance. Route
modules only ever read from it.
"""

from graph.neo4j_client import Neo4jClient

neo4j_client = Neo4jClient()