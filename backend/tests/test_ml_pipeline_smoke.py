"""
Week 7 Day 3 AM - ML pipeline smoke test.

Exercises the real end-to-end path: seed Neo4j -> POST /api/v1/ml/train ->
GET /api/v1/ml/anomalies -> GET /api/v1/ml/anomalies/{node_id:path}, through
the actual FastAPI app (not calling FeatureExtractor/IsolationForestDetector
directly) - matches the Day 1-7 "live-first verification" pattern.

CAVEAT: routes_ml.py's `detector` is a module-level IsolationForestDetector
singleton. Calling POST /ml/train here trains on this test's 10 synthetic
seeded nodes and persists that model to backend/ml/models/isolation_forest.pkl
via _save_model(), overwriting whatever model was there before. Fine for a
smoke test; means the model should be retrained on real scanned data before
any live demo. Same class of gap as clear_provider_data wiping demo data on
every scan - add both to the Week 8 demo-prep checklist.

Follows the Day 1 lesson: each test owns its own self-contained
Neo4jClient() instance rather than chaining async fixtures.
"""
import pytest
from httpx import AsyncClient, ASGITransport

from main import app
from graph.neo4j_client import Neo4jClient
from ml.feature_extractor import FeatureExtractor


async def _seed(neo4j, cypher, params=None):
    await neo4j.run_query(cypher, parameters=params or {})


async def _cleanup(neo4j, provider_tag):
    await neo4j.run_query(
        "MATCH (n) WHERE n.provider = $provider DETACH DELETE n",
        parameters={"provider": provider_tag},
    )


def _seed_nine_normal_plus_one_outlier(tag: str):
    """
    9 unremarkable low-privilege AWS users with modest connectivity, plus 1
    deliberately extreme node: privilege_level=5, wildcard policy,
    cross-account exposure, and far higher edge count than the rest. This
    mirrors the Week 5 live validation finding ("unsupervised model
    independently surfaced planted vulnerable test identities as top
    anomalies") - the smoke test's job is to confirm that still holds
    through the real API, not just in the standalone Week 5 script run.

    The outlier's id deliberately contains slashes (ARN-shaped) to also
    exercise the {node_id:path} route converter.
    """
    outlier_id = f"arn:aws:iam::403959680247:role/nested/path/anomalous-role"
    normal_ids = [f"{tag}:normal-user-{i}" for i in range(9)]

    create_lines = []
    params = {"tag": tag, "outlier_id": outlier_id}

    for i, nid in enumerate(normal_ids):
        key = f"n{i}"
        params[key] = nid
        create_lines.append(
            f"CREATE (:Identity {{id: ${key}, provider: $tag, "
            f"node_type: 'aws_user', privilege_level: 1, is_active: true, "
            f"has_wildcard_policy: false}})"
        )

    create_lines.append(
        "CREATE (:Identity {id: $outlier_id, provider: $tag, "
        "node_type: 'aws_role', privilege_level: 5, is_active: true, "
        "has_wildcard_policy: true})"
    )

    # Edges are created separately by _seed_edges() below (via MATCH,
    # after nodes exist) so the degree/betweenness signal on the outlier
    # is real graph topology, not just its own node attributes.
    cypher_nodes = "\n".join(create_lines)
    return cypher_nodes, params, normal_ids, outlier_id


async def _seed_edges(neo4j, tag: str, normal_ids, outlier_id):
    # sparse baseline edges among normal nodes
    for i in range(len(normal_ids) - 1):
        await neo4j.run_query(
            "MATCH (a:Identity {id: $src}), (b:Identity {id: $tgt}) "
            "CREATE (a)-[:HAS_ROLE]->(b)",
            parameters={"src": normal_ids[i], "tgt": normal_ids[i + 1]},
        )
    # dense, cross-account edges into the outlier from every normal node
    for nid in normal_ids:
        await neo4j.run_query(
            "MATCH (a:Identity {id: $src}), (b:Identity {id: $tgt}) "
            "CREATE (a)-[:CAN_ASSUME {is_cross_account: true}]->(b)",
            parameters={"src": nid, "tgt": outlier_id},
        )


@pytest.mark.asyncio
async def test_train_rejects_fewer_than_ten_nodes(auth_headers):
    tag = "test-mlsmoke-toofew"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        for i in range(5):
            await _seed(
                neo4j,
                "CREATE (:Identity {id: $id, provider: $tag, "
                "node_type: 'aws_user', privilege_level: 1})",
                {"id": f"{tag}:user-{i}", "tag": tag},
            )

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/api/v1/ml/train",
                params={"cloud_provider": tag},
                headers=auth_headers,
            )
            assert resp.status_code == 400, resp.text
            assert "at least 10 nodes" in resp.text
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_train_then_detect_surfaces_planted_outlier(auth_headers):
    """
    Full pipeline in one test, deliberately sequenced train-then-detect so
    the module-level detector singleton's model is guaranteed current for
    this test's data (it's a shared singleton across the whole test
    session, not reset between tests the way the five Neo4j singletons are).
    """
    tag = "test-mlsmoke-outlier"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        cypher_nodes, params, normal_ids, outlier_id = _seed_nine_normal_plus_one_outlier(tag)
        await _seed(neo4j, cypher_nodes, params)
        await _seed_edges(neo4j, tag, normal_ids, outlier_id)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            train_resp = await client.post(
                "/api/v1/ml/train",
                params={"cloud_provider": tag},
                headers=auth_headers,
            )
            assert train_resp.status_code == 200, train_resp.text
            train_summary = train_resp.json()
            assert train_summary["n_samples"] == 10
            assert train_summary["n_features"] == FeatureExtractor().feature_dim
            assert train_summary["n_anomalies_training"] >= 1

            anomalies_resp = await client.get(
                "/api/v1/ml/anomalies",
                params={"cloud_provider": tag},
                headers=auth_headers,
            )
            assert anomalies_resp.status_code == 200, anomalies_resp.text
            anomalies = anomalies_resp.json()
            assert anomalies["total"] == 10

            results_by_id = {r["node_id"]: r for r in anomalies["results"]}
            assert outlier_id in results_by_id
            outlier_result = results_by_id[outlier_id]
            normal_scores = [
                r["anomaly_score"] for nid, r in results_by_id.items() if nid != outlier_id
            ]

            assert outlier_result["is_anomaly"] is True
            assert outlier_result["anomaly_score"] > max(normal_scores), (
                "Planted outlier (privilege_level=5, wildcard policy, "
                "cross-account exposure, high degree) should score strictly "
                "higher than every normal node - if this fails, either the "
                "planted signal isn't extreme enough or something regressed "
                "in feature extraction / scoring since the Week 5 live "
                "validation."
            )

            # Single-node detail endpoint, also exercises the {node_id:path}
            # converter against a real ARN-shaped id with slashes.
            detail_resp = await client.get(
                f"/api/v1/ml/anomalies/{outlier_id}",
                params={"cloud_provider": tag},
                headers=auth_headers,
            )
            assert detail_resp.status_code == 200, detail_resp.text
            detail = detail_resp.json()
            assert detail["node_id"] == outlier_id
            assert detail["is_anomaly"] is True
            assert len(detail["feature_contributions"]) > 0

            missing_resp = await client.get(
                f"/api/v1/ml/anomalies/{tag}:does-not-exist",
                params={"cloud_provider": tag},
                headers=auth_headers,
            )
            assert missing_resp.status_code == 404
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()