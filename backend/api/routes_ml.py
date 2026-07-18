"""
TrustField - ML Routes
Anomaly detection endpoints for IAM graph nodes using Isolation Forest.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from auth.dependencies import get_current_user
from db.models import User
from graph.neo4j_client import Neo4jClient
from ml.feature_extractor import FeatureExtractor
from ml.isolation_forest import IsolationForestDetector

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ml", tags=["ML"])

neo4j_client = Neo4jClient()
extractor = FeatureExtractor()
detector = IsolationForestDetector()


@router.post("/train")
async def train_anomaly_model(
    cloud_provider: Optional[str] = Query(None, description="Restrict training to one provider"),
    current_user: User = Depends(get_current_user),
):
    """
    Train the Isolation Forest anomaly detector on the current graph state.
    Pulls all Identity nodes/edges from Neo4j, enriches with graph topology
    metrics, fits the model, and persists it to disk.
    """
    graph_data = await neo4j_client.get_all_nodes_and_edges(cloud_provider=cloud_provider)
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]

    if len(nodes) < 10:
        raise HTTPException(
            status_code=400,
            detail=f"Need at least 10 nodes to train; found {len(nodes)}. Run a scan first via POST /scan/.",
        )

    enriched_nodes = extractor.enrich_nodes_with_graph_metrics(nodes, edges)
    summary = detector.train(enriched_nodes)

    logger.info(f"ML model trained by user {current_user.id}: {summary}")
    return {"status": "trained", **summary}


@router.get("/anomalies")
async def get_anomalies(
    cloud_provider: Optional[str] = Query(None, description="Restrict to one provider"),
    threshold: Optional[float] = Query(None, ge=0.0, le=1.0, description="Override anomaly score threshold"),
    current_user: User = Depends(get_current_user),
):
    """
    Run anomaly detection on the current graph state.
    If no trained model exists on disk, auto-fits on the current dataset
    (unsupervised — acceptable for a capstone demo; production would want
    train and score to run on separate datasets).
    """
    graph_data = await neo4j_client.get_all_nodes_and_edges(cloud_provider=cloud_provider)
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]

    if not nodes:
        return {"total": 0, "anomalies": 0, "anomaly_rate": 0.0, "results": []}

    enriched_nodes = extractor.enrich_nodes_with_graph_metrics(nodes, edges)

    if threshold is not None:
        detector.anomaly_threshold = threshold

    results = detector.detect(enriched_nodes)
    summary = detector.get_anomaly_summary(results)

    return {**summary, "results": [r.to_dict() for r in results]}

@router.get("/anomalies/{node_id:path}")
async def get_node_anomaly_detail(
    node_id: str,
    cloud_provider: Optional[str] = Query(None, description="Restrict enrichment context to one provider"),
    current_user: User = Depends(get_current_user),
):
    """
    Get anomaly detection detail for a single node by ID.
    Uses :path so ARNs and emails containing slashes resolve correctly
    (same convention as GET /graph/nodes/{node_id:path}).

    Runs detection across the full graph (topology metrics like betweenness
    centrality and neighbor_avg_risk are only meaningful in the context of
    the whole graph) and returns just the requested node's result.
    """
    graph_data = await neo4j_client.get_all_nodes_and_edges(cloud_provider=cloud_provider)
    nodes = graph_data["nodes"]
    edges = graph_data["edges"]

    if not any(n.get("id") == node_id for n in nodes):
        raise HTTPException(status_code=404, detail=f"Node not found: {node_id}")

    enriched_nodes = extractor.enrich_nodes_with_graph_metrics(nodes, edges)
    results = detector.detect(enriched_nodes)

    match = next((r for r in results if r.node_id == node_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"No anomaly result computed for node: {node_id}")

    return match.to_dict()