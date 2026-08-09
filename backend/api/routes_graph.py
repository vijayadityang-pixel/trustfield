"""
TrustField - Graph Routes
Exposes trust graph data for visualization and analysis.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from db.database import get_db
from db.models import User
from auth.dependencies import get_current_user
from graph.graph_builder import TrustGraphBuilder
from graph.neo4j_singleton import neo4j_client
from detection.path_finder import PrivilegeEscalationPathFinder
from detection.risk_scorer import RiskScorer
from schemas.graph_schemas import (
    GraphResponse,
    NodeDetail,
    EdgeDetail,
    EscalationPathResponse,
    GraphStatsResponse,
    NodeSearchResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/graph", tags=["Trust Graph"])


graph_builder = TrustGraphBuilder(neo4j_client)
path_finder = PrivilegeEscalationPathFinder(neo4j_client)
risk_scorer = RiskScorer()


@router.get("/", response_model=GraphResponse)
async def get_trust_graph(
    cloud_provider: Optional[str] = Query(None, description="aws | azure | gcp | k8s"),
    account_id: Optional[str] = Query(None, description="Cloud account/subscription ID"),
    depth: int = Query(3, ge=1, le=6, description="Graph traversal depth"),
    min_trust_score: float = Query(0.0, ge=0.0, le=1.0),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve the full trust graph or a filtered subgraph.
    Returns nodes (identities/resources) and edges (trust relationships).
    """
    try:
        graph_data = await graph_builder.build_graph(
            cloud_provider=cloud_provider,
            account_id=account_id,
            depth=depth,
            min_trust_score=min_trust_score,
        )
        graph_data.setdefault("total_nodes", len(graph_data.get("nodes", [])))
        graph_data.setdefault("total_edges", len(graph_data.get("edges", [])))
        return graph_data
    except Exception as exc:
        logger.error(f"Failed to build trust graph: {exc}")
        raise HTTPException(status_code=500, detail=f"Graph build failed: {str(exc)}")


@router.get("/stats", response_model=GraphStatsResponse)
async def get_graph_stats(
    cloud_provider: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """
    Return high-level graph statistics:
    - Total nodes and edges
    - Average trust score
    - High-risk node count
    - Privilege escalation path count
    """
    stats = await graph_builder.compute_stats(cloud_provider=cloud_provider)
    return stats


@router.get("/nodes/search", response_model=List[NodeSearchResponse])
async def search_nodes(
    q: str = Query(..., min_length=2, description="Search by name, ARN, or resource ID"),
    cloud_provider: Optional[str] = None,
    node_type: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """Full-text search across graph nodes."""
    results = await neo4j_client.search_nodes(
        query=q,
        cloud_provider=cloud_provider,
        node_type=node_type,
        limit=limit,
    )
    return [
        NodeSearchResponse(
            node_id=r.get("id"),
            node_type=r.get("node_type"),
            name=r.get("name"),
            cloud_provider=r.get("provider"),
            risk_score=r.get("risk_score", 0.0),
        )
        for r in results
    ]

@router.get("/nodes/{node_id:path}", response_model=NodeDetail)
async def get_node_detail(
    node_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Get full details of a specific graph node including:
    - Identity/resource metadata
    - Attached permissions
    - Trust score and risk factors
    - Connected nodes (neighbors)
    """
    node = await neo4j_client.get_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")
    return NodeDetail(
        node_id=node.get("id"),
        node_type=node.get("node_type"),
        name=node.get("name"),
        cloud_provider=node.get("provider"),
        account_id=node.get("account_id"),
        risk_score=node.get("risk_score", 0.0),
        trust_score=node.get("risk_score", 0.0),
        neighbors=[n.get("neighbor_id") for n in node.get("neighbors", []) if n.get("neighbor_id")],
    )





@router.get("/escalation-paths", response_model=List[EscalationPathResponse])
async def get_escalation_paths(
    cloud_provider: Optional[str] = None,
    min_risk_score: float = Query(0.5, ge=0.0, le=1.0),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    """
    Detect and return privilege escalation paths in the trust graph.
    Each path shows the chain of identities/permissions leading to privilege gain.
    """
    try:
        paths = await path_finder.find_escalation_paths(
            cloud_provider=cloud_provider,
            min_risk_score=min_risk_score,
            limit=limit,
        )
        return [
            EscalationPathResponse(
                path_id=p.path_id,
                source_node_id=p.source_node,
                target_node_id=p.target_node,
                path_nodes=p.path_nodes,
                path_length=len(p.path_nodes) - 1,
                risk_score=p.risk_score,
                attack_techniques=[p.mitre_technique] if p.mitre_technique else [],
                cloud_provider=p.cloud_provider,
                metadata=p.metadata,
            )
            for p in paths
        ]
    except Exception as exc:
        logger.error(f"Escalation path detection failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/escalation-paths/{source_node}/{target_node}", response_model=EscalationPathResponse)
async def get_path_between_nodes(
    source_node: str,
    target_node: str,
    current_user: User = Depends(get_current_user),
):
    """
    Find the shortest trust path between two specific graph nodes.
    Useful for investigating suspicious lateral movement.
    """
    path = await path_finder.find_path(source_node, target_node)
    if not path:
        raise HTTPException(
            status_code=404,
            detail=f"No trust path found between {source_node} and {target_node}",
        )
    return EscalationPathResponse(
        path_id=path.path_id,
        source_node_id=path.source_node,
        target_node_id=path.target_node,
        path_nodes=path.path_nodes,
        path_length=len(path.path_nodes) - 1,
        risk_score=path.risk_score,
        attack_techniques=[path.mitre_technique] if path.mitre_technique else [],
        cloud_provider=path.cloud_provider,
        metadata=path.metadata,
    )


@router.post("/refresh")
async def refresh_graph(
    background_tasks: BackgroundTasks,
    cloud_provider: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Trigger a graph refresh by re-collecting IAM data from cloud providers.
    This is an async operation — check /scan/status for progress.
    """
    from api.routes_scan import trigger_scan
    from schemas.scan_schemas import ScanRequest

    scan_request = ScanRequest(
        providers=[cloud_provider] if cloud_provider else None,
    )
    return await trigger_scan(
        request=scan_request,
        background_tasks=background_tasks,
        db=db,
        current_user=current_user,
    )


@router.get("/subgraph/{node_id:path}", response_model=GraphResponse)
async def get_subgraph(
    node_id: str,
    depth: int = Query(2, ge=1, le=4),
    direction: str = Query("both", regex="^(inbound|outbound|both)$"),
    current_user: User = Depends(get_current_user),
):
    """
    Extract a subgraph centered on a specific node.
    Useful for investigating a single identity's trust relationships.
    """
    node = await neo4j_client.get_node_by_id(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    subgraph = await graph_builder.build_subgraph(
        center_node_id=node_id,
        depth=depth,
        direction=direction,
    )
    subgraph.setdefault("total_nodes", len(subgraph.get("nodes", [])))
    subgraph.setdefault("total_edges", len(subgraph.get("edges", [])))
    return subgraph


@router.get("/risk-scores", response_model=List[NodeDetail])
async def get_high_risk_nodes(
    cloud_provider: Optional[str] = None,
    threshold: float = Query(0.7, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    """
    Return nodes with trust/risk scores above the threshold.
    Ordered by risk score descending.
    """
    nodes = await neo4j_client.get_nodes_by_risk(
        cloud_provider=cloud_provider,
        min_risk=threshold,
        limit=limit,
    )
    return [
        NodeDetail(
            node_id=n.get("id"),
            node_type=n.get("node_type"),
            name=n.get("name"),
            cloud_provider=n.get("provider"),
            account_id=n.get("account_id"),
            risk_score=n.get("risk_score", 0.0),
            trust_score=n.get("risk_score", 0.0),
        )
        for n in nodes
    ]