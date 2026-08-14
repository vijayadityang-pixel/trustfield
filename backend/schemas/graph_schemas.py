"""
TrustField - Graph Schemas
Pydantic models for trust graph API request/response serialization.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict


# ─── Node / Edge primitives ───────────────────────────────────────────────────

class EdgeDetail(BaseModel):
    """A directed trust relationship between two graph nodes."""

    model_config = ConfigDict(from_attributes=True)

    source_id: str
    target_id: str
    relationship_type: str
    trust_score: float = 0.0
    properties: Optional[Dict[str, Any]] = None


class NodeDetail(BaseModel):
    """Full detail of a single IAM identity or resource node."""

    model_config = ConfigDict(from_attributes=True)

    node_id: str
    node_type: str                          # USER, ROLE, GROUP, SERVICE_ACCOUNT, etc.
    name: str
    cloud_provider: Optional[str] = None
    account_id: Optional[str] = None
    region: Optional[str] = None
    risk_score: float = 0.0
    trust_score: float = 0.0
    permissions: Optional[List[str]] = None
    properties: Optional[Dict[str, Any]] = None
    neighbors: Optional[List[str]] = None   # Adjacent node IDs


# ─── Graph response ───────────────────────────────────────────────────────────

class GraphResponse(BaseModel):
    """Full or filtered trust graph returned by GET /graph/."""

    model_config = ConfigDict(from_attributes=True)

    nodes: List[NodeDetail]
    edges: List[EdgeDetail]
    total_nodes: int
    total_edges: int
    cloud_provider: Optional[str] = None
    generated_at: Optional[datetime] = None


# ─── Stats ────────────────────────────────────────────────────────────────────

class GraphStatsResponse(BaseModel):
    """High-level graph statistics returned by GET /graph/stats."""

    model_config = ConfigDict(from_attributes=True)

    total_nodes: int
    total_edges: int
    avg_trust_score: float = 0.0
    high_risk_nodes: int = 0
    escalation_path_count: int = 0
    cloud_provider: Optional[str] = None
    providers_connected: List[str] = []
    computed_at: Optional[datetime] = None


# ─── Escalation paths ─────────────────────────────────────────────────────────

class EscalationPathResponse(BaseModel):
    """A detected privilege escalation path through the trust graph."""

    model_config = ConfigDict(from_attributes=True)

    path_id: Optional[str] = None
    source_node_id: str
    target_node_id: str
    path_nodes: List[str]               # Ordered list of node IDs forming the path
    path_length: int
    risk_score: float = 0.0
    attack_techniques: Optional[List[str]] = None   # MITRE ATT&CK technique IDs
    cloud_provider: Optional[str] = None
    detected_at: Optional[datetime] = None
    metadata: Optional[Dict] = None

# ─── Node search ──────────────────────────────────────────────────────────────

class NodeSearchResponse(BaseModel):
    """Lightweight node result returned by GET /graph/nodes/search."""

    model_config = ConfigDict(from_attributes=True)

    node_id: str
    node_type: str
    name: str
    cloud_provider: Optional[str] = None
    risk_score: float = 0.0