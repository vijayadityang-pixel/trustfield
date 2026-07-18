"""
TrustField - Graph Schema
Pydantic models and dataclasses for graph nodes and edges.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


@dataclass
class GraphNode:
    id: str
    name: str
    provider: str                   # aws | azure | gcp | k8s
    node_type: str                  # aws_user | aws_role | azure_sp | etc.
    risk_score: float = 0.0
    privilege_level: int = 1
    labels: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relationship: str               # CAN_ASSUME | HAS_ROLE | BOUND_TO
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    is_high_risk: bool = False


class GraphNodeResponse(BaseModel):
    id: str
    name: str
    provider: str
    node_type: str
    risk_score: float = 0.0
    privilege_level: int = 1
    labels: List[str] = []
    properties: Dict[str, Any] = {}

    class Config:
        from_attributes = True


class GraphEdgeResponse(BaseModel):
    source: str
    target: str
    relationship: str
    properties: Dict[str, Any] = {}
    risk_score: float = 0.0
    is_high_risk: bool = False

    class Config:
        from_attributes = True