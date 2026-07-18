"""
TrustField - Feature Extractor
Transforms raw IAM graph node data into numerical feature vectors for ML models.
"""

import logging
import numpy as np
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ─── Feature Definitions ──────────────────────────────────────────────────────

# All features extracted per node — order matters for the feature matrix
FEATURE_NAMES = [
    # Identity attributes
    "privilege_level",          # 1-5 scale
    "is_active",                # 0 or 1
    "mfa_enabled",              # 0 or 1
    "has_wildcard_policy",      # 0 or 1
    "has_inline_admin_policy",  # 0 or 1
    "is_cross_account",         # 0 or 1

    # Credential age
    "access_key_age_days_norm", # normalized 0-1 (max 365 days)
    "days_since_last_used_norm",# normalized 0-1 (max 365 days)

    # Permission counts
    "attached_policy_count",    # raw count, capped at 20
    "inline_policy_count",      # raw count, capped at 10
    "group_count",              # AWS groups membership count
    "admin_role_count",         # number of admin-level role assignments

    # Graph topology
    "inbound_edge_count",       # how many entities trust this node
    "outbound_edge_count",      # how many entities this node trusts
    "neighbor_avg_risk",        # average risk score of connected nodes
    "betweenness_centrality",   # graph centrality (importance in paths)

    # Provider one-hot encoding
    "provider_aws",
    "provider_azure",
    "provider_gcp",
    "provider_k8s",

    # Node type one-hot encoding
    "type_user",
    "type_role",
    "type_service_account",
    "type_service_principal",
    "type_group",
]

PROVIDER_MAP = {"aws": 16, "azure": 17, "gcp": 18, "k8s": 19}
NODE_TYPE_MAP = {
    "aws_user": 20,
    "azure_user": 20,
    "aws_role": 21,
    "azure_service_principal": 23,
    "gcp_service_account": 22,
    "k8s_service_account": 22,
    "aws_group": 24,
    "azure_group": 24,
}


class FeatureExtractor:
    """
    Converts graph node dictionaries into fixed-length numerical feature vectors.
    Used as the preprocessing step for IsolationForest and GNN models.
    """

    def __init__(self, max_key_age_days: int = 365, max_inactive_days: int = 365):
        self.max_key_age_days = max_key_age_days
        self.max_inactive_days = max_inactive_days
        self.feature_names = FEATURE_NAMES

    @property
    def feature_dim(self) -> int:
        return len(FEATURE_NAMES)

    def _normalize(self, value: float, max_val: float) -> float:
        """Normalize a value to [0, 1] range."""
        if max_val == 0:
            return 0.0
        return min(1.0, max(0.0, value / max_val))

    def extract_node(self, node: Dict) -> np.ndarray:
        """
        Extract a feature vector from a single node dictionary.
        Returns a numpy array of shape (feature_dim,).
        """
        features = np.zeros(self.feature_dim, dtype=np.float32)

        # ── Identity attributes ──────────────────────────────────────────────
        features[0] = self._normalize(node.get("privilege_level", 1), 5)
        features[1] = float(node.get("is_active", True))
        features[2] = float(node.get("mfa_enabled", False))
        features[3] = float(node.get("has_wildcard_policy", False))
        features[4] = float(node.get("has_inline_admin_policy", False))
        features[5] = float(node.get("is_cross_account", False))

        # ── Credential age ───────────────────────────────────────────────────
        key_age = node.get("access_key_age_days", 0) or 0
        features[6] = self._normalize(key_age, self.max_key_age_days)

        inactive_days = node.get("days_since_last_used", 0) or 0
        features[7] = self._normalize(inactive_days, self.max_inactive_days)

        # ── Permission counts ────────────────────────────────────────────────
        features[8] = self._normalize(node.get("attached_policy_count", 0), 20)
        features[9] = self._normalize(node.get("inline_policy_count", 0), 10)
        features[10] = self._normalize(node.get("group_count", 0), 10)
        features[11] = self._normalize(node.get("admin_role_count", 0), 5)

        # ── Graph topology ───────────────────────────────────────────────────
        features[12] = self._normalize(node.get("inbound_edge_count", 0), 100)
        features[13] = self._normalize(node.get("outbound_edge_count", 0), 100)
        features[14] = float(node.get("neighbor_avg_risk", 0.0))
        features[15] = float(node.get("betweenness_centrality", 0.0))

        # ── Provider one-hot ─────────────────────────────────────────────────
        provider = (node.get("provider") or "").lower()
        if provider in PROVIDER_MAP:
            features[PROVIDER_MAP[provider]] = 1.0

        # ── Node type one-hot ────────────────────────────────────────────────
        node_type = (node.get("node_type") or "").lower()
        if node_type in NODE_TYPE_MAP:
            features[NODE_TYPE_MAP[node_type]] = 1.0

        return features

    def extract_batch(self, nodes: List[Dict]) -> Tuple[np.ndarray, List[str]]:
        """
        Extract features for a list of nodes.
        Returns:
            - feature matrix of shape (n_nodes, feature_dim)
            - list of node IDs (same order as rows)
        """
        if not nodes:
            return np.empty((0, self.feature_dim), dtype=np.float32), []

        node_ids = []
        feature_matrix = np.zeros((len(nodes), self.feature_dim), dtype=np.float32)

        for i, node in enumerate(nodes):
            feature_matrix[i] = self.extract_node(node)
            node_ids.append(node.get("id", str(i)))

        logger.info(
            f"Extracted features for {len(nodes)} nodes | "
            f"shape={feature_matrix.shape} | "
            f"non-zero={np.count_nonzero(feature_matrix)}"
        )
        return feature_matrix, node_ids

    def extract_edge(self, edge: Dict) -> np.ndarray:
        """
        Extract a feature vector for a graph edge (trust relationship).
        Used by the GNN model for edge-weighted message passing.
        """
        features = np.zeros(6, dtype=np.float32)
        features[0] = float(edge.get("is_cross_account", False))
        features[1] = float(edge.get("has_condition", False))
        features[2] = float(edge.get("is_high_risk", False))
        features[3] = float(edge.get("principal") == "*")  # wildcard principal

        rel = (edge.get("relationship") or "").upper()
        features[4] = float(rel == "CAN_ASSUME")
        features[5] = float(rel in ("HAS_ROLE", "BOUND_TO"))

        return features

    def get_feature_importance_labels(self) -> List[str]:
        """Return human-readable labels for each feature dimension."""
        return self.feature_names

    def enrich_nodes_with_graph_metrics(
        self,
        nodes: List[Dict],
        edges: List[Dict],
    ) -> List[Dict]:
        """
        Pre-compute graph topology metrics (in/out degree, neighbor avg risk)
        and inject them into each node dict before feature extraction.
        """
        from collections import defaultdict

        in_degree: Dict[str, int] = defaultdict(int)
        out_degree: Dict[str, int] = defaultdict(int)
        neighbor_risks: Dict[str, List[float]] = defaultdict(list)

        node_risk = {n["id"]: n.get("risk_score", 0.0) for n in nodes}

        for edge in edges:
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            if src and tgt:
                out_degree[src] += 1
                in_degree[tgt] += 1
                neighbor_risks[src].append(node_risk.get(tgt, 0.0))
                neighbor_risks[tgt].append(node_risk.get(src, 0.0))

        for node in nodes:
            nid = node["id"]
            node["inbound_edge_count"] = in_degree.get(nid, 0)
            node["outbound_edge_count"] = out_degree.get(nid, 0)
            risks = neighbor_risks.get(nid, [])
            node["neighbor_avg_risk"] = float(np.mean(risks)) if risks else 0.0

        return nodes