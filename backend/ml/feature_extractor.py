"""
TrustField - Feature Extractor
Transforms raw IAM graph node data into numerical feature vectors for ML models.
"""

import logging
import numpy as np
import networkx as nx
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Feature Definitions ──────────────────────────────────────────────────────
# Trimmed to fields actually populated by graph_builder.py (Weeks 1-4).
# Fields like mfa_enabled, access_key_age_days, attached_policy_count etc. were
# in the original scaffold but never written by any collector — including them
# just silently zero-fills the vector. Documented as a Week 8 limitation:
# richer per-identity attributes (key age, policy counts, MFA) would require
# extending all four collectors, deferred as future work.

FEATURE_NAMES = [
    # Identity attributes (real signal)
    "privilege_level",           # 1-5 scale, normalized
    "is_active",                 # 0/1 — only Azure sets this explicitly; others default True
    "has_wildcard_policy",       # 0/1 — only AWS roles set this today
    "is_cross_account",          # 0/1 — derived node-level from inbound CAN_ASSUME edge flags

    # Graph topology (computed at enrichment time)
    "inbound_edge_count",
    "outbound_edge_count",
    "neighbor_avg_risk",
    "betweenness_centrality",    # real networkx computation, normalized [0,1]

    # Provider one-hot
    "provider_aws",
    "provider_azure",
    "provider_gcp",
    "provider_k8s",

    # Node type one-hot — covers every node_type string graph_builder.py
    # actually writes across all four providers (fixes the original map,
    # which had no entries for role/role-definition node types and dead
    # entries for group nodes that are never ingested).
    "type_aws_user",
    "type_aws_role",
    "type_azure_user",
    "type_azure_service_principal",
    "type_azure_role_definition",
    "type_gcp_service_account",
    "type_gcp_custom_role",
    "type_gcp_builtin_role",
    "type_k8s_service_account",
    "type_k8s_role",
    "type_k8s_cluster_role",
    "type_k8s_user",
    "type_k8s_group",
]

PROVIDER_MAP = {"aws": 8, "azure": 9, "gcp": 10, "k8s": 11}
NODE_TYPE_MAP = {
    "aws_user": 12,
    "aws_role": 13,
    "azure_user": 14,
    "azure_service_principal": 15,
    "azure_role_definition": 16,
    "gcp_service_account": 17,
    "gcp_custom_role": 18,
    "gcp_builtin_role": 19,
    "k8s_service_account": 20,
    "k8s_role": 21,
    "k8s_cluster_role": 22,
    "k8s_user": 23,
    "k8s_group": 24,
}


class FeatureExtractor:
    """
    Converts graph node dictionaries into fixed-length numerical feature vectors.
    Used as the preprocessing step for IsolationForest (and GNN, if enabled).
    """

    def __init__(self):
        self.feature_names = FEATURE_NAMES

    @property
    def feature_dim(self) -> int:
        return len(FEATURE_NAMES)

    def _normalize(self, value: float, max_val: float) -> float:
        if max_val == 0:
            return 0.0
        return min(1.0, max(0.0, value / max_val))

    def extract_node(self, node: Dict) -> np.ndarray:
        """Extract a feature vector from a single node dictionary."""
        features = np.zeros(self.feature_dim, dtype=np.float32)

        features[0] = self._normalize(node.get("privilege_level", 1), 5)
        features[1] = float(node.get("is_active", True))
        features[2] = float(node.get("has_wildcard_policy", False))
        features[3] = float(node.get("is_cross_account", False))

        features[4] = self._normalize(node.get("inbound_edge_count", 0), 100)
        features[5] = self._normalize(node.get("outbound_edge_count", 0), 100)
        features[6] = float(node.get("neighbor_avg_risk", 0.0))
        features[7] = float(node.get("betweenness_centrality", 0.0))

        provider = (node.get("provider") or "").lower()
        if provider in PROVIDER_MAP:
            features[PROVIDER_MAP[provider]] = 1.0

        node_type = (node.get("node_type") or "").lower()
        if node_type in NODE_TYPE_MAP:
            features[NODE_TYPE_MAP[node_type]] = 1.0
        else:
            logger.debug(f"Unmapped node_type '{node_type}' for node {node.get('id')} — type one-hot left zero")

        return features

    def extract_batch(self, nodes: List[Dict]) -> Tuple[np.ndarray, List[str]]:
        """
        Extract features for a list of nodes.
        Returns (feature matrix of shape (n_nodes, feature_dim), list of node IDs).
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
            f"shape={feature_matrix.shape} | non-zero={np.count_nonzero(feature_matrix)}"
        )
        return feature_matrix, node_ids

    def extract_edge(self, edge: Dict) -> np.ndarray:
        """
        Extract a feature vector for a graph edge (trust relationship).
        Used only by the GNN model (out of scope for Week 5's Isolation Forest).
        """
        features = np.zeros(6, dtype=np.float32)
        features[0] = float(edge.get("is_cross_account", False))
        features[1] = float(edge.get("has_condition", False))
        features[2] = float(edge.get("is_high_risk", False))
        features[3] = float(edge.get("principal") == "*")

        rel = (edge.get("relationship") or "").upper()
        features[4] = float(rel == "CAN_ASSUME")
        features[5] = float(rel in ("HAS_ROLE", "BOUND_TO"))

        return features

    def get_feature_importance_labels(self) -> List[str]:
        return self.feature_names

    def enrich_nodes_with_graph_metrics(
        self,
        nodes: List[Dict],
        edges: List[Dict],
    ) -> List[Dict]:
        """
        Pre-compute graph topology metrics — in/out degree, neighbor avg risk,
        betweenness centrality, node-level cross-account exposure — and inject
        them into each node dict before feature extraction.

        Edges are expected as flat dicts: {source, target, relationship, ...props}
        matching Neo4jClient.get_all_nodes_and_edges() output.
        """
        from collections import defaultdict

        in_degree: Dict[str, int] = defaultdict(int)
        out_degree: Dict[str, int] = defaultdict(int)
        neighbor_risks: Dict[str, List[float]] = defaultdict(list)
        cross_account_exposure: Dict[str, bool] = defaultdict(bool)

        node_risk = {n["id"]: n.get("risk_score", 0.0) for n in nodes if n.get("id")}

        graph = nx.DiGraph()
        for node in nodes:
            nid = node.get("id")
            if nid:
                graph.add_node(nid)

        for edge in edges:
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            if not (src and tgt):
                continue

            out_degree[src] += 1
            in_degree[tgt] += 1
            neighbor_risks[src].append(node_risk.get(tgt, 0.0))
            neighbor_risks[tgt].append(node_risk.get(src, 0.0))
            graph.add_edge(src, tgt)

            # Node-level cross-account exposure derived from the edge-level
            # flag graph_builder.py already sets on CAN_ASSUME edges. The
            # *target* of a cross-account CAN_ASSUME edge is the identity
            # exposed to external trust — that's the node worth flagging.
            if edge.get("relationship") == "CAN_ASSUME" and edge.get("is_cross_account"):
                cross_account_exposure[tgt] = True

        # Betweenness centrality — cheap at this graph's scale (hundreds to
        # low-thousands of nodes per Week 4's live Azure/GCP tests), already
        # normalized to [0, 1] by networkx.
        try:
            centrality = nx.betweenness_centrality(graph, normalized=True)
        except Exception as exc:
            logger.warning(f"Betweenness centrality computation failed: {exc}")
            centrality = {}

        for node in nodes:
            nid = node.get("id")
            if not nid:
                continue
            node["inbound_edge_count"] = in_degree.get(nid, 0)
            node["outbound_edge_count"] = out_degree.get(nid, 0)
            risks = neighbor_risks.get(nid, [])
            node["neighbor_avg_risk"] = float(np.mean(risks)) if risks else 0.0
            node["betweenness_centrality"] = float(centrality.get(nid, 0.0))
            node["is_cross_account"] = cross_account_exposure.get(nid, False)

        return nodes