"""
TrustField - Risk Scorer
Computes composite risk scores for graph nodes, edges, and escalation paths.
"""

import logging
import math
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ─── Weight Constants ─────────────────────────────────────────────────────────

ESCALATION_TYPE_WEIGHTS = {
    "privilege_escalation": 0.90,
    "role_chaining": 0.80,
    "wildcard_trust": 0.85,
    "cross_account": 0.70,
    "anomaly": 0.75,
}

PRIVILEGE_LEVEL_WEIGHTS = {
    1: 0.10,    # Viewer / read-only
    2: 0.25,    # Limited write
    3: 0.45,    # Service-level write
    4: 0.75,    # Account admin
    5: 1.00,    # Root / Global admin
}

SEVERITY_SCORES = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.50,
    "low": 0.25,
    "info": 0.10,
}


class RiskScorer:
    """
    Computes risk scores (0.0 – 1.0) for trust graph entities and escalation paths.

    Scoring model:
    - Base score from escalation type / privilege level
    - Depth penalty: shorter paths = higher risk (easier to exploit)
    - Exposure factor: cross-account, wildcard, or public exposure multiplier
    - ML anomaly score overlay (from isolation forest)
    """

    def score_path(
        self,
        path_length: int,
        privilege_level: int,
        escalation_type: str,
        has_wildcard: bool = False,
        is_cross_account: bool = False,
        anomaly_score: float = 0.0,
    ) -> float:
        """
        Score a privilege escalation path.

        Returns a float in [0.0, 1.0] where 1.0 = maximum risk.
        """
        # Base score from escalation type
        base = ESCALATION_TYPE_WEIGHTS.get(escalation_type, 0.60)

        # Privilege level of the target role/resource
        priv_weight = PRIVILEGE_LEVEL_WEIGHTS.get(min(privilege_level, 5), 0.50)

        # Depth penalty: shorter paths are easier to exploit
        # path_length=1 → penalty=0, path_length=5 → penalty=0.4
        depth_penalty = min(0.40, (path_length - 1) * 0.10)

        # Exposure multipliers
        wildcard_bonus = 0.15 if has_wildcard else 0.0
        cross_account_bonus = 0.10 if is_cross_account else 0.0

        # ML anomaly overlay (adds up to 0.20 on top of rule score)
        ml_overlay = min(0.20, anomaly_score * 0.20)

        raw = (base * priv_weight) - depth_penalty + wildcard_bonus + cross_account_bonus + ml_overlay
        return round(min(1.0, max(0.0, raw)), 4)

    def score_node(self, node_data: Dict) -> float:
        """
        Score an individual graph node (identity or resource).

        Factors:
        - Privilege level
        - Access key age
        - MFA status
        - Policy permissiveness
        - Activity recency
        """
        score = 0.0

        priv_level = node_data.get("privilege_level", 1)
        score += PRIVILEGE_LEVEL_WEIGHTS.get(priv_level, 0.10) * 0.40

        # MFA penalty
        if not node_data.get("mfa_enabled", True):
            score += 0.20

        # Stale credentials
        key_age = node_data.get("access_key_age_days", 0)
        if key_age >= 180:
            score += 0.20
        elif key_age >= 90:
            score += 0.10

        # Wildcard policy
        if node_data.get("has_wildcard_policy", False):
            score += 0.20

        # Admin inline policy
        if node_data.get("has_inline_admin_policy", False):
            score += 0.15

        # No recent activity (potential zombie account)
        days_inactive = node_data.get("days_since_last_used", 0)
        if days_inactive >= 180:
            score += 0.15
        elif days_inactive >= 90:
            score += 0.08

        # External exposure
        if node_data.get("is_cross_account", False):
            score += 0.10

        return round(min(1.0, max(0.0, score)), 4)

    def score_edge(self, edge_data: Dict) -> float:
        """
        Score a trust relationship edge.

        High-risk edges: wildcard principals, no MFA conditions, cross-account.
        """
        score = 0.30  # Baseline: any trust relationship carries some risk

        if edge_data.get("principal") == "*":
            score += 0.40

        if not edge_data.get("has_condition", False):
            score += 0.20

        if edge_data.get("is_cross_account", False):
            score += 0.15

        if edge_data.get("relationship") in ["CAN_ASSUME", "HAS_ROLE"]:
            score += 0.10

        if edge_data.get("is_high_risk", False):
            score += 0.25

        return round(min(1.0, max(0.0, score)), 4)

    def severity_from_score(self, score: float) -> str:
        """Convert a numeric risk score to a severity label."""
        if score >= 0.85:
            return "critical"
        elif score >= 0.65:
            return "high"
        elif score >= 0.40:
            return "medium"
        elif score >= 0.20:
            return "low"
        return "info"

    def score_batch_nodes(self, nodes: List[Dict]) -> List[Dict]:
        """Score a list of nodes and inject risk_score + severity into each."""
        for node in nodes:
            node["risk_score"] = self.score_node(node)
            node["severity"] = self.severity_from_score(node["risk_score"])
        return nodes

    def compute_graph_risk_summary(self, nodes: List[Dict]) -> Dict:
        """
        Compute aggregate risk statistics across all scored nodes.
        Returns distribution counts and average risk score.
        """
        if not nodes:
            return {
                "total_nodes": 0,
                "avg_risk_score": 0.0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "risk_score_p50": 0.0,
                "risk_score_p90": 0.0,
            }

        scored = [self.score_node(n) for n in nodes]
        scored_sorted = sorted(scored)
        n = len(scored_sorted)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for s in scored:
            counts[self.severity_from_score(s)] += 1

        def percentile(arr, p):
            idx = int(math.ceil(p / 100.0 * len(arr))) - 1
            return arr[max(0, min(idx, len(arr) - 1))]

        return {
            "total_nodes": n,
            "avg_risk_score": round(sum(scored) / n, 4),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "risk_score_p50": round(percentile(scored_sorted, 50), 4),
            "risk_score_p90": round(percentile(scored_sorted, 90), 4),
        }