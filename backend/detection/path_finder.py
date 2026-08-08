"""
TrustField - Privilege Escalation Path Finder
Detects privilege escalation paths in the IAM trust graph using Neo4j graph traversal.
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from graph.neo4j_client import Neo4jClient
from detection.risk_scorer import RiskScorer

logger = logging.getLogger(__name__)


@dataclass
class EscalationPath:
    """Represents a detected privilege escalation path in the trust graph."""
    path_id: str
    source_node: str
    target_node: str
    path_nodes: List[str]
    path_edges: List[Dict]
    risk_score: float
    escalation_type: str
    description: str
    cloud_provider: str
    mitre_technique: str = ""
    remediation: str = ""
    metadata: Dict = field(default_factory=dict)


# ─── Cypher Queries ───────────────────────────────────────────────────────────

# Find paths where a low-privilege identity can reach admin-level permissions
QUERY_PRIVILEGE_ESCALATION = """
MATCH path = (source:Identity)-[:CAN_ASSUME|HAS_ROLE|BOUND_TO*1..5]->(target:Identity)
WHERE source.privilege_level < 3
  AND target.privilege_level >= 4
  AND source.id <> target.id
  AND ($cloud_provider IS NULL OR source.provider = $cloud_provider)
WITH path, source, target,
     length(path) AS path_length,
     [n IN nodes(path) | n.id] AS node_ids,
     [r IN relationships(path) | type(r)] AS rel_types
WHERE path_length <= $max_depth
RETURN
    source.id AS source_id,
    source.name AS source_name,
    source.provider AS provider,
    target.id AS target_id,
    target.name AS target_name,
    node_ids,
    rel_types,
    path_length
ORDER BY path_length ASC
LIMIT $limit
"""

# Find roles that can be assumed transitively (role chaining)
QUERY_ROLE_CHAINING = """
MATCH path = (source:Identity)-[:CAN_ASSUME*2..4]->(target:Identity)
WHERE target.privilege_level >= 4
  AND ($cloud_provider IS NULL OR source.provider = $cloud_provider)
WITH source, target,
     [n IN nodes(path) | n.id] AS chain,
     [r IN relationships(path) | type(r)] AS rel_types,
     length(path) AS depth
RETURN
    source.id AS source_id,
    target.id AS target_id,
    source.provider AS provider,
    target.privilege_level AS privilege_level,
    chain,
    rel_types,
    depth
ORDER BY depth
LIMIT $limit
"""

# Find overly permissive trust policies (wildcard principals)
QUERY_WILDCARD_TRUST = """
MATCH (source)-[r:CAN_ASSUME]->(target:Identity)
WHERE r.principal = '*'
  AND ($cloud_provider IS NULL OR target.provider = $cloud_provider)
RETURN
    source.id AS source_id,
    source.name AS source_name,
    target.id AS target_id,
    target.name AS target_name,
    target.privilege_level AS privilege_level,
    r.principal AS principal
LIMIT $limit
"""

# Find cross-account trust relationships
# Find cross-account trust relationships
QUERY_CROSS_ACCOUNT = """
MATCH (source)-[r:CAN_ASSUME]->(target:Identity)
WHERE r.is_cross_account = true
  AND ($cloud_provider IS NULL OR target.provider = $cloud_provider)
RETURN
    source.id AS source_id,
    coalesce(source.name, source.id) AS source_name,
    target.id AS target_id,
    target.account_id AS target_account,
    target.privilege_level AS privilege_level,
    target.provider AS provider
LIMIT $limit
"""

# Find identities with bind/escalate rights on a high-privilege
# Role/ClusterRole - these are K8s RBAC's built-in escalation primitives
# (bind/escalate verbs exist specifically to be gated). The target here is
# a Role/ClusterRole (a permission bundle), not an Identity, so this can't
# reuse QUERY_PRIVILEGE_ESCALATION's :Identity->:Identity pattern - same
# structural reason HAS_ROLE doesn't work as a standalone chain-ender for
# Azure/GCP. impersonate rights are handled separately via synthetic
# CAN_ASSUME edges emitted at ingest time, which DO ride the generic query.
QUERY_K8S_ESCALATION_PRIMITIVE = """
MATCH (source:Identity)-[r:CAN_ESCALATE_VIA]->(target:Role)
WHERE target.privilege_level >= 3
  AND ($cloud_provider IS NULL OR source.provider = $cloud_provider)
RETURN
    source.id AS source_id,
    source.name AS source_name,
    target.id AS target_id,
    target.name AS target_name,
    target.privilege_level AS privilege_level,
    source.provider AS provider,
    r.verb AS verb,
    r.via_role AS via_role
LIMIT $limit
"""

ESCALATION_TYPE_DESCRIPTIONS = {
    "privilege_escalation": (
        "Identity can reach higher-privilege permissions through trust chain",
        "T1078 - Valid Accounts",
        "Restrict trust policies; apply least-privilege; use permission boundaries",
    ),
    "role_chaining": (
        "Multi-hop role assumption chain allowing privilege escalation",
        "T1548.005 - Abuse Elevation Control Mechanism",
        "Break role chaining by adding explicit deny conditions; use SCPs",
    ),
    "wildcard_trust": (
        "Role trust policy allows any principal to assume it (Principal: *)",
        "T1078.004 - Cloud Accounts",
        "Replace wildcard principals with specific account/role ARNs",
    ),
    "cross_account": (
        "Cross-account trust relationship with high-privilege role",
        "T1199 - Trusted Relationship",
        "Audit cross-account roles; require ExternalId conditions",
    ),
    "k8s_escalation_primitive": (
        "Identity holds bind/escalate rights on a high-privilege Role/ClusterRole, "
        "allowing self-escalation by creating a new binding or editing the role",
        "T1548.005 - Abuse Elevation Control Mechanism",
        "Restrict bind/escalate verbs to trusted cluster admins; avoid granting "
        "broad access to roles/clusterroles resources",
    ),
}


class PrivilegeEscalationPathFinder:
    """
    Detects privilege escalation paths using Neo4j graph traversal queries.
    Each detector corresponds to a specific attack pattern.
    """

    def __init__(self, neo4j_client: Neo4jClient):
        self.neo4j = neo4j_client
        self.risk_scorer = RiskScorer()

    def _build_path_id(self, source: str, target: str, etype: str) -> str:
        import hashlib
        return hashlib.md5(f"{etype}:{source}:{target}".encode()).hexdigest()[:16]

    def _record_to_path(self, record: Dict, escalation_type: str) -> EscalationPath:
        """Convert a Neo4j record to an EscalationPath dataclass."""
        description, mitre, remediation = ESCALATION_TYPE_DESCRIPTIONS.get(
            escalation_type, ("Unknown escalation type", "", "")
        )
        source_id = record.get("source_id", "")
        target_id = record.get("target_id", "")
        node_ids = record.get("node_ids") or record.get("chain", [source_id, target_id])

        # is_cross_account / has_wildcard were previously never passed here,
        # leaving risk_scorer's bonus params dead code despite being fully
        # implemented and tested in isolation (test_risk_scorer.py). Both are
        # safe to derive from escalation_type rather than the raw record: the
        # cross_account detector's own query (QUERY_CROSS_ACCOUNT) filters on
        # r.is_cross_account = true, and the wildcard_trust detector's query
        # (QUERY_WILDCARD_TRUST) filters on r.principal = '*' - so every
        # result from either detector is true by construction, not a guess.
        # This also fixes a real detection gap: without the cross_account
        # bonus, a privilege_level=4 cross-account target scored 0.425 (raw
        # base*priv_weight - depth_penalty) and was silently dropped by the
        # aggregator's min_risk=0.5 filter, while only privilege_level=5
        # targets (0.60) survived - see Week 8 punch list.
        risk = self.risk_scorer.score_path(
            path_length=record.get("depth", record.get("path_length", 2)),
            privilege_level=record.get("privilege_level", 4),
            escalation_type=escalation_type,
            is_cross_account=(escalation_type == "cross_account"),
            has_wildcard=(escalation_type == "wildcard_trust"),
        )

        return EscalationPath(
            path_id=self._build_path_id(source_id, target_id, escalation_type),
            source_node=source_id,
            target_node=target_id,
            path_nodes=node_ids,
            path_edges=record.get("rel_types", []),
            risk_score=risk,
            escalation_type=escalation_type,
            description=description,
            cloud_provider=record.get("provider", "unknown"),
            mitre_technique=mitre,
            remediation=remediation,
            metadata={
                "source_name": record.get("source_name"),
                "target_name": record.get("target_name"),
                "source_account": record.get("source_account"),
                "target_account": record.get("target_account"),
                "via_role": record.get("via_role"),
                "verb": record.get("verb"),
            },
        )
    async def find_privilege_escalation_paths(
        self,
        cloud_provider: Optional[str] = None,
        max_depth: int = 5,
        limit: int = 50,
    ) -> List[EscalationPath]:
        """Find all multi-hop privilege escalation paths."""
        records = await self.neo4j.run_query(
            QUERY_PRIVILEGE_ESCALATION,
            parameters={
                "cloud_provider": cloud_provider,
                "max_depth": max_depth,
                "limit": limit,
            },
        )
        return [self._record_to_path(r, "privilege_escalation") for r in records]

    async def find_role_chaining(
        self,
        cloud_provider: Optional[str] = None,
        limit: int = 50,
    ) -> List[EscalationPath]:
        """Detect multi-hop role assumption chains."""
        records = await self.neo4j.run_query(
            QUERY_ROLE_CHAINING,
            parameters={"cloud_provider": cloud_provider, "limit": limit},
        )
        return [self._record_to_path(r, "role_chaining") for r in records]

    async def find_wildcard_trust(
        self,
        cloud_provider: Optional[str] = None,
        limit: int = 50,
    ) -> List[EscalationPath]:
        """Find roles with wildcard principal trust policies."""
        records = await self.neo4j.run_query(
            QUERY_WILDCARD_TRUST,
            parameters={"cloud_provider": cloud_provider, "limit": limit},
        )
        return [self._record_to_path(r, "wildcard_trust") for r in records]

    async def find_cross_account_risks(
        self,
        cloud_provider: Optional[str] = None,
        limit: int = 50,
    ) -> List[EscalationPath]:
        """Find high-privilege cross-account trust relationships."""
        records = await self.neo4j.run_query(
            QUERY_CROSS_ACCOUNT,
            parameters={"cloud_provider": cloud_provider, "limit": limit},
        )
        return [self._record_to_path(r, "cross_account") for r in records]

    async def find_k8s_escalation_primitives(
        self,
        cloud_provider: Optional[str] = None,
        limit: int = 50,
    ) -> List[EscalationPath]:
        """
        Find identities with bind/escalate rights on a high-privilege
        Role/ClusterRole. NOTE: this only covers bind/escalate - the
        impersonate primitive is covered separately by
        find_privilege_escalation_paths() via synthetic CAN_ASSUME edges
        emitted at ingest time, since impersonate targets a real Identity.
        """
        records = await self.neo4j.run_query(
            QUERY_K8S_ESCALATION_PRIMITIVE,
            parameters={"cloud_provider": cloud_provider, "limit": limit},
        )
        return [self._record_to_path(r, "k8s_escalation_primitive") for r in records]

    async def find_escalation_paths(
        self,
        cloud_provider: Optional[str] = None,
        min_risk_score: float = 0.5,
        limit: int = 100,
    ) -> List[EscalationPath]:
        """
        Run all detection queries and return deduplicated results
        filtered by minimum risk score.
        """
        all_paths: List[EscalationPath] = []
        detectors = [
            self.find_privilege_escalation_paths(cloud_provider, limit=limit),
            self.find_role_chaining(cloud_provider, limit=limit),
            self.find_wildcard_trust(cloud_provider, limit=limit),
            self.find_cross_account_risks(cloud_provider, limit=limit),
            self.find_k8s_escalation_primitives(cloud_provider, limit=limit),
        ]

        import asyncio
        results = await asyncio.gather(*detectors, return_exceptions=True)
        seen_ids = set()
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Detector failed: {result}")
                continue
            for path in result:
                if path.path_id not in seen_ids and path.risk_score >= min_risk_score:
                    all_paths.append(path)
                    seen_ids.add(path.path_id)

        all_paths.sort(key=lambda p: p.risk_score, reverse=True)
        logger.info(f"Found {len(all_paths)} escalation paths (min_risk={min_risk_score})")
        return all_paths[:limit]

    async def find_path(self, source_node: str, target_node: str) -> Optional[EscalationPath]:
        """Find the shortest trust path between two specific nodes."""
        query = """
        MATCH path = shortestPath(
            (source:Identity {id: $source_id})-[*..6]->(target:Identity {id: $target_id})
        )
        RETURN
            source.id AS source_id,
            source.name AS source_name,
            target.id AS target_id,
            target.name AS target_name,
            [n IN nodes(path) | n.id] AS node_ids,
            [r IN relationships(path) | type(r)] AS rel_types,
            length(path) AS path_length,
            source.provider AS provider
        """
        records = await self.neo4j.run_query(
            query,
            parameters={"source_id": source_node, "target_id": target_node},
        )
        if not records:
            return None
        return self._record_to_path(records[0], "privilege_escalation")