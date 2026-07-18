"""
TrustField - Trust Graph Builder
Ingests collected IAM data and builds the Neo4j trust graph.
"""

import logging
import asyncio
from typing import Any, Dict, List, Optional

from graph.neo4j_client import Neo4jClient
from graph.schema import GraphNode, GraphEdge
from detection.risk_scorer import RiskScorer

logger = logging.getLogger(__name__)

risk_scorer = RiskScorer()


class TrustGraphBuilder:
    """
    Translates raw IAM data from collectors into Neo4j graph nodes and edges.
    Handles all four providers: AWS, Azure, GCP, Kubernetes.
    """

    def __init__(self, neo4j_client: Neo4jClient):
        self.neo4j = neo4j_client

    # ─── AWS ──────────────────────────────────────────────────────────────────

    async def _ingest_aws(self, data: Any) -> Dict:
        """Ingest AWS IAM data into the trust graph."""
        nodes_created = 0
        edges_created = 0

        # Users
        for user in data.users:
            node_id = user.get("Arn") or f"aws:user:{user['UserName']}"
            props = {
                "id": node_id,
                "name": user["UserName"],
                "arn": user.get("Arn", ""),
                "provider": "aws",
                "node_type": "aws_user",
                "account_id": data.account_id,
                "mfa_enabled": user.get("mfa_enabled", False),
                "privilege_level": self._aws_user_privilege(user),
                "access_key_count": len(user.get("AccessKeys", [])),
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "AWSUser"], props)
            nodes_created += 1

        # Roles
        for role in data.roles:
            node_id = role.get("Arn") or f"aws:role:{role['RoleName']}"
            props = {
                "id": node_id,
                "name": role["RoleName"],
                "arn": role.get("Arn", ""),
                "provider": "aws",
                "node_type": "aws_role",
                "account_id": data.account_id,
                "privilege_level": self._aws_role_privilege(role),
                "has_wildcard_policy": self._has_wildcard_policy(role),
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "AWSRole"], props)
            nodes_created += 1

        # Trust relationship edges
        for trust in data.trust_relationships:
            source = trust.get("source", "")
            target = trust.get("target", "")
            if source and target:
                edge_props = {
                    "principal": source,
                    "condition": str(trust.get("condition", {})),
                    "is_cross_account": ":" in source and data.account_id not in source,
                }
                success = await self.neo4j.upsert_edge(source, target, "CAN_ASSUME", edge_props)
                if success:
                    edges_created += 1

        return {"nodes": nodes_created, "edges": edges_created}

    
    # ─── Azure ────────────────────────────────────────────────────────────────

    async def _ingest_azure(self, data: Any) -> Dict:
        """Ingest Azure IAM data into the trust graph."""
        nodes_created = 0
        edges_created = 0

        # Role definitions first, so we can look up privilege_level while
        # scoring users/service principals below. Unlike GCP, Azure's
        # collector already computes privilege_level per role definition
        # (via _role_definition_privilege), so no heuristic needed here.
        role_privilege_map: Dict[str, int] = {
            rd.get("id"): rd.get("privilege_level", 1)
            for rd in data.role_definitions
            if rd.get("id")
        }

        # Derive each principal's privilege_level from the highest-privilege
        # role it actually holds, so CAN_ASSUME targets carry real privilege
        # for the privilege_escalation / role_chaining detectors.
        principal_max_privilege: Dict[str, int] = {}
        for t in data.trust_relationships:
            if t.get("relationship") != "HAS_ROLE":
                continue
            source = t.get("source", "")
            target = t.get("target", "")
            role_priv = role_privilege_map.get(target, 1)
            principal_max_privilege[source] = max(principal_max_privilege.get(source, 1), role_priv)

        # Users — id is raw AAD object id, matching principal_id used in edges
        for user in data.users:
            node_id = user.get("id") or f"azure:user:{user.get('userPrincipalName')}"
            props = {
                "id": node_id,
                "name": user.get("displayName", ""),
                "upn": user.get("userPrincipalName", ""),
                "provider": "azure",
                "node_type": "azure_user",
                "subscription_id": data.subscription_id,
                "tenant_id": data.tenant_id,
                "is_active": user.get("accountEnabled", True),
                "privilege_level": principal_max_privilege.get(node_id, 1),
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "AzureUser"], props)
            nodes_created += 1

        # Service principals — same raw-id rule
        for sp in data.service_principals:
            node_id = sp.get("id") or f"azure:sp:{sp.get('appId', 'unknown')}"
            props = {
                "id": node_id,
                "name": sp.get("displayName", ""),
                "app_id": sp.get("appId", ""),
                "provider": "azure",
                "node_type": "azure_service_principal",
                "subscription_id": data.subscription_id,
                "tenant_id": data.tenant_id,
                "is_active": sp.get("accountEnabled", True),
                "privilege_level": principal_max_privilege.get(node_id, 1),
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "AzureServicePrincipal"], props)
            nodes_created += 1

        # Role definitions — MUST be their own Identity nodes so HAS_ROLE
        # targets are traversable by the generic privilege_escalation query.
        # Reuses privilege_level already computed by the collector.
        for role_def in data.role_definitions:
            node_id = role_def.get("id")
            if not node_id:
                continue
            props = {
                "id": node_id,
                "name": role_def.get("name", ""),
                "provider": "azure",
                "node_type": "azure_role_definition",
                "subscription_id": data.subscription_id,
                "role_type": role_def.get("role_type", ""),
                "privilege_level": role_def.get("privilege_level", 1),
                "grants_self_escalation": role_def.get("grants_self_escalation", False),
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "AzureRoleDefinition"], props)
            nodes_created += 1

        # Edges: HAS_ROLE (assignments) + CAN_ASSUME (real self-escalation)
        for trust in data.trust_relationships:
            source = trust.get("source", "")
            target = trust.get("target", "")
            rel_type = trust.get("relationship", "HAS_ROLE")
            if not (source and target):
                continue

            if rel_type == "CAN_ASSUME":
                edge_props = {
                    "principal": trust.get("principal", source),
                    "condition": str(trust.get("condition", {})),
                    "is_cross_account": trust.get("is_cross_account", False),
                }
            else:
                edge_props = {
                    "scope": trust.get("scope", ""),
                    "principal_type": trust.get("principal_type", ""),
                    "role_name": trust.get("role_name", ""),
                }

            success = await self.neo4j.upsert_edge(source, target, rel_type, edge_props)
            if success:
                edges_created += 1

        return {"nodes": nodes_created, "edges": edges_created}

    # ─── GCP ──────────────────────────────────────────────────────────────────

    async def _ingest_gcp(self, data: Any) -> Dict:
        """Ingest GCP IAM data into the trust graph."""
        nodes_created = 0
        edges_created = 0

        # Role nodes first, so we can look up privilege_level while
        # scoring service accounts below.
        custom_role_map = {cr.get("name"): cr for cr in data.custom_roles if cr.get("name")}

        def _gcp_role_privilege(role_id: str, role_def: Optional[Dict]) -> int:
            if role_id in {"roles/owner", "roles/editor"}:
                return 5
            if role_id == "roles/viewer":
                return 1
            if role_def:
                perms = role_def.get("includedPermissions", []) or []
                if any("admin" in p.lower() or "iam" in p.lower() for p in perms):
                    return 4
            if "admin" in role_id.lower() or "owner" in role_id.lower():
                return 4
            return 2

        referenced_roles = {
            t.get("target") for t in data.trust_relationships
            if t.get("relationship") == "HAS_ROLE" and t.get("target")
        }
        all_role_ids = referenced_roles | set(custom_role_map.keys())
        role_privilege_map = {}

        for role_id in all_role_ids:
            role_def = custom_role_map.get(role_id)
            priv = _gcp_role_privilege(role_id, role_def)
            role_privilege_map[role_id] = priv
            props = {
                "id": role_id,
                "name": (role_def.get("title") if role_def else role_id) or role_id,
                "provider": "gcp",
                "node_type": "gcp_custom_role" if role_def else "gcp_builtin_role",
                "project_id": data.project_id,
                "privilege_level": priv,
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(role_id, ["Identity", "GCPRole"], props)
            nodes_created += 1

        # Derive each principal's privilege_level from the highest-privilege
        # role it actually holds, so CAN_ASSUME targets carry real privilege
        # for the privilege_escalation / role_chaining detectors.
        principal_max_privilege: Dict[str, int] = {}
        for t in data.trust_relationships:
            if t.get("relationship") != "HAS_ROLE":
                continue
            source = t.get("source", "")
            target = t.get("target", "")
            role_priv = role_privilege_map.get(target, 1)
            principal_max_privilege[source] = max(principal_max_privilege.get(source, 1), role_priv)

        # Service accounts — id is raw email, matching member_id used in edges
        for sa in data.service_accounts:
            node_id = sa.get("email") or sa.get("uniqueId")
            if not node_id:
                continue
            props = {
                "id": node_id,
                "name": sa.get("displayName") or sa.get("email", ""),
                "email": sa.get("email", ""),
                "provider": "gcp",
                "node_type": "gcp_service_account",
                "project_id": data.project_id,
                "user_managed_key_count": len(sa.get("keys", [])),
                "privilege_level": principal_max_privilege.get(node_id, 1),
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "GCPServiceAccount"], props)
            nodes_created += 1

        # Edges: HAS_ROLE (bindings) + CAN_ASSUME (real per-SA impersonation)
        for trust in data.trust_relationships:
            source = trust.get("source", "")
            target = trust.get("target", "")
            rel_type = trust.get("relationship", "HAS_ROLE")
            if not (source and target):
                continue

            if rel_type == "CAN_ASSUME":
                edge_props = {
                    "principal": trust.get("principal", source),
                    "condition": str(trust.get("condition", {})),
                    "is_cross_account": trust.get("is_cross_account", False),
                }
            else:
                edge_props = {
                    "scope": trust.get("scope", ""),
                    "condition": str(trust.get("condition", {})),
                }

            success = await self.neo4j.upsert_edge(source, target, rel_type, edge_props)
            if success:
                edges_created += 1

        return {"nodes": nodes_created, "edges": edges_created}

    # ─── Kubernetes ───────────────────────────────────────────────────────────

    async def _ingest_k8s(self, data: Any) -> Dict:
        nodes_created = 0
        edges_created = 0

        for sa in data.service_accounts:
            node_id = f"k8s:sa:{sa['namespace']}:{sa['name']}"
            props = {
                "id": node_id,
                "name": sa["name"],
                "namespace": sa["namespace"],
                "provider": "k8s",
                "node_type": "k8s_service_account",
                "privilege_level": 2,
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "K8sServiceAccount"], props)
            nodes_created += 1

        for trust in data.trust_relationships:
            is_high_risk = trust.get("is_high_risk", False)
            await self.neo4j.upsert_edge(
                trust["source"], trust["target"], "BOUND_TO",
                {
                    "namespace": trust.get("namespace"),
                    "binding_name": trust.get("binding_name"),
                    "is_high_risk": is_high_risk,
                },
            )
            edges_created += 1

        return {"nodes": nodes_created, "edges": edges_created}

    # ─── Public Interface ─────────────────────────────────────────────────────

    async def ingest_collected_data(self, all_data: Dict[str, Any]) -> Dict:
        """
        Ingest data from all providers.
        Clears existing provider data before re-ingesting.
        """
        total_nodes = 0
        total_edges = 0

        ingest_map = {
            "aws": self._ingest_aws,
            "azure": self._ingest_azure,
            "gcp": self._ingest_gcp,
            "k8s": self._ingest_k8s,
        }

        for provider, data in all_data.items():
            if provider not in ingest_map:
                continue
            logger.info(f"Ingesting {provider.upper()} data into graph")
            await self.neo4j.clear_provider_data(provider)
            stats = await ingest_map[provider](data)
            total_nodes += stats["nodes"]
            total_edges += stats["edges"]
            logger.info(f"{provider.upper()}: {stats['nodes']} nodes, {stats['edges']} edges")

        return {"nodes": total_nodes, "edges": total_edges}

    async def build_graph(
        self,
        cloud_provider: Optional[str] = None,
        account_id: Optional[str] = None,
        depth: int = 3,
        min_trust_score: float = 0.0,
    ) -> Dict:
        """Query Neo4j and return graph data for visualization."""
        query = """
        MATCH (n:Identity)
        WHERE ($provider IS NULL OR n.provider = $provider)
          AND ($account IS NULL OR n.account_id = $account)
          AND n.risk_score >= $min_score
        WITH n LIMIT 500
        OPTIONAL MATCH (n)-[r]->(m:Identity)
        WHERE ($provider IS NULL OR m.provider = $provider)
        RETURN
            collect(DISTINCT {
                node_id: n.id, name: n.name, cloud_provider: n.provider,
                node_type: n.node_type, risk_score: n.risk_score,
                trust_score: n.risk_score
            }) AS nodes,
            [e IN collect(DISTINCT CASE WHEN r IS NOT NULL THEN {
                source_id: startNode(r).id, target_id: endNode(r).id,
                relationship_type: type(r), properties: properties(r)
            } END) WHERE e IS NOT NULL] AS edges
        """
        records = await self.neo4j.run_query(query, {
            "provider": cloud_provider,
            "account": account_id,
            "min_score": min_trust_score,
        })
        if not records:
            return {"nodes": [], "edges": []}
        return {
            "nodes": records[0].get("nodes", []),
            "edges": records[0].get("edges", []),
        }

    async def build_subgraph(
        self, center_node_id: str, depth: int = 2, direction: str = "both"
    ) -> Dict:
        """Build a subgraph centered on a specific node."""
        if direction == "outbound":
            rel_pattern = f"(center)-[r*1..{depth}]->(neighbor)"
        elif direction == "inbound":
            rel_pattern = f"(center)<-[r*1..{depth}]-(neighbor)"
        else:
            rel_pattern = f"(center)-[r*1..{depth}]-(neighbor)"

        query = f"""
        MATCH (center:Identity {{id: $center_id}})
        MATCH {rel_pattern}
        RETURN
            collect(DISTINCT {{
                id: neighbor.id, name: neighbor.name,
                provider: neighbor.provider, risk_score: neighbor.risk_score,
                node_type: neighbor.node_type
            }}) AS nodes,
            collect(DISTINCT {{
                source: startNode(last(r)).id,
                target: endNode(last(r)).id,
                type: type(last(r))
            }}) AS edges
        """
        records = await self.neo4j.run_query(query, {"center_id": center_node_id})
        if not records:
            return {"nodes": [], "edges": []}
        return {
            "nodes": [{"id": center_node_id}] + records[0].get("nodes", []),
            "edges": records[0].get("edges", []),
        }

    async def compute_stats(self, cloud_provider: Optional[str] = None) -> Dict:
        """Compute graph-level statistics for the dashboard."""
        stats = await self.neo4j.get_graph_statistics()
        risk_stats = await self.neo4j.get_risk_statistics(cloud_provider=cloud_provider)
        return {
        "total_nodes": stats.get("node_count", 0),
        "total_edges": stats.get("edge_count", 0),
        "avg_trust_score": risk_stats["avg_risk"],
        "high_risk_nodes": risk_stats["high_risk_count"],
        "escalation_path_count": 0,
        "cloud_provider": cloud_provider,
    }

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _aws_user_privilege(self, user: Dict) -> int:
        policies = [p["PolicyName"] for p in user.get("AttachedPolicies", [])]
        if "AdministratorAccess" in policies:
            return 5
        if any("Admin" in p or "FullAccess" in p for p in policies):
            return 4
        if any("ReadOnly" in p for p in policies):
            return 1
        return 2

    def _aws_role_privilege(self, role: Dict) -> int:
        policies = [p["PolicyName"] for p in role.get("AttachedPolicies", [])]
        if "AdministratorAccess" in policies:
            return 5
        if any("Admin" in p or "FullAccess" in p for p in policies):
            return 4
        return 3

    def _has_wildcard_policy(self, entity: Dict) -> bool:
        for policy in entity.get("InlinePolicies", []):
            doc = policy.get("PolicyDocument", {})
            for stmt in doc.get("Statement", []):
                if stmt.get("Action") == "*" and stmt.get("Resource") == "*":
                    return True
        return False