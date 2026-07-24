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

    # Roles/names considered high-risk even without wildcard rules visible
    # (mirrors K8sCollector.HIGH_RISK_ROLE_NAMES - kept in sync manually).
    _K8S_HIGH_RISK_ROLE_NAMES = {"cluster-admin", "admin", "edit"}

    @classmethod
    def _k8s_role_privilege(cls, role: Dict, is_cluster_role: bool) -> int:
        """
        Heuristic privilege score for a Role/ClusterRole, used to seed
        risk scoring and to propagate privilege onto bound identities.
        Same tier scheme as AWS/Azure/GCP role privilege (1-5).
        """
        name = role.get("name", "")
        rules = role.get("rules") or []
        is_wildcard = any(
            "*" in (r.get("resources") or []) or "*" in (r.get("verbs") or [])
            for r in rules
        )
        if name in cls._K8S_HIGH_RISK_ROLE_NAMES or is_wildcard:
            return 5
        # ClusterRoles have cluster-wide blast radius even without wildcard
        # rules, so they start a tier above an equivalent namespaced Role.
        return 3 if is_cluster_role else 2

    # K8s RBAC's built-in escalation primitives - verbs that exist
    # specifically because they bypass the normal "can't grant what you
    # don't have" check, so holding them is itself the finding.
    _K8S_IMPERSONATE_RESOURCES = {"users", "groups", "serviceaccounts"}
    _K8S_BIND_RESOURCES = {"roles", "clusterroles"}
    _K8S_ESCALATE_RESOURCES = {"roles", "clusterroles"}

    @staticmethod
    def _k8s_matching_rules(rules: List[Dict], verb: str, resource_set: set) -> List[Dict]:
        """Rules granting `verb` (or '*') on any resource in `resource_set` (or '*')."""
        matches = []
        for rule in rules or []:
            verbs = set(rule.get("verbs") or [])
            resources = set(rule.get("resources") or [])
            if verb not in verbs and "*" not in verbs:
                continue
            if not (resource_set & resources) and "*" not in resources:
                continue
            matches.append(rule)
        return matches

    async def _compute_k8s_escalation_primitives(self, data: Any) -> int:
        """
        Detect impersonate/bind/escalate verb grants and emit synthetic
        edges so they're visible to detectors, instead of silently sitting
        unused in each role's `rules` list.

          - impersonate -> synthetic CAN_ASSUME straight to the
            impersonated Identity. Reuses find_privilege_escalation_paths()
            for free since CAN_ASSUME is already in its pattern.
          - bind / escalate -> synthetic CAN_ESCALATE_VIA to the
            Role/ClusterRole itself, since the target isn't an existing
            Identity. Needs its own detector (find_k8s_escalation_primitives).

        Heuristic simplifications - flag in the Week 8 limitations writeup:
          - A ClusterRole granting impersonate/bind on a *namespaced*
            resource can't be resolved to one namespace, so we check the
            resourceName against every known namespace and connect to
            whichever targets actually exist. May under- or over-connect
            versus real cluster behavior.
          - "Unrestricted" grants (no resourceNames) are capped to targets
            that are already privilege_level >= 4, to avoid an edge-count
            blowup rather than connecting to every identity/role in the
            cluster. This likely under-reports the true blast radius of an
            unrestricted grant - worth revisiting if false negatives show
            up in testing.
        """
        edges_created = 0

        role_by_id = {r["node_id"]: r for r in data.roles}
        cluster_role_by_id = {r["node_id"]: r for r in data.cluster_roles}
        sa_ids = {sa["node_id"] for sa in data.service_accounts}

        high_priv = await self.neo4j.run_query(
            """
            MATCH (i:Identity)
            WHERE i.provider = 'k8s' AND i.privilege_level >= 4
            RETURN i.id AS id, i.node_type AS node_type
            """,
            parameters={},
        )
        high_priv_by_kind: Dict[str, List[str]] = {}
        for rec in high_priv:
            high_priv_by_kind.setdefault(rec["node_type"], []).append(rec["id"])

        for trust in data.trust_relationships:
            if trust.get("source_kind") not in ("ServiceAccount", "User", "Group"):
                continue
            identity_id = trust["source"]
            role_id = trust["target"]
            is_cluster_role = trust.get("target_kind") == "ClusterRole"
            role = (cluster_role_by_id if is_cluster_role else role_by_id).get(role_id)
            if not role:
                continue
            rules = role.get("rules") or []

            # ── impersonate ──
            for rule in self._k8s_matching_rules(rules, "impersonate", self._K8S_IMPERSONATE_RESOURCES):
                resource_names = rule.get("resource_names") or []
                rule_resources = set(rule.get("resources") or [])
                kinds = self._K8S_IMPERSONATE_RESOURCES if "*" in rule_resources else (
                    rule_resources & self._K8S_IMPERSONATE_RESOURCES
                )
                for kind in kinds:
                    node_type = {
                        "serviceaccounts": "k8s_service_account",
                        "users": "k8s_user",
                        "groups": "k8s_group",
                    }[kind]
                    if resource_names:
                        for name in resource_names:
                            target_ids = []
                            if kind == "serviceaccounts":
                                if is_cluster_role:
                                    target_ids = [
                                        f"{ns}:{name}" for ns in data.namespaces
                                        if f"{ns}:{name}" in sa_ids
                                    ]
                                else:
                                    cand = f"{role['namespace']}:{name}"
                                    target_ids = [cand] if cand in sa_ids else []
                            elif kind == "users":
                                target_ids = [f"user:{name}"]
                            elif kind == "groups":
                                target_ids = [f"group:{name}"]
                            for target_id in target_ids:
                                await self.neo4j.upsert_edge(
                                    identity_id, target_id, "CAN_ASSUME",
                                    {"synthetic": True, "reason": "impersonate", "via_role": role_id},
                                )
                                edges_created += 1
                    else:
                        for target_id in high_priv_by_kind.get(node_type, []):
                            if target_id == identity_id:
                                continue  # don't emit "X can impersonate X"
                            await self.neo4j.upsert_edge(
                                identity_id, target_id, "CAN_ASSUME",
                                {"synthetic": True, "reason": "impersonate_unrestricted", "via_role": role_id},
                            )
                            edges_created += 1

            # ── bind / escalate ──
            for verb, resource_set in (
                ("bind", self._K8S_BIND_RESOURCES),
                ("escalate", self._K8S_ESCALATE_RESOURCES),
            ):
                for rule in self._k8s_matching_rules(rules, verb, resource_set):
                    resource_names = rule.get("resource_names") or []
                    rule_resources = set(rule.get("resources") or [])
                    if "*" in rule_resources:
                        rule_resources = resource_set
                    targets_cluster_roles = "clusterroles" in rule_resources
                    targets_roles = "roles" in rule_resources

                    if resource_names:
                        for name in resource_names:
                            candidate_ids = []
                            if targets_cluster_roles:
                                candidate_ids.append(name)
                            if targets_roles:
                                if is_cluster_role:
                                    candidate_ids += [f"{ns}:{name}" for ns in data.namespaces]
                                else:
                                    candidate_ids.append(f"{role['namespace']}:{name}")
                            for candidate_id in candidate_ids:
                                if candidate_id in role_by_id or candidate_id in cluster_role_by_id:
                                    await self.neo4j.upsert_edge(
                                        identity_id, candidate_id, "CAN_ESCALATE_VIA",
                                        {"verb": verb, "synthetic": True,"via_role": role_id},
                                    )
                                    edges_created += 1
                    else:
                        pool = {}
                        if targets_cluster_roles:
                            pool.update(cluster_role_by_id)
                        if targets_roles:
                            pool.update(role_by_id)
                        for other_id, other_role in pool.items():
                            if other_role.get("privilege_level", 0) >= 4 and other_id != role_id:
                                await self.neo4j.upsert_edge(
                                    identity_id, other_id, "CAN_ESCALATE_VIA",
                                    {"verb": f"{verb}_unrestricted", "synthetic": True, "via_role": role_id},
                                )
                                edges_created += 1

        return edges_created

    async def _ingest_k8s(self, data: Any) -> Dict:
        nodes_created = 0
        edges_created = 0

        # ── Pass 1: identity nodes (ServiceAccounts) ──
        for sa in data.service_accounts:
            node_id = sa["node_id"]  # reuse collector's ID, don't re-derive
            props = {
                "id": node_id,
                "name": sa["name"],
                "namespace": sa["namespace"],
                "provider": "k8s",
                "node_type": "k8s_service_account",
                "privilege_level": 1,  # baseline; corrected in pass 3 below
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "K8sServiceAccount"], props)
            nodes_created += 1

        # ── Pass 1b: identity nodes for User/Group subjects ──
        # Kubernetes has no "list users" API - Users and Groups only exist
        # as names referenced inside bindings. Derive the distinct set from
        # trust_relationships so they get real nodes instead of becoming
        # bare MERGE stubs when edges are ingested.
        seen_subject_ids = set()
        for trust in data.trust_relationships:
            kind = trust.get("source_kind")
            if kind not in ("User", "Group"):
                continue
            node_id = trust["source"]
            if node_id in seen_subject_ids:
                continue
            seen_subject_ids.add(node_id)
            name = node_id.split(":", 1)[1]
            props = {
                "id": node_id,
                "name": name,
                "provider": "k8s",
                "node_type": f"k8s_{kind.lower()}",
                "privilege_level": 1,  # corrected in pass 3
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", f"K8s{kind}"], props)
            nodes_created += 1

        # ── Pass 2: role nodes (Roles + ClusterRoles) ──
        for role in data.roles:
            node_id = role["node_id"]
            privilege = self._k8s_role_privilege(role, is_cluster_role=False)
            role["privilege_level"] = privilege  # so Pass 5 can read it back off data.roles
            props = {
                "id": node_id,
                "name": role["name"],
                "namespace": role["namespace"],
                "provider": "k8s",
                "node_type": "k8s_role",
                "privilege_level": privilege,
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Role", "K8sRole"], props)
            nodes_created += 1

        for cr in data.cluster_roles:
            node_id = cr["node_id"]
            privilege = self._k8s_role_privilege(cr, is_cluster_role=True)
            cr["privilege_level"] = privilege  # so Pass 5 can read it back off data.cluster_roles
            props = {
                "id": node_id,
                "name": cr["name"],
                "provider": "k8s",
                "node_type": "k8s_cluster_role",
                "privilege_level": privilege,
                "rules_may_be_incomplete": cr.get("rules_may_be_incomplete", False),
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Role", "K8sClusterRole"], props)
            nodes_created += 1

        # ── Pass 3: edges ──
        for trust in data.trust_relationships:
            await self.neo4j.upsert_edge(
                trust["source"], trust["target"], "BOUND_TO",
                {
                    "namespace": trust.get("namespace"),
                    "binding_name": trust.get("binding_name"),
                    "is_high_risk": trust.get("is_high_risk", False),
                    "is_wildcard_role": trust.get("is_wildcard_role", False),
                },
            )
            edges_created += 1

        # ── Pass 4: propagate privilege from bound roles onto identities ──
        # Same principal_max_privilege pattern used to fix Azure/GCP in
        # Week 4 - without this, every identity keeps the privilege_level=1
        # baseline from pass 1 regardless of what it's actually bound to.
        await self.neo4j.run_write_query(
            """
            MATCH (i:Identity)-[:BOUND_TO]->(r:Role)
            WHERE i.provider = 'k8s'
            WITH i, max(r.privilege_level) AS max_priv
            SET i.privilege_level = max_priv
            """
        )
        # risk_score depends on privilege_level, so recompute for k8s
        # identities now that privilege has been propagated. If risk_scorer
        # needs full node props (not just id), swap this for a fetch +
        # score_node + upsert_node loop instead of raw Cypher.
        await self.neo4j.run_write_query(
            """
            MATCH (i:Identity)
            WHERE i.provider = 'k8s' AND i.privilege_level >= 4
            SET i.risk_score = CASE WHEN i.risk_score < 0.7 THEN 0.7 ELSE i.risk_score END
            """
        )

        # ── Pass 5: escalation primitives (impersonate/bind/escalate) ──
        # Must run after pass 4 - "unrestricted" grant fan-out depends on
        # privilege_level already being propagated onto Identity nodes.
        edges_created += await self._compute_k8s_escalation_primitives(data)

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