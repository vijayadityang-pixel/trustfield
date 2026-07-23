"""
Fixture test for _ingest_k8s / _compute_k8s_escalation_primitives.

Uses the EXACT method bodies from ingest_k8s_fixed.py (pasted verbatim
below, not retyped) wrapped in a minimal harness with an in-memory mock
Neo4j client, so we can verify the escalation-primitive heuristics against
known ground truth before trusting them against a real cluster.
"""

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List


# ─── Mock risk_scorer (module-level, matching how graph_builder.py calls it) ──
class _MockRiskScorer:
    def score_node(self, props: Dict) -> float:
        return round(props.get("privilege_level", 1) / 5.0, 2)

risk_scorer = _MockRiskScorer()


# ─── Mock Neo4j client ─────────────────────────────────────────────────────
class MockNeo4j:
    """
    In-memory stand-in for Neo4jClient. Only implements the exact query
    patterns _ingest_k8s / _compute_k8s_escalation_primitives actually use -
    not a general Cypher engine. Good enough to validate ingestion logic
    without a real database.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict] = {}
        self.edges: List[Dict] = []
        self.orphan_edge_endpoints: set = set()

    async def upsert_node(self, node_id, labels, props):
        self.nodes[node_id] = {**props, "_labels": labels}

    async def upsert_edge(self, source, target, rel_type, props):
        # Real Neo4j MERGE creates bare stub nodes for missing endpoints -
        # replicate that so we can detect it, same as the Week 2 bug class.
        for endpoint in (source, target):
            if endpoint not in self.nodes:
                self.orphan_edge_endpoints.add(endpoint)
        self.edges.append({"source": source, "target": target, "type": rel_type, **props})

    async def run_write_query(self, query, parameters=None):
        if "SET i.privilege_level = max_priv" in query:
            for node_id, node in self.nodes.items():
                if "Identity" not in node["_labels"] or node.get("provider") != "k8s":
                    continue
                bound_role_privs = [
                    self.nodes[e["target"]]["privilege_level"]
                    for e in self.edges
                    if e["type"] == "BOUND_TO" and e["source"] == node_id
                    and e["target"] in self.nodes
                    and "Role" in self.nodes[e["target"]]["_labels"]
                ]
                if bound_role_privs:
                    node["privilege_level"] = max(bound_role_privs)
        elif "SET i.risk_score" in query:
            for node in self.nodes.values():
                if "Identity" in node["_labels"] and node.get("provider") == "k8s":
                    if node.get("privilege_level", 0) >= 4:
                        node["risk_score"] = max(node.get("risk_score", 0), 0.7)

    async def run_query(self, query, parameters=None):
        if "i.privilege_level >= 4" in query and "RETURN i.id" in query:
            return [
                {"id": nid, "node_type": n["node_type"]}
                for nid, n in self.nodes.items()
                if "Identity" in n["_labels"] and n.get("provider") == "k8s"
                and n.get("privilege_level", 0) >= 4
            ]
        return []


# ─── GraphBuilder under test (exact code from ingest_k8s_fixed.py) ────────
class GraphBuilder:
    def __init__(self, neo4j):
        self.neo4j = neo4j

    # ─── Kubernetes ────────────────────────────────────────────────────

    _K8S_HIGH_RISK_ROLE_NAMES = {"cluster-admin", "admin", "edit"}

    @classmethod
    def _k8s_role_privilege(cls, role: Dict, is_cluster_role: bool) -> int:
        name = role.get("name", "")
        rules = role.get("rules") or []
        is_wildcard = any(
            "*" in (r.get("resources") or []) or "*" in (r.get("verbs") or [])
            for r in rules
        )
        if name in cls._K8S_HIGH_RISK_ROLE_NAMES or is_wildcard:
            return 5
        return 3 if is_cluster_role else 2

    _K8S_IMPERSONATE_RESOURCES = {"users", "groups", "serviceaccounts"}
    _K8S_BIND_RESOURCES = {"roles", "clusterroles"}
    _K8S_ESCALATE_RESOURCES = {"roles", "clusterroles"}

    @staticmethod
    def _k8s_matching_rules(rules: List[Dict], verb: str, resource_set: set) -> List[Dict]:
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
                                        {"verb": verb, "synthetic": True},
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
                                    {"verb": f"{verb}_unrestricted", "synthetic": True},
                                )
                                edges_created += 1

        return edges_created

    async def _ingest_k8s(self, data: Any) -> Dict:
        nodes_created = 0
        edges_created = 0

        for sa in data.service_accounts:
            node_id = sa["node_id"]
            props = {
                "id": node_id, "name": sa["name"], "namespace": sa["namespace"],
                "provider": "k8s", "node_type": "k8s_service_account", "privilege_level": 1,
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", "K8sServiceAccount"], props)
            nodes_created += 1

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
                "id": node_id, "name": name, "provider": "k8s",
                "node_type": f"k8s_{kind.lower()}", "privilege_level": 1,
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Identity", f"K8s{kind}"], props)
            nodes_created += 1

        for role in data.roles:
            node_id = role["node_id"]
            privilege = self._k8s_role_privilege(role, is_cluster_role=False)
            role["privilege_level"] = privilege  # so Pass 5 can read it back off data.roles
            props = {
                "id": node_id, "name": role["name"], "namespace": role["namespace"],
                "provider": "k8s", "node_type": "k8s_role", "privilege_level": privilege,
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Role", "K8sRole"], props)
            nodes_created += 1

        for cr in data.cluster_roles:
            node_id = cr["node_id"]
            privilege = self._k8s_role_privilege(cr, is_cluster_role=True)
            cr["privilege_level"] = privilege  # so Pass 5 can read it back off data.cluster_roles
            props = {
                "id": node_id, "name": cr["name"], "provider": "k8s",
                "node_type": "k8s_cluster_role", "privilege_level": privilege,
                "rules_may_be_incomplete": cr.get("rules_may_be_incomplete", False),
            }
            props["risk_score"] = risk_scorer.score_node(props)
            await self.neo4j.upsert_node(node_id, ["Role", "K8sClusterRole"], props)
            nodes_created += 1

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

        await self.neo4j.run_write_query(
            """
            MATCH (i:Identity)-[:BOUND_TO]->(r:Role)
            WHERE i.provider = 'k8s'
            WITH i, max(r.privilege_level) AS max_priv
            SET i.privilege_level = max_priv
            """
        )
        await self.neo4j.run_write_query(
            """
            MATCH (i:Identity)
            WHERE i.provider = 'k8s' AND i.privilege_level >= 4
            SET i.risk_score = CASE WHEN i.risk_score < 0.7 THEN 0.7 ELSE i.risk_score END
            """
        )

        edges_created += await self._compute_k8s_escalation_primitives(data)

        return {"nodes": nodes_created, "edges": edges_created}


# ─── Fixture ────────────────────────────────────────────────────────────
def build_fixture():
    namespaces = ["default", "ns-a"]

    service_accounts = [
        {"node_id": "default:build-bot", "name": "build-bot", "namespace": "default"},
        {"node_id": "default:admin-sa", "name": "admin-sa", "namespace": "default"},
        {"node_id": "ns-a:worker", "name": "worker", "namespace": "ns-a"},
        {"node_id": "default:helper", "name": "helper", "namespace": "default"},
        {"node_id": "default:helper2", "name": "helper2", "namespace": "default"},
        {"node_id": "default:super-helper", "name": "super-helper", "namespace": "default"},
    ]

    roles = [
        {"node_id": "default:editor", "name": "editor", "namespace": "default",
         "rules": [{"resources": ["pods"], "verbs": ["get", "list"], "resource_names": []}]},
        {"node_id": "default:secret-admin", "name": "secret-admin", "namespace": "default",
         "rules": [{"resources": ["*"], "verbs": ["*"], "resource_names": []}]},
        {"node_id": "default:bind-secret-admin-role", "name": "bind-secret-admin-role", "namespace": "default",
         "rules": [{"resources": ["roles"], "verbs": ["bind"], "resource_names": ["secret-admin"]}]},
    ]

    cluster_roles = [
        {"node_id": "cluster-admin", "name": "cluster-admin",
         "rules": [{"resources": ["*"], "verbs": ["*"], "resource_names": []}]},
        {"node_id": "impersonator", "name": "impersonator",
         "rules": [{"resources": ["serviceaccounts"], "verbs": ["impersonate"], "resource_names": ["admin-sa"]}]},
        {"node_id": "unrestricted-impersonator", "name": "unrestricted-impersonator",
         "rules": [{"resources": ["users"], "verbs": ["impersonate"], "resource_names": []}]},
        {"node_id": "escalate-cr", "name": "escalate-cr",
         "rules": [{"resources": ["clusterroles"], "verbs": ["escalate"], "resource_names": ["cluster-admin"]}]},
        {"node_id": "any-bind", "name": "any-bind",
         "rules": [{"resources": ["roles", "clusterroles"], "verbs": ["bind"], "resource_names": []}]},
    ]

    trust_relationships = [
        {"source": "default:build-bot", "source_kind": "ServiceAccount", "target": "default:editor",
         "target_kind": "Role", "namespace": "default", "binding_name": "b1"},
        {"source": "default:admin-sa", "source_kind": "ServiceAccount", "target": "cluster-admin",
         "target_kind": "ClusterRole", "namespace": "cluster", "binding_name": "b2"},
        {"source": "ns-a:worker", "source_kind": "ServiceAccount", "target": "impersonator",
         "target_kind": "ClusterRole", "namespace": "cluster", "binding_name": "b3"},
        {"source": "user:alice", "source_kind": "User", "target": "cluster-admin",
         "target_kind": "ClusterRole", "namespace": "cluster", "binding_name": "b4"},
        {"source": "default:build-bot", "source_kind": "ServiceAccount", "target": "unrestricted-impersonator",
         "target_kind": "ClusterRole", "namespace": "cluster", "binding_name": "b5"},
        {"source": "default:helper", "source_kind": "ServiceAccount", "target": "default:bind-secret-admin-role",
         "target_kind": "Role", "namespace": "default", "binding_name": "b6"},
        {"source": "default:helper2", "source_kind": "ServiceAccount", "target": "escalate-cr",
         "target_kind": "ClusterRole", "namespace": "cluster", "binding_name": "b7"},
        {"source": "default:super-helper", "source_kind": "ServiceAccount", "target": "any-bind",
         "target_kind": "ClusterRole", "namespace": "cluster", "binding_name": "b8"},
    ]

    return SimpleNamespace(
        namespaces=namespaces,
        service_accounts=service_accounts,
        roles=roles,
        cluster_roles=cluster_roles,
        trust_relationships=trust_relationships,
    )


async def main():
    mock = MockNeo4j()
    gb = GraphBuilder(mock)
    data = build_fixture()

    stats = await gb._ingest_k8s(data)
    print(f"stats: {stats}\n")

    print("=== Final privilege levels ===")
    for nid, n in sorted(mock.nodes.items()):
        if "Identity" in n["_labels"]:
            print(f"  {nid:35s} priv={n['privilege_level']} risk={n.get('risk_score')}")

    print("\n=== BOUND_TO edges ===")
    for e in mock.edges:
        if e["type"] == "BOUND_TO":
            print(f"  {e['source']:25s} -> {e['target']}")

    print("\n=== Synthetic CAN_ASSUME edges (impersonate) ===")
    for e in mock.edges:
        if e["type"] == "CAN_ASSUME":
            print(f"  {e['source']:25s} -> {e['target']:25s} reason={e['reason']}")

    print("\n=== Synthetic CAN_ESCALATE_VIA edges (bind/escalate) ===")
    for e in mock.edges:
        if e["type"] == "CAN_ESCALATE_VIA":
            print(f"  {e['source']:25s} -> {e['target']:25s} verb={e['verb']}")

    print("\n=== Checks ===")
    self_loops = [e for e in mock.edges if e["source"] == e["target"]]
    print(f"Self-loop edges: {len(self_loops)}")
    for e in self_loops:
        print(f"  BUG: {e}")

    print(f"Orphan edge endpoints (nodes referenced but never created): {mock.orphan_edge_endpoints}")

    # Ground-truth assertions for the deliberately-restricted cases
    def has_edge(src, tgt, etype, **props):
        return any(
            e["source"] == src and e["target"] == tgt and e["type"] == etype
            and all(e.get(k) == v for k, v in props.items())
            for e in mock.edges
        )

    checks = [
        ("worker impersonates admin-sa (cross-namespace resolved via ClusterRole)",
         has_edge("ns-a:worker", "default:admin-sa", "CAN_ASSUME", reason="impersonate")),
        ("worker does NOT impersonate a nonexistent ns-a:admin-sa",
         not any(e["source"] == "ns-a:worker" and e["target"] == "ns-a:admin-sa" for e in mock.edges)),
        ("build-bot impersonates alice (unrestricted, users kind)",
         has_edge("default:build-bot", "user:alice", "CAN_ASSUME", reason="impersonate_unrestricted")),
        ("helper can CAN_ESCALATE_VIA secret-admin (restricted bind, namespaced Role)",
         has_edge("default:helper", "default:secret-admin", "CAN_ESCALATE_VIA", verb="bind")),
        ("helper2 can CAN_ESCALATE_VIA cluster-admin (restricted escalate, bare ClusterRole id)",
         has_edge("default:helper2", "cluster-admin", "CAN_ESCALATE_VIA", verb="escalate")),
        ("super-helper unrestricted-bind fans out to secret-admin",
         has_edge("default:super-helper", "default:secret-admin", "CAN_ESCALATE_VIA", verb="bind_unrestricted")),
        ("super-helper unrestricted-bind fans out to cluster-admin",
         has_edge("default:super-helper", "cluster-admin", "CAN_ESCALATE_VIA", verb="bind_unrestricted")),
        ("no orphan edge endpoints (every edge endpoint has a real node)",
         len(mock.orphan_edge_endpoints) == 0),
    ]
    all_pass = True
    for label, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
        all_pass = all_pass and ok

    print(f"\n{'ALL CHECKS PASSED' if all_pass else 'SOME CHECKS FAILED'}")
    print(f"Self-loops found: {len(self_loops)} -> {'ISSUE TO FIX' if self_loops else 'none'}")


if __name__ == "__main__":
    asyncio.run(main())