"""
TrustField - Kubernetes RBAC Collector
Collects K8s service accounts, roles, cluster roles, and bindings.
"""

import asyncio
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)

# Roles that are high-risk by name alone, even if TrustField can't see their
# rules (e.g. built-in ClusterRoles whose manifests aren't reproduced here).
HIGH_RISK_ROLE_NAMES = {"cluster-admin", "admin", "edit"}


@dataclass
class K8sRBACData:
    """Container for all collected Kubernetes RBAC data."""
    provider: str = "k8s"
    service_accounts: List[Dict] = field(default_factory=list)
    roles: List[Dict] = field(default_factory=list)
    cluster_roles: List[Dict] = field(default_factory=list)
    role_bindings: List[Dict] = field(default_factory=list)
    cluster_role_bindings: List[Dict] = field(default_factory=list)
    trust_relationships: List[Dict] = field(default_factory=list)
    namespaces: List[str] = field(default_factory=list)
    cluster_name: str = ""
    errors: List[str] = field(default_factory=list)


class K8sCollector:
    """
    Collects Kubernetes RBAC data for trust graph construction.
    Supports in-cluster config (when running inside K8s) and kubeconfig file.
    """

    def __init__(
        self,
        kubeconfig_path: Optional[str] = None,
        context: Optional[str] = None,
        in_cluster: bool = False,
    ):
        self.kubeconfig_path = kubeconfig_path
        self.context = context
        self.in_cluster = in_cluster
        self._v1: Optional[client.CoreV1Api] = None
        self._rbac_v1: Optional[client.RbacAuthorizationV1Api] = None

    def _init_clients(self):
        """Initialize Kubernetes API clients."""
        if self.in_cluster:
            config.load_incluster_config()
        elif self.kubeconfig_path:
            config.load_kube_config(
                config_file=self.kubeconfig_path,
                context=self.context,
            )
        else:
            config.load_kube_config(context=self.context)

        self._v1 = client.CoreV1Api()
        self._rbac_v1 = client.RbacAuthorizationV1Api()

    def _get_namespaces(self) -> List[str]:
        """List all namespaces in the cluster."""
        try:
            ns_list = self._v1.list_namespace()
            return [ns.metadata.name for ns in ns_list.items]
        except ApiException as exc:
            logger.warning(f"Could not list namespaces: {exc}")
            return ["default"]

    # ------------------------------------------------------------------
    # Node ID helpers
    #
    # These are the single source of truth for how each RBAC object is
    # identified as a graph node / edge endpoint. _build_trust_relationships
    # must produce IDs that match these exactly, or edges will silently
    # fail to resolve against their nodes at ingest time.
    # ------------------------------------------------------------------

    @staticmethod
    def _service_account_id(namespace: str, name: str) -> str:
        return f"{namespace}:{name}"

    @staticmethod
    def _role_id(namespace: str, name: str) -> str:
        # Role names are only unique within a namespace - two different
        # Roles named "editor" in different namespaces are different
        # objects and must not collide into one node.
        return f"{namespace}:{name}"

    @staticmethod
    def _cluster_role_id(name: str) -> str:
        # ClusterRole names ARE cluster-wide unique, so no qualifier needed.
        return name

    @staticmethod
    def _subject_id(kind: str, name: str, namespace: Optional[str]) -> str:
        # ServiceAccounts are namespace-scoped identities - qualify them.
        # User and Group are cluster-scoped identities in Kubernetes RBAC
        # (there is no real per-namespace "user"), so they must NOT be
        # qualified with whatever namespace a particular binding happens to
        # live in. Doing so would fragment one real identity into multiple
        # graph nodes (e.g. "ns-a:alice" and "ns-b:alice" for the same
        # user), making cross-namespace escalation paths undetectable.
        if kind == "ServiceAccount":
            return f"{namespace}:{name}"
        return f"{kind.lower()}:{name}"

    def _collect_service_accounts(self, namespaces: List[str]) -> List[Dict]:
        """Collect service accounts from all namespaces."""
        service_accounts = []
        for ns in namespaces:
            try:
                sa_list = self._v1.list_namespaced_service_account(namespace=ns)
                for sa in sa_list.items:
                    service_accounts.append({
                        "node_id": self._service_account_id(sa.metadata.namespace, sa.metadata.name),
                        "name": sa.metadata.name,
                        "namespace": sa.metadata.namespace,
                        "uid": sa.metadata.uid,
                        "secrets": [s.name for s in (sa.secrets or [])],
                        "annotations": sa.metadata.annotations or {},
                        "labels": sa.metadata.labels or {},
                        "node_type": "k8s_service_account",
                        "provider": "k8s",
                    })
            except ApiException as exc:
                logger.warning(f"SA collection failed for ns {ns}: {exc}")
        return service_accounts

    def _collect_roles(self, namespaces: List[str]) -> List[Dict]:
        """Collect namespaced Roles."""
        roles = []
        for ns in namespaces:
            try:
                role_list = self._rbac_v1.list_namespaced_role(namespace=ns)
                for role in role_list.items:
                    roles.append({
                        "node_id": self._role_id(role.metadata.namespace, role.metadata.name),
                        "name": role.metadata.name,
                        "namespace": role.metadata.namespace,
                        "uid": role.metadata.uid,
                        "rules": [
                            {
                                "api_groups": r.api_groups or [],
                                "resources": r.resources or [],
                                "verbs": r.verbs or [],
                                # NOTE: previously missing entirely for namespaced
                                # Roles (only ClusterRole captured this) - meant
                                # every restricted grant (e.g. bind/escalate/
                                # impersonate limited to specific resourceNames)
                                # on a Role silently looked unrestricted downstream.
                                # Found via live-cluster test, not the fixture -
                                # the fixture hand-built role dicts with this
                                # field present, which didn't match real output.
                                "resource_names": r.resource_names or [],
                            }
                            for r in (role.rules or [])
                        ],
                        "node_type": "k8s_role",
                        "provider": "k8s",
                    })
            except ApiException as exc:
                logger.warning(f"Role collection failed for ns {ns}: {exc}")
        return roles

    def _collect_cluster_roles(self) -> List[Dict]:
        """Collect cluster-wide ClusterRoles."""
        cluster_roles = []
        try:
            cr_list = self._rbac_v1.list_cluster_role()
            for cr in cr_list.items:
                is_aggregated = bool(cr.aggregation_rule)
                rules = [
                    {
                        "api_groups": r.api_groups or [],
                        "resources": r.resources or [],
                        "verbs": r.verbs or [],
                        "resource_names": r.resource_names or [],
                    }
                    for r in (cr.rules or [])
                ]
                if is_aggregated and not rules:
                    # Kubernetes computes the effective rule set for
                    # aggregated ClusterRoles dynamically via label
                    # selector, at the control-plane level. The API object
                    # itself often reports an empty `rules` list even
                    # though real permissions apply. Flag this rather than
                    # silently treating the role as a no-op - it's a known
                    # detection gap, not a fixed-here bug.
                    logger.warning(
                        f"ClusterRole '{cr.metadata.name}' is aggregated with "
                        f"no directly-declared rules; effective permissions "
                        f"may be under-counted."
                    )
                cluster_roles.append({
                    "node_id": self._cluster_role_id(cr.metadata.name),
                    "name": cr.metadata.name,
                    "uid": cr.metadata.uid,
                    "rules": rules,
                    "aggregation_rule": is_aggregated,
                    "rules_may_be_incomplete": is_aggregated and not rules,
                    "node_type": "k8s_cluster_role",
                    "provider": "k8s",
                })
        except ApiException as exc:
            logger.warning(f"ClusterRole collection failed: {exc}")
        return cluster_roles

    def _collect_role_bindings(self, namespaces: List[str]) -> List[Dict]:
        """Collect namespaced RoleBindings."""
        bindings = []
        for ns in namespaces:
            try:
                rb_list = self._rbac_v1.list_namespaced_role_binding(namespace=ns)
                for rb in rb_list.items:
                    bindings.append({
                        "name": rb.metadata.name,
                        "namespace": rb.metadata.namespace,
                        "uid": rb.metadata.uid,
                        "role_ref": {
                            "kind": rb.role_ref.kind,
                            "name": rb.role_ref.name,
                            "api_group": rb.role_ref.api_group,
                        },
                        "subjects": [
                            {
                                "kind": s.kind,
                                "name": s.name,
                                "namespace": getattr(s, "namespace", ns),
                            }
                            for s in (rb.subjects or [])
                        ],
                        "node_type": "k8s_role_binding",
                        "provider": "k8s",
                    })
            except ApiException as exc:
                logger.warning(f"RoleBinding collection failed for ns {ns}: {exc}")
        return bindings

    def _collect_cluster_role_bindings(self) -> List[Dict]:
        """Collect cluster-wide ClusterRoleBindings."""
        bindings = []
        try:
            crb_list = self._rbac_v1.list_cluster_role_binding()
            for crb in crb_list.items:
                bindings.append({
                    "name": crb.metadata.name,
                    "uid": crb.metadata.uid,
                    "role_ref": {
                        "kind": crb.role_ref.kind,
                        "name": crb.role_ref.name,
                    },
                    "subjects": [
                        {
                            "kind": s.kind,
                            "name": s.name,
                            "namespace": getattr(s, "namespace", ""),
                        }
                        for s in (crb.subjects or [])
                    ],
                    "node_type": "k8s_cluster_role_binding",
                    "provider": "k8s",
                })
        except ApiException as exc:
            logger.warning(f"ClusterRoleBinding collection failed: {exc}")
        return bindings

    @staticmethod
    def _rules_are_wildcard(rules: List[Dict]) -> bool:
        """True if any rule grants '*' on resources or verbs (or both)."""
        for rule in rules or []:
            resources = rule.get("resources") or []
            verbs = rule.get("verbs") or []
            if "*" in resources or "*" in verbs:
                return True
        return False

    def _build_role_rules_lookup(
        self,
        roles: List[Dict],
        cluster_roles: List[Dict],
    ) -> Dict[str, Dict]:
        """
        Map (kind, node_id) -> role dict, so trust-relationship building can
        look up a role_ref's actual rules regardless of whether it's a
        namespaced Role or a cluster-wide ClusterRole.
        """
        lookup = {}
        for role in roles:
            lookup[("Role", role["node_id"])] = role
        for cr in cluster_roles:
            lookup[("ClusterRole", cr["node_id"])] = cr
        return lookup

    def _build_trust_relationships(
        self,
        role_bindings: List[Dict],
        cluster_role_bindings: List[Dict],
        roles: List[Dict],
        cluster_roles: List[Dict],
    ) -> List[Dict]:
        """
        Build trust edges from bindings:
        subject → (BOUND_TO) → role/clusterrole
        Flags high-risk bindings by name (cluster-admin/admin/edit) AND by
        actual wildcard rule content, since custom ClusterRoles with
        resources: ["*"], verbs: ["*"] are just as dangerous but wouldn't
        be caught by a name-only check.
        """
        rules_lookup = self._build_role_rules_lookup(roles, cluster_roles)
        edges = []

        for binding in role_bindings + cluster_role_bindings:
            role_kind = binding["role_ref"]["kind"]
            role_name = binding["role_ref"]["name"]
            binding_namespace = binding.get("namespace", "cluster")

            if role_kind == "ClusterRole":
                target_id = self._cluster_role_id(role_name)
            else:
                # A RoleBinding's role_ref of kind "Role" always refers to a
                # Role in the binding's own namespace.
                target_id = self._role_id(binding_namespace, role_name)

            role_obj = rules_lookup.get((role_kind, target_id))
            is_wildcard = self._rules_are_wildcard(role_obj["rules"]) if role_obj else False
            is_high_risk = role_name in HIGH_RISK_ROLE_NAMES or is_wildcard

            for subject in binding.get("subjects", []):
                source_id = self._subject_id(
                    subject["kind"], subject["name"], subject.get("namespace")
                )
                edges.append({
                    "source": source_id,
                    "source_kind": subject["kind"],
                    "target": target_id,
                    "target_kind": role_kind,
                    "relationship": "BOUND_TO",
                    "namespace": binding_namespace,
                    "is_high_risk": is_high_risk,
                    "is_wildcard_role": is_wildcard,
                    "binding_name": binding["name"],
                })

        return edges

    async def collect(self) -> K8sRBACData:
        """Main entry point: collect all K8s RBAC data asynchronously."""
        loop = asyncio.get_event_loop()
        data = K8sRBACData()

        try:
            await loop.run_in_executor(None, self._init_clients)
            logger.info("Kubernetes clients initialized")

            data.namespaces = await loop.run_in_executor(None, self._get_namespaces)
            logger.info(f"Found {len(data.namespaces)} namespaces")

            data.service_accounts = await loop.run_in_executor(
                None, self._collect_service_accounts, data.namespaces
            )
            logger.info(f"Collected {len(data.service_accounts)} service accounts")

            data.roles = await loop.run_in_executor(
                None, self._collect_roles, data.namespaces
            )
            logger.info(f"Collected {len(data.roles)} roles")

            data.cluster_roles = await loop.run_in_executor(
                None, self._collect_cluster_roles
            )
            logger.info(f"Collected {len(data.cluster_roles)} cluster roles")

            data.role_bindings = await loop.run_in_executor(
                None, self._collect_role_bindings, data.namespaces
            )
            logger.info(f"Collected {len(data.role_bindings)} role bindings")

            data.cluster_role_bindings = await loop.run_in_executor(
                None, self._collect_cluster_role_bindings
            )
            logger.info(f"Collected {len(data.cluster_role_bindings)} cluster role bindings")

            data.trust_relationships = self._build_trust_relationships(
                data.role_bindings,
                data.cluster_role_bindings,
                data.roles,
                data.cluster_roles,
            )
            logger.info(f"Extracted {len(data.trust_relationships)} trust relationships")

        except Exception as exc:
            msg = f"K8s collection failed: {exc}"
            logger.error(msg, exc_info=True)
            data.errors.append(msg)

        return data