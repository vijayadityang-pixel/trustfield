"""
TrustField - Kubernetes Containment Engine
Executes automated incident response actions against Kubernetes RBAC bindings.
"""

import asyncio
import logging
from typing import Any, Dict, Optional

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config

logger = logging.getLogger(__name__)

ACTION_REMOVE_ROLE_BINDING = "REMOVE_ROLE_BINDING"


def _parse_target_resource(target_resource: str) -> Dict[str, Optional[str]]:
    """
    Parses the composite target_resource ID produced by the K8s collector's
    node_id convention:
      - "k8s:rolebinding:<namespace>:<name>"        -> namespaced RoleBinding
      - "k8s:clusterrolebinding:<name>"              -> ClusterRoleBinding
    """
    parts = target_resource.split(":")
    if len(parts) == 4 and parts[0] == "k8s" and parts[1] == "rolebinding":
        return {"kind": "RoleBinding", "namespace": parts[2], "name": parts[3]}
    if len(parts) == 3 and parts[0] == "k8s" and parts[1] == "clusterrolebinding":
        return {"kind": "ClusterRoleBinding", "namespace": None, "name": parts[2]}
    raise ValueError(
        f"Invalid K8s target_resource format: {target_resource}. "
        "Expected 'k8s:rolebinding:<namespace>:<name>' or 'k8s:clusterrolebinding:<name>'"
    )


class K8sContainmentEngine:
    """
    Executes containment and remediation actions against Kubernetes RBAC.
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
        self._rbac_api: Optional[k8s_client.RbacAuthorizationV1Api] = None

    def _get_rbac_api(self) -> k8s_client.RbacAuthorizationV1Api:
        if not self._rbac_api:
            if self.in_cluster:
                k8s_config.load_incluster_config()
            else:
                k8s_config.load_kube_config(
                    config_file=self.kubeconfig_path, context=self.context
                )
            self._rbac_api = k8s_client.RbacAuthorizationV1Api()
        return self._rbac_api

    def _remove_role_binding(self, target_resource: str) -> Dict:
        """
        Deletes the RoleBinding/ClusterRoleBinding identified by
        target_resource. Fetches the manifest first so it's captured in the
        result for potential manual/automated rollback later (rollback isn't
        actually wired for any provider yet - this just avoids losing the
        data needed to do it).
        """
        rbac = self._get_rbac_api()
        parsed = _parse_target_resource(target_resource)

        if parsed["kind"] == "RoleBinding":
            manifest = rbac.read_namespaced_role_binding(
                name=parsed["name"], namespace=parsed["namespace"]
            )
            rbac.delete_namespaced_role_binding(
                name=parsed["name"], namespace=parsed["namespace"]
            )
            logger.warning(
                f"Removed RoleBinding {parsed['namespace']}/{parsed['name']}"
            )
        else:
            manifest = rbac.read_cluster_role_binding(name=parsed["name"])
            rbac.delete_cluster_role_binding(name=parsed["name"])
            logger.warning(f"Removed ClusterRoleBinding {parsed['name']}")

        return {
            "action": ACTION_REMOVE_ROLE_BINDING,
            "target": target_resource,
            "kind": parsed["kind"],
            "removed_manifest": k8s_client.ApiClient().sanitize_for_serialization(manifest),
        }

    async def remove_role_binding(self, target_resource: str) -> Dict:
        """Remove a specific RoleBinding or ClusterRoleBinding."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._remove_role_binding, target_resource)

    async def execute(self, action_type: str, target_resource: str) -> Dict:
        """Dispatch the containment action to the appropriate handler."""
        dispatch = {
            ACTION_REMOVE_ROLE_BINDING: self.remove_role_binding,
        }

        handler = dispatch.get(action_type)
        if not handler:
            raise ValueError(
                f"Unknown K8s action type: {action_type}. Supported: {list(dispatch.keys())}"
            )
        return await handler(target_resource)