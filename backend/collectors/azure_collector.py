"""
TrustField - Azure IAM Collector
Collects Azure AD users, service principals, role assignments, and trust data.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.subscription import SubscriptionClient
from msgraph import GraphServiceClient
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph.generated.service_principals.service_principals_request_builder import ServicePrincipalsRequestBuilder

logger = logging.getLogger(__name__)

# --- Add near the top, after ESCALATION_TYPE_DESCRIPTIONS-style constants would go ---

# Actions that let a principal grant itself (or anyone) additional roles —
# i.e. Azure's equivalent of an AWS wildcard trust policy.
DANGEROUS_AZURE_ACTIONS = {
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/*/write",
    "Microsoft.Authorization/*",
    "*",
}

BUILTIN_HIGH_PRIVILEGE_ROLES = {"Owner", "Contributor", "User Access Administrator"}
@dataclass
class AzureIAMData:
    """Container for all collected Azure IAM data."""
    provider: str = "azure"
    users: List[Dict] = field(default_factory=list)
    service_principals: List[Dict] = field(default_factory=list)
    managed_identities: List[Dict] = field(default_factory=list)
    role_assignments: List[Dict] = field(default_factory=list)
    role_definitions: List[Dict] = field(default_factory=list)
    trust_relationships: List[Dict] = field(default_factory=list)
    subscription_id: str = ""
    tenant_id: str = ""
    errors: List[str] = field(default_factory=list)


class AzureCollector:
    """
    Collects Azure AD and RBAC data for trust graph construction.
    Supports DefaultAzureCredential (managed identity / CLI) and service principal auth.
    """

    def __init__(
        self,
        subscription_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
    ):
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._credential = None
        self._auth_client = None
        self._graph_client: Optional[GraphServiceClient] = None

    def _get_credential(self):
        if self._credential is None:
            if self.client_id and self.client_secret and self.tenant_id:
                self._credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                )
            else:
                self._credential = DefaultAzureCredential()
        return self._credential

    def _get_graph_client(self) -> GraphServiceClient:
        if not self._graph_client:
            self._graph_client = GraphServiceClient(credentials=self._get_credential())
        return self._graph_client

    def _get_auth_client(self) -> AuthorizationManagementClient:
        if not self._auth_client:
            self._auth_client = AuthorizationManagementClient(
                self._get_credential(), self.subscription_id
            )
        return self._auth_client

    def _resolve_subscription(self) -> str:
        """Resolve subscription ID if not explicitly provided."""
        if self.subscription_id:
            return self.subscription_id
        sub_client = SubscriptionClient(self._get_credential())
        subs = list(sub_client.subscriptions.list())
        if not subs:
            raise ValueError("No Azure subscriptions found for the given credentials.")
        sub_id = subs[0].subscription_id
        logger.info(f"Using Azure subscription: {sub_id}")
        return sub_id

    async def _collect_users_via_graph(self) -> List[Dict]:
        """
        Enumerate Azure AD users via Microsoft Graph SDK.
        Returns user objects with display name, UPN, and object ID.
        """
        try:
            graph = self._get_graph_client()

            # Select only needed fields
            query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
                select=["id", "displayName", "userPrincipalName", "accountEnabled"]
            )
            from kiota_abstractions.base_request_configuration import RequestConfiguration
            request_config = RequestConfiguration(query_parameters=query_params)

            result = await graph.users.get(request_configuration=request_config)
            users = result.value or []

            return [
                {
                    "id": u.id,
                    "displayName": u.display_name,
                    "userPrincipalName": u.user_principal_name,
                    "accountEnabled": u.account_enabled,
                    "node_type": "azure_user",
                    "provider": "azure",
                }
                for u in users
            ]
        except Exception as exc:
            logger.warning(f"Graph API user collection failed: {exc}")
            return []

    async def _collect_service_principals(self) -> List[Dict]:
        """Enumerate Azure AD service principals (app registrations & managed identities)."""
        try:
            graph = self._get_graph_client()

            query_params = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
                select=["id", "displayName", "appId", "servicePrincipalType", "accountEnabled"]
            )
            from kiota_abstractions.base_request_configuration import RequestConfiguration
            request_config = RequestConfiguration(query_parameters=query_params)

            result = await graph.service_principals.get(request_configuration=request_config)
            sps = result.value or []

            return [
                {
                    "id": sp.id,
                    "displayName": sp.display_name,
                    "appId": sp.app_id,
                    "servicePrincipalType": sp.service_principal_type,
                    "accountEnabled": sp.account_enabled,
                    "node_type": "azure_service_principal",
                    "provider": "azure",
                }
                for sp in sps
            ]
        except Exception as exc:
            logger.warning(f"Service principal collection failed: {exc}")
            return []

    def _collect_role_assignments(self, subscription_id: str) -> List[Dict]:
        """
        Enumerate all RBAC role assignments in the subscription.
        Each assignment links a principal to a role at a specific scope.
        """
        auth_client = self._get_auth_client()
        assignments = []
        try:
            for assignment in auth_client.role_assignments.list_for_subscription():
                assignments.append({
                    "id": assignment.id,
                    "name": assignment.name,
                    "principal_id": assignment.principal_id,
                    "principal_type": assignment.principal_type,
                    "role_definition_id": assignment.role_definition_id,
                    "scope": assignment.scope,
                    "node_type": "azure_role_assignment",
                    "provider": "azure",
                })
        except Exception as exc:
            logger.warning(f"Role assignment collection failed: {exc}")
        return assignments

    def _collect_role_definitions(self, subscription_id: str) -> List[Dict]:
        """Enumerate built-in and custom role definitions."""
        auth_client = self._get_auth_client()
        definitions = []
        try:
            scope = f"/subscriptions/{subscription_id}"
            for role_def in auth_client.role_definitions.list(scope):
                role_dict = {
                    "id": role_def.id,
                    "name": role_def.role_name,
                    "description": role_def.description,
                    "role_type": role_def.role_type,
                    "permissions": [
                        {
                            "actions": p.actions,
                            "not_actions": p.not_actions,
                            "data_actions": p.data_actions,
                        }
                        for p in (role_def.permissions or [])
                    ],
                    "node_type": "azure_role_definition",
                    "provider": "azure",
                }
                role_dict["privilege_level"] = self._role_definition_privilege(role_dict)
                role_dict["grants_self_escalation"] = self._role_grants_self_escalation(role_dict)
                definitions.append(role_dict)
        except Exception as exc:
            logger.warning(f"Role definition collection failed: {exc}")
        return definitions
    
    def _role_definition_privilege(self, role_def: Dict) -> int:
        """
        Score a role definition 1-5 based on how much access it grants.
        Mirrors the intent of _aws_role_privilege — used to make role
        definitions viable :Identity targets for the generic
        privilege_escalation detector (CAN_ASSUME|HAS_ROLE|BOUND_TO).
        """
        name = (role_def.get("name") or "")
        if name in BUILTIN_HIGH_PRIVILEGE_ROLES:
            return 5
        actions = set()
        for perm in role_def.get("permissions", []):
            actions.update(perm.get("actions") or [])
        if "*" in actions:
            return 5
        if any(a in DANGEROUS_AZURE_ACTIONS for a in actions):
            return 5
        if any(a.endswith("/write") or a.endswith("/*") for a in actions):
            return 3
        return 1

    def _role_grants_self_escalation(self, role_def: Dict) -> bool:
        """True if holding this role lets the principal grant itself further roles."""
        actions = set()
        for perm in role_def.get("permissions", []):
            actions.update(perm.get("actions") or [])
        return bool(actions & DANGEROUS_AZURE_ACTIONS) or "*" in actions

    def _build_trust_relationships(
        self,
        role_assignments: List[Dict],
        role_definitions: List[Dict],
    ) -> List[Dict]:
        """
        Build both HAS_ROLE edges (permission bundles) and, where a role
        grants roleAssignments/write, real CAN_ASSUME self-escalation edges
        so the existing role_chaining / wildcard_trust / cross_account
        detectors (which are hardcoded to CAN_ASSUME) can fire on Azure data.
        """
        role_def_map = {rd["id"]: rd for rd in role_definitions}
        high_priv_role_ids = [
            rd["id"] for rd in role_definitions
            if self._role_definition_privilege(rd) >= 4
        ]

        edges = []
        for assignment in role_assignments:
            role_def = role_def_map.get(assignment["role_definition_id"], {})
            role_name = role_def.get("name", "Unknown")
            scope = assignment["scope"]

            edges.append({
                "source": assignment["principal_id"],
                "target": assignment["role_definition_id"],
                "relationship": "HAS_ROLE",
                "scope": scope,
                "principal_type": assignment["principal_type"],
                "role_name": role_name,
            })

            # Self-escalation: this principal can grant itself (or anyone)
            # any role — model as CAN_ASSUME to every high-privilege role
            # visible at this scope, same semantic as an AWS wildcard trust.
            if self._role_grants_self_escalation(role_def):
                is_cross_scope = "/subscriptions/" in scope and scope.count("/") <= 2
                for target_role_id in high_priv_role_ids:
                    if target_role_id == assignment["role_definition_id"]:
                        continue
                    edges.append({
                        "source": assignment["principal_id"],
                        "target": target_role_id,
                        "relationship": "CAN_ASSUME",
                        "principal": assignment["principal_id"],
                        "condition": {"via": "roleAssignments/write", "scope": scope},
                        "is_cross_account": is_cross_scope,
                    })
        return edges

    async def collect(self) -> AzureIAMData:
        """Main entry point: collect all Azure IAM data asynchronously."""
        loop = asyncio.get_event_loop()
        data = AzureIAMData()

        try:
            data.subscription_id = await loop.run_in_executor(
                None, self._resolve_subscription
            )
            data.tenant_id = self.tenant_id or ""
            logger.info(f"Collecting Azure IAM for subscription {data.subscription_id}")

            # Graph API calls are natively async with msgraph-sdk
            data.users = await self._collect_users_via_graph()
            logger.info(f"Collected {len(data.users)} Azure AD users")

            data.service_principals = await self._collect_service_principals()
            logger.info(f"Collected {len(data.service_principals)} service principals")

            # ARM calls are synchronous — run in executor
            data.role_assignments = await loop.run_in_executor(
                None, self._collect_role_assignments, data.subscription_id
            )
            logger.info(f"Collected {len(data.role_assignments)} role assignments")

            data.role_definitions = await loop.run_in_executor(
                None, self._collect_role_definitions, data.subscription_id
            )
            logger.info(f"Collected {len(data.role_definitions)} role definitions")

            data.trust_relationships = self._build_trust_relationships(
                data.role_assignments, data.role_definitions
            )
            logger.info(f"Extracted {len(data.trust_relationships)} trust relationships")

        except Exception as exc:
            msg = f"Azure collection failed: {exc}"
            logger.error(msg, exc_info=True)
            data.errors.append(msg)

        return data