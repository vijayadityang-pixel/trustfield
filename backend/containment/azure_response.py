"""
TrustField - Azure Containment Engine
Executes automated incident response actions against Azure AD and RBAC resources.
"""

import asyncio
import logging
from typing import Any, Dict, Optional

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from msgraph import GraphServiceClient
from msgraph.generated.models.user import User as GraphUser
from msgraph.generated.models.service_principal import ServicePrincipal as GraphServicePrincipal

logger = logging.getLogger(__name__)

ACTION_DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
ACTION_REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
ACTION_REMOVE_ROLE = "REMOVE_ROLE_ASSIGNMENT"
ACTION_BLOCK_SP = "DISABLE_SERVICE_PRINCIPAL"


class AzureContainmentEngine:
    """
    Executes containment and remediation actions against Azure AD and RBAC.
    """

    def __init__(
        self,
        subscription_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
    ):
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self._credential = None
        self._auth_client = None
        self._graph_client: Optional[GraphServiceClient] = None

    def _get_credential(self):
        if not self._credential:
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

    async def _disable_user(self, object_id: str) -> Dict:
        """Disable an Azure AD user account via Graph SDK."""
        graph = self._get_graph_client()
        body = GraphUser()
        body.account_enabled = False
        await graph.users.by_user_id(object_id).patch(body)
        logger.warning(f"Disabled Azure AD user {object_id}")
        return {"action": ACTION_DISABLE_ACCOUNT, "target": object_id, "type": "user"}

    async def _disable_service_principal(self, object_id: str) -> Dict:
        """Disable an Azure AD service principal."""
        graph = self._get_graph_client()
        body = GraphServicePrincipal()
        body.account_enabled = False
        await graph.service_principals.by_service_principal_id(object_id).patch(body)
        logger.warning(f"Disabled service principal {object_id}")
        return {"action": ACTION_BLOCK_SP, "target": object_id, "type": "service_principal"}

    async def _revoke_refresh_tokens(self, object_id: str) -> Dict:
        """Revoke all refresh tokens for an Azure AD user (forces re-auth)."""
        graph = self._get_graph_client()
        await graph.users.by_user_id(object_id).revoke_sign_in_sessions.post()
        logger.warning(f"Revoked all refresh tokens for user {object_id}")
        return {"action": ACTION_REVOKE_CREDENTIALS, "target": object_id}

    def _remove_role_assignment(self, assignment_id: str) -> Dict:
        """Remove a specific RBAC role assignment (synchronous ARM call)."""
        auth = self._get_auth_client()
        parts = assignment_id.split("/providers/Microsoft.Authorization/roleAssignments/")
        if len(parts) != 2:
            raise ValueError(f"Invalid role assignment ID format: {assignment_id}")
        scope, ra_id = parts[0], parts[1]
        auth.role_assignments.delete(scope=scope, role_assignment_name=ra_id)
        logger.warning(f"Removed role assignment {assignment_id}")
        return {"action": ACTION_REMOVE_ROLE, "target": assignment_id}

    async def disable_account(self, target: str) -> Dict:
        """
        Disable an Azure AD user or service principal.
        Also revokes all active refresh tokens.
        """
        results = {}
        try:
            results["disable"] = await self._disable_user(target)
            results["revoke"] = await self._revoke_refresh_tokens(target)
        except Exception as exc:
            logger.warning(f"User disable failed, trying SP: {exc}")
            results["disable"] = await self._disable_service_principal(target)
        return results

    async def revoke_credentials(self, target: str) -> Dict:
        """Revoke all sign-in sessions and refresh tokens for a user."""
        return await self._revoke_refresh_tokens(target)

    async def remove_role_assignment(self, assignment_id: str) -> Dict:
        """Remove a specific RBAC role assignment."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._remove_role_assignment, assignment_id)

    async def execute(self, action_type: str, target_resource: str) -> Dict:
        """Dispatch the containment action to the appropriate handler."""
        dispatch = {
            ACTION_DISABLE_ACCOUNT: self.disable_account,
            ACTION_REVOKE_CREDENTIALS: self.revoke_credentials,
            ACTION_REMOVE_ROLE: self.remove_role_assignment,
            ACTION_BLOCK_SP: self._disable_service_principal,
        }

        handler = dispatch.get(action_type)
        if not handler:
            raise ValueError(
                f"Unknown Azure action type: {action_type}. Supported: {list(dispatch.keys())}"
            )
        return await handler(target_resource)