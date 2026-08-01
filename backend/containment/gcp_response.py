"""
TrustField - GCP Containment Engine
Executes automated incident response actions against GCP IAM bindings.
"""

import asyncio
import logging
from typing import Dict, Optional

from googleapiclient import discovery
from google.oauth2 import service_account
import google.auth

logger = logging.getLogger(__name__)

ACTION_REMOVE_IAM_BINDING = "REMOVE_IAM_BINDING"


def _parse_target_resource(target_resource: str) -> Dict[str, str]:
    """
    Parses the composite target_resource ID produced by
    GET /containment/resolve/gcp-binding:
      "gcp:sa-binding:<sa_email>|<role>|<member>"

    Pipe-delimited for the variable parts (unlike K8s's colon-delimited
    format) because GCP `member` strings already contain a colon, e.g.
    "serviceAccount:x@y.iam.gserviceaccount.com" - a colon-split parse
    would break on that.
    """
    prefix = "gcp:sa-binding:"
    if not target_resource.startswith(prefix):
        raise ValueError(
            f"Invalid GCP target_resource format: {target_resource}. "
            f"Expected '{prefix}<sa_email>|<role>|<member>'"
        )
    parts = target_resource[len(prefix):].split("|")
    if len(parts) != 3:
        raise ValueError(
            f"Invalid GCP target_resource format: {target_resource}. "
            f"Expected '{prefix}<sa_email>|<role>|<member>' "
            f"(3 pipe-delimited parts, got {len(parts)})"
        )
    sa_email, role, member = parts
    return {"sa_email": sa_email, "role": role, "member": member}


class GCPContainmentEngine:
    """
    Executes containment actions against GCP IAM.

    First (and currently only) supported action is REMOVE_IAM_BINDING:
    revoking the specific per-service-account IAM policy binding that
    grants an impersonation role (serviceAccountTokenCreator /
    serviceAccountUser / serviceAccountKeyAdmin) to a member. This is the
    real GCP escalation primitive GCPCollector._build_trust_relationships
    turns into CAN_ASSUME edges, so removing it closes the actual
    escalation path rather than locking out the account wholesale.

    Mirrors the K8s engine's "read state, remove the specific grant"
    pattern rather than AWS's account-level lockout actions - GCP's
    escalation edges are always binding-scoped (member+role+resource),
    not account-scoped, so a scoped removal is both the minimal action
    and the one closest to what the detector actually found.
    """

    def __init__(
        self,
        project_id: Optional[str] = None,
        service_account_key_path: Optional[str] = None,
    ):
        self.project_id = project_id
        self.service_account_key_path = service_account_key_path
        self._credentials = None
        self._iam_service = None

    def _get_credentials(self):
        if self._credentials is None:
            if self.service_account_key_path:
                self._credentials = service_account.Credentials.from_service_account_file(
                    self.service_account_key_path,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"],
                )
            else:
                self._credentials, _ = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
        return self._credentials

    def _get_iam_service(self):
        if not self._iam_service:
            self._iam_service = discovery.build(
                "iam", "v1", credentials=self._get_credentials(), cache_discovery=False
            )
        return self._iam_service

    def _remove_iam_binding(self, target_resource: str) -> Dict:
        parsed = _parse_target_resource(target_resource)
        if not self.project_id:
            raise ValueError(
                "GCPContainmentEngine.project_id is not set; cannot construct "
                "the service account resource name."
            )
        sa_name = f"projects/{self.project_id}/serviceAccounts/{parsed['sa_email']}"
        service = self._get_iam_service()

        policy = service.projects().serviceAccounts().getIamPolicy(resource=sa_name).execute()
        bindings = policy.get("bindings", [])

        removed_snapshot = None
        new_bindings = []
        for binding in bindings:
            if binding.get("role") != parsed["role"]:
                new_bindings.append(binding)
                continue
            members = binding.get("members", [])
            if parsed["member"] in members:
                removed_snapshot = {"role": binding["role"], "member": parsed["member"]}
                members = [m for m in members if m != parsed["member"]]
            if members:
                new_bindings.append({**binding, "members": members})
            # if members is now empty, the binding is dropped entirely

        if removed_snapshot is None:
            raise ValueError(
                f"Binding not found: role '{parsed['role']}' with member "
                f"'{parsed['member']}' on service account '{parsed['sa_email']}'. "
                "It may have already been removed."
            )

        policy["bindings"] = new_bindings
        service.projects().serviceAccounts().setIamPolicy(
            resource=sa_name, body={"policy": policy}
        ).execute()

        logger.warning(
            f"Removed IAM binding on {parsed['sa_email']}: "
            f"role={parsed['role']} member={parsed['member']}"
        )
        return {
            "action": ACTION_REMOVE_IAM_BINDING,
            "target": parsed["sa_email"],
            "removed_binding": removed_snapshot,
        }

    async def remove_iam_binding(self, target_resource: str) -> Dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._remove_iam_binding, target_resource)

    async def execute(self, action_type: str, target_resource: str) -> Dict:
        """Dispatch the containment action to the appropriate handler."""
        dispatch = {
            ACTION_REMOVE_IAM_BINDING: self.remove_iam_binding,
        }
        handler = dispatch.get(action_type)
        if not handler:
            raise ValueError(
                f"Unknown GCP action type: {action_type}. Supported: {list(dispatch.keys())}"
            )
        return await handler(target_resource)