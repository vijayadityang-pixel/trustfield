"""
TrustField - GCP IAM Collector
Collects GCP service accounts, IAM bindings, and trust relationships.
"""

import asyncio
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2
from googleapiclient import discovery
from google.oauth2 import service_account
import google.auth

logger = logging.getLogger(__name__)

# Roles that let a member impersonate/act as a specific service account —
# GCP's real analogue to AWS's CAN_ASSUME trust relationship.
IMPERSONATION_ROLES = {
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
}

# Built-in roles treated as high privilege for privilege_level scoring.
HIGH_PRIVILEGE_GCP_ROLES = {"roles/owner", "roles/editor"}


@dataclass
class GCPIAMData:
    """Container for all collected GCP IAM data."""
    provider: str = "gcp"
    service_accounts: List[Dict] = field(default_factory=list)
    iam_bindings: List[Dict] = field(default_factory=list)
    custom_roles: List[Dict] = field(default_factory=list)
    trust_relationships: List[Dict] = field(default_factory=list)
    project_id: str = ""
    errors: List[str] = field(default_factory=list)


class GCPCollector:
    """
    Collects GCP IAM data for trust graph construction.
    Uses Application Default Credentials or service account key file.
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
                self._credentials, project = google.auth.default(
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                if not self.project_id:
                    self.project_id = project
        return self._credentials

    def _get_iam_service(self):
        if not self._iam_service:
            self._iam_service = discovery.build(
                "iam", "v1", credentials=self._get_credentials(), cache_discovery=False
            )
        return self._iam_service

    def _resolve_project(self) -> str:
        if self.project_id:
            return self.project_id
        _, project = google.auth.default()
        if not project:
            raise ValueError(
                "GCP project ID not set. Provide project_id or set GOOGLE_CLOUD_PROJECT env var."
            )
        return project

    def _collect_service_accounts(self, project_id: str) -> List[Dict]:
        """List all service accounts in the project."""
        service = self._get_iam_service()
        result = service.projects().serviceAccounts().list(
            name=f"projects/{project_id}"
        ).execute()

        accounts = result.get("accounts", [])
        enriched = []
        for sa in accounts:
            try:
                # Get service account keys
                keys_response = service.projects().serviceAccounts().keys().list(
                    name=sa["name"]
                ).execute()
                sa["keys"] = keys_response.get("keys", [])
            except Exception:
                sa["keys"] = []
            sa["node_type"] = "gcp_service_account"
            sa["provider"] = "gcp"
            enriched.append(sa)
        return enriched

    def _collect_iam_policy(self, project_id: str) -> List[Dict]:
        """
        Retrieve the project-level IAM policy and flatten bindings.
        Each binding maps a role to a list of members (users, SAs, groups).
        """
        crm_service = discovery.build(
            "cloudresourcemanager", "v3",
            credentials=self._get_credentials(),
            cache_discovery=False,
        )
        policy = crm_service.projects().getIamPolicy(
            resource=f"projects/{project_id}", body={}
        ).execute()

        bindings = []
        for binding in policy.get("bindings", []):
            role = binding["role"]
            for member in binding.get("members", []):
                bindings.append({
                    "role": role,
                    "member": member,
                    "condition": binding.get("condition"),
                    "node_type": "gcp_iam_binding",
                    "provider": "gcp",
                })
        return bindings

    def _collect_custom_roles(self, project_id: str) -> List[Dict]:
        """List all custom roles defined in the project."""
        service = self._get_iam_service()
        try:
            result = service.projects().roles().list(
                parent=f"projects/{project_id}"
            ).execute()
            roles = result.get("roles", [])
            return [
                {**role, "node_type": "gcp_custom_role", "provider": "gcp"}
                for role in roles
            ]
        except Exception as exc:
            logger.warning(f"Custom role collection failed: {exc}")
            return []

    def _collect_sa_iam_policies(self, project_id: str, service_accounts: List[Dict]) -> List[Dict]:
        """
        Fetch the per-resource IAM policy for each service account.
        This is where real impersonation grants live — the project-level
        policy (_collect_iam_policy) never shows who can act as a specific SA.
        """
        service = self._get_iam_service()
        sa_policies = []
        for sa in service_accounts:
            sa_name = sa.get("name")  # e.g. "projects/PROJECT/serviceAccounts/EMAIL"
            if not sa_name:
                continue
            try:
                policy = service.projects().serviceAccounts().getIamPolicy(
                    resource=sa_name
                ).execute()
                for binding in policy.get("bindings", []):
                    role = binding["role"]
                    for member in binding.get("members", []):
                        sa_policies.append({
                            "sa_email": sa.get("email", ""),
                            "sa_unique_id": sa.get("uniqueId", ""),
                            "role": role,
                            "member": member,
                            "condition": binding.get("condition"),
                        })
            except Exception as exc:
                logger.warning(f"Per-SA IAM policy fetch failed for {sa_name}: {exc}")
        return sa_policies

    def _role_privilege(self, role: str) -> int:
        """Score a role 1-5. Built-in owner/editor are high; viewer/custom default lower."""
        if role in HIGH_PRIVILEGE_GCP_ROLES:
            return 5
        if role == "roles/viewer":
            return 1
        if role.startswith("roles/") and ("admin" in role.lower() or "owner" in role.lower()):
            return 4
        return 2

    def _build_trust_relationships(
        self,
        bindings: List[Dict],
        service_accounts: List[Dict],
        sa_iam_policies: List[Dict],
    ) -> List[Dict]:
        """
        Build HAS_ROLE edges from project-level bindings (permission bundles)
        and real CAN_ASSUME impersonation edges from per-SA IAM policies —
        the latter feeds role_chaining / wildcard_trust / cross_account,
        which are hardcoded to CAN_ASSUME.
        """
        edges = []

        # HAS_ROLE: member -> role, at project scope
        for binding in bindings:
            member = binding["member"]
            role = binding["role"]
            member_type, _, member_id = member.partition(":")
            edges.append({
                "source": member_id or member,
                "source_type": member_type,
                "target": role,
                "relationship": "HAS_ROLE",
                "scope": "project",
                "condition": binding.get("condition"),
            })

        # CAN_ASSUME: real impersonation via per-SA IAM policy
        for grant in sa_iam_policies:
            if grant["role"] not in IMPERSONATION_ROLES:
                continue
            member = grant["member"]
            member_type, _, member_id = member.partition(":")
            target_sa = grant["sa_email"]

            # Cross-project impersonation: the acting member belongs to a
            # different project than the SA it can impersonate.
            is_cross_account = False
            if member_type == "serviceAccount" and "@" in member_id:
                member_project = member_id.split("@")[-1].split(".")[0]
                target_project = target_sa.split("@")[-1].split(".")[0] if "@" in target_sa else ""
                is_cross_account = bool(member_project and target_project and member_project != target_project)

            edges.append({
                "source": member_id or member,
                "target": target_sa,
                "relationship": "CAN_ASSUME",
                "principal": member,
                "condition": {"via": grant["role"]},
                "is_cross_account": is_cross_account,
            })

        return edges

    async def collect(self) -> GCPIAMData:
        """Main entry point: collect all GCP IAM data asynchronously."""
        loop = asyncio.get_event_loop()
        data = GCPIAMData()

        try:
            data.project_id = await loop.run_in_executor(None, self._resolve_project)
            logger.info(f"Collecting GCP IAM for project {data.project_id}")

            data.service_accounts = await loop.run_in_executor(
                None, self._collect_service_accounts, data.project_id
            )
            logger.info(f"Collected {len(data.service_accounts)} service accounts")

            data.iam_bindings = await loop.run_in_executor(
                None, self._collect_iam_policy, data.project_id
            )
            logger.info(f"Collected {len(data.iam_bindings)} IAM bindings")

            data.custom_roles = await loop.run_in_executor(
                None, self._collect_custom_roles, data.project_id
            )
            logger.info(f"Collected {len(data.custom_roles)} custom roles")

            sa_iam_policies = await loop.run_in_executor(
                None, self._collect_sa_iam_policies, data.project_id, data.service_accounts
            )
            logger.info(f"Collected {len(sa_iam_policies)} per-SA IAM policy grants")

            data.trust_relationships = self._build_trust_relationships(
                data.iam_bindings, data.service_accounts, sa_iam_policies
            )
            logger.info(f"Extracted {len(data.trust_relationships)} trust relationships")

        except Exception as exc:
            msg = f"GCP collection failed: {exc}"
            logger.error(msg, exc_info=True)
            data.errors.append(msg)

        return data