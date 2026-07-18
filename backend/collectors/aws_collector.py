"""
TrustField - AWS IAM Collector
Collects IAM users, roles, policies, and trust relationships from AWS.
"""

import asyncio
import boto3
import json
import logging
from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError, NoCredentialsError
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class AWSIAMData:
    """Container for all collected AWS IAM data."""
    provider: str = "aws"
    users: List[Dict] = field(default_factory=list)
    roles: List[Dict] = field(default_factory=list)
    groups: List[Dict] = field(default_factory=list)
    policies: List[Dict] = field(default_factory=list)
    trust_relationships: List[Dict] = field(default_factory=list)
    account_id: str = ""
    region: str = ""
    errors: List[str] = field(default_factory=list)


class AWSCollector:
    """
    Collects AWS IAM data for trust graph construction.
    Uses boto3 to enumerate users, roles, groups, and their trust policies.
    """

    def __init__(
        self,
        region: str = "us-east-1",
        profile_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
    ):
        self.region = region
        self.profile_name = profile_name
        self.role_arn = role_arn
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self._session: Optional[boto3.Session] = None
        self._iam_client = None
        self._sts_client = None

    def _get_session(self) -> boto3.Session:
        """Build or return cached boto3 session."""
        if self._session is None:
            if self.profile_name:
                self._session = boto3.Session(profile_name=self.profile_name, region_name=self.region)
            elif self.access_key_id and self.secret_access_key:
                self._session = boto3.Session(
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name=self.region,
                )
            else:
                self._session = boto3.Session(region_name=self.region)

            # Optionally assume a cross-account role
            if self.role_arn:
                sts = self._session.client("sts")
                creds = sts.assume_role(
                    RoleArn=self.role_arn,
                    RoleSessionName="TrustFieldCollector",
                )["Credentials"]
                self._session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                    region_name=self.region,
                )
        return self._session

    def _iam(self):
        if not self._iam_client:
            self._iam_client = self._get_session().client("iam")
        return self._iam_client

    def _sts(self):
        if not self._sts_client:
            self._sts_client = self._get_session().client("sts")
        return self._sts_client

    def _paginate(self, method_name: str, result_key: str, **kwargs) -> List[Dict]:
        """Generic paginator helper for IAM list operations."""
        paginator = self._iam().get_paginator(method_name)
        results = []
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))
        return results

    def _get_account_id(self) -> str:
        try:
            return self._sts().get_caller_identity()["Account"]
        except Exception as exc:
            logger.warning(f"Could not retrieve account ID: {exc}")
            return "unknown"

    def _collect_users(self) -> List[Dict]:
        """Enumerate all IAM users with attached policies and group memberships."""
        users = []
        raw_users = self._paginate("list_users", "Users")
        for user in raw_users:
            username = user["UserName"]
            try:
                # Attached managed policies
                managed = self._paginate(
                    "list_attached_user_policies", "AttachedPolicies", UserName=username
                )
                # Inline policies
                inline_names = self._paginate(
                    "list_user_policies", "PolicyNames", UserName=username
                )
                inline_policies = []
                for policy_name in inline_names:
                    try:
                        doc = self._iam().get_user_policy(
                            UserName=username, PolicyName=policy_name
                        )["PolicyDocument"]
                        inline_policies.append({"PolicyName": policy_name, "PolicyDocument": doc})
                    except ClientError:
                        pass

                # Group memberships
                groups = self._paginate("list_groups_for_user", "Groups", UserName=username)

                users.append({
                    **user,
                    "AttachedPolicies": managed,
                    "InlinePolicies": inline_policies,
                    "Groups": [g["GroupName"] for g in groups],
                    "node_type": "aws_user",
                })
            except ClientError as exc:
                logger.warning(f"Error collecting user {username}: {exc}")
        return users

    def _collect_roles(self) -> List[Dict]:
        """Enumerate all IAM roles with trust policies and attached policies."""
        roles = []
        raw_roles = self._paginate("list_roles", "Roles")
        for role in raw_roles:
            role_name = role["RoleName"]
            try:
                managed = self._paginate(
                    "list_attached_role_policies", "AttachedPolicies", RoleName=role_name
                )
                inline_names = self._paginate(
                    "list_role_policies", "PolicyNames", RoleName=role_name
                )
                inline_policies = []
                for policy_name in inline_names:
                    try:
                        doc = self._iam().get_role_policy(
                            RoleName=role_name, PolicyName=policy_name
                        )["PolicyDocument"]
                        inline_policies.append({"PolicyName": policy_name, "PolicyDocument": doc})
                    except ClientError:
                        pass

                roles.append({
                    **role,
                    "AttachedPolicies": managed,
                    "InlinePolicies": inline_policies,
                    "node_type": "aws_role",
                })
            except ClientError as exc:
                logger.warning(f"Error collecting role {role_name}: {exc}")
        return roles

    def _collect_groups(self) -> List[Dict]:
        """Enumerate all IAM groups with policies."""
        groups = []
        raw_groups = self._paginate("list_groups", "Groups")
        for group in raw_groups:
            group_name = group["GroupName"]
            try:
                managed = self._paginate(
                    "list_attached_group_policies", "AttachedPolicies", GroupName=group_name
                )
                groups.append({**group, "AttachedPolicies": managed, "node_type": "aws_group"})
            except ClientError as exc:
                logger.warning(f"Error collecting group {group_name}: {exc}")
        return groups

    def _collect_policies(self) -> List[Dict]:
        """Enumerate all customer-managed policies and their documents."""
        raw_policies = self._paginate("list_policies", "Policies", Scope="Local")
        policies = []
        for policy in raw_policies:
            try:
                version = self._iam().get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=policy["DefaultVersionId"],
                )["PolicyVersion"]["Document"]
                policies.append({**policy, "PolicyDocument": version, "node_type": "aws_policy"})
            except ClientError as exc:
                logger.warning(f"Error collecting policy {policy['PolicyName']}: {exc}")
        return policies

    def _extract_trust_relationships(
        self, roles: List[Dict]
    ) -> List[Dict]:
        """
        Parse AssumeRolePolicyDocument from each role to extract
        trust edges: who can assume this role (principal → role).
        """
        edges = []
        for role in roles:
            trust_doc = role.get("AssumeRolePolicyDocument", {})
            for statement in trust_doc.get("Statement", []):
                if statement.get("Effect") != "Allow":
                    continue
                principal = statement.get("Principal", {})
                if isinstance(principal, str):
                    principals = [principal]
                elif isinstance(principal, dict):
                    principals = []
                    for p_type, p_value in principal.items():
                        if isinstance(p_value, list):
                            principals.extend(p_value)
                        else:
                            principals.append(p_value)
                else:
                    continue

                for p in principals:
                    edges.append({
                        "source": p,
                        "target": role["Arn"],
                        "relationship": "CAN_ASSUME",
                        "condition": statement.get("Condition", {}),
                        "actions": statement.get("Action", []),
                    })
        return edges

    async def collect(self) -> AWSIAMData:
        """
        Main entry point: run all collectors and return structured IAM data.
        Runs synchronous boto3 calls in thread pool to avoid blocking the event loop.
        """
        loop = asyncio.get_event_loop()
        data = AWSIAMData(region=self.region)

        try:
            data.account_id = await loop.run_in_executor(None, self._get_account_id)
            logger.info(f"Collecting AWS IAM for account {data.account_id}")

            data.users = await loop.run_in_executor(None, self._collect_users)
            logger.info(f"Collected {len(data.users)} users")

            data.roles = await loop.run_in_executor(None, self._collect_roles)
            logger.info(f"Collected {len(data.roles)} roles")

            data.groups = await loop.run_in_executor(None, self._collect_groups)
            logger.info(f"Collected {len(data.groups)} groups")

            data.policies = await loop.run_in_executor(None, self._collect_policies)
            logger.info(f"Collected {len(data.policies)} customer-managed policies")

            data.trust_relationships = self._extract_trust_relationships(data.roles)
            logger.info(f"Extracted {len(data.trust_relationships)} trust relationships")

        except NoCredentialsError:
            msg = "AWS credentials not found. Configure AWS_ACCESS_KEY_ID or use an IAM role."
            logger.error(msg)
            data.errors.append(msg)
        except ClientError as exc:
            msg = f"AWS API error: {exc}"
            logger.error(msg)
            data.errors.append(msg)
        except Exception as exc:
            msg = f"Unexpected error during AWS collection: {exc}"
            logger.error(msg, exc_info=True)
            data.errors.append(msg)

        return data