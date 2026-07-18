"""
TrustField - AWS Containment Engine
Executes automated incident response actions against AWS resources.
"""

import asyncio
import boto3
import logging
from typing import Any, Dict, Optional
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Supported action types
ACTION_REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
ACTION_DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
ACTION_ISOLATE_RESOURCE = "ISOLATE_RESOURCE"
ACTION_BLOCK_IP = "BLOCK_IP"
ACTION_ROTATE_KEYS = "ROTATE_KEYS"
ACTION_DETACH_POLICIES = "DETACH_POLICIES"
ACTION_DENY_POLICY = "ATTACH_DENY_ALL_POLICY"


class AWSContainmentEngine:
    """
    Executes containment and remediation actions against AWS IAM entities.
    All actions are audited and reversible where possible.
    """

    # Deny-all policy document for emergency lockdowns
    DENY_ALL_POLICY = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Sid": "TrustFieldEmergencyDenyAll",
            }
        ],
    }

    def __init__(self, region: str = "us-east-1", role_arn: Optional[str] = None):
        self.region = region
        self.role_arn = role_arn
        self._iam: Optional[Any] = None
        self._ec2: Optional[Any] = None
        self._waf: Optional[Any] = None

    def _get_client(self, service: str):
        """Get or create a boto3 client for the given service."""
        session = boto3.Session(region_name=self.region)
        if self.role_arn:
            sts = session.client("sts")
            creds = sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName="TrustFieldContainment",
            )["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region,
            )
        return session.client(service)

    # ─── IAM Actions ────────────────────────────────────────────────────────

    async def revoke_credentials(self, target: str) -> Dict:
        """
        Revoke all active sessions for an IAM user or role.
        For users: delete all access keys.
        For roles: attach a deny-all policy + update revocation date.
        """
        loop = asyncio.get_event_loop()
        iam = await loop.run_in_executor(None, self._get_client, "iam")

        # Determine if target is user ARN or role ARN
        if ":user/" in target:
            username = target.split(":user/")[-1]
            return await loop.run_in_executor(None, self._delete_user_keys, iam, username)
        elif ":role/" in target:
            role_name = target.split(":role/")[-1]
            return await loop.run_in_executor(None, self._revoke_role_sessions, iam, role_name)
        else:
            # Assume it's a username
            return await loop.run_in_executor(None, self._delete_user_keys, iam, target)

    def _delete_user_keys(self, iam, username: str) -> Dict:
        """Delete all access keys for an IAM user."""
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        deleted = []
        for key in keys:
            iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"])
            deleted.append(key["AccessKeyId"])
        logger.warning(f"Revoked {len(deleted)} access keys for user {username}")
        return {"action": ACTION_REVOKE_CREDENTIALS, "target": username, "keys_deleted": deleted}

    def _revoke_role_sessions(self, iam, role_name: str) -> Dict:
        """
        Revoke all active role sessions by updating AWSRevokeOlderSessions policy.
        Any token issued before the current time will be denied.
        """
        import json
        from datetime import datetime, timezone

        revoke_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["*"],
                    "Resource": ["*"],
                    "Condition": {
                        "DateLessThan": {
                            "aws:TokenIssueTime": datetime.now(timezone.utc).isoformat()
                        }
                    },
                    "Sid": "TrustFieldRevokeOlderSessions",
                }
            ],
        }
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="AWSRevokeOlderSessions",
            PolicyDocument=json.dumps(revoke_policy),
        )
        logger.warning(f"Revoked all sessions for role {role_name}")
        return {"action": ACTION_REVOKE_CREDENTIALS, "target": role_name, "method": "token_revocation"}

    async def disable_account(self, target: str) -> Dict:
        """Disable an IAM user by removing their login profile and access keys."""
        loop = asyncio.get_event_loop()
        iam = await loop.run_in_executor(None, self._get_client, "iam")
        username = target.split(":user/")[-1] if ":user/" in target else target

        def _disable():
            results = []
            # Remove console access
            try:
                iam.delete_login_profile(UserName=username)
                results.append("login_profile_deleted")
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

            # Deactivate all access keys
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                iam.update_access_key(
                    UserName=username,
                    AccessKeyId=key["AccessKeyId"],
                    Status="Inactive",
                )
            results.append(f"deactivated_{len(keys)}_access_keys")

            logger.warning(f"Disabled IAM user {username}")
            return {"action": ACTION_DISABLE_ACCOUNT, "target": username, "steps": results}

        return await loop.run_in_executor(None, _disable)

    async def attach_deny_all_policy(self, target: str) -> Dict:
        """
        Attach an inline Deny-All policy to an IAM user or role.
        Provides immediate lockout while preserving the account for investigation.
        """
        import json
        loop = asyncio.get_event_loop()
        iam = await loop.run_in_executor(None, self._get_client, "iam")

        def _attach():
            policy_doc = json.dumps(self.DENY_ALL_POLICY)
            if ":user/" in target or not (":" in target):
                username = target.split(":user/")[-1] if ":user/" in target else target
                iam.put_user_policy(
                    UserName=username,
                    PolicyName="TrustFieldDenyAll",
                    PolicyDocument=policy_doc,
                )
                logger.warning(f"Attached Deny-All policy to user {username}")
                return {"action": ACTION_DENY_POLICY, "target": username}
            elif ":role/" in target:
                role_name = target.split(":role/")[-1]
                iam.put_role_policy(
                    RoleName=role_name,
                    PolicyName="TrustFieldDenyAll",
                    PolicyDocument=policy_doc,
                )
                logger.warning(f"Attached Deny-All policy to role {role_name}")
                return {"action": ACTION_DENY_POLICY, "target": role_name}

        return await loop.run_in_executor(None, _attach)

    async def isolate_ec2(self, instance_id: str) -> Dict:
        """
        Isolate an EC2 instance by moving it to an isolation security group.
        The isolation SG has no inbound or outbound rules.
        """
        loop = asyncio.get_event_loop()
        ec2 = await loop.run_in_executor(None, self._get_client, "ec2")

        def _isolate():
            # Find or create the isolation security group
            vpc_id = ec2.describe_instances(InstanceIds=[instance_id])[
                "Reservations"
            ][0]["Instances"][0]["VpcId"]

            try:
                sg = ec2.create_security_group(
                    GroupName="TrustFieldIsolation",
                    Description="TrustField - Empty isolation security group",
                    VpcId=vpc_id,
                )
                isolation_sg_id = sg["GroupId"]
            except ClientError as e:
                if e.response["Error"]["Code"] == "InvalidGroup.Duplicate":
                    sgs = ec2.describe_security_groups(
                        Filters=[
                            {"Name": "group-name", "Values": ["TrustFieldIsolation"]},
                            {"Name": "vpc-id", "Values": [vpc_id]},
                        ]
                    )["SecurityGroups"]
                    isolation_sg_id = sgs[0]["GroupId"]
                else:
                    raise

            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[isolation_sg_id],
            )
            logger.warning(f"Isolated EC2 instance {instance_id} to SG {isolation_sg_id}")
            return {
                "action": ACTION_ISOLATE_RESOURCE,
                "target": instance_id,
                "isolation_sg": isolation_sg_id,
            }

        return await loop.run_in_executor(None, _isolate)

    async def execute(self, action_type: str, target_resource: str) -> Dict:
        """
        Dispatch the containment action to the appropriate handler.
        """
        dispatch = {
            ACTION_REVOKE_CREDENTIALS: self.revoke_credentials,
            ACTION_DISABLE_ACCOUNT: self.disable_account,
            ACTION_DENY_POLICY: self.attach_deny_all_policy,
            ACTION_ISOLATE_RESOURCE: self.isolate_ec2,
        }

        handler = dispatch.get(action_type)
        if not handler:
            raise ValueError(f"Unknown action type: {action_type}. Supported: {list(dispatch.keys())}")

        return await handler(target_resource)