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
    async def rotate_keys(self, target: str) -> Dict:
        """
        Rotate access keys for an IAM user: create a new active key, then
        deactivate every key that existed before rotation. New-key-first
        ordering avoids a credential gap for legitimate automated
        consumers of the key.

        The new SecretAccessKey is deliberately excluded from the returned
        result - ContainmentAction.result is persisted as plaintext JSON in
        Postgres, and this API can be read back via GET /containment/actions/{id}.
        Storing a live AWS secret there would be a real credential-leak
        vector in a tool whose entire purpose is IAM security, so this
        action is scoped to "invalidate old keys" rather than "hand a new
        credential to an operator" - if a human needs the new secret, it
        must be retrieved out-of-band (e.g. AWS console, audited channel),
        not through this endpoint.
        """
        loop = asyncio.get_event_loop()
        iam = await loop.run_in_executor(None, self._get_client, "iam")
        username = target.split(":user/")[-1] if ":user/" in target else target

        def _rotate():
            old_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            old_key_ids = [k["AccessKeyId"] for k in old_keys]

            new_key = iam.create_access_key(UserName=username)["AccessKey"]

            deactivated = []
            for key_id in old_key_ids:
                iam.update_access_key(
                    UserName=username, AccessKeyId=key_id, Status="Inactive"
                )
                deactivated.append(key_id)

            logger.warning(
                f"Rotated keys for user {username}: created {new_key['AccessKeyId']}, "
                f"deactivated {len(deactivated)} old key(s)"
            )
            return {
                "action": ACTION_ROTATE_KEYS,
                "target": username,
                "new_access_key_id": new_key["AccessKeyId"],
                "old_keys_deactivated": deactivated,
                "note": "New secret access key was not persisted; retrieve via a secure out-of-band channel.",
            }

        return await loop.run_in_executor(None, _rotate)

    async def block_ip(self, ip_address: str) -> Dict:
        """
        Block an IP address at the network layer by adding explicit deny
        rules to the VPC's default Network ACL (both ingress and egress).

        Uses NACLs rather than Security Groups, since SGs are allow-only
        and have no deny semantics. AWS WAF was considered as an
        alternative but requires a pre-existing Web ACL to attach an IP
        set to, which target_resource (a bare IP string) doesn't carry -
        NACL deny rules are the option that works with no pre-existing
        infrastructure.
        """
        loop = asyncio.get_event_loop()
        ec2 = await loop.run_in_executor(None, self._get_client, "ec2")

        def _block():
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]
            if not vpcs:
                raise ValueError("No default VPC found in region; cannot determine target NACL")
            vpc_id = vpcs[0]["VpcId"]

            nacls = ec2.describe_network_acls(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "default", "Values": ["true"]},
                ]
            )["NetworkAcls"]
            if not nacls:
                raise ValueError(f"No default NACL found for VPC {vpc_id}")
            nacl_id = nacls[0]["NetworkAclId"]

            existing_entries = nacls[0]["Entries"]
            used_numbers = {e["RuleNumber"] for e in existing_entries if e["RuleNumber"] < 32767}
            rule_number = max(used_numbers, default=90) + 1
            while rule_number in used_numbers:
                rule_number += 1

            cidr = f"{ip_address}/32"

            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=rule_number,
                Protocol="-1",
                RuleAction="deny",
                Egress=False,
                CidrBlock=cidr,
            )
            ec2.create_network_acl_entry(
                NetworkAclId=nacl_id,
                RuleNumber=rule_number,
                Protocol="-1",
                RuleAction="deny",
                Egress=True,
                CidrBlock=cidr,
            )

            logger.warning(f"Blocked IP {ip_address} via NACL {nacl_id}, rule {rule_number}")
            return {
                "action": ACTION_BLOCK_IP,
                "target": ip_address,
                "vpc_id": vpc_id,
                "nacl_id": nacl_id,
                "rule_number": rule_number,
            }

        return await loop.run_in_executor(None, _block)
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
            ACTION_ROTATE_KEYS: self.rotate_keys,
            ACTION_BLOCK_IP: self.block_ip,
        }

        handler = dispatch.get(action_type)
        if not handler:
            raise ValueError(f"Unknown action type: {action_type}. Supported: {list(dispatch.keys())}")

        return await handler(target_resource)