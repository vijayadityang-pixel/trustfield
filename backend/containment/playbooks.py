"""
TrustField - Incident Response Playbooks
Chains multiple containment actions into automated response workflows.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

PLAYBOOKS = {
    "compromised_iam_user": {
        "id": "compromised_iam_user",
        "name": "Compromised IAM User",
        "description": "Full containment for a compromised AWS IAM user account.",
        "provider": "aws",
        "steps": [
            {"action": "REVOKE_CREDENTIALS", "description": "Delete all access keys"},
            {"action": "DISABLE_ACCOUNT", "description": "Disable console login"},
            {"action": "ATTACH_DENY_ALL_POLICY", "description": "Attach deny-all inline policy"},
        ],
    },
    "privilege_escalation_detected": {
        "id": "privilege_escalation_detected",
        "name": "Privilege Escalation Detected",
        "description": "Contain and investigate a detected privilege escalation path.",
        "provider": "aws",
        "steps": [
            {"action": "REVOKE_CREDENTIALS", "description": "Revoke active sessions"},
            {"action": "ATTACH_DENY_ALL_POLICY", "description": "Lock down the identity"},
        ],
    },
    "azure_account_takeover": {
        "id": "azure_account_takeover",
        "name": "Azure Account Takeover",
        "description": "Respond to a suspected Azure AD account takeover.",
        "provider": "azure",
        "steps": [
            {"action": "REVOKE_CREDENTIALS", "description": "Revoke all refresh tokens"},
            {"action": "DISABLE_ACCOUNT", "description": "Disable the Azure AD account"},
        ],
    },
    "k8s_rbac_abuse": {
        "id": "k8s_rbac_abuse",
        "name": "Kubernetes RBAC Abuse",
        "description": "Respond to suspected Kubernetes RBAC privilege abuse.",
        "provider": "k8s",
        "steps": [
            {"action": "REVOKE_CREDENTIALS", "description": "Rotate service account token"},
            {"action": "ISOLATE_RESOURCE", "description": "Isolate the affected pod"},
        ],
    },
}


class PlaybookEngine:
    """Manages and executes incident response playbooks."""

    def list_playbooks(self) -> List[Dict]:
        return list(PLAYBOOKS.values())

    def get_playbook(self, playbook_id: str) -> Optional[Dict]:
        return PLAYBOOKS.get(playbook_id)

    async def execute_playbook(
        self,
        playbook_id: str,
        alert: Any,
        action_record: Any,
        db: Any,
    ) -> None:
        """
        Execute all steps of a playbook sequentially.
        Updates the action record after each step.
        """
        from containment.aws_response import AWSContainmentEngine
        from containment.azure_response import AzureContainmentEngine

        playbook = self.get_playbook(playbook_id)
        if not playbook:
            logger.error(f"Playbook {playbook_id} not found")
            return

        provider = getattr(alert, "cloud_provider", "aws").lower()
        engine = AWSContainmentEngine() if provider == "aws" else AzureContainmentEngine()
        target = getattr(alert, "resource_id", "")

        results = []
        for step in playbook["steps"]:
            try:
                logger.info(f"[Playbook {playbook_id}] Executing step: {step['action']}")
                result = await engine.execute(step["action"], target)
                results.append({"step": step["action"], "status": "success", "result": result})
            except Exception as exc:
                logger.error(f"[Playbook {playbook_id}] Step {step['action']} failed: {exc}")
                results.append({"step": step["action"], "status": "failed", "error": str(exc)})

        # Update action record
        action_record.result = str(results)
        action_record.status = "COMPLETED"
        action_record.completed_at = datetime.utcnow()
        db.commit()
        logger.info(f"Playbook {playbook_id} completed with {len(results)} steps")