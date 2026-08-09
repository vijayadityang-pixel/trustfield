"""
TrustField - Containment Schemas
Pydantic models for containment action API request/response serialization.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict

from db.models import ContainmentStatus


# ─── Request ─────────────────────────────────────────────────────────────────

class ContainmentRequest(BaseModel):
    """Body for POST /containment/trigger."""

    model_config = ConfigDict(extra="forbid")

    action_type: str            # REVOKE_CREDENTIALS | DISABLE_ACCOUNT | ISOLATE_RESOURCE | etc.
    cloud_provider: str         # aws | azure | gcp | k8s
    target_resource: str        # ARN, object ID, IP address, etc.
    alert_id: Optional[int] = None
    reason: Optional[str] = None


# ─── Response (lightweight — returned immediately on trigger) ─────────────────

class ContainmentResponse(BaseModel):
    """Immediate response after queuing a containment action."""

    action_id: int
    status: ContainmentStatus
    message: str


# ─── Detail (full record — returned by GET /containment/actions/{id}) ─────────

class ContainmentActionDetail(BaseModel):
    """Full containment action record."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: Optional[int] = None
    parent_action_id: Optional[int] = None

    action_type: str
    cloud_provider: str
    target_resource: str

    status: ContainmentStatus
    result: Optional[str] = None
    error_message: Optional[str] = None

    initiated_by: int

    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ─── Playbook ─────────────────────────────────────────────────────────────────

class PlaybookListResponse(BaseModel):
    """A single playbook entry returned by GET /containment/playbooks."""

    model_config = ConfigDict(from_attributes=True)

    playbook_id: str
    name: str
    description: Optional[str] = None
    supported_providers: Optional[List[str]] = None
    action_count: Optional[int] = None
    tags: Optional[List[str]] = None