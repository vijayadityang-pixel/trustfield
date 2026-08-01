"""
TrustField - Containment Routes
Triggers and manages automated containment actions across cloud providers.
"""

import os
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import json
import logging
import ast

from db.database import get_db, SessionLocal
from db.models import ContainmentAction, ContainmentStatus, Alert, User, UserRole
from auth.dependencies import get_current_user, require_role
from containment.aws_response import AWSContainmentEngine
from containment.azure_response import AzureContainmentEngine
from containment.k8s_response import K8sContainmentEngine
from containment.gcp_response import GCPContainmentEngine
from containment.playbooks import PlaybookEngine
from containment.notifier import AlertNotifier
from config import settings
from graph.neo4j_client import Neo4jClient
from schemas.containment_schemas import (
    ContainmentRequest,
    ContainmentResponse,
    ContainmentActionDetail,
    PlaybookListResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/containment", tags=["Containment"])

# Engine singletons (injected via DI in production)
aws_engine = AWSContainmentEngine(role_arn=settings.AWS_CONTAINMENT_ROLE_ARN)
azure_engine = AzureContainmentEngine()
if settings.GOOGLE_APPLICATION_CREDENTIALS:
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = settings.GOOGLE_APPLICATION_CREDENTIALS
gcp_engine = GCPContainmentEngine(project_id=settings.GCP_PROJECT_ID)
k8s_engine = K8sContainmentEngine(
    kubeconfig_path=settings.K8S_KUBECONFIG_PATH,
    context=settings.K8S_CONTEXT,
    in_cluster=settings.K8S_IN_CLUSTER,
)
playbook_engine = PlaybookEngine()
notifier = AlertNotifier()
neo4j_client = Neo4jClient()


async def _execute_containment(
    action_id: int,
    request: ContainmentRequest,
):
    """
    Background task: executes the containment action and updates its status.
    Dispatches to the appropriate cloud engine based on provider.

    Uses its own fresh DB session rather than the request-scoped session
    from Depends(get_db). FastAPI tears down yield-dependencies (closing
    that session) before the response is sent, and background tasks run
    after the response is sent - so by the time this function ran, `db`
    was already closed and the `action` ORM object was detached from it.
    Mutating a detached object and calling db.commit() doesn't raise (a
    closed Session silently opens a new connection on next use), but the
    detached object's changes were never tracked by that new transaction,
    so nothing was actually persisted - status stayed "pending" and
    result stayed null forever, with misleading "completed successfully"
    log lines masking the failure. Same root cause class as routes_scan.py's
    _run_scan, which already works around it the same way: open our own
    SessionLocal() and re-fetch the row inside it.
    """
    db = SessionLocal()
    action = None
    try:
        action = db.query(ContainmentAction).filter(ContainmentAction.id == action_id).first()
        if not action:
            logger.error(f"[Containment {action_id}] Action not found in fresh session")
            return

        action.status = ContainmentStatus.IN_PROGRESS
        action.started_at = datetime.utcnow()
        db.commit()

        provider = request.cloud_provider.lower()
        if provider == "aws":
            result = await aws_engine.execute(request.action_type, request.target_resource)
        elif provider == "azure":
            result = await azure_engine.execute(request.action_type, request.target_resource)
        elif provider == "k8s":
            result = await k8s_engine.execute(request.action_type, request.target_resource)
        elif provider == "gcp":
            result = await gcp_engine.execute(request.action_type, request.target_resource)
        else:
            raise ValueError(f"Unsupported cloud provider: {provider}")

        action.status = ContainmentStatus.COMPLETED
        # `result` is a Python dict returned by the engine, but
        # ContainmentAction.result is a Text column (and the response
        # schema types it as Optional[str]) - it must be serialized before
        # assignment.
        action.result = json.dumps(result)
        action.completed_at = datetime.utcnow()
        db.commit()
        logger.info(f"Containment action {action.id} completed successfully")

    except Exception as exc:
        db.rollback()
        action = db.query(ContainmentAction).filter(ContainmentAction.id == action_id).first()
        if action:
            action.status = ContainmentStatus.FAILED
            action.error_message = str(exc)
            action.completed_at = datetime.utcnow()
            db.commit()
        logger.error(f"Containment action {action_id} failed: {exc}", exc_info=True)

    finally:
        if action:
            await notifier.send_containment_notification(action)
        db.close()

@router.get("/resolve/k8s-binding")
async def resolve_k8s_binding(
    identity_id: str,
    via_role: str,
    current_user: User = Depends(get_current_user),
):
    """
    Resolve a k8s_escalation_primitive finding's identity + via_role into
    the actual RoleBinding/ClusterRoleBinding that grants the bind/escalate
    access, so it can be passed as target_resource to REMOVE_ROLE_BINDING.

    Bridges the synthetic CAN_ESCALATE_VIA edge (which points at the
    dangerous target role the identity could escalate to) back to the real
    BOUND_TO edge (which points at via_role, the role the identity already
    holds that grants the bind/escalate verb) - that BOUND_TO grant is the
    actual access that needs revoking, not the target role.
    """
    records = await neo4j_client.run_query(
        """
        MATCH (i:Identity {id: $identity_id})-[b:BOUND_TO]->(r:Role {id: $via_role})
        RETURN b.namespace AS namespace, b.binding_name AS binding_name
        LIMIT 1
        """,
        {"identity_id": identity_id, "via_role": via_role},
    )
    if not records:
        raise HTTPException(
            status_code=404,
            detail=f"No BOUND_TO edge found between '{identity_id}' and '{via_role}'",
        )
    rec = records[0]
    if rec.get("namespace"):
        target_resource = f"k8s:rolebinding:{rec['namespace']}:{rec['binding_name']}"
    else:
        target_resource = f"k8s:clusterrolebinding:{rec['binding_name']}"

    return {"target_resource": target_resource}


@router.get("/resolve/gcp-binding")
async def resolve_gcp_binding(
    identity_id: str,
    target_sa_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Resolve an identity + impersonated service account into the actual
    IAM binding (role + member) that grants the impersonation access, so
    it can be passed as target_resource to REMOVE_IAM_BINDING.

    Reads the CAN_ASSUME edge's condition.via role and principal field
    (set by GCPCollector._build_trust_relationships) to reconstruct the
    exact role+member pair GCP's IAM policy holds - that's the specific
    grant that needs revoking, not any other role the identity holds.
    """
    records = await neo4j_client.run_query(
        """
        MATCH (i:Identity {id: $identity_id})-[c:CAN_ASSUME]->(sa {id: $target_sa_id})
        RETURN c.condition AS condition, c.principal AS principal
        LIMIT 1
        """,
        {"identity_id": identity_id, "target_sa_id": target_sa_id},
    )
    if not records:
        raise HTTPException(
            status_code=404,
            detail=f"No CAN_ASSUME edge found between '{identity_id}' and '{target_sa_id}'",
        )
    rec = records[0]
    condition_raw = rec.get("condition")
    condition = {}
    if condition_raw:
        try:
            condition = ast.literal_eval(condition_raw) if isinstance(condition_raw, str) else condition_raw
        except (ValueError, SyntaxError):
            condition = {}
    role = condition.get("via")
    member = rec.get("principal")
    if not role or not member:
        raise HTTPException(
            status_code=422,
            detail="CAN_ASSUME edge is missing role/member data required to resolve the binding",
        )

    target_resource = f"gcp:sa-binding:{target_sa_id}|{role}|{member}"
    return {"target_resource": target_resource}


@router.post("/trigger", response_model=ContainmentResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_containment(
    request: ContainmentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ANALYST, UserRole.ADMIN)),
):
    """
    Trigger a containment action against a specific cloud resource.
    Executes asynchronously in the background.

    Supported action types:
    - REVOKE_CREDENTIALS
    - DISABLE_ACCOUNT
    - ISOLATE_RESOURCE
    - BLOCK_IP
    - ROTATE_KEYS
    - REMOVE_ROLE_BINDING (k8s)
    - REMOVE_IAM_BINDING (gcp)
    """
    # Validate the alert exists if provided
    if request.alert_id:
        alert = db.query(Alert).filter(Alert.id == request.alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Referenced alert not found")

    action = ContainmentAction(
        alert_id=request.alert_id,
        action_type=request.action_type,
        cloud_provider=request.cloud_provider,
        target_resource=request.target_resource,
        initiated_by=current_user.id,
        status=ContainmentStatus.PENDING,
        created_at=datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    background_tasks.add_task(_execute_containment, action.id, request)
    logger.info(
        f"Containment action {action.id} queued by user {current_user.id} "
        f"against {request.target_resource}"
    )
    return ContainmentResponse(
        action_id=action.id,
        status=action.status,
        message="Containment action queued for execution",
    )


@router.get("/actions", response_model=List[ContainmentActionDetail])
async def list_containment_actions(
    alert_id: Optional[int] = None,
    cloud_provider: Optional[str] = None,
    action_status: Optional[ContainmentStatus] = None,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all containment actions with optional filters."""
    query = db.query(ContainmentAction)
    if alert_id:
        query = query.filter(ContainmentAction.alert_id == alert_id)
    if cloud_provider:
        query = query.filter(ContainmentAction.cloud_provider == cloud_provider)
    if action_status:
        query = query.filter(ContainmentAction.status == action_status)

    actions = query.order_by(ContainmentAction.created_at.desc()).offset(skip).limit(limit).all()
    return actions


@router.get("/actions/{action_id}", response_model=ContainmentActionDetail)
async def get_containment_action(
    action_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get details of a specific containment action including execution result."""
    action = db.query(ContainmentAction).filter(ContainmentAction.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Containment action not found")
    return action


@router.post("/actions/{action_id}/rollback", response_model=ContainmentResponse)
async def rollback_containment(
    action_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
):
    """
    Rollback a completed containment action (admin only).
    Creates a reverse action to undo the original containment.
    """
    original = db.query(ContainmentAction).filter(ContainmentAction.id == action_id).first()
    if not original:
        raise HTTPException(status_code=404, detail="Containment action not found")
    if original.status != ContainmentStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot rollback action in {original.status} state",
        )

    rollback_action = ContainmentAction(
        alert_id=original.alert_id,
        action_type=f"ROLLBACK_{original.action_type}",
        cloud_provider=original.cloud_provider,
        target_resource=original.target_resource,
        initiated_by=current_user.id,
        status=ContainmentStatus.PENDING,
        parent_action_id=original.id,
        created_at=datetime.utcnow(),
    )
    db.add(rollback_action)
    db.commit()
    db.refresh(rollback_action)

    rollback_request = ContainmentRequest(
        action_type=rollback_action.action_type,
        cloud_provider=original.cloud_provider,
        target_resource=original.target_resource,
    )
    background_tasks.add_task(_execute_containment, rollback_action.id, rollback_request)

    return ContainmentResponse(
        action_id=rollback_action.id,
        status=rollback_action.status,
        message="Rollback action queued",
    )


@router.get("/playbooks", response_model=List[PlaybookListResponse])
async def list_playbooks(
    current_user: User = Depends(get_current_user),
):
    """List all available incident response playbooks."""
    playbooks = playbook_engine.list_playbooks()
    return playbooks


@router.post("/playbooks/{playbook_id}/run", response_model=ContainmentResponse)
async def run_playbook(
    playbook_id: str,
    alert_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.ANALYST, UserRole.ADMIN)),
):
    """
    Execute a predefined incident response playbook against an alert.
    Playbooks chain multiple containment actions in sequence.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    playbook = playbook_engine.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found")

    action = ContainmentAction(
        alert_id=alert_id,
        action_type=f"PLAYBOOK:{playbook_id}",
        cloud_provider=alert.cloud_provider,
        target_resource=alert.resource_id,
        initiated_by=current_user.id,
        status=ContainmentStatus.PENDING,
        created_at=datetime.utcnow(),
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    background_tasks.add_task(playbook_engine.execute_playbook, playbook_id, alert, action, db)

    return ContainmentResponse(
        action_id=action.id,
        status=action.status,
        message=f"Playbook '{playbook_id}' started",
    )