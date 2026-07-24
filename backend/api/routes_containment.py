"""
TrustField - Containment Routes
Triggers and manages automated containment actions across cloud providers.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
import json
import logging

from db.database import get_db, SessionLocal
from db.models import ContainmentAction, ContainmentStatus, Alert, User, UserRole
from auth.dependencies import get_current_user, require_role
from containment.aws_response import AWSContainmentEngine
from containment.azure_response import AzureContainmentEngine
from containment.k8s_response import K8sContainmentEngine
from containment.playbooks import PlaybookEngine
from containment.notifier import AlertNotifier
from config import settings
from schemas.containment_schemas import (
    ContainmentRequest,
    ContainmentResponse,
    ContainmentActionDetail,
    PlaybookListResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/containment", tags=["Containment"])

# Engine singletons (injected via DI in production)
aws_engine = AWSContainmentEngine()
azure_engine = AzureContainmentEngine()
k8s_engine = K8sContainmentEngine(
    kubeconfig_path=settings.K8S_KUBECONFIG_PATH,
    context=settings.K8S_CONTEXT,
    in_cluster=settings.K8S_IN_CLUSTER,
)
playbook_engine = PlaybookEngine()
notifier = AlertNotifier()


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