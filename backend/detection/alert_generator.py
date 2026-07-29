"""
TrustField - Alert Generator
Converts detected EscalationPath findings into persisted Alert rows.
"""

import json
import logging
from typing import List

from sqlalchemy.orm import Session

from db.models import Alert, AlertSeverity, AlertStatus
from detection.path_finder import EscalationPath

logger = logging.getLogger(__name__)


def _severity_for_risk(risk_score: float) -> AlertSeverity:
    if risk_score >= 0.85:
        return AlertSeverity.CRITICAL
    if risk_score >= 0.7:
        return AlertSeverity.HIGH
    if risk_score >= 0.55:
        return AlertSeverity.MEDIUM
    return AlertSeverity.LOW


def _title_for_path(path: EscalationPath) -> str:
    label = path.escalation_type.replace("_", " ").title()
    src = path.metadata.get("source_name") or path.source_node
    tgt = path.metadata.get("target_name") or path.target_node
    return f"{label}: {src} -> {tgt}"


class AlertGenerator:
    """
    Converts EscalationPath findings into Alert rows, deduplicating
    against existing open/in-progress alerts via EscalationPath.path_id.
    """

    def generate_alerts(self, db: Session, paths: List[EscalationPath]) -> int:
        """
        Insert new Alert rows for paths not already alerted on.
        Returns the number of NEW alerts created (not the total paths seen).
        """
        if not paths:
            return 0

        existing_path_ids = {
            row[0]
            for row in db.query(Alert.path_id)
            .filter(
                Alert.path_id.isnot(None),
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
            )
            .all()
        }

        created = 0
        for path in paths:
            if path.path_id in existing_path_ids:
                continue

            alert = Alert(
                title=_title_for_path(path),
                description=path.description,
                severity=_severity_for_risk(path.risk_score),
                status=AlertStatus.OPEN,
                cloud_provider=path.cloud_provider,
                resource_id=path.target_node,
                resource_type=None,
                alert_type=path.escalation_type.upper(),
                risk_score=path.risk_score,
                confidence=1.0,  # rule-based detector, not probabilistic
                detection_source="rule_engine",
                raw_evidence=json.loads(json.dumps({
                    "path_nodes": path.path_nodes,
                    "path_edges": path.path_edges,
                    "mitre_technique": path.mitre_technique,
                    "remediation": path.remediation,
                    "metadata": path.metadata,
                })),
                source_node_id=path.source_node,
                target_node_id=path.target_node,
                escalation_path=path.path_nodes,
                path_id=path.path_id,
            )
            db.add(alert)
            existing_path_ids.add(path.path_id)
            created += 1

        if created:
            db.commit()
            logger.info(f"AlertGenerator: created {created} new alert(s) from {len(paths)} finding(s)")

        return created