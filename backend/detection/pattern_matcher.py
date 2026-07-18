"""
TrustField - Pattern Matcher
Rule-based detection engine using escalation_patterns.json definitions.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PATTERNS_FILE = Path(__file__).parent / "escalation_patterns.json"


class PatternMatch:
    """Result of a pattern match against a graph node or relationship."""

    def __init__(
        self,
        pattern_id: str,
        pattern_name: str,
        severity: str,
        matched_resource: str,
        evidence: Dict,
        description: str,
        mitre_technique: str = "",
        remediation: str = "",
    ):
        self.pattern_id = pattern_id
        self.pattern_name = pattern_name
        self.severity = severity
        self.matched_resource = matched_resource
        self.evidence = evidence
        self.description = description
        self.mitre_technique = mitre_technique
        self.remediation = remediation

    def to_dict(self) -> Dict:
        return {
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "matched_resource": self.matched_resource,
            "evidence": self.evidence,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "remediation": self.remediation,
        }


class PatternMatcher:
    """
    Evaluates IAM data against predefined patterns from escalation_patterns.json.
    Each pattern defines conditions that indicate a security risk.
    """

    def __init__(self, patterns_file: Path = PATTERNS_FILE):
        self.patterns: List[Dict] = []
        self._load_patterns(patterns_file)

    def _load_patterns(self, patterns_file: Path) -> None:
        """Load and validate patterns from JSON file."""
        try:
            with open(patterns_file) as f:
                data = json.load(f)
            self.patterns = data.get("patterns", [])
            logger.info(f"Loaded {len(self.patterns)} detection patterns")
        except FileNotFoundError:
            logger.warning(f"Patterns file not found: {patterns_file}, using defaults")
            self.patterns = self._default_patterns()
        except json.JSONDecodeError as exc:
            logger.error(f"Invalid patterns JSON: {exc}")
            self.patterns = self._default_patterns()

    def _default_patterns(self) -> List[Dict]:
        """Built-in fallback patterns when the JSON file is unavailable."""
        return [
            {
                "id": "ADMIN_ACCESS_NO_MFA",
                "name": "Admin Access Without MFA",
                "severity": "critical",
                "description": "IAM user with admin permissions and no MFA enabled",
                "conditions": [
                    {"field": "has_admin_policy", "operator": "eq", "value": True},
                    {"field": "mfa_enabled", "operator": "eq", "value": False},
                ],
                "mitre_technique": "T1078.004",
                "remediation": "Enable MFA for all privileged users",
            },
            {
                "id": "WILDCARD_ACTION_POLICY",
                "name": "Wildcard Action in Policy",
                "severity": "high",
                "description": "IAM policy grants Action: * on Resource: *",
                "conditions": [
                    {"field": "policy_actions", "operator": "contains", "value": "*"},
                    {"field": "policy_resources", "operator": "contains", "value": "*"},
                ],
                "mitre_technique": "T1548",
                "remediation": "Replace wildcard actions with explicit least-privilege actions",
            },
            {
                "id": "STALE_ACCESS_KEY",
                "name": "Stale Access Key",
                "severity": "medium",
                "description": "IAM user has access keys older than 90 days",
                "conditions": [
                    {"field": "access_key_age_days", "operator": "gte", "value": 90},
                ],
                "mitre_technique": "T1078",
                "remediation": "Rotate access keys every 90 days; use IAM roles where possible",
            },
            {
                "id": "CROSS_ACCOUNT_WILDCARD",
                "name": "Cross-Account Wildcard Trust",
                "severity": "critical",
                "description": "Role trust policy allows any entity from another account",
                "conditions": [
                    {"field": "trust_principal", "operator": "contains", "value": "*"},
                    {"field": "is_cross_account", "operator": "eq", "value": True},
                ],
                "mitre_technique": "T1199",
                "remediation": "Require ExternalId condition on all cross-account trust policies",
            },
            {
                "id": "SERVICE_ACCOUNT_CLUSTER_ADMIN",
                "name": "Service Account with cluster-admin",
                "severity": "critical",
                "description": "Kubernetes service account bound to cluster-admin ClusterRole",
                "conditions": [
                    {"field": "role_name", "operator": "eq", "value": "cluster-admin"},
                    {"field": "subject_kind", "operator": "eq", "value": "ServiceAccount"},
                ],
                "mitre_technique": "T1548.005",
                "remediation": "Replace cluster-admin with namespace-scoped roles; apply RBAC least privilege",
            },
        ]

    def _evaluate_condition(self, condition: Dict, node_data: Dict) -> bool:
        """Evaluate a single condition against node data."""
        field = condition.get("field", "")
        operator = condition.get("operator", "eq")
        expected = condition.get("value")
        actual = node_data.get(field)

        if actual is None:
            return False

        if operator == "eq":
            return actual == expected
        elif operator == "neq":
            return actual != expected
        elif operator == "gte":
            return float(actual) >= float(expected)
        elif operator == "lte":
            return float(actual) <= float(expected)
        elif operator == "gt":
            return float(actual) > float(expected)
        elif operator == "lt":
            return float(actual) < float(expected)
        elif operator == "contains":
            if isinstance(actual, list):
                return expected in actual
            return str(expected) in str(actual)
        elif operator == "not_contains":
            if isinstance(actual, list):
                return expected not in actual
            return str(expected) not in str(actual)
        elif operator == "regex":
            return bool(re.search(str(expected), str(actual)))
        elif operator == "in":
            return actual in expected
        elif operator == "not_in":
            return actual not in expected
        return False

    def match_node(self, node_data: Dict) -> List[PatternMatch]:
        """
        Evaluate all patterns against a single node's data.
        Returns a list of matches (may be empty).
        """
        matches = []
        resource_id = node_data.get("id") or node_data.get("name", "unknown")

        for pattern in self.patterns:
            conditions = pattern.get("conditions", [])
            logic = pattern.get("logic", "AND").upper()

            condition_results = [
                self._evaluate_condition(cond, node_data) for cond in conditions
            ]

            matched = (
                all(condition_results)
                if logic == "AND"
                else any(condition_results)
            )

            if matched:
                evidence = {
                    cond["field"]: node_data.get(cond["field"])
                    for cond in conditions
                }
                matches.append(
                    PatternMatch(
                        pattern_id=pattern["id"],
                        pattern_name=pattern["name"],
                        severity=pattern.get("severity", "medium"),
                        matched_resource=resource_id,
                        evidence=evidence,
                        description=pattern.get("description", ""),
                        mitre_technique=pattern.get("mitre_technique", ""),
                        remediation=pattern.get("remediation", ""),
                    )
                )
        return matches

    def match_batch(self, nodes: List[Dict]) -> List[PatternMatch]:
        """Evaluate all patterns against a batch of nodes."""
        all_matches = []
        for node in nodes:
            all_matches.extend(self.match_node(node))
        logger.info(
            f"Pattern matching: {len(all_matches)} matches across {len(nodes)} nodes"
        )
        return all_matches

    def get_pattern(self, pattern_id: str) -> Optional[Dict]:
        """Retrieve a specific pattern by ID."""
        return next((p for p in self.patterns if p["id"] == pattern_id), None)

    def reload_patterns(self) -> int:
        """Reload patterns from disk (useful for hot-reload without restart)."""
        self._load_patterns(PATTERNS_FILE)
        return len(self.patterns)