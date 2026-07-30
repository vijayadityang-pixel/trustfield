"""
Week 7 Day 2 PM - RiskScorer unit tests (pure function, no Neo4j needed).

These pin down exact boundary values discovered by reading path_finder.py's
_record_to_path() call sites against risk_scorer.py's formula, BEFORE writing
any integration test. Key findings encoded here as regression protection:

1. Previously, _record_to_path() never passed has_wildcard/is_cross_account/
   anomaly_score to score_path(), leaving those bonus terms dead code from
   every real detector call. Fixed Week 8: is_cross_account is now derived
   from escalation_type == "cross_account", and has_wildcard from
   escalation_type == "wildcard_trust", in _record_to_path().

2. role_chaining only ever crosses min_risk=0.5 at exactly depth=2:
   0.80 * 0.75 - 0.10 = 0.50 (exact boundary, fragile to float drift).
   depth=3 -> 0.40 (fails). depth=4 -> 0.30 (fails).

3. cross_account previously only fired for privilege_level=5 (root) targets
   without the is_cross_account bonus:
   level 5 -> 0.70 * 1.00 - 0.10 = 0.60 (passed)
   level 4 -> 0.70 * 0.75 - 0.10 = 0.425 (failed - real gap)
   Fixed Week 8: is_cross_account=True is now always passed for this
   escalation_type, adding +0.10 - level 4 now scores 0.525 and passes too.

4. "k8s_escalation_primitive" is NOT a key in ESCALATION_TYPE_WEIGHTS, so it
   silently falls back to the generic 0.60 default. Combined with the query
   never returning path_length/depth (so _record_to_path defaults to 2),
   this lands exactly on the 0.5 boundary for a level-5 target:
   0.60 * 1.00 - 0.10 = 0.50 (exact boundary, same fragility as #2).

5. privilege_escalation has real headroom, not a knife-edge boundary:
   path_length=2 -> 0.90 * 0.75 - 0.10 = 0.575 (passes)
   path_length=3 -> 0.90 * 0.75 - 0.20 = 0.475 (fails)
"""
import pytest
from detection.risk_scorer import RiskScorer


@pytest.fixture
def scorer():
    return RiskScorer()


class TestPrivilegeEscalationScoring:
    """privilege_escalation: base=0.90, real boundary between depth 2 and 3."""

    def test_two_hop_passes_threshold(self, scorer):
        score = scorer.score_path(
            path_length=2, privilege_level=4, escalation_type="privilege_escalation"
        )
        assert score == 0.575
        assert score >= 0.5

    def test_three_hop_fails_threshold(self, scorer):
        score = scorer.score_path(
            path_length=3, privilege_level=4, escalation_type="privilege_escalation"
        )
        assert score == 0.475
        assert score < 0.5

    def test_one_hop_direct_assume_is_highest_risk(self, scorer):
        score = scorer.score_path(
            path_length=1, privilege_level=4, escalation_type="privilege_escalation"
        )
        assert score == 0.675


class TestRoleChainingScoring:
    """
    role_chaining: base=0.80, ONLY passes at depth=2 (exact 0.5 boundary).
    QUERY_ROLE_CHAINING requires *2..4 hops, so depth=3 and depth=4 (valid
    query matches) never surface via find_escalation_paths()'s min_risk
    filter - this detector is effectively single-depth in practice.
    """

    def test_depth_two_lands_exactly_on_threshold(self, scorer):
        score = scorer.score_path(
            path_length=2, privilege_level=4, escalation_type="role_chaining"
        )
        assert score == 0.5
        assert score >= 0.5  # passes because filter uses >=

    def test_depth_three_fails_threshold(self, scorer):
        score = scorer.score_path(
            path_length=3, privilege_level=4, escalation_type="role_chaining"
        )
        assert score == 0.4
        assert score < 0.5

    def test_depth_four_fails_threshold(self, scorer):
        score = scorer.score_path(
            path_length=4, privilege_level=4, escalation_type="role_chaining"
        )
        assert score == 0.3
        assert score < 0.5


class TestWildcardTrustScoring:
    """wildcard_trust: base=0.85, gated by target privilege_level bucket jump."""

    def test_root_target_passes(self, scorer):
        score = scorer.score_path(
            path_length=2, privilege_level=5, escalation_type="wildcard_trust"
        )
        assert score == 0.75

    def test_account_admin_target_passes(self, scorer):
        score = scorer.score_path(
            path_length=2, privilege_level=4, escalation_type="wildcard_trust"
        )
        assert score == 0.5375
        assert score >= 0.5

    def test_service_level_target_fails(self, scorer):
        score = scorer.score_path(
            path_length=2, privilege_level=3, escalation_type="wildcard_trust"
        )
        assert score == 0.2825
        assert score < 0.5


class TestCrossAccountScoring:
    """
    cross_account: base=0.70. score_path() itself has always supported the
    is_cross_account bonus (+0.10) - this class pins its raw behavior with
    the bonus explicitly off/on. The real historical gap was that
    _record_to_path() never passed is_cross_account=True despite
    QUERY_CROSS_ACCOUNT guaranteeing it for every result - fixed Week 8,
    see test_detector_regression.py for the integration-level confirmation.
    """

    def test_root_target_passes_without_bonus(self, scorer):
        score = scorer.score_path(
            path_length=2, privilege_level=5, escalation_type="cross_account"
        )
        assert score == 0.6
        assert score >= 0.5

    def test_account_admin_target_needs_bonus_to_pass(self, scorer):
        without_bonus = scorer.score_path(
            path_length=2, privilege_level=4, escalation_type="cross_account"
        )
        assert without_bonus == 0.425
        assert without_bonus < 0.5

        with_bonus = scorer.score_path(
            path_length=2, privilege_level=4, escalation_type="cross_account",
            is_cross_account=True,
        )
        assert with_bonus == 0.525
        assert with_bonus >= 0.5, (
            "Confirms the Week 8 fix: is_cross_account=True (now always "
            "passed by _record_to_path() for this escalation_type) lifts "
            "an account-admin-level cross-account trust over min_risk=0.5, "
            "closing what was previously a real detection gap."
        )


class TestK8sEscalationPrimitiveScoring:
    """
    k8s_escalation_primitive: NOT in ESCALATION_TYPE_WEIGHTS, falls back to
    the generic 0.60 default base weight. QUERY_K8S_ESCALATION_PRIMITIVE
    returns neither 'depth' nor 'path_length', so _record_to_path's
    record.get("depth", record.get("path_length", 2)) always defaults to 2.
    Result: lands exactly on the 0.5 boundary for a level-5 target, same
    fragility class as role_chaining.
    """

    def test_uses_fallback_base_weight_not_a_dedicated_one(self, scorer):
        # Confirms "k8s_escalation_primitive" isn't a real key - if someone
        # adds a dedicated weight for it later, this test's expected value
        # will need updating, which is the point (regression tripwire).
        from detection.risk_scorer import ESCALATION_TYPE_WEIGHTS
        assert "k8s_escalation_primitive" not in ESCALATION_TYPE_WEIGHTS

    def test_default_depth_two_root_target_lands_on_exact_boundary(self, scorer):
        score = scorer.score_path(
            path_length=2, privilege_level=5, escalation_type="k8s_escalation_primitive"
        )
        assert score == 0.5
        assert score >= 0.5

    def test_level_three_target_fails_despite_passing_query_filter(self, scorer):
        # QUERY_K8S_ESCALATION_PRIMITIVE's WHERE clause allows privilege_level
        # >= 3 through at the Cypher level, but the risk score for a level-3
        # target is nowhere near the alerting threshold - the raw detector
        # over-matches relative to what actually gets surfaced to a user.
        score = scorer.score_path(
            path_length=2, privilege_level=3, escalation_type="k8s_escalation_primitive"
        )
        assert score == 0.17
        assert score < 0.5


class TestExposureBonusParamsWorkInIsolation:
    """
    Confirms score_path()'s bonus params change output correctly when
    passed directly. is_cross_account and has_wildcard are now wired
    through by _record_to_path() for cross_account/wildcard_trust
    respectively (Week 8 fix) - anomaly_score remains unwired from any
    real detector, still a documented gap.
    """

    def test_wildcard_bonus_works_when_explicitly_passed(self, scorer):
        without = scorer.score_path(
            path_length=2, privilege_level=3, escalation_type="cross_account",
            has_wildcard=False,
        )
        with_bonus = scorer.score_path(
            path_length=2, privilege_level=3, escalation_type="cross_account",
            has_wildcard=True,
        )
        assert with_bonus == round(without + 0.15, 4)

    def test_cross_account_bonus_works_when_explicitly_passed(self, scorer):
        without = scorer.score_path(
            path_length=2, privilege_level=3, escalation_type="wildcard_trust",
            is_cross_account=False,
        )
        with_bonus = scorer.score_path(
            path_length=2, privilege_level=3, escalation_type="wildcard_trust",
            is_cross_account=True,
        )
        assert with_bonus == round(without + 0.10, 4)