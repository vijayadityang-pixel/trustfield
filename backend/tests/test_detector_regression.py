"""
Week 7 Day 2 PM - Detector regression suite.

Seeds Neo4j directly with minimal graphs (bypassing the full scan pipeline -
this tests the path_finder.py detector layer itself, not ingestion) and
exercises all 5 detectors: privilege_escalation, role_chaining,
wildcard_trust, cross_account, k8s_escalation_primitive - plus the
find_escalation_paths() aggregator's min_risk filtering.

Each test uses a unique cloud_provider tag (test-detreg-<name>) both to
scope the Cypher $cloud_provider filter and to make cleanup unambiguous.
Follows the Day 1 lesson: never chain async Neo4j fixtures, each test
owns its own self-contained Neo4jClient() instance.
"""
import pytest
from graph.neo4j_client import Neo4jClient
from detection.path_finder import PrivilegeEscalationPathFinder


async def _seed(neo4j, cypher, params=None):
    await neo4j.run_query(cypher, parameters=params or {})


async def _cleanup(neo4j, provider_tag):
    await neo4j.run_query(
        "MATCH (n) WHERE n.provider = $provider DETACH DELETE n",
        parameters={"provider": provider_tag},
    )


@pytest.mark.asyncio
async def test_privilege_escalation_two_hop_passes_aggregator_threshold():
    """
    Real boundary case (test_risk_scorer.py pins the math): a 2-hop
    CAN_ASSUME chain from a low-privilege identity to a privilege_level=4
    target scores 0.575, which passes find_escalation_paths()'s default
    min_risk=0.5 filter.
    """
    tag = "test-detreg-pe2hop"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (a:Identity {id: $a, name: 'low-priv-user', provider: $tag, privilege_level: 1})
            CREATE (b:Identity {id: $b, name: 'mid-role', provider: $tag, privilege_level: 3})
            CREATE (c:Identity {id: $c, name: 'admin-role', provider: $tag, privilege_level: 4})
            CREATE (a)-[:HAS_ROLE]->(b)
            CREATE (b)-[:CAN_ASSUME]->(c)
        """, {"a": f"{tag}:user", "b": f"{tag}:mid", "c": f"{tag}:admin", "tag": tag})
        # mid-role is privilege_level=3 (not <3) so it doesn't qualify as its
        # own source. The first hop uses HAS_ROLE (not CAN_ASSUME) so this
        # chain satisfies privilege_escalation's broader
        # CAN_ASSUME|HAS_ROLE|BOUND_TO union but does NOT satisfy
        # role_chaining's strict CAN_ASSUME*2..4-only pattern - isolating
        # exactly the detector this test is targeting. (role_chaining has
        # no source-privilege filter at all, so an all-CAN_ASSUME chain here
        # would legitimately double-fire both detectors - confirmed
        # empirically, not a bug.)

        finder = PrivilegeEscalationPathFinder(neo4j)
        raw_paths = await finder.find_privilege_escalation_paths(cloud_provider=tag)
        assert len(raw_paths) == 1
        assert raw_paths[0].risk_score == 0.575

        filtered = await finder.find_escalation_paths(cloud_provider=tag, min_risk_score=0.5)
        assert len(filtered) == 1
        assert filtered[0].escalation_type == "privilege_escalation"
        assert filtered[0].source_node == f"{tag}:user"
        assert filtered[0].target_node == f"{tag}:admin"
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_privilege_escalation_three_hop_detected_but_filtered_by_aggregator():
    """
    The raw Cypher query matches 3-hop chains fine (max_depth=5 allows it),
    but the risk score (0.475) falls below min_risk=0.5 - so it's detected
    at the query layer but invisible at the alerting layer. This is the
    exact gap class that bit the GCP test this morning.
    """
    tag = "test-detreg-pe3hop"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (a:Identity {id: $a, name: 'low-priv-user', provider: $tag, privilege_level: 1})
            CREATE (b:Identity {id: $b, name: 'hop1', provider: $tag, privilege_level: 3})
            CREATE (c:Identity {id: $c, name: 'hop2', provider: $tag, privilege_level: 3})
            CREATE (d:Identity {id: $d, name: 'admin-role', provider: $tag, privilege_level: 4})
            CREATE (a)-[:HAS_ROLE]->(b)
            CREATE (b)-[:CAN_ASSUME]->(c)
            CREATE (c)-[:CAN_ASSUME]->(d)
        """, {"a": f"{tag}:user", "b": f"{tag}:hop1", "c": f"{tag}:hop2",
              "d": f"{tag}:admin", "tag": tag})
        # Same isolation approach as the 2-hop test: hop1/hop2 are
        # privilege_level=3 (not <3), and the first hop uses HAS_ROLE so
        # role_chaining's CAN_ASSUME-only pattern can't match the full
        # user->admin chain. It WILL still match hop1->hop2->admin (a valid
        # 2-hop all-CAN_ASSUME sub-chain) at exactly the 0.5 boundary - that
        # is correct, expected overlap and is asserted separately below
        # rather than treated as contamination.

        finder = PrivilegeEscalationPathFinder(neo4j)
        raw_paths = await finder.find_privilege_escalation_paths(cloud_provider=tag)
        assert len(raw_paths) == 1
        assert raw_paths[0].risk_score == 0.475

        filtered = await finder.find_escalation_paths(cloud_provider=tag, min_risk_score=0.5)
        pe_hits = [p for p in filtered if p.escalation_type == "privilege_escalation"]
        assert len(pe_hits) == 0, (
            "3-hop privilege_escalation chain should be detected by the raw "
            "query but filtered out of alerted results by min_risk - "
            "detected-but-not-alerted gap, not a query bug."
        )
        # The hop1->hop2->admin sub-chain legitimately fires role_chaining
        # at the exact 0.5 boundary (both hops are CAN_ASSUME, depth=2) -
        # this is expected, not test contamination.
        rc_hits = [p for p in filtered if p.escalation_type == "role_chaining"]
        assert len(rc_hits) == 1
        assert rc_hits[0].risk_score == 0.5
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_role_chaining_depth_two_detected_at_exact_boundary():
    """
    role_chaining only fires at depth=2 (score exactly 0.5, per
    test_risk_scorer.py). Seeds a valid 2-hop CAN_ASSUME chain and confirms
    it clears the aggregator's >= 0.5 filter.
    """
    tag = "test-detreg-rolechain"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (a:Identity {id: $a, name: 'chainer', provider: $tag, privilege_level: 1})
            CREATE (b:Identity {id: $b, name: 'mid', provider: $tag, privilege_level: 2})
            CREATE (c:Identity {id: $c, name: 'target-role', provider: $tag, privilege_level: 4})
            CREATE (a)-[:CAN_ASSUME]->(b)
            CREATE (b)-[:CAN_ASSUME]->(c)
        """, {"a": f"{tag}:chainer", "b": f"{tag}:mid", "c": f"{tag}:target", "tag": tag})

        finder = PrivilegeEscalationPathFinder(neo4j)
        raw_paths = await finder.find_role_chaining(cloud_provider=tag)
        assert len(raw_paths) == 1
        assert raw_paths[0].risk_score == 0.5

        filtered = await finder.find_escalation_paths(cloud_provider=tag, min_risk_score=0.5)
        # Both privilege_escalation and role_chaining detectors will match
        # this same seeded chain (it satisfies both patterns) - dedup by
        # path_id keeps them distinct since escalation_type differs.
        escalation_types = {p.escalation_type for p in filtered}
        assert "role_chaining" in escalation_types
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_role_chaining_ignores_actual_target_privilege_level():
    """
    QUERY_ROLE_CHAINING correctly returns 'depth' (confirmed by the
    depth-boundary test above), but it never SELECTs target.privilege_level
    even though its WHERE clause requires target.privilege_level >= 4.
    _record_to_path()'s record.get('privilege_level', 4) default therefore
    applies unconditionally - a genuinely root-level (privilege_level=5)
    target scores IDENTICALLY to a merely admin-level (privilege_level=4)
    one, at the same depth. This under-reports risk for chains that
    actually reach root.
    """
    tag = "test-detreg-rolechain-privlvl"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (a:Identity {id: $a, name: 'chainer-to-admin', provider: $tag, privilege_level: 1})
            CREATE (b:Identity {id: $b, name: 'mid-admin', provider: $tag, privilege_level: 2})
            CREATE (admin:Identity {id: $admin, name: 'admin-target', provider: $tag, privilege_level: 4})
            CREATE (c:Identity {id: $c, name: 'chainer-to-root', provider: $tag, privilege_level: 1})
            CREATE (d:Identity {id: $d, name: 'mid-root', provider: $tag, privilege_level: 2})
            CREATE (root:Identity {id: $root, name: 'root-target', provider: $tag, privilege_level: 5})
            CREATE (a)-[:CAN_ASSUME]->(b)
            CREATE (b)-[:CAN_ASSUME]->(admin)
            CREATE (c)-[:CAN_ASSUME]->(d)
            CREATE (d)-[:CAN_ASSUME]->(root)
        """, {"a": f"{tag}:chainer-admin", "b": f"{tag}:mid-admin", "admin": f"{tag}:admin-target",
              "c": f"{tag}:chainer-root", "d": f"{tag}:mid-root", "root": f"{tag}:root-target",
              "tag": tag})

        finder = PrivilegeEscalationPathFinder(neo4j)
        raw_paths = await finder.find_role_chaining(cloud_provider=tag)
        assert len(raw_paths) == 2

        scores_by_target = {p.target_node: p.risk_score for p in raw_paths}
        admin_score = scores_by_target[f"{tag}:admin-target"]
        root_score = scores_by_target[f"{tag}:root-target"]

        assert admin_score == 0.5
        assert root_score == 0.5, (
            "If this fails, target.privilege_level is now being read "
            "correctly and this test (plus finding #2 in the Week 8 "
            "writeup) needs updating - a root target SHOULD score higher "
            "(0.70) than an admin target (0.50) once fixed."
        )
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_role_chaining_three_hop_to_root_silently_dropped():
    """
    Combines the depth-penalty and privilege_level-defaulting gaps: a
    3-hop CAN_ASSUME chain to a genuinely root-level (privilege_level=5)
    target is detected by the raw Cypher query, but because the scorer
    treats every role_chaining target as privilege_level=4 regardless of
    reality, the depth-3 penalty (0.20) drops it below min_risk=0.5
    (0.60 - 0.20 = 0.40) even though a real attacker reaching root in 3
    hops is materially dangerous. Same detected-but-not-alerted class as
    test_privilege_escalation_three_hop_detected_but_filtered_by_aggregator.
    """
    tag = "test-detreg-rolechain-3hop-root"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (a:Identity {id: $a, name: 'chainer', provider: $tag, privilege_level: 1})
            CREATE (b:Identity {id: $b, name: 'hop1', provider: $tag, privilege_level: 2})
            CREATE (c:Identity {id: $c, name: 'hop2', provider: $tag, privilege_level: 2})
            CREATE (root:Identity {id: $root, name: 'root-target', provider: $tag, privilege_level: 5})
            CREATE (a)-[:CAN_ASSUME]->(b)
            CREATE (b)-[:CAN_ASSUME]->(c)
            CREATE (c)-[:CAN_ASSUME]->(root)
        """, {"a": f"{tag}:chainer", "b": f"{tag}:hop1", "c": f"{tag}:hop2",
              "root": f"{tag}:root-target", "tag": tag})

        finder = PrivilegeEscalationPathFinder(neo4j)
        raw_paths = await finder.find_role_chaining(cloud_provider=tag)
        # The *2..4 Cypher pattern matches every sub-chain ending at a
        # qualifying target, not just the full path - so hop1->hop2->root
        # (depth=2) fires as its own row alongside the full
        # chainer->hop1->hop2->root (depth=3) row. Same row-multiplicity
        # pattern as the privilege_escalation "once per qualifying node"
        # finding, just triggered by sub-chains here instead of multiple
        # qualifying sources. Isolate the specific 3-hop chain by source
        # rather than assuming a single result.
        assert len(raw_paths) == 2
        by_source = {p.source_node: p for p in raw_paths}

        full_chain = by_source[f"{tag}:chainer"]
        sub_chain = by_source[f"{tag}:hop1"]
        assert full_chain.risk_score == 0.4
        assert sub_chain.risk_score == 0.5

        filtered = await finder.find_escalation_paths(cloud_provider=tag, min_risk_score=0.5)
        rc_hits = [p for p in filtered if p.escalation_type == "role_chaining"]
        rc_sources = {p.source_node for p in rc_hits}
        assert f"{tag}:chainer" not in rc_sources, (
            "The full 3-hop chain (chainer -> root) should be detected by "
            "the raw query but filtered from alerted results, purely "
            "because target.privilege_level is never selected by the "
            "query - a real Week 8 finding distinct from the depth=2 "
            "boundary. The 2-hop hop1->root sub-chain legitimately clears "
            "the bar on its own and is expected to still appear."
        )
        assert f"{tag}:hop1" in rc_sources
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_wildcard_trust_requires_principal_star():
    """
    QUERY_WILDCARD_TRUST matches ONLY on r.principal = '*'. A CAN_ASSUME
    edge without that exact property should not be picked up by this
    detector (even if it would match privilege_escalation).
    """
    tag = "test-detreg-wildcard"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (a:Identity {id: $a, name: 'anyone', provider: $tag, privilege_level: 1})
            CREATE (b:Identity {id: $b, name: 'open-role', provider: $tag, privilege_level: 5})
            CREATE (c:Identity {id: $c, name: 'scoped-role', provider: $tag, privilege_level: 5})
            CREATE (a)-[:CAN_ASSUME {principal: '*'}]->(b)
            CREATE (a)-[:CAN_ASSUME {principal: 'arn:aws:iam::123:role/specific'}]->(c)
        """, {"a": f"{tag}:anyone", "b": f"{tag}:open", "c": f"{tag}:scoped", "tag": tag})

        finder = PrivilegeEscalationPathFinder(neo4j)
        raw_paths = await finder.find_wildcard_trust(cloud_provider=tag)
        assert len(raw_paths) == 1
        assert raw_paths[0].target_node == f"{tag}:open"
        assert raw_paths[0].risk_score == 0.75  # privilege_level=5 case
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_cross_account_root_passes_admin_level_fails():
    """
    Documents the real gap pinned in test_risk_scorer.py: cross-account
    trust into a root (privilege_level=5) target passes min_risk=0.5,
    but the same trust into an account-admin (privilege_level=4) target
    does not, even though both have r.is_cross_account=true.
    """
    tag = "test-detreg-crossacct"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (a:Identity {id: $a, name: 'external', provider: $tag, privilege_level: 1})
            CREATE (root:Identity {id: $root, name: 'root-role', provider: $tag,
                                    privilege_level: 5, account_id: '999999999999'})
            CREATE (admin:Identity {id: $admin, name: 'admin-role', provider: $tag,
                                     privilege_level: 4, account_id: '999999999999'})
            CREATE (a)-[:CAN_ASSUME {is_cross_account: true}]->(root)
            CREATE (a)-[:CAN_ASSUME {is_cross_account: true}]->(admin)
        """, {"a": f"{tag}:external", "root": f"{tag}:root", "admin": f"{tag}:admin", "tag": tag})

        finder = PrivilegeEscalationPathFinder(neo4j)
        raw_paths = await finder.find_cross_account_risks(cloud_provider=tag)
        # Raw query matches BOTH (no risk filtering at the Cypher layer)
        assert len(raw_paths) == 2

        filtered = await finder.find_escalation_paths(cloud_provider=tag, min_risk_score=0.5)
        cross_account_hits = [p for p in filtered if p.escalation_type == "cross_account"]
        assert len(cross_account_hits) == 1, (
            "Only the root-level (privilege_level=5) cross-account trust "
            "should clear min_risk - the admin-level (privilege_level=4) "
            "one scores 0.425 and is silently dropped. Real Week 8 gap."
        )
        assert cross_account_hits[0].target_node == f"{tag}:root"
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_k8s_escalation_primitive_detected_via_can_escalate_via():
    """
    Mirrors the real bind-granter-role/admin-role shape from Week 6/7's
    live kind cluster test, but seeded directly rather than through a real
    K8sCollector scan. via_role stores the GRANTING role (bind-granter-role),
    not the target (admin-role) - same distinction the containment resolver
    relies on.
    """
    tag = "test-detreg-k8sprim"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (sa:Identity {id: $sa, name: 'victim-sa', provider: $tag, privilege_level: 1})
            CREATE (role:Role {id: $role, name: 'admin-role', provider: $tag, privilege_level: 5})
            CREATE (sa)-[:CAN_ESCALATE_VIA {verb: 'bind', via_role: $via}]->(role)
        """, {"sa": f"{tag}:victim-sa", "role": f"{tag}:admin-role",
              "via": f"{tag}:bind-granter-role", "tag": tag})

        finder = PrivilegeEscalationPathFinder(neo4j)
        raw_paths = await finder.find_k8s_escalation_primitives(cloud_provider=tag)
        assert len(raw_paths) == 1
        assert raw_paths[0].risk_score == 0.5  # exact boundary, per risk_scorer tests
        assert raw_paths[0].metadata["verb"] == "bind"
        assert raw_paths[0].metadata["via_role"] == f"{tag}:bind-granter-role"

        filtered = await finder.find_escalation_paths(cloud_provider=tag, min_risk_score=0.5)
        k8s_hits = [p for p in filtered if p.escalation_type == "k8s_escalation_primitive"]
        assert len(k8s_hits) == 1
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()


@pytest.mark.asyncio
async def test_find_escalation_paths_deduplicates_by_path_id():
    """
    A single seeded 2-hop CAN_ASSUME chain satisfies both
    privilege_escalation AND role_chaining patterns. They should NOT be
    deduplicated against each other (different escalation_type -> different
    path_id hash), but running find_escalation_paths() twice against the
    SAME unfiltered data should not produce duplicate entries within a
    single call.
    """
    tag = "test-detreg-dedup"
    neo4j = Neo4jClient()
    try:
        await neo4j.connect()
        await _seed(neo4j, """
            CREATE (a:Identity {id: $a, name: 'user', provider: $tag, privilege_level: 1})
            CREATE (b:Identity {id: $b, name: 'mid', provider: $tag, privilege_level: 2})
            CREATE (c:Identity {id: $c, name: 'admin', provider: $tag, privilege_level: 4})
            CREATE (a)-[:CAN_ASSUME]->(b)
            CREATE (b)-[:CAN_ASSUME]->(c)
        """, {"a": f"{tag}:user", "b": f"{tag}:mid", "c": f"{tag}:admin", "tag": tag})

        finder = PrivilegeEscalationPathFinder(neo4j)
        filtered = await finder.find_escalation_paths(cloud_provider=tag, min_risk_score=0.5)

        path_ids = [p.path_id for p in filtered]
        assert len(path_ids) == len(set(path_ids)), "Duplicate path_id found"

        escalation_types = {p.escalation_type for p in filtered}
        assert "privilege_escalation" in escalation_types
        assert "role_chaining" in escalation_types

        # Sorted descending by risk_score
        scores = [p.risk_score for p in filtered]
        assert scores == sorted(scores, reverse=True)
    finally:
        await _cleanup(neo4j, tag)
        await neo4j.close()