// ============================================================
// TrustField - Neo4j Cypher Query Library
// Reference queries for graph analytics and detection.
// ============================================================

// ── Schema Initialization ────────────────────────────────────

// Unique constraint on Identity id
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Identity) REQUIRE n.id IS UNIQUE;

// Indexes for common filter fields
CREATE INDEX IF NOT EXISTS FOR (n:Identity) ON (n.provider);
CREATE INDEX IF NOT EXISTS FOR (n:Identity) ON (n.risk_score);
CREATE INDEX IF NOT EXISTS FOR (n:Identity) ON (n.node_type);
CREATE INDEX IF NOT EXISTS FOR (n:Identity) ON (n.account_id);

// Full-text index for search
CREATE FULLTEXT INDEX IF NOT EXISTS identityNameSearch
FOR (n:Identity) ON EACH [n.name, n.arn, n.email];

// ── Trust Graph Queries ───────────────────────────────────────

// Get full graph for a provider (limited to 500 nodes)
MATCH (n:Identity)
WHERE n.provider = $provider
WITH n LIMIT 500
OPTIONAL MATCH (n)-[r]->(m:Identity)
RETURN n, r, m;

// Get subgraph centered on a node (depth 2)
MATCH path = (center:Identity {id: $node_id})-[*1..2]-(neighbor:Identity)
RETURN path;

// Get all neighbors of a node
MATCH (n:Identity {id: $node_id})-[r]-(neighbor:Identity)
RETURN neighbor, type(r) AS relationship,
       CASE WHEN startNode(r).id = $node_id THEN 'outbound' ELSE 'inbound' END AS direction;

// ── Privilege Escalation Detection ───────────────────────────

// Find all privilege escalation paths (low → high privilege)
MATCH path = (source:Identity)-[:CAN_ASSUME|HAS_ROLE|BOUND_TO*1..5]->(target:Identity)
WHERE source.privilege_level < 3
  AND target.privilege_level >= 4
  AND source.id <> target.id
RETURN
    source.id AS source,
    source.name AS source_name,
    target.id AS target,
    target.name AS target_name,
    [n IN nodes(path) | n.id] AS path_nodes,
    length(path) AS hops
ORDER BY hops ASC
LIMIT 50;

// Role assumption chaining (2-4 hops)
MATCH path = (source:Identity)-[:CAN_ASSUME*2..4]->(target:Identity)
WHERE target.privilege_level >= 4
RETURN
    source.id, target.id,
    [n IN nodes(path) | n.id] AS chain,
    length(path) AS depth
ORDER BY depth;

// Wildcard trust policies
MATCH (source:Identity)-[r:CAN_ASSUME]->(target:Identity)
WHERE r.principal = '*' OR r.condition IS NULL
RETURN source.id, source.name, target.id, target.name,
       target.privilege_level, r.principal;

// Cross-account trust relationships
MATCH (source:Identity)-[:CAN_ASSUME]->(target:Identity)
WHERE source.account_id <> target.account_id
RETURN source.id, source.account_id,
       target.id, target.account_id,
       target.privilege_level
ORDER BY target.privilege_level DESC;

// ── Risk Analysis ─────────────────────────────────────────────

// Top 20 highest risk nodes
MATCH (n:Identity)
WHERE n.risk_score IS NOT NULL
RETURN n.id, n.name, n.provider, n.node_type,
       n.risk_score, n.privilege_level
ORDER BY n.risk_score DESC
LIMIT 20;

// Risk score distribution by provider
MATCH (n:Identity)
WHERE n.risk_score IS NOT NULL
RETURN n.provider AS provider,
       count(n) AS node_count,
       avg(n.risk_score) AS avg_risk,
       max(n.risk_score) AS max_risk,
       min(n.risk_score) AS min_risk;

// Nodes with critical risk (>= 0.85)
MATCH (n:Identity)
WHERE n.risk_score >= 0.85
RETURN n.id, n.name, n.provider, n.risk_score
ORDER BY n.risk_score DESC;

// ── Kubernetes RBAC ───────────────────────────────────────────

// Service accounts bound to cluster-admin
MATCH (sa:Identity:K8sServiceAccount)-[r:BOUND_TO]->(role:Identity)
WHERE role.name = 'cluster-admin' OR r.is_high_risk = true
RETURN sa.name, sa.namespace, role.name, r.binding_name;

// High-risk K8s bindings
MATCH (subject:Identity)-[r:BOUND_TO {is_high_risk: true}]->(role:Identity)
RETURN subject.name, subject.namespace,
       role.name, r.binding_name, r.namespace;

// ── AWS Specific ──────────────────────────────────────────────

// IAM users without MFA
MATCH (u:Identity:AWSUser)
WHERE u.mfa_enabled = false
RETURN u.name, u.arn, u.risk_score, u.privilege_level
ORDER BY u.privilege_level DESC;

// Roles with wildcard policies
MATCH (r:Identity:AWSRole)
WHERE r.has_wildcard_policy = true
RETURN r.name, r.arn, r.privilege_level, r.risk_score;

// All assume-role edges for a specific role ARN
MATCH (source:Identity)-[r:CAN_ASSUME]->(target:Identity {arn: $role_arn})
RETURN source.id, source.name, r.principal, r.condition;

// ── Graph Statistics ──────────────────────────────────────────

// Overall node and edge counts
MATCH (n:Identity)
WITH count(n) AS node_count
MATCH ()-[r]->()
RETURN node_count, count(r) AS edge_count;

// Node count by type and provider
MATCH (n:Identity)
RETURN n.provider AS provider, n.node_type AS type, count(n) AS count
ORDER BY count DESC;

// Shortest path between two nodes
MATCH path = shortestPath(
    (source:Identity {id: $source_id})-[*..6]->(target:Identity {id: $target_id})
)
RETURN
    [n IN nodes(path) | n.id] AS node_ids,
    [r IN relationships(path) | type(r)] AS rel_types,
    length(path) AS path_length;

// ── Cleanup ────────────────────────────────────────────────────

// Delete all nodes for a specific provider
MATCH (n:Identity {provider: $provider})
DETACH DELETE n;

// Delete a specific node and its relationships
MATCH (n:Identity {id: $node_id})
DETACH DELETE n;
