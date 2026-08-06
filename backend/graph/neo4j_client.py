"""
TrustField - Neo4j Client
Async wrapper around the Neo4j Python driver for graph operations.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
from neo4j.exceptions import ServiceUnavailable, AuthError

from config import settings

logger = logging.getLogger(__name__)


class Neo4jClient:
    """
    Async Neo4j client for TrustField graph operations.
    Manages the driver lifecycle, connection pooling, and query execution.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "neo4j",
    ):
        self.uri = uri or settings.NEO4J_URI
        self.username = username or settings.NEO4J_USERNAME
        self.password = password or settings.NEO4J_PASSWORD
        self.database = database
        self._driver: Optional[AsyncDriver] = None

    async def connect(self) -> None:
        """Initialize the Neo4j async driver."""
        try:
            self._driver = AsyncGraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                max_connection_pool_size=50,
                connection_timeout=10,
            )
            await self._driver.verify_connectivity()
            logger.info(f"Connected to Neo4j at {self.uri}")
        except AuthError as exc:
            logger.error(f"Neo4j authentication failed: {exc}")
            raise
        except ServiceUnavailable as exc:
            logger.error(f"Neo4j service unavailable: {exc}")
            raise

    async def close(self) -> None:
        """Close the Neo4j driver and all pooled connections."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")

    @asynccontextmanager
    async def session(self):
        """Yield an async Neo4j session, auto-closing on exit."""
        if not self._driver:
            await self.connect()
        async with self._driver.session(database=self.database) as session:
            yield session

    async def run_query(
        self,
        query: str,
        parameters: Optional[Dict] = None,
    ) -> List[Dict]:
        """
        Execute a Cypher query and return results as a list of dicts.
        """
        async with self.session() as session:
            result = await session.run(query, parameters or {})
            records = await result.data()
            return records

    async def run_write_query(
        self,
        query: str,
        parameters: Optional[Dict] = None,
    ) -> List[Dict]:
        """Execute a write Cypher query inside a transaction."""
        async with self.session() as session:
            result = await session.execute_write(
                lambda tx: tx.run(query, parameters or {})
            )
            return result

    # ─── Node Operations ──────────────────────────────────────────────────────

    async def upsert_node(self, node_id: str, labels: List[str], properties: Dict) -> None:
        """
        Create or update a graph node.
        Uses MERGE on node id + primary label only (not the full label set),
        since MERGE matches on the whole pattern including labels. Merging
        on the full label set means the same id ingested under a different
        label combination (e.g. a managed identity that's also a service
        principal) creates a second node and collides with the id uniqueness
        constraint instead of updating the existing one. Additional labels
        are added via SET so they accumulate on the same node over repeated
        ingests instead of being overwritten or causing a mismatch.
        """
        primary_label = labels[0]
        extra_label_stmts = "\n".join(f"SET n:{lbl}" for lbl in labels[1:])
        query = f"""
        MERGE (n:{primary_label} {{id: $id}})
        {extra_label_stmts}
        SET n += $properties
        SET n.updated_at = datetime()
        """
        await self.run_query(query, {"id": node_id, "properties": properties})

    async def upsert_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        properties: Optional[Dict] = None,
    ) -> bool:
        """
        Create or update a directed relationship between two nodes.
        Uses MERGE (not MATCH) on both endpoints so the edge is still written
        even if one side hasn't been ingested as a full node yet (e.g. an AWS
        service principal referenced only in a trust policy). Returns True if
        the edge was actually written.
        """
        query = f"""
        MERGE (source {{id: $source_id}})
        MERGE (target {{id: $target_id}})
        MERGE (source)-[r:{relationship}]->(target)
        SET r += $properties
        SET r.updated_at = datetime()
        RETURN r
        """
        result = await self.run_query(
            query,
            {
                "source_id": source_id,
                "target_id": target_id,
                "properties": properties or {},
            },
        )
        return len(result) > 0
    async def get_node_by_id(self, node_id: str) -> Optional[Dict]:
        """Retrieve a node and its properties by ID."""
        query = """
        MATCH (n {id: $id})
        OPTIONAL MATCH (n)-[r]-(neighbor)
        RETURN
            n,
            labels(n) AS labels,
            collect({
                neighbor_id: neighbor.id,
                neighbor_name: neighbor.name,
                relationship: type(r),
                direction: CASE WHEN startNode(r) = n THEN 'outbound' ELSE 'inbound' END
            }) AS neighbors
        LIMIT 1
        """
        records = await self.run_query(query, {"id": node_id})
        if not records:
            return None
        rec = records[0]
        node = dict(rec["n"])
        node["labels"] = rec["labels"]
        node["neighbors"] = rec["neighbors"]
        return node

    async def get_nodes_by_risk(
        self,
        cloud_provider: Optional[str] = None,
        min_risk: float = 0.7,
        limit: int = 50,
    ) -> List[Dict]:
        """Return nodes ordered by risk_score descending."""
        query = """
        MATCH (n:Identity)
        WHERE n.risk_score >= $min_risk
          AND ($provider IS NULL OR n.provider = $provider)
        RETURN n, labels(n) AS labels
        ORDER BY n.risk_score DESC
        LIMIT $limit
        """
        records = await self.run_query(
            query,
            {"min_risk": min_risk, "provider": cloud_provider, "limit": limit},
        )
        return [{"labels": r["labels"], **dict(r["n"])} for r in records]

    async def search_nodes(
        self,
        query: str,
        cloud_provider: Optional[str] = None,
        node_type: Optional[str] = None,
        limit: int = 20,
    ) -> List[Dict]:
        """Full-text search on node name, id, and arn fields."""
        cypher = """
        MATCH (n:Identity)
        WHERE (n.name CONTAINS $q OR n.id CONTAINS $q OR n.arn CONTAINS $q)
          AND ($provider IS NULL OR n.provider = $provider)
          AND ($node_type IS NULL OR n.node_type = $node_type)
        RETURN n, labels(n) AS labels
        ORDER BY n.risk_score DESC
        LIMIT $limit
        """
        records = await self.run_query(
            cypher,
            {
                "q": query,
                "provider": cloud_provider,
                "node_type": node_type,
                "limit": limit,
            },
        )
        return [{"labels": r["labels"], **dict(r["n"])} for r in records]

    async def delete_node(self, node_id: str) -> None:
        """Delete a node and all its relationships."""
        await self.run_query(
            "MATCH (n {id: $id}) DETACH DELETE n",
            {"id": node_id},
        )

    async def clear_provider_data(self, cloud_provider: str) -> int:
        """Delete all nodes for a specific cloud provider (used before re-ingestion)."""
        result = await self.run_query(
            """
            MATCH (n:Identity {provider: $provider})
            WITH n, count(n) AS cnt
            DETACH DELETE n
            RETURN cnt
            """,
            {"provider": cloud_provider},
        )
        count = result[0]["cnt"] if result else 0
        logger.info(f"Cleared {count} nodes for provider {cloud_provider}")
        return count

    async def get_graph_statistics(self) -> Dict:
        """Return overall graph statistics."""
        result = await self.run_query("""
        MATCH (n:Identity)
        WITH count(n) AS node_count
        MATCH ()-[r]->()
        RETURN node_count, count(r) AS edge_count
        """)
        if result:
            return {
                "node_count": result[0]["node_count"],
                "edge_count": result[0]["edge_count"],
            }
        return {"node_count": 0, "edge_count": 0}
    
    async def get_risk_statistics(self, cloud_provider: Optional[str] = None) -> Dict:
        """Compute average risk score and high-risk node count."""
        query = """
        MATCH (n:Identity)
        WHERE ($provider IS NULL OR n.provider = $provider)
        RETURN
        avg(n.risk_score) AS avg_risk,
        count(CASE WHEN n.risk_score >= 0.7 THEN 1 END) AS high_risk_count
        """
        records = await self.run_query(query, {"provider": cloud_provider})
        if not records or records[0]["avg_risk"] is None:
            return {"avg_risk": 0.0, "high_risk_count": 0}
        return {
        "avg_risk": records[0]["avg_risk"],
        "high_risk_count": records[0]["high_risk_count"],
        }
    
    async def get_all_nodes_and_edges(self, cloud_provider: Optional[str] = None) -> Dict[str, List[Dict]]:
        """
        Return the full graph as raw node/edge dicts using the real stored
        property names (id, provider, node_type, privilege_level, etc.) —
        NOT the renamed node_id/cloud_provider naming build_graph() uses for
        its API response schema. FeatureExtractor expects these raw names.
        """
        node_query = """
        MATCH (n:Identity)
        WHERE ($provider IS NULL OR n.provider = $provider)
        RETURN n
        """
        node_records = await self.run_query(node_query, {"provider": cloud_provider})
        nodes = [dict(r["n"]) for r in node_records]

        # No :Identity restriction on edges — this intentionally includes
        # edges to/from skeleton nodes (e.g. wildcard "*" principals, external
        # account roots) created by upsert_edge's MERGE, since those edges
        # still matter for degree/centrality even though the endpoint itself
        # was never ingested as a full Identity node.
        edge_query = """
        MATCH (source)-[r]->(target)
        WHERE ($provider IS NULL OR source.provider = $provider)
        RETURN source.id AS source, target.id AS target,
               type(r) AS relationship, properties(r) AS properties
        """
        edge_records = await self.run_query(edge_query, {"provider": cloud_provider})
        edges = []
        for r in edge_records:
            edge = {"source": r["source"], "target": r["target"], "relationship": r["relationship"]}
            edge.update(r.get("properties") or {})
            edges.append(edge)

        return {"nodes": nodes, "edges": edges}

    async def apply_indexes(self) -> None:
        """Create Neo4j indexes and constraints for performance."""
        indexes = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Identity) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (n:Role) REQUIRE n.id IS UNIQUE",
            "CREATE INDEX IF NOT EXISTS FOR (n:Identity) ON (n.provider)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Identity) ON (n.risk_score)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Identity) ON (n.node_type)",
            "CREATE FULLTEXT INDEX identityNameSearch IF NOT EXISTS FOR (n:Identity) ON EACH [n.name, n.arn]",
        ]
        for idx in indexes:
            try:
                await self.run_query(idx)
            except Exception as exc:
                logger.warning(f"Index creation skipped: {exc}")
        logger.info("Neo4j indexes applied")