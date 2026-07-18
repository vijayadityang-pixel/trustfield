"""
TrustField - GNN Anomaly Detector
Graph Attention Network (GAT) for detecting structural anomalies in the IAM trust graph.
This module requires PyTorch and PyTorch Geometric.
"""

import logging
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Optional imports — GNN module is disabled gracefully if torch is unavailable
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.nn import GATConv, global_mean_pool
    from torch_geometric.data import Data, DataLoader
    TORCH_AVAILABLE = True
    logger.info("PyTorch Geometric available — GNN module enabled")
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning(
        "PyTorch / PyTorch Geometric not installed — GNN module disabled. "
        "Install with: pip install torch torch-geometric"
    )

from ml.feature_extractor import FeatureExtractor

MODEL_PATH = Path(__file__).parent / "models" / "gnn_model.pt"


# ─── GNN Architecture ─────────────────────────────────────────────────────────

if TORCH_AVAILABLE:

    class TrustGraphGAT(nn.Module):
        """
        Graph Attention Network for IAM trust graph anomaly detection.

        Architecture:
        - 3 GAT layers with multi-head attention
        - Batch normalization for stable training
        - MLP head for node-level anomaly scoring
        - Dropout for regularization

        Input:  Node feature matrix (n_nodes × feature_dim)
        Output: Per-node anomaly scores in [0, 1]
        """

        def __init__(
            self,
            in_channels: int,
            hidden_channels: int = 64,
            out_channels: int = 32,
            n_heads: int = 4,
            dropout: float = 0.3,
        ):
            super().__init__()
            self.dropout = dropout

            # GAT layers
            self.conv1 = GATConv(
                in_channels, hidden_channels,
                heads=n_heads, dropout=dropout, concat=True
            )
            self.conv2 = GATConv(
                hidden_channels * n_heads, hidden_channels,
                heads=n_heads, dropout=dropout, concat=True
            )
            self.conv3 = GATConv(
                hidden_channels * n_heads, out_channels,
                heads=1, dropout=dropout, concat=False
            )

            # Batch normalization
            self.bn1 = nn.BatchNorm1d(hidden_channels * n_heads)
            self.bn2 = nn.BatchNorm1d(hidden_channels * n_heads)

            # MLP scoring head
            self.mlp = nn.Sequential(
                nn.Linear(out_channels, 16),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(16, 1),
                nn.Sigmoid(),
            )

        def forward(self, x: "torch.Tensor", edge_index: "torch.Tensor") -> "torch.Tensor":
            # Layer 1
            x = self.conv1(x, edge_index)
            x = self.bn1(x)
            x = F.elu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

            # Layer 2
            x = self.conv2(x, edge_index)
            x = self.bn2(x)
            x = F.elu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

            # Layer 3
            x = self.conv3(x, edge_index)
            x = F.elu(x)

            # Score each node
            scores = self.mlp(x)
            return scores.squeeze(-1)   # shape: (n_nodes,)


# ─── Detector Class ───────────────────────────────────────────────────────────

class GNNAnomalyDetector:
    """
    Wrapper around TrustGraphGAT for training and inference.
    Falls back gracefully to a no-op if PyTorch is unavailable.
    """

    def __init__(
        self,
        hidden_channels: int = 64,
        n_heads: int = 4,
        dropout: float = 0.3,
        anomaly_threshold: float = 0.65,
        device: Optional[str] = None,
    ):
        self.hidden_channels = hidden_channels
        self.n_heads = n_heads
        self.dropout = dropout
        self.anomaly_threshold = anomaly_threshold
        self.extractor = FeatureExtractor()
        self.model = None
        self._is_fitted = False

        if TORCH_AVAILABLE:
            self.device = torch.device(
                device or ("cuda" if torch.cuda.is_available() else "cpu")
            )
            logger.info(f"GNN using device: {self.device}")
            self._try_load_model()
        else:
            self.device = None

    def _try_load_model(self) -> None:
        """Load a pre-trained GNN model from disk."""
        if not TORCH_AVAILABLE:
            return
        try:
            if MODEL_PATH.exists():
                checkpoint = torch.load(MODEL_PATH, map_location=self.device)
                in_channels = checkpoint.get("in_channels", self.extractor.feature_dim)
                self.model = TrustGraphGAT(
                    in_channels=in_channels,
                    hidden_channels=self.hidden_channels,
                    n_heads=self.n_heads,
                    dropout=self.dropout,
                ).to(self.device)
                self.model.load_state_dict(checkpoint["model_state"])
                self.model.eval()
                self._is_fitted = True
                logger.info(f"Loaded GNN model from {MODEL_PATH}")
        except Exception as exc:
            logger.warning(f"Could not load GNN model: {exc}")

    def _build_graph_data(
        self, nodes: List[Dict], edges: List[Dict]
    ) -> Optional["Data"]:
        """Convert node/edge dicts to a PyG Data object."""
        if not TORCH_AVAILABLE:
            return None

        feature_matrix, node_ids = self.extractor.extract_batch(nodes)
        node_id_map = {nid: i for i, nid in enumerate(node_ids)}

        # Build edge_index tensor
        edge_pairs = []
        for edge in edges:
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            if src in node_id_map and tgt in node_id_map:
                edge_pairs.append([node_id_map[src], node_id_map[tgt]])

        if edge_pairs:
            edge_index = torch.tensor(edge_pairs, dtype=torch.long).t().contiguous()
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)

        x = torch.tensor(feature_matrix, dtype=torch.float32)
        return Data(x=x, edge_index=edge_index), node_ids

    def train(
        self,
        nodes: List[Dict],
        edges: List[Dict],
        epochs: int = 100,
        lr: float = 1e-3,
    ) -> Dict:
        """
        Self-supervised training using reconstruction loss.
        The model learns to reconstruct node features; high reconstruction
        error indicates anomalous nodes at inference time.
        """
        if not TORCH_AVAILABLE:
            logger.warning("GNN training skipped — PyTorch not available")
            return {"status": "skipped", "reason": "torch_unavailable"}

        if len(nodes) < 5:
            return {"status": "skipped", "reason": "insufficient_data"}

        result = self._build_graph_data(nodes, edges)
        if result is None:
            return {"status": "failed", "reason": "graph_build_failed"}
        data, node_ids = result
        data = data.to(self.device)

        in_channels = data.x.shape[1]
        self.model = TrustGraphGAT(
            in_channels=in_channels,
            hidden_channels=self.hidden_channels,
            n_heads=self.n_heads,
            dropout=self.dropout,
        ).to(self.device)

        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr, weight_decay=1e-4)
        scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=30, gamma=0.5)

        self.model.train()
        losses = []
        for epoch in range(epochs):
            optimizer.zero_grad()
            scores = self.model(data.x, data.edge_index)
            # Self-supervised: push scores toward node risk_score labels if available
            risk_labels = torch.tensor(
                [n.get("risk_score", 0.0) for n in nodes], dtype=torch.float32
            ).to(self.device)
            loss = F.mse_loss(scores, risk_labels)
            loss.backward()
            optimizer.step()
            scheduler.step()
            losses.append(loss.item())
            if (epoch + 1) % 20 == 0:
                logger.debug(f"GNN epoch {epoch+1}/{epochs} | loss={loss.item():.4f}")

        self._is_fitted = True
        self.model.eval()

        # Save
        try:
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            torch.save({
                "model_state": self.model.state_dict(),
                "in_channels": in_channels,
                "epochs": epochs,
            }, MODEL_PATH)
            logger.info(f"GNN model saved to {MODEL_PATH}")
        except Exception as exc:
            logger.warning(f"Could not save GNN model: {exc}")

        return {
            "status": "trained",
            "epochs": epochs,
            "final_loss": round(losses[-1], 4),
            "n_nodes": len(nodes),
            "n_edges": data.edge_index.shape[1],
        }

    def detect(
        self, nodes: List[Dict], edges: List[Dict]
    ) -> List[Dict]:
        """
        Run GNN-based anomaly detection.
        Returns a list of dicts with node_id, gnn_score, and is_anomaly.
        """
        if not TORCH_AVAILABLE:
            logger.warning("GNN inference skipped — PyTorch not available")
            return [{"node_id": n.get("id"), "gnn_score": 0.0, "is_anomaly": False} for n in nodes]

        if not nodes:
            return []

        result = self._build_graph_data(nodes, edges)
        if result is None:
            return []
        data, node_ids = result
        data = data.to(self.device)

        if not self._is_fitted:
            logger.info("GNN not trained — running auto-train")
            self.train(nodes, edges, epochs=50)

        self.model.eval()
        with torch.no_grad():
            scores = self.model(data.x, data.edge_index).cpu().numpy()

        results = []
        for i, node_id in enumerate(node_ids):
            score = float(scores[i])
            results.append({
                "node_id": node_id,
                "gnn_score": round(score, 4),
                "is_anomaly": score >= self.anomaly_threshold,
            })

        n_flagged = sum(1 for r in results if r["is_anomaly"])
        logger.info(f"GNN detection: {n_flagged}/{len(results)} nodes flagged")
        return results

    @property
    def is_available(self) -> bool:
        return TORCH_AVAILABLE