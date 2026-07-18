"""
TrustField - Isolation Forest Anomaly Detector
Detects anomalous IAM entities using scikit-learn's IsolationForest.
"""

import logging
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ml.feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "models" / "isolation_forest.pkl"
SCALER_PATH = Path(__file__).parent / "models" / "scaler.pkl"


class AnomalyResult:
    """Result of anomaly detection for a single node."""

    def __init__(
        self,
        node_id: str,
        is_anomaly: bool,
        anomaly_score: float,
        raw_score: float,
        feature_contributions: Optional[Dict] = None,
    ):
        self.node_id = node_id
        self.is_anomaly = is_anomaly
        self.anomaly_score = anomaly_score      # normalized 0-1, higher = more anomalous
        self.raw_score = raw_score              # raw IsolationForest score
        self.feature_contributions = feature_contributions or {}

    def to_dict(self) -> Dict:
        return {
            "node_id": self.node_id,
            "is_anomaly": self.is_anomaly,
            "anomaly_score": self.anomaly_score,
            "raw_score": self.raw_score,
            "feature_contributions": self.feature_contributions,
        }


class IsolationForestDetector:
    """
    Anomaly detection for IAM graph nodes using Isolation Forest.

    Workflow:
    1. Extract features from nodes using FeatureExtractor
    2. Scale features with StandardScaler
    3. Run IsolationForest to get anomaly scores
    4. Return AnomalyResult for each node

    The model can be trained on historical clean data and saved/loaded from disk.
    In absence of a trained model, it auto-fits on the current dataset (unsupervised).
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        max_samples: str = "auto",
        random_state: int = 42,
        anomaly_threshold: float = 0.6,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.random_state = random_state
        self.anomaly_threshold = anomaly_threshold

        self.extractor = FeatureExtractor()
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self._is_fitted = False

        # Try to load a pre-trained model
        self._load_model()

    def _load_model(self) -> None:
        """Load a pre-trained model and scaler from disk if available."""
        try:
            if MODEL_PATH.exists() and SCALER_PATH.exists():
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(SCALER_PATH, "rb") as f:
                    self.scaler = pickle.load(f)
                self._is_fitted = True
                logger.info("Loaded pre-trained IsolationForest model from disk")
        except Exception as exc:
            logger.warning(f"Could not load pre-trained model: {exc}")

    def _save_model(self) -> None:
        """Persist the trained model and scaler to disk."""
        try:
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(MODEL_PATH, "wb") as f:
                pickle.dump(self.model, f)
            with open(SCALER_PATH, "wb") as f:
                pickle.dump(self.scaler, f)
            logger.info(f"Model saved to {MODEL_PATH}")
        except Exception as exc:
            logger.warning(f"Could not save model: {exc}")

    def _build_model(self) -> IsolationForest:
        return IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            random_state=self.random_state,
            n_jobs=-1,
        )

    def _raw_score_to_anomaly_score(self, raw_scores: np.ndarray) -> np.ndarray:
        """
        Convert IsolationForest raw scores (negative float) to [0, 1] anomaly scores.
        Lower raw score = more anomalous → higher output score.
        """
        # Raw scores are in range [-0.5, 0.5] roughly; negate and normalize
        normalized = (-raw_scores - (-0.5)) / (0.5 - (-0.5))
        return np.clip(normalized, 0.0, 1.0)

    def train(self, nodes: List[Dict]) -> Dict:
        """
        Train the Isolation Forest on a set of node feature vectors.
        Call this with a representative clean dataset.

        Returns training summary statistics.
        """
        if len(nodes) < 10:
            raise ValueError(f"Need at least 10 nodes to train; got {len(nodes)}")

        feature_matrix, node_ids = self.extractor.extract_batch(nodes)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(feature_matrix)

        self.model = self._build_model()
        self.model.fit(X_scaled)
        self._is_fitted = True

        # Get training scores for summary
        raw_scores = self.model.score_samples(X_scaled)
        anomaly_scores = self._raw_score_to_anomaly_score(raw_scores)
        predicted = self.model.predict(X_scaled)
        n_anomalies = int(np.sum(predicted == -1))

        self._save_model()
        logger.info(
            f"IsolationForest trained on {len(nodes)} nodes | "
            f"anomalies detected: {n_anomalies} ({n_anomalies/len(nodes)*100:.1f}%)"
        )
        return {
            "n_samples": len(nodes),
            "n_features": feature_matrix.shape[1],
            "n_anomalies_training": n_anomalies,
            "contamination": self.contamination,
            "avg_anomaly_score": float(np.mean(anomaly_scores)),
        }

    def detect(self, nodes: List[Dict]) -> List[AnomalyResult]:
        """
        Run anomaly detection on a list of graph nodes.
        If no trained model exists, auto-fits on the provided data.

        Returns a list of AnomalyResult objects (one per node).
        """
        if not nodes:
            return []

        feature_matrix, node_ids = self.extractor.extract_batch(nodes)

        if not self._is_fitted:
            logger.info("No trained model found — fitting on current dataset (unsupervised)")
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(feature_matrix)
            self.model = self._build_model()
            self.model.fit(X_scaled)
            self._is_fitted = True
        else:
            X_scaled = self.scaler.transform(feature_matrix)

        raw_scores = self.model.score_samples(X_scaled)
        anomaly_scores = self._raw_score_to_anomaly_score(raw_scores)
        predictions = self.model.predict(X_scaled)

        results = []
        for i, node_id in enumerate(node_ids):
            is_anomaly = (
                predictions[i] == -1
                or anomaly_scores[i] >= self.anomaly_threshold
            )
            feature_contributions = self._compute_feature_contributions(
                X_scaled[i], anomaly_scores[i]
            )
            results.append(
                AnomalyResult(
                    node_id=node_id,
                    is_anomaly=is_anomaly,
                    anomaly_score=round(float(anomaly_scores[i]), 4),
                    raw_score=round(float(raw_scores[i]), 4),
                    feature_contributions=feature_contributions,
                )
            )

        n_anomalies = sum(1 for r in results if r.is_anomaly)
        logger.info(
            f"Anomaly detection complete: {n_anomalies}/{len(nodes)} nodes flagged "
            f"(threshold={self.anomaly_threshold})"
        )
        return results

    def _compute_feature_contributions(
        self, scaled_features: np.ndarray, anomaly_score: float
    ) -> Dict[str, float]:
        """
        Estimate which features contributed most to the anomaly score.
        Uses feature magnitude as a simple proxy (no SHAP dependency).
        """
        feature_names = self.extractor.get_feature_importance_labels()
        abs_values = np.abs(scaled_features)

        # Normalize contributions to sum to 1
        total = abs_values.sum()
        if total == 0:
            return {}

        contributions = abs_values / total
        top_indices = np.argsort(contributions)[-5:][::-1]  # Top 5 features

        return {
            feature_names[i]: round(float(contributions[i] * anomaly_score), 4)
            for i in top_indices
            if contributions[i] > 0.01
        }

    def get_anomaly_summary(self, results: List[AnomalyResult]) -> Dict:
        """Aggregate anomaly detection results into a summary."""
        if not results:
            return {"total": 0, "anomalies": 0, "anomaly_rate": 0.0}

        anomalies = [r for r in results if r.is_anomaly]
        scores = [r.anomaly_score for r in results]

        return {
            "total": len(results),
            "anomalies": len(anomalies),
            "anomaly_rate": round(len(anomalies) / len(results), 4),
            "avg_anomaly_score": round(float(np.mean(scores)), 4),
            "max_anomaly_score": round(float(np.max(scores)), 4),
            "top_anomalous_nodes": [
                {"node_id": r.node_id, "score": r.anomaly_score}
                for r in sorted(anomalies, key=lambda x: x.anomaly_score, reverse=True)[:10]
            ],
        }