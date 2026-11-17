import os
import math
import random
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.config import settings
from app.database import db_manager

logger = logging.getLogger("wifi_monitor.ml")

FEATURE_KEYS = [
    "packet_rate",
    "byte_rate",
    "unique_dst_ports",
    "unique_dst_ips",
    "syn_ratio",
    "udp_ratio",
    "avg_packet_size"
]

# ==============================================================================
# Pure-Python Isolation Forest Implementation
# Reference: Liu, Ting, Zhou (IEEE ICDM 2008: "Isolation Forest")
# Guarantees 100% operation on restricted systems where native C/DLLs are blocked
# ==============================================================================

def c_factor(n: int) -> float:
    """Average path length of unsuccessful search in a Binary Search Tree (BST)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    euler_mascheroni = 0.5772156649
    return 2.0 * (math.log(n - 1) + euler_mascheroni) - (2.0 * (n - 1) / n)

class IsolationTreeNode:
    def __init__(self, left=None, right=None, split_feature: int = 0, split_value: float = 0.0, size: int = 0):
        self.left = left
        self.right = right
        self.split_feature = split_feature
        self.split_value = split_value
        self.size = size
        self.is_leaf = (left is None and right is None)

class PureIsolationTree:
    def __init__(self, max_depth: int):
        self.max_depth = max_depth
        self.root = None

    def fit(self, X: List[List[float]], current_depth: int = 0) -> IsolationTreeNode:
        n_samples = len(X)
        if current_depth >= self.max_depth or n_samples <= 1:
            return IsolationTreeNode(size=n_samples)

        n_features = len(X[0])
        # Randomly choose a split feature
        feat_idx = random.randint(0, n_features - 1)
        values = [row[feat_idx] for row in X]
        min_v, max_v = min(values), max(values)

        if min_v == max_v:
            return IsolationTreeNode(size=n_samples)

        split_v = random.uniform(min_v, max_v)
        left_X = [row for row in X if row[feat_idx] < split_v]
        right_X = [row for row in X if row[feat_idx] >= split_v]

        left_node = self.fit(left_X, current_depth + 1)
        right_node = self.fit(right_X, current_depth + 1)

        return IsolationTreeNode(
            left=left_node,
            right=right_node,
            split_feature=feat_idx,
            split_value=split_v,
            size=n_samples
        )

    def path_length(self, x: List[float], node: IsolationTreeNode, current_depth: int = 0) -> float:
        if node.is_leaf:
            return current_depth + c_factor(node.size)
        if x[node.split_feature] < node.split_value:
            return self.path_length(x, node.left, current_depth + 1)
        else:
            return self.path_length(x, node.right, current_depth + 1)

class PureIsolationForest:
    def __init__(self, n_estimators: int = 60, max_samples: int = 256, contamination: float = 0.05):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.trees: List[PureIsolationTree] = []
        self.subsample_size: int = 0

    def fit(self, X: List[List[float]]):
        self.subsample_size = min(len(X), self.max_samples)
        max_depth = math.ceil(math.log2(max(self.subsample_size, 2)))
        self.trees = []

        for _ in range(self.n_estimators):
            sample = random.sample(X, self.subsample_size)
            tree = PureIsolationTree(max_depth=max_depth)
            tree.root = tree.fit(sample)
            self.trees.append(tree)

    def compute_anomaly_score(self, x: List[float]) -> float:
        """
        Calculates Liu et al. anomaly score:
        s(x, n) = 2^(- E(h(x)) / c(n))
        Scores close to 1 are definite anomalies; scores < 0.5 are normal.
        """
        if not self.trees or self.subsample_size <= 1:
            return 0.5
        avg_path = sum(t.path_length(x, t.root) for t in self.trees) / len(self.trees)
        c = c_factor(self.subsample_size)
        if c == 0:
            return 0.5
        score = 2.0 ** (- (avg_path / c))
        return score

# ==============================================================================
# Unified Detector Interface with Automatic Fallback
# ==============================================================================

class IsolationForestDetector:
    def __init__(self):
        self.engine_type = "sklearn"
        self.sklearn_model = None
        self.pure_model = None
        self.is_trained: bool = False
        self.last_trained_time: Optional[datetime] = None
        self._init_engine()

    def _init_engine(self):
        """Attempt to load scikit-learn; fallback gracefully to PureIsolationForest on DLL policy blocks."""
        try:
            from sklearn.ensemble import IsolationForest
            self.engine_type = "sklearn"
            logger.info("Using scikit-learn IsolationForest engine.")
        except Exception as e:
            self.engine_type = "pure_python"
            logger.warning(
                f"Scikit-learn / NumPy native DLLs blocked by OS policy ({e}). "
                "Active engine: High-performance Pure-Python Isolation Forest."
            )
        self.train()

    def _features_to_list(self, feat: Dict[str, Any]) -> List[float]:
        return [
            float(feat.get("packet_rate", 0.0)),
            float(feat.get("byte_rate", 0.0)),
            float(feat.get("unique_dst_ports", 0)),
            float(feat.get("unique_dst_ips", 0)),
            float(feat.get("syn_ratio", 0.0)),
            float(feat.get("udp_ratio", 0.0)),
            float(feat.get("avg_packet_size", 0.0))
        ]

    def _generate_synthetic_baseline(self, num_samples: int = 300) -> List[List[float]]:
        """Create baseline distribution of benign Wi-Fi client behaviors."""
        random.seed(42)
        dataset = []
        for _ in range(num_samples):
            packet_rate = random.uniform(1.0, 15.0)
            byte_rate = random.uniform(500.0, 150000.0)
            ports = float(random.randint(1, 4))
            ips = float(random.randint(1, 3))
            syn_ratio = random.uniform(0.0, 0.12)
            udp_ratio = random.uniform(0.1, 0.4)
            avg_size = random.uniform(200.0, 1200.0)
            dataset.append([packet_rate, byte_rate, ports, ips, syn_ratio, udp_ratio, avg_size])
        return dataset

    def train(self, data: Optional[List[List[float]]] = None):
        """Train Isolation Forest on baseline traffic."""
        try:
            dataset = data if data and len(data) >= 50 else self._generate_synthetic_baseline(300)

            if self.engine_type == "sklearn":
                try:
                    from sklearn.ensemble import IsolationForest
                    import numpy as np
                    mat = np.array(dataset)
                    self.sklearn_model = IsolationForest(
                        n_estimators=100,
                        contamination=settings.ML_CONTAMINATION,
                        random_state=42
                    )
                    self.sklearn_model.fit(mat)
                    self.is_trained = True
                    self.last_trained_time = datetime.now(timezone.utc)
                    logger.info("Scikit-Learn IsolationForest model trained.")
                    return
                except Exception as e:
                    logger.warning(f"Failed sklearn fit ({e}). Switching to pure Python engine.")
                    self.engine_type = "pure_python"

            # Pure Python fit
            self.pure_model = PureIsolationForest(
                n_estimators=60,
                max_samples=180,
                contamination=settings.ML_CONTAMINATION
            )
            self.pure_model.fit(dataset)
            self.is_trained = True
            self.last_trained_time = datetime.now(timezone.utc)
            logger.info("Pure-Python Isolation Forest engine trained successfully.")
        except Exception as e:
            logger.error(f"Error training Isolation Forest: {e}")

    def score_features(self, ip: str, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluate real-time IP feature vector for anomaly isolation."""
        if not self.is_trained:
            return None

        # Ignore negligible background traffic
        if features.get("packet_rate", 0) < 1.0:
            return None

        try:
            vec = self._features_to_list(features)
            is_anomaly = False
            normalized_score = 0.0

            if self.engine_type == "sklearn" and self.sklearn_model:
                import numpy as np
                score_val = float(self.sklearn_model.decision_function(np.array([vec]))[0])
                pred = int(self.sklearn_model.predict(np.array([vec]))[0])
                normalized_score = round(score_val, 4)
                if pred == -1 or score_val < -0.05:
                    is_anomaly = True
            elif self.pure_model:
                # Score ranges from 0.0 (normal) to 1.0 (severe anomaly)
                score_val = self.pure_model.compute_anomaly_score(vec)
                normalized_score = round(score_val, 4)
                # In Liu et al., s > 0.60 is an anomalous outlier
                if score_val >= 0.58:
                    is_anomaly = True

            if is_anomaly:
                # Generate explanation
                reasons = []
                if features["syn_ratio"] > 0.35:
                    reasons.append(f"Elevated SYN probes ({features['syn_ratio']:.0%})")
                if features["unique_dst_ports"] >= 8:
                    reasons.append(f"Broad port probing ({features['unique_dst_ports']} distinct ports)")
                if features["packet_rate"] >= 25.0:
                    reasons.append(f"Rapid packet rate ({features['packet_rate']} pkts/s)")
                if features["byte_rate"] >= 200000.0:
                    reasons.append(f"High data throughput ({round(features['byte_rate']/1024, 1)} KB/s)")

                explanation = "; ".join(reasons) if reasons else "Statistical multidimensional outlier"
                severity = "HIGH" if normalized_score >= 0.68 or (self.engine_type == "sklearn" and normalized_score < -0.2) else "MEDIUM"

                anomaly_record = {
                    "timestamp": datetime.now(timezone.utc),
                    "ip_target": ip,
                    "detector": f"IsolationForest ({self.engine_type})",
                    "anomaly_score": normalized_score,
                    "features": features,
                    "severity": severity,
                    "explanation": explanation
                }
                db_manager.insert_anomaly(anomaly_record)
                return anomaly_record

        except Exception as e:
            logger.error(f"Error scoring features: {e}")

        return None

ml_detector = IsolationForestDetector()
