
from pathlib import Path

import xgboost as xgb


FEATURES = [
    "query_count",
    "unique_query_count",
    "unique_query_ratio",
    "queries_per_second",
    "avg_query_length",
    "max_query_length",
    "entropy",
    "avg_subdomain_length",
    "max_subdomain_length",
    "avg_subdomain_entropy",
    "max_subdomain_entropy",
    "unique_subdomain_count",
    "unique_subdomain_ratio",
    "mean_interarrival",
    "std_interarrival",
    "avg_packet_length",
    "max_packet_length",
]

MINIMUM_QUERY_COUNT = 10
THRESHOLD = 0.5


class MLDetector:
    """XGBoost-based DNS tunneling detector."""

    def __init__(self, model_path=None, threshold=THRESHOLD):
        project_root = Path(__file__).resolve().parents[2]

        if model_path is None:
            model_path = (
                project_root
                / "model_training"
                / "DNSHawk_D1_artifacts"
                / "models"
                / "xgboost_dns_tunnel_d1.json"
            )

        self.model_path = Path(model_path)
        self.threshold = threshold
        self.model = xgb.XGBClassifier()
        self.model.load_model(str(self.model_path))

    def predict(self, features):
        """
        Classify one feature dictionary.

        Returns insufficient evidence for windows containing
        fewer than 10 DNS queries.
        """

        query_count = int(features.get("query_count", 0))

        if query_count < MINIMUM_QUERY_COUNT:
            return {
                "status": "insufficient_evidence",
                "query_count": query_count,
                "prediction": None,
                "probability": None,
                "threshold": self.threshold,
            }

        missing = [
            name for name in FEATURES
            if name not in features
        ]

        if missing:
            raise ValueError(
                f"Missing required ML features: {missing}"
            )

        row = [[float(features[name]) for name in FEATURES]]

        probabilities = self.model.predict_proba(row)[0]
        classes = list(self.model.classes_)

        if 1 not in classes:
            raise ValueError(
                "The loaded model has no positive class (1)."
            )

        tunnel_probability = float(
            probabilities[classes.index(1)]
        )

        prediction = int(
            tunnel_probability >= self.threshold
        )

        return {
            "status": "classified",
            "query_count": query_count,
            "prediction": prediction,
            "label": (
                "dns_tunneling"
                if prediction == 1
                else "benign"
            ),
            "probability": tunnel_probability,
            "threshold": self.threshold,
        }
