"""Lightweight ML-assisted risk classifier for audit result patterns.

The model uses expert-labeled sample profiles because real RouterOS audit
training datasets are sensitive and not available in this project.
"""

from __future__ import annotations

from math import sqrt
from typing import Any

KNN_MODEL_VERSION = "1.0"
KNN_NEIGHBOR_COUNT = 3

FEATURE_NAMES = (
    "score",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "finding_count",
    "firewall_risk_gap",
    "nat_risk_gap",
    "services_risk_gap",
)

TRAINING_PROFILES = (
    {
        "name": "Clean office router",
        "label": "Low",
        "priority": "Normal",
        "features": (94, 0, 0, 1, 2, 3, 4, 2, 3),
    },
    {
        "name": "Mostly safe branch router",
        "label": "Low",
        "priority": "Normal",
        "features": (86, 0, 1, 2, 3, 6, 12, 8, 10),
    },
    {
        "name": "Moderate configuration drift",
        "label": "Medium",
        "priority": "Important",
        "features": (72, 0, 2, 5, 4, 11, 25, 18, 22),
    },
    {
        "name": "Weak service restrictions",
        "label": "Medium",
        "priority": "Important",
        "features": (64, 0, 3, 6, 5, 14, 32, 20, 38),
    },
    {
        "name": "High-risk firewall exposure",
        "label": "High",
        "priority": "Urgent",
        "features": (49, 0, 6, 7, 6, 19, 58, 44, 45),
    },
    {
        "name": "Public management exposure",
        "label": "High",
        "priority": "Urgent",
        "features": (42, 1, 4, 5, 5, 15, 52, 36, 60),
    },
    {
        "name": "Critical perimeter failure",
        "label": "Critical",
        "priority": "Immediate",
        "features": (28, 2, 7, 8, 4, 21, 74, 68, 70),
    },
    {
        "name": "Multiple critical exposures",
        "label": "Critical",
        "priority": "Immediate",
        "features": (18, 4, 8, 8, 5, 25, 82, 75, 78),
    },
)

FEATURE_SCALES = (100, 5, 10, 12, 12, 30, 100, 100, 100)


class KNearestNeighborsRiskClassifier:
    """Small KNN classifier for audit risk profile prediction."""

    def __init__(
        self,
        training_profiles=TRAINING_PROFILES,
        neighbor_count: int = KNN_NEIGHBOR_COUNT,
    ):
        self.training_profiles = training_profiles
        self.neighbor_count = neighbor_count

    @staticmethod
    def _risk_gap(category_scores: dict[str, Any], category: str) -> int:
        score = category_scores.get(category)
        if score is None:
            return 0
        try:
            return max(0, 100 - int(score))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _normalized_distance(
        left: tuple[float, ...], right: tuple[float, ...]
    ) -> float:
        total = 0.0
        for left_value, right_value, scale in zip(left, right, FEATURE_SCALES):
            total += ((left_value - right_value) / scale) ** 2
        return sqrt(total)

    def build_feature_vector(
        self,
        *,
        score: int,
        counts: dict[str, int],
        category_scores: dict[str, Any],
        finding_count: int,
    ) -> tuple[float, ...]:
        """Convert one audit result into numeric ML classifier features."""
        return (
            float(score),
            float(counts.get("critical", 0)),
            float(counts.get("high", 0)),
            float(counts.get("medium", 0)),
            float(counts.get("low", 0)),
            float(finding_count),
            float(self._risk_gap(category_scores, "Firewall")),
            float(self._risk_gap(category_scores, "NAT")),
            float(self._risk_gap(category_scores, "Services")),
        )

    def classify(
        self,
        *,
        score: int,
        counts: dict[str, int],
        category_scores: dict[str, Any],
        finding_count: int,
    ) -> dict[str, Any]:
        """Predict risk using labeled audit profiles."""

        feature_vector = self.build_feature_vector(
            score=score,
            counts=counts,
            category_scores=category_scores,
            finding_count=finding_count,
        )

        distances = [
            (
                KNearestNeighborsRiskClassifier._normalized_distance(
                    feature_vector, profile["features"]
                ),
                profile,
            )
            for profile in self.training_profiles
        ]
        distances.sort(key=lambda item: item[0])

        neighbors = distances[: self.neighbor_count]
        label_scores: dict[str, float] = {}

        for distance, profile in neighbors:
            label = str(profile["label"])
            label_scores[label] = label_scores.get(label, 0.0) + (1 / (distance + 0.001))

        predicted_label = max(
            label_scores,
            key=label_scores.get,
        )

        confidence = round(
            (label_scores[predicted_label] / sum(label_scores.values())) * 100
        )

        nearest_distance, nearest_profile = neighbors[0]
        priority = next(
            str(profile["priority"])
            for _, profile in neighbors
            if profile["label"] == predicted_label
        )

        drivers = []

        if counts.get("critical", 0):
            drivers.append("critical findings")

        if counts.get("high", 0):
            drivers.append("high-severity findings")

        weak_categories = [
            category
            for category, category_score in category_scores.items()
            if isinstance(category_score, int) and category_score < 65
        ]

        if weak_categories:
            drivers.append("weak category scores in " + ", ".join(weak_categories[:3]))

        if not drivers:
            drivers.append("low severity count and strong category scores")

        return {
            "version": KNN_MODEL_VERSION,
            "algorithm": "K-Nearest Neighbors classifier",
            "training_source": "Expert-labeled sample audit profiles",
            "predicted_risk": predicted_label,
            "remediation_priority": priority,
            "confidence": confidence,
            "nearest_profile": str(nearest_profile["name"]),
            "nearest_distance": round(nearest_distance, 3),
            "neighbor_count": self.neighbor_count,
            "features": dict(zip(FEATURE_NAMES, feature_vector)),
            "explanation": "Prediction is based on " + ", ".join(drivers) + ".",
        }


def build_feature_vector(
    *,
    score: int,
    counts: dict[str, int],
    category_scores: dict[str, Any],
    finding_count: int,
) -> tuple[float, ...]:
    """Compatibility wrapper around KNearestNeighborsRiskClassifier.build_feature_vector."""
    return KNearestNeighborsRiskClassifier().build_feature_vector(
        score=score,
        counts=counts,
        category_scores=category_scores,
        finding_count=finding_count,
    )


def classify_risk(
    *,
    score: int,
    counts: dict[str, int],
    category_scores: dict[str, Any],
    finding_count: int,
) -> dict[str, Any]:
    """Compatibility wrapper around the OOP KNN risk classifier."""

    return KNearestNeighborsRiskClassifier().classify(
        score=score,
        counts=counts,
        category_scores=category_scores,
        finding_count=finding_count,
    )

