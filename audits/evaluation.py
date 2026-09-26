from __future__ import annotations

from collections.abc import Iterable


class RuleMetricsCalculator:
    """Calculates rule-level classification metrics."""

    def calculate(
        self,
        expected_rule_ids: Iterable[str],
        actual_rule_ids: Iterable[str],
        universe_rule_ids: Iterable[str],
    ) -> dict[str, object]:
        """Calculate precision, recall, F1, accuracy and related rule ID sets."""

        expected = {
            str(rule_id).strip().upper()
            for rule_id in expected_rule_ids
            if str(rule_id).strip()
        }

        actual = {
            str(rule_id).strip().upper()
            for rule_id in actual_rule_ids
            if str(rule_id).strip()
        }

        universe = {
            str(rule_id).strip().upper()
            for rule_id in universe_rule_ids
            if str(rule_id).strip()
        }

        true_positive_ids = expected & actual
        false_positive_ids = actual - expected
        false_negative_ids = expected - actual

        true_negative_ids = (
            universe
            - expected
            - actual
        )

        true_positives = len(true_positive_ids)
        false_positives = len(false_positive_ids)
        false_negatives = len(false_negative_ids)
        true_negatives = len(true_negative_ids)

        precision_denominator = (
            true_positives + false_positives
        )
        recall_denominator = (
            true_positives + false_negatives
        )
        accuracy_denominator = len(universe)

        precision = (
            true_positives / precision_denominator
            if precision_denominator
            else 1.0
        )

        recall = (
            true_positives / recall_denominator
            if recall_denominator
            else 1.0
        )

        f1_score = (
            2 * precision * recall
            / (precision + recall)
            if precision + recall
            else 0.0
        )

        accuracy = (
            (true_positives + true_negatives)
            / accuracy_denominator
            if accuracy_denominator
            else 1.0
        )

        return {
            "true_positives": true_positives,
            "false_positives": false_positives,
            "false_negatives": false_negatives,
            "true_negatives": true_negatives,
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1_score": round(f1_score, 6),
            "accuracy": round(accuracy, 6),
            "true_positive_ids": sorted(
                true_positive_ids
            ),
            "false_positive_ids": sorted(
                false_positive_ids
            ),
            "false_negative_ids": sorted(
                false_negative_ids
            ),
        }


# backward-compat alias
def calculate_rule_metrics(
    expected_rule_ids: Iterable[str],
    actual_rule_ids: Iterable[str],
    universe_rule_ids: Iterable[str],
) -> dict[str, object]:
    """Compatibility wrapper around RuleMetricsCalculator."""
    return RuleMetricsCalculator().calculate(
        expected_rule_ids, actual_rule_ids, universe_rule_ids
    )

