from django.test import SimpleTestCase

from .evaluation import calculate_rule_metrics


class EvaluationMetricTests(SimpleTestCase):
    def test_perfect_detection(self):
        metrics = calculate_rule_metrics(
            expected_rule_ids={
                "FW-001",
                "NAT-002",
            },
            actual_rule_ids={
                "FW-001",
                "NAT-002",
            },
            universe_rule_ids={
                "FW-001",
                "NAT-002",
                "IP-001",
            },
        )

        self.assertEqual(
            metrics["true_positives"],
            2,
        )
        self.assertEqual(
            metrics["false_positives"],
            0,
        )
        self.assertEqual(
            metrics["false_negatives"],
            0,
        )
        self.assertEqual(
            metrics["precision"],
            1.0,
        )
        self.assertEqual(
            metrics["recall"],
            1.0,
        )
        self.assertEqual(
            metrics["f1_score"],
            1.0,
        )

    def test_false_positive_and_false_negative(self):
        metrics = calculate_rule_metrics(
            expected_rule_ids={
                "FW-001",
                "NAT-002",
            },
            actual_rule_ids={
                "FW-001",
                "IP-001",
            },
            universe_rule_ids={
                "FW-001",
                "NAT-002",
                "IP-001",
            },
        )

        self.assertEqual(
            metrics["true_positives"],
            1,
        )
        self.assertEqual(
            metrics["false_positives"],
            1,
        )
        self.assertEqual(
            metrics["false_negatives"],
            1,
        )
        self.assertEqual(
            metrics["precision"],
            0.5,
        )
        self.assertEqual(
            metrics["recall"],
            0.5,
        )
        self.assertEqual(
            metrics["f1_score"],
            0.5,
        )

# [rev-3551] Reviewed 07 Jul 2026

# [rev-6226] Reviewed 14 Jul 2026

# [rev-4868] Reviewed 24 Aug 2026

# [rev-1656] Reviewed 28 Aug 2026

# [rev-8137] Reviewed 10 Sep 2026
