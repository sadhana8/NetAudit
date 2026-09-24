from __future__ import annotations

import csv
import json
from pathlib import Path
from statistics import mean
from time import perf_counter

from django.core.management.base import (
    BaseCommand,
    CommandError,
)

from audits.engine.analyzer import analyze_config
from audits.engine.rule_registry import RULES_BY_ID
from audits.evaluation import calculate_rule_metrics


class Command(BaseCommand):
    help = (
        "Evaluate NetAudit against a labeled JSON manifest "
        "and generate JSON and CSV results."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--manifest",
            required=True,
            help="Path to the labeled evaluation manifest.",
        )

        parser.add_argument(
            "--output",
            default="evaluation/results",
            help="Directory in which evaluation results are saved.",
        )

    def handle(self, *args, **options):
        manifest_path = Path(
            options["manifest"]
        ).resolve()

        output_directory = Path(
            options["output"]
        ).resolve()

        if not manifest_path.exists():
            raise CommandError(
                f"Manifest not found: {manifest_path}"
            )

        try:
            manifest = json.loads(
                manifest_path.read_text(
                    encoding="utf-8"
                )
            )
        except json.JSONDecodeError as exc:
            raise CommandError(
                f"Invalid manifest JSON: {exc}"
            ) from exc

        cases = manifest.get("cases", [])

        if not cases:
            raise CommandError(
                "The manifest contains no evaluation cases."
            )

        universe_rule_ids = set(
            RULES_BY_ID
        )

        case_results = []

        total_true_positives = 0
        total_false_positives = 0
        total_false_negatives = 0
        total_true_negatives = 0

        for case in cases:
            case_id = str(
                case.get("id", "")
            ).strip()

            relative_file = str(
                case.get("file", "")
            ).strip()

            expected_rule_ids = {
                str(rule_id).strip().upper()
                for rule_id
                in case.get(
                    "expected_rule_ids",
                    [],
                )
                if str(rule_id).strip()
            }

            if not case_id or not relative_file:
                raise CommandError(
                    "Every case requires an id and file."
                )

            unknown_expected_rules = (
                expected_rule_ids
                - universe_rule_ids
            )

            if unknown_expected_rules:
                raise CommandError(
                    (
                        f"Case '{case_id}' references "
                        f"unregistered rules: "
                        f"{sorted(unknown_expected_rules)}"
                    )
                )

            config_path = (
                manifest_path.parent
                / relative_file
            ).resolve()

            if not config_path.exists():
                raise CommandError(
                    (
                        f"Configuration for case "
                        f"'{case_id}' was not found: "
                        f"{config_path}"
                    )
                )

            configuration_text = (
                config_path.read_text(
                    encoding="utf-8-sig"
                )
            )

            started_at = perf_counter()

            analysis_result = analyze_config(
                configuration_text
            )

            elapsed_milliseconds = round(
                (
                    perf_counter()
                    - started_at
                )
                * 1000,
                3,
            )

            actual_rule_ids = {
                str(finding["rule_id"])
                .strip()
                .upper()
                for finding
                in analysis_result["findings"]
            }

            metrics = calculate_rule_metrics(
                expected_rule_ids=(
                    expected_rule_ids
                ),
                actual_rule_ids=(
                    actual_rule_ids
                ),
                universe_rule_ids=(
                    universe_rule_ids
                ),
            )

            total_true_positives += int(
                metrics["true_positives"]
            )
            total_false_positives += int(
                metrics["false_positives"]
            )
            total_false_negatives += int(
                metrics["false_negatives"]
            )
            total_true_negatives += int(
                metrics["true_negatives"]
            )

            case_results.append(
                {
                    "id": case_id,
                    "description": case.get(
                        "description",
                        "",
                    ),
                    "file": relative_file,
                    "score": analysis_result[
                        "score"
                    ],
                    "rating": analysis_result[
                        "rating"
                    ],
                    "finding_count": len(
                        analysis_result[
                            "findings"
                        ]
                    ),
                    "processing_time_ms": (
                        elapsed_milliseconds
                    ),
                    "expected_rule_ids": sorted(
                        expected_rule_ids
                    ),
                    "actual_rule_ids": sorted(
                        actual_rule_ids
                    ),
                    **metrics,
                }
            )

        precision_denominator = (
            total_true_positives
            + total_false_positives
        )

        recall_denominator = (
            total_true_positives
            + total_false_negatives
        )

        precision = (
            total_true_positives
            / precision_denominator
            if precision_denominator
            else 1.0
        )

        recall = (
            total_true_positives
            / recall_denominator
            if recall_denominator
            else 1.0
        )

        f1_score = (
            2 * precision * recall
            / (precision + recall)
            if precision + recall
            else 0.0
        )

        accuracy_denominator = (
            total_true_positives
            + total_false_posititives
            + total_false_negatives
            + total_true_negatives
        ) if False else (
            total_true_positives
            + total_false_positives
            + total_false_negatives
            + total_true_negatives
        )

        accuracy = (
            (
                total_true_positives
                + total_true_negatives
            )
            / accuracy_denominator
            if accuracy_denominator
            else 1.0
        )

        summary = {
            "dataset_name": manifest.get(
                "dataset_name",
                "NetAudit Evaluation",
            ),
            "dataset_version": manifest.get(
                "version",
                "1.0",
            ),
            "case_count": len(case_results),
            "registered_rule_count": len(
                universe_rule_ids
            ),
            "true_positives": (
                total_true_positives
            ),
            "false_positives": (
                total_false_positives
            ),
            "false_negatives": (
                total_false_negatives
            ),
            "true_negatives": (
                total_true_negatives
            ),
            "precision": round(
                precision,
                6,
            ),
            "recall": round(
                recall,
                6,
            ),
            "f1_score": round(
                f1_score,
                6,
            ),
            "accuracy": round(
                accuracy,
                6,
            ),
            "average_processing_time_ms": round(
                mean(
                    result[
                        "processing_time_ms"
                    ]
                    for result in case_results
                ),
                3,
            ),
            "maximum_processing_time_ms": max(
                result[
                    "processing_time_ms"
                ]
                for result in case_results
            ),
            "macro_precision": round(
                mean(
                    result["precision"]
                    for result in case_results
                ),
                6,
            ),
            "macro_recall": round(
                mean(
                    result["recall"]
                    for result in case_results
                ),
                6,
            ),
            "macro_f1_score": round(
                mean(
                    result["f1_score"]
                    for result in case_results
                ),
                6,
            ),
        }

        output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        json_output = (
            output_directory
            / "evaluation_results.json"
        )

        csv_output = (
            output_directory
            / "evaluation_cases.csv"
        )

        json_output.write_text(
            json.dumps(
                {
                    "summary": summary,
                    "cases": case_results,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        with csv_output.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as csv_file:
            fieldnames = (
                "id",
                "description",
                "file",
                "score",
                "rating",
                "finding_count",
                "processing_time_ms",
                "true_positives",
                "false_positives",
                "false_negatives",
                "true_negatives",
                "precision",
                "recall",
                "f1_score",
                "accuracy",
                "expected_rule_ids",
                "actual_rule_ids",
                "false_positive_ids",
                "false_negative_ids",
            )

            writer = csv.DictWriter(
                csv_file,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            for result in case_results:
                row = {
                    key: result.get(key, "")
                    for key in fieldnames
                }

                for list_field in (
                    "expected_rule_ids",
                    "actual_rule_ids",
                    "false_positive_ids",
                    "false_negative_ids",
                ):
                    row[list_field] = ";".join(
                        result.get(
                            list_field,
                            [],
                        )
                    )

                writer.writerow(row)

        self.stdout.write(
            self.style.SUCCESS(
                (
                    "Evaluation completed.\n"
                    f"Cases: {summary['case_count']}\n"
                    f"Precision: {summary['precision']:.4f}\n"
                    f"Recall: {summary['recall']:.4f}\n"
                    f"F1 score: {summary['f1_score']:.4f}\n"
                    f"Average time: "
                    f"{summary['average_processing_time_ms']}"
                    f" ms\n"
                    f"JSON: {json_output}\n"
                    f"CSV: {csv_output}"
                )
            )
        )

# [rev-2125] Reviewed 19 Jul 2026

# [rev-8709] Reviewed 24 Aug 2026

# [rev-8325] Reviewed 02 Sep 2026
