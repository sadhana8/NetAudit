import re
from collections import defaultdict

from django.db import transaction
from django.utils import timezone

from .engine import RouterOSAuditAnalyzer
from .models import Audit, Finding



class RouterOSExportValidator:
    """Checks whether uploaded text looks like a RouterOS export."""

    SECTION_PATTERN = re.compile(
        r"^\s*/(?:interface|ip|ipv6|system|routing|tool|queue|user|certificate|ppp|snmp|radius|port|log|file|caps-man|caps|wireless|routing)\b",
        re.IGNORECASE,
    )
    INLINE_COMMAND_PATTERN = re.compile(
        r"^\s*/.+\b(add|set|remove|enable|disable|export|print)\b",
        re.IGNORECASE,
    )
    COMMAND_PATTERN = re.compile(
        r"^\s*(add|set|remove|enable|disable|export|print)\b",
        re.IGNORECASE,
    )

    def validate(self, text: str) -> None:
        normalized = str(text or "").strip()
        if not normalized:
            raise ValueError("The uploaded file is empty. Upload a RouterOS export file.")

        section_count = 0
        command_count = 0
        current_section_seen = False

        for raw_line in normalized.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if self.SECTION_PATTERN.match(line):
                section_count += 1
                current_section_seen = True
                if self.INLINE_COMMAND_PATTERN.match(line):
                    command_count += 1
                continue

            if current_section_seen and self.COMMAND_PATTERN.match(line):
                command_count += 1

        if section_count < 1 or command_count < 1:
            raise ValueError(
                "This file does not look like a MikroTik RouterOS export. "
                "NetAudit only accepts RouterOS .rsc/.txt exports, for example files created with /export."
            )

class ConfigFileDecoder:
    """Decodes uploaded RouterOS export files into text."""

    def decode(self, uploaded_file) -> str:
        uploaded_file.seek(0)
        raw = uploaded_file.read()
        uploaded_file.seek(0)
        if isinstance(raw, str):
            return raw
        for encoding in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        raise ValueError("The configuration file encoding is not supported.")


class AuditRunner:
    """Coordinates decoding, analysis, persistence, and audit status updates."""

    def __init__(
        self,
        analyzer: RouterOSAuditAnalyzer | None = None,
        decoder: ConfigFileDecoder | None = None,
    ):
        self.analyzer = analyzer or RouterOSAuditAnalyzer()
        self.decoder = decoder or ConfigFileDecoder()

    @transaction.atomic
    def run(self, audit: Audit, text: str | None = None) -> Audit:
        audit.status = Audit.Status.PENDING
        audit.error_message = ""
        audit.save(update_fields=["status", "error_message"])

        try:
            if text is None:
                text = self.decoder.decode(audit.config_file)
            RouterOSExportValidator().validate(text)
            result = self.analyzer.analyze(text)

            audit.findings.all().delete()
            Finding.objects.bulk_create([
                Finding(audit=audit, **finding) for finding in result["findings"]
            ])

            counts = result["counts"]
            audit.raw_text = text
            audit.parsed_data = result["entries"]
            audit.configuration_summary = result["configuration_summary"]
            audit.category_scores = result["category_scores"]
            audit.score_details = result["score_details"]
            audit.score = result["score"]
            audit.rating = result["rating"]
            audit.status = Audit.Status.COMPLETED
            audit.finding_count = len(result["findings"])
            audit.critical_count = counts.get("critical", 0)
            audit.high_count = counts.get("high", 0)
            audit.medium_count = counts.get("medium", 0)
            audit.low_count = counts.get("low", 0)
            audit.analyzed_at = timezone.now()
            audit.save()
        except Exception as exc:
            audit.status = Audit.Status.FAILED
            audit.error_message = str(exc)
            audit.configuration_summary = {}
            audit.category_scores = {}
            audit.score_details = {}
            audit.analyzed_at = timezone.now()
            audit.save(
                update_fields=[
                    "status",
                    "error_message",
                    "configuration_summary",
                    "category_scores",
                    "score_details",
                    "analyzed_at",
                ]
            )
        return audit


def decode_config(uploaded_file) -> str:
    """Compatibility wrapper around the OOP file decoder."""

    return ConfigFileDecoder().decode(uploaded_file)


def run_audit(audit: Audit, text: str | None = None) -> Audit:
    """Compatibility wrapper around the OOP audit runner."""

    return AuditRunner().run(audit, text=text)


COMPARISON_SEVERITIES = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)


class AuditComparisonService:
    """Compares two completed audits and produces a structured diff report."""

    @staticmethod
    def _normalize_comparison_text(value: str) -> str:
        """Normalize finding evidence for stable audit comparison."""
        normalized = str(value or "").strip().lower()
        normalized = re.sub(r"\s+", " ", normalized)
        return normalized

    @staticmethod
    def _finding_comparison_key(finding: Finding) -> tuple[str, str, str]:
        """Create a stable key for matching findings between audits."""
        return (
            str(finding.rule_id).strip().upper(),
            str(finding.category).strip().lower(),
            AuditComparisonService._normalize_comparison_text(
                finding.evidence or finding.title
            ),
        )

    @staticmethod
    def _serialize_comparison_finding(finding: Finding) -> dict[str, object]:
        """Convert a Finding model into template-safe comparison data."""
        return {
            "id": finding.pk,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "description": finding.description,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "suggested_command": finding.suggested_command,
            "line_number": finding.line_number,
        }

    def _summarize_comparison_findings(
        self,
        findings: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        """Group repeated comparison findings into beginner-friendly rows."""
        grouped: dict[tuple[object, ...], dict[str, object]] = {}

        for finding in findings:
            key = (
                finding.get("severity"),
                finding.get("rule_id"),
                finding.get("category"),
                finding.get("title"),
                finding.get("description"),
                finding.get("recommendation"),
            )

            if key not in grouped:
                grouped[key] = {
                    "severity": finding.get("severity"),
                    "rule_id": finding.get("rule_id"),
                    "category": finding.get("category"),
                    "title": finding.get("title"),
                    "description": finding.get("description"),
                    "recommendation": finding.get("recommendation"),
                    "count": 0,
                    "lines": [],
                    "line_label": "",
                }

            group = grouped[key]
            group["count"] = int(group["count"]) + 1

            line_number = finding.get("line_number")
            if line_number:
                group["lines"].append(line_number)

        summaries = list(grouped.values())

        for group in summaries:
            lines = sorted(set(group["lines"]))
            group["lines"] = lines
            if lines:
                prefix = "Line" if len(lines) == 1 else "Lines"
                group["line_label"] = f"{prefix} {', '.join(str(line) for line in lines)}"

        finding_sort_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }

        summaries.sort(
            key=lambda item: (
                finding_sort_order.get(str(item["severity"]), 5),
                str(item["rule_id"]),
                str(item["title"]),
            )
        )

        return summaries

    def _group_comparison_findings(
        self,
        findings,
    ) -> dict[tuple[str, str, str], list[Finding]]:
        """Group findings while preserving repeated occurrences."""
        grouped = defaultdict(list)
        for finding in findings:
            grouped[
                AuditComparisonService._finding_comparison_key(finding)
            ].append(finding)
        return grouped

    def compare(
        self,
        baseline: Audit,
        current: Audit,
    ) -> dict[str, object]:
        """Compare two completed audits belonging to the same user."""
        if baseline.pk == current.pk:
            raise ValueError(
                "An audit cannot be compared with itself."
            )

        if baseline.owner_id != current.owner_id:
            raise ValueError(
                "Only audits belonging to the same user can be compared."
            )

        if baseline.status != Audit.Status.COMPLETED:
            raise ValueError(
                "The baseline audit must be completed."
            )

        if current.status != Audit.Status.COMPLETED:
            raise ValueError(
                "The current audit must be completed."
            )

        baseline_findings = list(baseline.findings.all())
        current_findings = list(current.findings.all())

        baseline_groups = self._group_comparison_findings(baseline_findings)
        current_groups = self._group_comparison_findings(current_findings)

        comparison_keys = set(baseline_groups) | set(current_groups)

        resolved_findings = []
        new_findings = []
        unchanged_findings = []

        for key in comparison_keys:
            baseline_items = baseline_groups.get(key, [])
            current_items = current_groups.get(key, [])

            unchanged_count = min(len(baseline_items), len(current_items))

            for index in range(unchanged_count):
                unchanged_findings.append(
                    AuditComparisonService._serialize_comparison_finding(
                        current_items[index]
                    )
                )

            for finding in baseline_items[unchanged_count:]:
                resolved_findings.append(
                    AuditComparisonService._serialize_comparison_finding(finding)
                )

            for finding in current_items[unchanged_count:]:
                new_findings.append(
                    AuditComparisonService._serialize_comparison_finding(finding)
                )

        finding_sort_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }

        def finding_sort_key(item):
            return (
                finding_sort_order.get(str(item["severity"]), 5),
                str(item["rule_id"]),
                str(item["title"]),
            )

        resolved_findings.sort(key=finding_sort_key)
        new_findings.sort(key=finding_sort_key)
        unchanged_findings.sort(key=finding_sort_key)

        baseline_category_scores = baseline.category_scores or {}
        current_category_scores = current.category_scores or {}

        category_names = sorted(
            set(baseline_category_scores) | set(current_category_scores)
        )

        category_changes = []

        for category in category_names:
            baseline_score = baseline_category_scores.get(category)
            current_score = current_category_scores.get(category)
            delta = None

            if baseline_score is not None and current_score is not None:
                delta = int(current_score) - int(baseline_score)

            category_changes.append(
                {
                    "category": category,
                    "baseline_score": baseline_score,
                    "current_score": current_score,
                    "delta": delta,
                }
            )

        severity_changes = []

        for severity in COMPARISON_SEVERITIES:
            baseline_count = sum(
                1 for finding in baseline_findings if finding.severity == severity
            )
            current_count = sum(
                1 for finding in current_findings if finding.severity == severity
            )
            severity_changes.append(
                {
                    "severity": severity,
                    "baseline_count": baseline_count,
                    "current_count": current_count,
                    "delta": current_count - baseline_count,
                }
            )

        score_delta = int(current.score) - int(baseline.score)
        finding_delta = int(current.finding_count) - int(baseline.finding_count)

        if score_delta > 0:
            outcome = "Improved"
        elif score_delta < 0:
            outcome = "Declined"
        else:
            outcome = "Unchanged"

        return {
            "baseline": baseline,
            "current": current,
            "score_delta": score_delta,
            "finding_delta": finding_delta,
            "outcome": outcome,
            "resolved_findings": resolved_findings,
            "new_findings": new_findings,
            "unchanged_findings": unchanged_findings,
            "resolved_groups": self._summarize_comparison_findings(resolved_findings),
            "new_groups": self._summarize_comparison_findings(new_findings),
            "unchanged_groups": self._summarize_comparison_findings(unchanged_findings),
            "resolved_count": len(resolved_findings),
            "new_count": len(new_findings),
            "unchanged_count": len(unchanged_findings),
            "category_changes": category_changes,
            "severity_changes": severity_changes,
        }


def compare_audits(
    baseline: Audit,
    current: Audit,
) -> dict[str, object]:
    """Compatibility wrapper around AuditComparisonService."""
    return AuditComparisonService().compare(baseline, current)


