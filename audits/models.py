from django.conf import settings
from django.core.validators import FileExtensionValidator
from django.db import models


class Audit(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="router_audits",
    )
    title = models.CharField(max_length=160)
    config_file = models.FileField(
        upload_to="audits/%Y/%m/",
        validators=[FileExtensionValidator(["rsc", "txt"])],
    )
    original_filename = models.CharField(max_length=255)
    raw_text = models.TextField(blank=True)
    parsed_data = models.JSONField(default=list, blank=True)
    configuration_summary = models.JSONField(default=dict, blank=True)
    category_scores = models.JSONField(default=dict, blank=True)
    score_details = models.JSONField(default=dict, blank=True)
    score = models.PositiveSmallIntegerField(default=0)
    rating = models.CharField(max_length=40, blank=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )
    error_message = models.TextField(blank=True)
    finding_count = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    analyzed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} ({self.owner})"


class Finding(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Information"

    audit = models.ForeignKey(Audit, on_delete=models.CASCADE, related_name="findings")
    rule_id = models.CharField(max_length=30)
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=80)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    description = models.TextField()
    evidence = models.TextField(blank=True)
    recommendation = models.TextField()
    suggested_command = models.TextField(blank=True)
    line_number = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = [
            models.Case(
                models.When(severity="critical", then=0),
                models.When(severity="high", then=1),
                models.When(severity="medium", then=2),
                models.When(severity="low", then=3),
                default=4,
                output_field=models.IntegerField(),
            ),
            "rule_id",
            "id",
        ]

    def __str__(self):
        return f"{self.rule_id}: {self.title}"

