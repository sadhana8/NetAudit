from django.conf import settings
from django.db import migrations, models
import django.core.validators
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="Audit",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("title", models.CharField(max_length=160)),
                ("config_file", models.FileField(upload_to="audits/%Y/%m/", validators=[django.core.validators.FileExtensionValidator(["rsc", "txt"])])),
                ("original_filename", models.CharField(max_length=255)),
                ("raw_text", models.TextField(blank=True)),
                ("parsed_data", models.JSONField(blank=True, default=list)),
                ("score", models.PositiveSmallIntegerField(default=0)),
                ("rating", models.CharField(blank=True, max_length=40)),
                ("status", models.CharField(choices=[("pending", "Pending"), ("completed", "Completed"), ("failed", "Failed")], default="pending", max_length=20)),
                ("error_message", models.TextField(blank=True)),
                ("finding_count", models.PositiveIntegerField(default=0)),
                ("critical_count", models.PositiveIntegerField(default=0)),
                ("high_count", models.PositiveIntegerField(default=0)),
                ("medium_count", models.PositiveIntegerField(default=0)),
                ("low_count", models.PositiveIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("analyzed_at", models.DateTimeField(blank=True, null=True)),
                ("owner", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="router_audits", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="Finding",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("rule_id", models.CharField(max_length=30)),
                ("title", models.CharField(max_length=200)),
                ("category", models.CharField(max_length=80)),
                ("severity", models.CharField(choices=[("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Information")], max_length=20)),
                ("description", models.TextField()),
                ("evidence", models.TextField(blank=True)),
                ("recommendation", models.TextField()),
                ("suggested_command", models.TextField(blank=True)),
                ("line_number", models.PositiveIntegerField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("audit", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="findings", to="audits.audit")),
            ],
        ),
    ]
