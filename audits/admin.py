from django.contrib import admin, messages

from .models import Audit, Finding
from .services import AuditRunner


class AuditAdminActionHandler:
    """Handles custom actions for the Django Audit admin."""

    def __init__(self, audit_runner: AuditRunner | None = None):
        self.audit_runner = audit_runner or AuditRunner()

    def reanalyze_selected(self, modeladmin, request, queryset):
        completed = 0
        failed = 0

        for audit in queryset.select_related("owner"):
            self.audit_runner.run(audit, audit.raw_text or None)

            if audit.status == Audit.Status.COMPLETED:
                completed += 1
            else:
                failed += 1

        if completed:
            modeladmin.message_user(
                request,
                f"{completed} audit(s) were analyzed successfully.",
                level=messages.SUCCESS,
            )

        if failed:
            modeladmin.message_user(
                request,
                f"{failed} audit(s) failed during analysis.",
                level=messages.ERROR,
            )


admin_action_handler = AuditAdminActionHandler()


@admin.action(description="Reanalyze selected audits")
def reanalyze_selected(modeladmin, request, queryset):
    return admin_action_handler.reanalyze_selected(modeladmin, request, queryset)


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0
    readonly_fields = ("rule_id", "severity", "title", "category")


@admin.register(Audit)
class AuditAdmin(admin.ModelAdmin):
    list_display = (
        "title",
        "owner",
        "score",
        "rating",
        "status",
        "finding_count",
        "critical_count",
        "created_at",
    )
    list_filter = (
        "status",
        "rating",
        "created_at",
        "analyzed_at",
    )
    search_fields = (
        "title",
        "original_filename",
        "owner__username",
        "owner__email",
    )
    readonly_fields = (
        "original_filename",
        "raw_text",
        "parsed_data",
        "configuration_summary",
        "category_scores",
        "score_details",
        "score",
        "rating",
        "status",
        "error_message",
        "finding_count",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "created_at",
        "analyzed_at",
    )
    list_select_related = ("owner",)
    date_hierarchy = "created_at"
    ordering = ("-created_at",)
    actions = (reanalyze_selected,)
    inlines = [FindingInline]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = (
        "rule_id",
        "title",
        "severity",
        "category",
        "audit",
        "line_number",
    )
    list_filter = (
        "severity",
        "category",
        "created_at",
    )
    search_fields = (
        "rule_id",
        "title",
        "description",
        "evidence",
        "audit__title",
        "audit__owner__username",
    )
    list_select_related = ("audit", "audit__owner")
    readonly_fields = (
        "audit",
        "rule_id",
        "title",
        "category",
        "severity",
        "description",
        "evidence",
        "recommendation",
        "suggested_command",
        "line_number",
        "created_at",
    )
    ordering = ("audit", "rule_id")


admin.site.site_header = "NetAudit Administration"
admin.site.site_title = "NetAudit Admin"
admin.site.index_title = "System administration"


# Maintenance review completed.

# [rev-7511] Reviewed 06 Sep 2026

# [rev-9145] Reviewed 11 Sep 2026
