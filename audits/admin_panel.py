from datetime import datetime, time

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User
from django.db.models import Avg, Count, Sum
from django.db.models.functions import Coalesce
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from .models import Audit, Finding
from .permissions import is_administrator
from .services import AuditRunner


admin_required = user_passes_test(is_administrator, login_url="login")


class AdminDateParser:
    """Parses admin filter dates into timezone-aware datetimes."""

    def parse(self, value, end_of_day=False):
        if not value:
            return None
        try:
            day = datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            return None
        moment = datetime.combine(day, time.max if end_of_day else time.min)
        return timezone.make_aware(moment, timezone.get_current_timezone())


class AdminDashboardContextBuilder:
    """Builds summary data for the custom administration dashboard."""

    def build(self):
        users = User.objects.all()
        audits = Audit.objects.select_related("owner")
        completed = audits.filter(status=Audit.Status.COMPLETED)
        failed = audits.filter(status=Audit.Status.FAILED)

        top_rules = (
            Finding.objects.values("rule_id", "title")
            .annotate(total=Count("id"))
            .order_by("-total", "rule_id")[:10]
        )

        avg_score = completed.aggregate(avg=Avg("score"))["avg"] or 0
        finding_totals = audits.aggregate(
            critical=Coalesce(Sum("critical_count"), 0),
            high=Coalesce(Sum("high_count"), 0),
        )

        return {
            "total_users": users.count(),
            "active_users": users.filter(is_active=True).count(),
            "total_audits": audits.count(),
            "completed_audits": completed.count(),
            "failed_audits": failed.count(),
            "average_score": round(avg_score),
            "critical_findings": finding_totals["critical"],
            "high_findings": finding_totals["high"],
            "top_rules": top_rules,
            "recent_audits": audits[:8],
            "recent_users": users.order_by("-date_joined")[:8],
        }


class AdminAuditListContextBuilder:
    """Applies admin audit filters and prepares list-page context."""

    def __init__(self, date_parser: AdminDateParser | None = None):
        self.date_parser = date_parser or AdminDateParser()

    def build(self, request):
        audits = Audit.objects.select_related("owner").all()
        owner_id = request.GET.get("user", "").strip()
        status = request.GET.get("status", "").strip()
        rating = request.GET.get("rating", "").strip()
        date_from = request.GET.get("from", "").strip()
        date_to = request.GET.get("to", "").strip()

        if owner_id.isdigit():
            audits = audits.filter(owner_id=int(owner_id))
        if status:
            audits = audits.filter(status=status)
        if rating:
            audits = audits.filter(rating__iexact=rating)

        start = self.date_parser.parse(date_from)
        end = self.date_parser.parse(date_to, end_of_day=True)
        if start:
            audits = audits.filter(created_at__gte=start)
        if end:
            audits = audits.filter(created_at__lte=end)

        return {
            "audits": audits[:200],
            "users": User.objects.order_by("username"),
            "status_choices": Audit.Status.choices,
            "selected_user": owner_id,
            "selected_status": status,
            "selected_rating": rating,
            "date_from": date_from,
            "date_to": date_to,
            "ratings": (
                Audit.objects.exclude(rating="")
                .values_list("rating", flat=True)
                .distinct()
                .order_by("rating")
            ),
        }


class AdminAuditDetailContextBuilder:
    """Builds a filtered finding view for one audit in the admin panel."""

    def build(self, request, audit):
        severity = request.GET.get("severity", "")
        category = request.GET.get("category", "")
        findings = audit.findings.all()

        if severity:
            findings = findings.filter(severity=severity)
        if category:
            findings = findings.filter(category=category)

        return {
            "audit": audit,
            "findings": findings,
            "selected_severity": severity,
            "selected_category": category,
            "categories": audit.findings.values_list("category", flat=True).distinct().order_by("category"),
            "is_admin_view": True,
        }


class AdminAuditActionService:
    """Performs admin-only audit actions."""

    def __init__(self, audit_runner: AuditRunner | None = None):
        self.audit_runner = audit_runner or AuditRunner()

    def reanalyze(self, audit):
        return self.audit_runner.run(audit, audit.raw_text or None)

    def delete(self, audit):
        title = audit.title
        audit.config_file.delete(save=False)
        audit.delete()
        return title


class AdminPanelController:
    """Class-based controller for custom NetAudit admin pages."""

    dashboard_template = "admin_panel/dashboard.html"
    audit_list_template = "admin_panel/audit_list.html"
    audit_detail_template = "admin_panel/audit_detail.html"

    def __init__(
        self,
        dashboard_builder: AdminDashboardContextBuilder | None = None,
        list_builder: AdminAuditListContextBuilder | None = None,
        detail_builder: AdminAuditDetailContextBuilder | None = None,
        action_service: AdminAuditActionService | None = None,
    ):
        self.dashboard_builder = dashboard_builder or AdminDashboardContextBuilder()
        self.list_builder = list_builder or AdminAuditListContextBuilder()
        self.detail_builder = detail_builder or AdminAuditDetailContextBuilder()
        self.action_service = action_service or AdminAuditActionService()

    def dashboard(self, request):
        return render(request, self.dashboard_template, self.dashboard_builder.build())

    def audit_list(self, request):
        return render(request, self.audit_list_template, self.list_builder.build(request))

    def audit_detail(self, request, pk):
        audit = get_object_or_404(Audit.objects.select_related("owner"), pk=pk)
        return render(request, self.audit_detail_template, self.detail_builder.build(request, audit))

    def reanalyze_audit(self, request, pk):
        audit = get_object_or_404(Audit, pk=pk)
        self.action_service.reanalyze(audit)
        if audit.status == Audit.Status.COMPLETED:
            messages.success(request, f"Reanalyzed audit #{audit.pk}.")
        else:
            messages.error(request, audit.error_message)
        return redirect("admin_audit_detail", pk=pk)

    def delete_audit(self, request, pk):
        audit = get_object_or_404(Audit, pk=pk)
        title = self.action_service.delete(audit)
        messages.success(request, f"Deleted audit: {title}")
        return redirect("admin_audits")


admin_panel_controller = AdminPanelController()


@admin_required
def admin_dashboard(request):
    return admin_panel_controller.dashboard(request)


@admin_required
def admin_audit_list(request):
    return admin_panel_controller.audit_list(request)


@admin_required
def admin_audit_detail(request, pk):
    return admin_panel_controller.audit_detail(request, pk)


@admin_required
@require_POST
def admin_audit_reanalyze(request, pk):
    return admin_panel_controller.reanalyze_audit(request, pk)


@admin_required
@require_POST
def admin_audit_delete(request, pk):
    return admin_panel_controller.delete_audit(request, pk)

