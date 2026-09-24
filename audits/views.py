import csv
from io import BytesIO
from pathlib import Path
from html import escape

from django.contrib import messages
from django.contrib.auth import (
    login,
    logout,
    update_session_auth_hash,
)
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView
from django.core.paginator import Paginator
from django.db.models import Avg, Count, Q, Sum
from django.http import FileResponse, Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .forms import (
    AdminUserCreateForm,
    AdminSetPasswordForm,
    AdminUserUpdateForm,
    AuditUploadForm,
    ProfilePasswordForm,
    ProfileUpdateForm,
    RegistrationForm,
)
from .http_utils import form_errors_payload, wants_json
from .models import Audit
from .sample_configs import SAMPLE_CONFIGS, SAMPLES_BY_SLUG
from .permissions import is_administrator
from .engine.rule_registry import (
    CATEGORY_ORDER,
    SEVERITY_ORDER,
    filter_rules,
    get_rule_statistics,
    group_rules,
)
from .services import compare_audits, run_audit


admin_required = user_passes_test(
    is_administrator,
    login_url="login",
)


def _active_superuser_count():
    return User.objects.filter(
        is_superuser=True,
        is_active=True,
    ).count()


def home(request):
    statistics = get_rule_statistics()

    return render(
        request,
        "home.html",
        {
            "supported_rule_count": statistics["total"],
        },
    )


def features(request):
    latest_audit = None
    baseline_audit = None

    if request.user.is_authenticated:
        completed_audits = request.user.router_audits.filter(
            status=Audit.Status.COMPLETED,
        ).order_by("-created_at")

        latest_audit = completed_audits.first()

        if latest_audit is not None:
            baseline_audit = completed_audits.exclude(
                pk=latest_audit.pk,
            ).first()

    return render(
        request,
        "audits/features.html",
        {
            "latest_audit": latest_audit,
            "baseline_audit": baseline_audit,
        },
    )


def _completed_audits_for_user(user):
    return user.router_audits.filter(
        status=Audit.Status.COMPLETED,
    ).order_by("-created_at")


FEATURE_START_PAGES = {
    "audit_result": {
        "eyebrow": "Audit review",
        "title": "Audit result",
        "summary": "Review score, findings, evidence, and remediation guidance for a selected RouterOS export.",
        "route_name": "audit_detail",
        "next_module": "detail",
        "steps": [
            "Choose or upload a RouterOS export.",
            "NetAudit analyzes the configuration and calculates risk.",
            "Open the result to review findings and fixes.",
        ],
    },
    "network_map": {
        "eyebrow": "Configuration topology",
        "title": "Network map",
        "summary": "Build a readable WAN, LAN, interface, DHCP, route, and NAT inventory from one selected export.",
        "route_name": "audit_topology",
        "next_module": "topology",
        "steps": [
            "Choose or upload the export you want to map.",
            "NetAudit extracts interfaces, addresses, DHCP, routes, and NAT entries.",
            "Open the map to inspect router structure section by section.",
        ],
    },
    "attack_surface": {
        "eyebrow": "Exposure analysis",
        "title": "Attack surface",
        "summary": "Inspect exposed services, WAN accepts, destination NAT, and high-risk entry points for a selected export.",
        "route_name": "audit_attack_surface",
        "next_module": "attack_surface",
        "steps": [
            "Choose or upload the export you want to inspect.",
            "NetAudit detects externally reachable services and forwarding paths.",
            "Open the surface view to decide what should be restricted first.",
        ],
    },
    "hardening_script": {
        "eyebrow": "RouterOS hardening",
        "title": "Hardening script",
        "summary": "Generate reviewable RouterOS commands from supported findings in a selected audit.",
        "route_name": "audit_hardening",
        "next_module": "hardening",
        "steps": [
            "Choose or upload the export that needs hardening guidance.",
            "NetAudit converts supported findings into safe review commands.",
            "Review every command before applying anything on a real router.",
        ],
    },
    "before_after": {
        "eyebrow": "Audit comparison",
        "title": "Before-after comparison",
        "summary": "Compare a selected audit with another completed audit to see score changes, resolved issues, and new issues.",
        "route_name": "audit_compare",
        "next_module": "compare",
        "steps": [
            "Choose the current audit you want to compare.",
            "Select another completed audit as the baseline inside the comparison page.",
            "Review resolved, new, and unchanged findings.",
        ],
    },
}


NEXT_MODULE_ROUTES = {
    "detail": "audit_detail",
    "topology": "audit_topology",
    "attack_surface": "audit_attack_surface",
    "hardening": "audit_hardening",
    "compare": "audit_compare",
}


def _render_feature_start(request, feature_key):
    feature = FEATURE_START_PAGES[feature_key]
    completed_audits = _completed_audits_for_user(request.user)

    return render(
        request,
        "audits/feature_start.html",
        {
            "feature": feature,
            "audits": completed_audits,
            "form": AuditUploadForm(),
        },
    )


@login_required
def feature_audit_result(request):
    return _render_feature_start(request, "audit_result")


@login_required
def feature_network_map(request):
    return _render_feature_start(request, "network_map")


@login_required
def feature_attack_surface(request):
    return _render_feature_start(request, "attack_surface")


@login_required
def feature_hardening_script(request):
    return _render_feature_start(request, "hardening_script")


@login_required
def feature_before_after(request):
    return _render_feature_start(request, "before_after")

def supported_rules(request):
    query = request.GET.get("q", "").strip()
    category = request.GET.get(
        "category",
        "",
    ).strip()
    severity = request.GET.get(
        "severity",
        "",
    ).strip().lower()

    rules = filter_rules(
        query=query,
        category=category,
        severity=severity,
    )

    statistics = get_rule_statistics()

    return render(
        request,
        "audits/supported_rules.html",
        {
            "grouped_rules": group_rules(rules),
            "result_count": len(rules),
            "statistics": statistics,
            "categories": CATEGORY_ORDER,
            "severities": SEVERITY_ORDER,
            "query": query,
            "selected_category": category,
            "selected_severity": severity,
        },
    )


def post_login_redirect(user):
    if is_administrator(user):
        return reverse("admin_dashboard")
    return reverse("dashboard")


class NetAuditLoginView(LoginView):
    template_name = "registration/login.html"

    def get_success_url(self):
        return post_login_redirect(self.request.user)


def register_view(request):
    if request.user.is_authenticated:
        if wants_json(request):
            return JsonResponse({"ok": True, "redirect": post_login_redirect(request.user)})
        return redirect(post_login_redirect(request.user))
    form = RegistrationForm(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "Your NetAudit account is ready.")
            if wants_json(request):
                return JsonResponse({"ok": True, "redirect": reverse("dashboard")})
            return redirect("dashboard")
        if wants_json(request):
            return JsonResponse(form_errors_payload(form), status=400)
    return render(request, "registration/register.html", {"form": form})


@require_POST
def logout_view(request):
    logout(request)
    return redirect("home")


@login_required
def dashboard(request):
    audits = request.user.router_audits.all()
    context = {
        "audits": audits[:20],
        "audit_total": audits.count(),
        "completed_total": audits.filter(status=Audit.Status.COMPLETED).count(),
        "critical_total": sum(a.critical_count for a in audits),
        "average_score": round(sum(a.score for a in audits) / audits.count()) if audits else 0,
    }
    return render(request, "audits/dashboard.html", context)


@admin_required
def admin_users(request):
    search = request.GET.get("q", "").strip()
    status = request.GET.get("status", "").strip()

    users = User.objects.annotate(
        audit_count=Count("router_audits"),
    ).order_by("-date_joined")

    if search:
        users = users.filter(
            Q(username__icontains=search)
            | Q(email__icontains=search)
            | Q(first_name__icontains=search)
            | Q(last_name__icontains=search)
        )

    if status == "active":
        users = users.filter(is_active=True)
    elif status == "inactive":
        users = users.filter(is_active=False)
    elif status == "admin":
        users = users.filter(is_superuser=True)
    elif status == "user":
        users = users.filter(is_superuser=False)

    paginator = Paginator(users, 20)
    page = paginator.get_page(request.GET.get("page"))

    return render(
        request,
        "audits/admin_users.html",
        {
            "page": page,
            "search": search,
            "selected_status": status,
        },
    )


@admin_required
def admin_user_detail(request, user_id):
    account = get_object_or_404(
        User.objects.annotate(
            audit_count=Count("router_audits"),
        ),
        pk=user_id,
    )

    audits = account.router_audits.order_by(
        "-created_at",
    )

    audit_summary = audits.aggregate(
        average_score=Avg("score"),
        critical_total=Sum("critical_count"),
        high_total=Sum("high_count"),
    )

    context = {
        "account": account,
        "recent_audits": audits[:10],
        "average_score": round(
            audit_summary["average_score"] or 0
        ),
        "critical_total": (
            audit_summary["critical_total"] or 0
        ),
        "high_total": audit_summary["high_total"] or 0,
    }

    return render(
        request,
        "audits/admin_user_detail.html",
        context,
    )


@admin_required
def admin_user_create(request):
    form = AdminUserCreateForm(
        request.POST or None,
    )

    if request.method == "POST" and form.is_valid():
        account = form.save()

        messages.success(
            request,
            f"User account '{account.username}' was created.",
        )

        return redirect(
            "admin_user_detail",
            user_id=account.pk,
        )

    return render(
        request,
        "audits/admin_user_form.html",
        {
            "form": form,
            "page_title": "Create user",
            "page_description": (
                "Create a normal user or administrator account."
            ),
            "submit_label": "Create user",
        },
    )


@admin_required
def admin_user_edit(request, user_id):
    account = get_object_or_404(
        User,
        pk=user_id,
    )

    form = AdminUserUpdateForm(
        request.POST or None,
        instance=account,
    )

    if request.method == "POST" and form.is_valid():
        requested_access = form.cleaned_data[
            "access_level"
        ]
        requested_status = form.cleaned_data[
            "account_status"
        ]

        removing_admin_access = (
            account.is_superuser
            and requested_access != "admin"
        )

        deactivating_account = (
            account.is_active
            and requested_status != "active"
        )

        if account.pk == request.user.pk:
            if removing_admin_access:
                form.add_error(
                    "access_level",
                    "You cannot remove your own administrator access.",
                )

            if deactivating_account:
                form.add_error(
                    "account_status",
                    "You cannot deactivate your own account.",
                )

        elif (
            account.is_superuser
            and account.is_active
            and _active_superuser_count() == 1
            and (
                removing_admin_access
                or deactivating_account
            )
        ):
            form.add_error(
                None,
                (
                    "This account is the last active administrator. "
                    "Create another active administrator first."
                ),
            )

        if not form.errors:
            updated_account = form.save()

            messages.success(
                request,
                (
                    f"User account "
                    f"'{updated_account.username}' was updated."
                ),
            )

            return redirect(
                "admin_user_detail",
                user_id=updated_account.pk,
            )

    return render(
        request,
        "audits/admin_user_form.html",
        {
            "form": form,
            "account": account,
            "page_title": "Edit user",
            "page_description": (
                "Update account details, access level, "
                "and activation status."
            ),
            "submit_label": "Save changes",
        },
    )


@admin_required
def admin_user_reset_password(request, user_id):
    account = get_object_or_404(
        User,
        pk=user_id,
    )

    form = AdminSetPasswordForm(
        user=account,
        data=request.POST or None,
    )

    if request.method == "POST" and form.is_valid():
        updated_account = form.save()

        if updated_account.pk == request.user.pk:
            update_session_auth_hash(
                request,
                updated_account,
            )

        messages.success(
            request,
            (
                f"Password for '{updated_account.username}' "
                f"was updated."
            ),
        )

        return redirect(
            "admin_user_detail",
            user_id=updated_account.pk,
        )

    return render(
        request,
        "audits/admin_user_password.html",
        {
            "form": form,
            "account": account,
        },
    )


@admin_required
@require_POST
def admin_user_toggle_active(request, user_id):
    account = get_object_or_404(
        User,
        pk=user_id,
    )

    if account.pk == request.user.pk:
        messages.error(
            request,
            "You cannot deactivate your own account.",
        )

        return redirect(
            "admin_user_detail",
            user_id=account.pk,
        )

    if (
        account.is_superuser
        and account.is_active
        and _active_superuser_count() == 1
    ):
        messages.error(
            request,
            (
                "This account is the last active "
                "administrator and cannot be deactivated."
            ),
        )

        return redirect(
            "admin_user_detail",
            user_id=account.pk,
        )

    account.is_active = not account.is_active
    account.save(update_fields=["is_active"])

    status_label = (
        "activated"
        if account.is_active
        else "deactivated"
    )

    messages.success(
        request,
        (
            f"User account '{account.username}' "
            f"was {status_label}."
        ),
    )

    return redirect(
        "admin_user_detail",
        user_id=account.pk,
    )


@admin_required
def admin_user_delete(request, user_id):
    account = get_object_or_404(
        User,
        pk=user_id,
    )

    if account.pk == request.user.pk:
        messages.error(
            request,
            "You cannot delete your own account.",
        )

        return redirect(
            "admin_user_detail",
            user_id=account.pk,
        )

    if (
        account.is_superuser
        and account.is_active
        and _active_superuser_count() == 1
    ):
        messages.error(
            request,
            (
                "This account is the last active "
                "administrator and cannot be deleted."
            ),
        )

        return redirect(
            "admin_user_detail",
            user_id=account.pk,
        )

    if request.method == "POST":
        username = account.username

        for audit in account.router_audits.all():
            if audit.config_file:
                audit.config_file.delete(save=False)

        account.delete()

        messages.success(
            request,
            f"User account '{username}' was deleted.",
        )

        return redirect("admin_users")

    return render(
        request,
        "audits/admin_user_confirm_delete.html",
        {
            "account": account,
            "audit_count": account.router_audits.count(),
        },
    )


@admin_required
def admin_rules(request):
    query = request.GET.get("q", "").strip()
    category = request.GET.get(
        "category",
        "",
    ).strip()
    severity = request.GET.get(
        "severity",
        "",
    ).strip().lower()

    rules = filter_rules(
        query=query,
        category=category,
        severity=severity,
    )

    paginator = Paginator(rules, 20)
    page = paginator.get_page(
        request.GET.get("page")
    )

    statistics = get_rule_statistics()

    return render(
        request,
        "audits/admin_rules.html",
        {
            "page": page,
            "query": query,
            "selected_category": category,
            "selected_severity": severity,
            "categories": CATEGORY_ORDER,
            "severities": SEVERITY_ORDER,
            "statistics": statistics,
            "filtered_rule_count": len(rules),
        },
    )


@login_required
def profile(request):
    profile_form = ProfileUpdateForm(
        instance=request.user,
        prefix="profile",
    )

    password_form = ProfilePasswordForm(
        user=request.user,
        prefix="password",
    )

    if request.method == "POST":
        action = request.POST.get(
            "action",
            "",
        )

        if action == "update_profile":
            profile_form = ProfileUpdateForm(
                request.POST,
                instance=request.user,
                prefix="profile",
            )

            if profile_form.is_valid():
                profile_form.save()

                messages.success(
                    request,
                    "Your profile information was updated.",
                )

                return redirect("profile")

        elif action == "change_password":
            password_form = ProfilePasswordForm(
                user=request.user,
                data=request.POST,
                prefix="password",
            )

            if password_form.is_valid():
                updated_user = password_form.save()

                update_session_auth_hash(
                    request,
                    updated_user,
                )

                messages.success(
                    request,
                    "Your password was changed successfully.",
                )

                return redirect("profile")

    context = {
        "profile_form": profile_form,
        "password_form": password_form,
    }

    return render(
        request,
        "registration/profile.html",
        context,
    )


@login_required
def audit_create(request):
    form = AuditUploadForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        audit = form.save(commit=False)
        audit.owner = request.user
        audit.original_filename = Path(audit.config_file.name).name
        audit.save()
        run_audit(audit)
        if audit.status == Audit.Status.COMPLETED:
            messages.success(request, f"Analysis completed with a score of {audit.score}/100.")
            next_module = request.POST.get("next_module", "").strip()
            next_route = NEXT_MODULE_ROUTES.get(next_module)
            if next_route:
                return redirect(next_route, pk=audit.pk)
        else:
            messages.error(request, f"Analysis failed: {audit.error_message}")
        return redirect("audit_detail", pk=audit.pk)
    return render(request, "audits/audit_form.html", {"form": form, "sample_configs": SAMPLE_CONFIGS})


def _user_audit(request, pk):
    if request.user.is_superuser:
        queryset = Audit.objects.all()
    else:
        queryset = request.user.router_audits.all()

    return get_object_or_404(queryset, pk=pk)


@login_required
def audit_detail(request, pk):
    audit = _user_audit(request, pk)
    severity = request.GET.get("severity", "")
    category = request.GET.get("category", "")
    findings = audit.findings.all()
    if severity:
        findings = findings.filter(severity=severity)
    if category:
        findings = findings.filter(category=category)
    categories = audit.findings.values_list("category", flat=True).distinct().order_by("category")
    finding_groups = []
    grouped_findings = {}

    for finding in findings:
        group_key = (
            finding.rule_id,
            finding.title,
            finding.category,
            finding.severity,
            finding.recommendation,
        )
        group = grouped_findings.get(group_key)
        if group is None:
            group = {
                "finding": finding,
                "count": 0,
                "lines": [],
            }
            grouped_findings[group_key] = group
            finding_groups.append(group)

        group["count"] += 1
        if finding.line_number:
            group["lines"].append(str(finding.line_number))

    return render(request, "audits/audit_detail.html", {
        "audit": audit,
        "findings": findings,
        "finding_groups": finding_groups,
        "selected_severity": severity,
        "selected_category": category,
        "categories": categories,
    })


@login_required
def audit_compare(request, pk):
    current_audit = _user_audit(
        request,
        pk,
    )

    if (
        current_audit.status
        != Audit.Status.COMPLETED
    ):
        messages.error(
            request,
            (
                "The current audit must be completed "
                "before it can be compared."
            ),
        )

        return redirect(
            "audit_detail",
            pk=current_audit.pk,
        )

    baseline_candidates = (
        Audit.objects.filter(
            owner=current_audit.owner,
            status=Audit.Status.COMPLETED,
        )
        .exclude(pk=current_audit.pk)
        .order_by("-created_at")
    )

    selected_baseline_id = request.GET.get(
        "baseline",
        "",
    ).strip()

    baseline_audit = None
    comparison = None

    if selected_baseline_id:
        baseline_audit = get_object_or_404(
            baseline_candidates,
            pk=selected_baseline_id,
        )
    else:
        baseline_audit = (
            baseline_candidates.filter(
                created_at__lt=(
                    current_audit.created_at
                )
            )
            .order_by("-created_at")
            .first()
        )

    if baseline_audit is not None:
        try:
            comparison = compare_audits(
                baseline=baseline_audit,
                current=current_audit,
            )
        except ValueError as exc:
            messages.error(
                request,
                str(exc),
            )

    return render(
        request,
        "audits/audit_compare.html",
        {
            "current_audit": current_audit,
            "baseline_audit": baseline_audit,
            "baseline_candidates": (
                baseline_candidates
            ),
            "comparison": comparison,
            "selected_baseline_id": (
                str(baseline_audit.pk)
                if baseline_audit
                else ""
            ),
        },
    )


@login_required
@require_POST
def audit_reanalyze(request, pk):
    audit = _user_audit(request, pk)
    run_audit(audit, audit.raw_text or None)
    if audit.status == Audit.Status.COMPLETED:
        messages.success(request, "The configuration was analyzed again using the current rule engine.")
    else:
        messages.error(request, audit.error_message)
    return redirect("audit_detail", pk=pk)


@login_required
@require_POST
def audit_delete(request, pk):
    audit = _user_audit(request, pk)
    title = audit.title
    audit.config_file.delete(save=False)
    audit.delete()
    messages.success(request, f"Deleted audit: {title}")
    return redirect("dashboard")


@login_required
def export_csv(request, pk):
    audit = _user_audit(request, pk)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="netaudit-{audit.pk}-findings.csv"'
    writer = csv.writer(response)
    writer.writerow(["Rule ID", "Severity", "Category", "Title", "Evidence", "Recommendation", "Suggested command", "Line"])
    for finding in audit.findings.all():
        writer.writerow([
            finding.rule_id, finding.severity, finding.category, finding.title,
            finding.evidence, finding.recommendation, finding.suggested_command,
            finding.line_number or "",
        ])
    return response


@login_required
def export_pdf(request, pk):
    audit = _user_audit(request, pk)
    return PdfReportBuilder().build_response(audit)


class PdfReportBuilder:
    """Builds a paginated PDF report for one completed audit."""

    def __init__(self):
        self.styles = self._build_styles()

    def _build_styles(self):
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=styles["Title"],
                alignment=TA_CENTER,
                textColor=colors.HexColor("#0f2f4a"),
                fontSize=20,
                leading=24,
                spaceAfter=14,
            )
        )
        styles.add(
            ParagraphStyle(
                name="SectionTitle",
                parent=styles["Heading2"],
                textColor=colors.HexColor("#173f5f"),
                fontSize=13,
                leading=16,
                spaceBefore=12,
                spaceAfter=8,
            )
        )
        styles.add(
            ParagraphStyle(
                name="FindingTitle",
                parent=styles["Heading3"],
                textColor=colors.HexColor("#173f5f"),
                fontSize=11,
                leading=14,
                spaceBefore=0,
                spaceAfter=5,
            )
        )
        styles.add(
            ParagraphStyle(
                name="FindingMeta",
                parent=styles["BodyText"],
                textColor=colors.HexColor("#4b5563"),
                fontSize=8.5,
                leading=11,
                spaceAfter=4,
            )
        )
        styles.add(
            ParagraphStyle(
                name="ReportBody",
                parent=styles["BodyText"],
                fontSize=9.2,
                leading=12.5,
                spaceAfter=5,
            )
        )
        styles.add(
            ParagraphStyle(
                name="Label",
                parent=styles["BodyText"],
                fontName="Helvetica-Bold",
                fontSize=8.5,
                leading=11,
                spaceBefore=5,
                spaceAfter=3,
            )
        )
        styles.add(
            ParagraphStyle(
                name="SmallCode",
                parent=styles["Code"],
                fontName="Courier",
                fontSize=7.2,
                leading=9,
                textColor=colors.HexColor("#111827"),
            )
        )
        return styles

    def build_response(self, audit):
        buffer = BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=18 * mm,
            bottomMargin=20 * mm,
            title=f"NetAudit Report - {audit.title}",
        )
        document.build(self.build_story(audit))
        buffer.seek(0)
        return FileResponse(buffer, as_attachment=True, filename=f"netaudit-{audit.pk}-report.pdf")

    def build_story(self, audit):
        story = []
        story.extend(self._cover(audit))
        story.extend(self._severity_summary(audit))
        story.extend(self._configuration_summary(audit))
        story.extend(self._category_scores(audit))
        story.extend(self._findings(audit))
        story.extend(self._notice())
        return story

    def _cover(self, audit):
        return [
            Paragraph("NetAudit Security Report", self.styles["ReportTitle"]),
            Paragraph(f"<b>Audit:</b> {escape(audit.title)}", self.styles["ReportBody"]),
            Paragraph(f"<b>Source file:</b> {escape(audit.original_filename or 'Not specified')}", self.styles["ReportBody"]),
            Paragraph(f"<b>Score:</b> {audit.score}/100 ({escape(audit.rating)})", self.styles["ReportBody"]),
            Paragraph(f"<b>Findings:</b> {audit.finding_count}", self.styles["ReportBody"]),
            Spacer(1, 8),
        ]

    def _styled_table(self, data, col_widths, header_color="#173f5f"):
        table = Table(data, colWidths=col_widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(header_color)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#1f2937")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ]
            )
        )
        return table

    def _severity_summary(self, audit):
        data = [["Critical", "High", "Medium", "Low"], [audit.critical_count, audit.high_count, audit.medium_count, audit.low_count]]
        return [self._styled_table(data, [40 * mm] * 4), Spacer(1, 12)]

    def _configuration_summary(self, audit):
        configuration = audit.configuration_summary or {}
        if not configuration:
            return []
        rows = [
            ("Router identity", configuration.get("router_identity", "Not specified")),
            ("Parsed commands", configuration.get("total_commands", 0)),
            ("Interfaces", configuration.get("interface_count", 0)),
            ("IP addresses", configuration.get("ip_address_count", 0)),
            ("DHCP servers", configuration.get("dhcp_server_count", 0)),
            ("Firewall rules", configuration.get("firewall_filter_count", 0)),
            ("NAT rules", configuration.get("nat_rule_count", 0)),
            ("Static routes", configuration.get("route_count", 0)),
            ("Enabled services", configuration.get("enabled_service_count", 0)),
        ]
        data = [["Item", "Value"]] + [[label, escape(str(value))] for label, value in rows]
        return [Paragraph("Configuration summary", self.styles["SectionTitle"]), self._styled_table(data, [55 * mm, 95 * mm]), Spacer(1, 12)]

    def _category_scores(self, audit):
        category_scores = audit.category_scores or {}
        if not category_scores:
            return []
        data = [["Category", "Score"]]
        data.extend([escape(str(category)), f"{score}/100"] for category, score in category_scores.items())
        return [Paragraph("Category security scores", self.styles["SectionTitle"]), self._styled_table(data, [100 * mm, 50 * mm], header_color="#6D4FFC"), Spacer(1, 12)]

    def _code_table(self, value):
        code = escape(str(value or "")).replace("\n", "<br/>")
        table = Table([[Paragraph(code, self.styles["SmallCode"])]], colWidths=[160 * mm], splitByRow=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eef3f7")),
                    ("BOX", (0, 0), (-1, -1), 0.35, colors.HexColor("#d9e2ea")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return table

    def _finding_group_key(self, finding):
        return (finding.rule_id, finding.severity, finding.category, finding.title, finding.description, finding.recommendation, finding.suggested_command)

    def _group_findings(self, findings):
        grouped = {}
        for finding in findings:
            key = self._finding_group_key(finding)
            group = grouped.get(key)
            if group is None:
                group = {"finding": finding, "count": 0, "lines": [], "evidence": []}
                grouped[key] = group
            group["count"] += 1
            if finding.line_number:
                group["lines"].append(finding.line_number)
            if finding.evidence and finding.evidence not in group["evidence"]:
                group["evidence"].append(finding.evidence)
        return list(grouped.values())

    def _findings(self, audit):
        findings = list(audit.findings.all())
        if not findings:
            return [Paragraph("No findings were generated by the current rule set.", self.styles["ReportBody"])]
        story = [Paragraph("Findings and recommendations", self.styles["SectionTitle"])]
        for group in self._group_findings(findings):
            story.append(KeepTogether(self._finding_block(group)))
        return story

    def _finding_block(self, group):
        finding = group["finding"]
        title = f"{escape(finding.rule_id)} | {escape(finding.get_severity_display())} | {escape(finding.title)}"
        lines = sorted(set(group["lines"]))
        line_label = ""
        if lines:
            line_label = f" | {'Line' if len(lines) == 1 else 'Lines'} {', '.join(str(line) for line in lines)}"
        count_label = f" | {group['count']} occurrences" if group["count"] > 1 else ""
        block = [
            Paragraph(title, self.styles["FindingTitle"]),
            Paragraph(f"<b>Category:</b> {escape(finding.category)}{line_label}{count_label}", self.styles["FindingMeta"]),
            Paragraph(escape(finding.description), self.styles["ReportBody"]),
        ]
        if group["evidence"]:
            block.append(Paragraph("Evidence", self.styles["Label"]))
            block.append(self._code_table("\n\n".join(group["evidence"][:2])))
        block.append(Paragraph("Recommendation", self.styles["Label"]))
        block.append(Paragraph(escape(finding.recommendation), self.styles["ReportBody"]))
        if finding.suggested_command:
            block.append(Paragraph("Suggested command", self.styles["Label"]))
            block.append(self._code_table(finding.suggested_command))
        block.append(Spacer(1, 10))
        return block

    def _notice(self):
        return [
            PageBreak(),
            Paragraph("Important notice", self.styles["SectionTitle"]),
            Paragraph("Review recommendations carefully before applying them. NetAudit only analyzes uploaded files; it does not connect to the router or run commands.", self.styles["ReportBody"]),
        ]

def _is_unrestricted_address(value):
    normalized = str(value or "").strip().lower()
    return normalized in {"", "0.0.0.0/0", "::/0", "0.0.0.0/0,::/0"}


def _interfaces_for_list(configuration, list_name):
    target = str(list_name or "").strip().lower()
    members = configuration.get("interface_list_members", [])

    return sorted(
        {
            str(member.get("interface") or "")
            for member in members
            if str(member.get("list") or "").strip().lower() == target
            and str(member.get("interface") or "")
        }
    )


def _build_topology_model(audit):
    configuration = audit.configuration_summary or {}
    interfaces = configuration.get("interfaces", [])
    ip_addresses = configuration.get("ip_addresses", [])

    wan_names = set(_interfaces_for_list(configuration, "WAN"))
    lan_names = set(_interfaces_for_list(configuration, "LAN"))

    for interface in interfaces:
        name = str(interface.get("name") or "")
        lowered_name = name.lower()
        interface_type = str(interface.get("type") or "").lower()

        if "wan" in lowered_name or interface_type in {"pppoe-client", "lte"}:
            wan_names.add(name)
        elif "lan" in lowered_name or interface_type == "bridge":
            lan_names.add(name)

    def enrich(interface):
        name = str(interface.get("name") or "")
        addresses = [
            item
            for item in ip_addresses
            if str(item.get("interface") or "") == name
        ]
        return {**interface, "addresses": addresses}

    wan_interfaces = []
    lan_interfaces = []
    other_interfaces = []

    for interface in interfaces:
        name = str(interface.get("name") or "")
        item = enrich(interface)

        if name in wan_names:
            wan_interfaces.append(item)
        elif name in lan_names:
            lan_interfaces.append(item)
        else:
            other_interfaces.append(item)

    exposed_services = [
        service
        for service in configuration.get("services", [])
        if _is_unrestricted_address(service.get("address"))
    ]

    nat_exposures = [
        rule
        for rule in configuration.get("nat_rules", [])
        if str(rule.get("chain") or "").lower() == "dstnat"
    ]

    return {
        "router_identity": configuration.get("router_identity", "Not specified"),
        "wan_interfaces": wan_interfaces,
        "lan_interfaces": lan_interfaces,
        "other_interfaces": other_interfaces,
        "dhcp_pools": configuration.get("dhcp_pools", []),
        "dhcp_servers": configuration.get("dhcp_servers", []),
        "routes": configuration.get("routes", []),
        "exposed_services": exposed_services,
        "nat_exposures": nat_exposures,
        "total_interfaces": len(interfaces),
        "total_subnets": len(ip_addresses),
    }


def _build_attack_surface_model(audit):
    configuration = audit.configuration_summary or {}

    exposed_services = [
        service
        for service in configuration.get("services", [])
        if _is_unrestricted_address(service.get("address"))
    ]

    nat_exposures = [
        rule
        for rule in configuration.get("nat_rules", [])
        if str(rule.get("chain") or "").strip().lower() == "dstnat"
    ]

    wan_accepts = []

    for rule in configuration.get("firewall_rules", []):
        action = str(rule.get("action") or "").strip().lower()
        chain = str(rule.get("chain") or "").strip().lower()
        ingress = " ".join(
            (
                str(rule.get("in_interface") or ""),
                str(rule.get("in_interface_list") or ""),
            )
        ).lower()

        if chain == "input" and action == "accept" and ("wan" in ingress or not ingress.strip()):
            wan_accepts.append(rule)

    relevant_categories = {
        "Firewall",
        "NAT",
        "Services",
        "Security services",
        "Layer 2 management",
    }

    high_risk_findings = [
        finding
        for finding in audit.findings.all()
        if finding.category in relevant_categories
        and finding.severity in {"critical", "high"}
    ]

    high_risk_groups = []
    grouped_findings = {}
    for finding in high_risk_findings:
        group_key = (finding.rule_id, finding.title, finding.category, finding.severity)
        group = grouped_findings.get(group_key)
        if group is None:
            group = {"finding": finding, "count": 0, "lines": []}
            grouped_findings[group_key] = group
            high_risk_groups.append(group)
        group["count"] += 1
        if finding.line_number:
            group["lines"].append(str(finding.line_number))

    return {
        "exposed_services": exposed_services,
        "nat_exposures": nat_exposures,
        "wan_accepts": wan_accepts,
        "high_risk_findings": high_risk_findings,
        "high_risk_groups": high_risk_groups,
        "public_entry_count": len(exposed_services) + len(nat_exposures) + len(wan_accepts),
    }


def _build_hardening_plan(audit):
    commands = []
    manual_items = []
    seen_commands = set()
    severity_rank = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    findings = sorted(
        audit.findings.all(),
        key=lambda finding: (
            severity_rank.get(finding.severity, 9),
            finding.rule_id,
            finding.id,
        ),
    )

    for finding in findings:
        command = str(finding.suggested_command or "").strip()

        if command and command not in seen_commands:
            commands.append(
                {
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "command": command,
                }
            )
            seen_commands.add(command)
        else:
            manual_items.append(finding)

    script_lines = [
        "# NetAudit RouterOS hardening script",
        f"# Audit: {audit.title}",
        "# Review every command before applying it to a router.",
        "",
    ]

    if commands:
        for item in commands:
            script_lines.extend(
                [
                    f"# {item['rule_id']} - {item['title']}",
                    item["command"],
                    "",
                ]
            )
    else:
        script_lines.append(
            "# No direct commands were generated from current findings."
        )

    manual_groups = []
    grouped_manual = {}
    for finding in manual_items:
        group_key = (
            finding.rule_id,
            finding.title,
            finding.severity,
            finding.recommendation,
        )
        group = grouped_manual.get(group_key)
        if group is None:
            group = {"finding": finding, "count": 0, "lines": []}
            grouped_manual[group_key] = group
            manual_groups.append(group)
        group["count"] += 1
        if finding.line_number:
            group["lines"].append(str(finding.line_number))

    return {
        "commands": commands,
        "manual_items": manual_items,
        "manual_groups": manual_groups,
        "script": "\n".join(script_lines).strip() + "\n",
    }


@login_required
def audit_topology(request, pk):
    audit = _user_audit(request, pk)
    return render(
        request,
        "audits/audit_topology.html",
        {"audit": audit, "topology": TopologyModelBuilder().build(audit)},
    )



class TopologyModelBuilder:
    """Builds the network map view model for one audit."""

    def build(self, audit):
        return _build_topology_model(audit)


class AttackSurfaceModelBuilder:
    """Builds the exposure analysis view model for one audit."""

    def build(self, audit):
        return _build_attack_surface_model(audit)


class HardeningPlanBuilder:
    """Builds reviewable hardening command output for one audit."""

    def build(self, audit):
        return _build_hardening_plan(audit)
@login_required
def audit_attack_surface(request, pk):
    audit = _user_audit(request, pk)
    return render(
        request,
        "audits/audit_attack_surface.html",
        {"audit": audit, "surface": AttackSurfaceModelBuilder().build(audit)},
    )


@login_required
def audit_hardening(request, pk):
    audit = _user_audit(request, pk)
    return render(
        request,
        "audits/audit_hardening.html",
        {"audit": audit, "hardening": HardeningPlanBuilder().build(audit)},
    )


@login_required
def hardening_download(request, pk):
    audit = _user_audit(request, pk)
    plan = HardeningPlanBuilder().build(audit)
    response = HttpResponse(plan["script"], content_type="text/plain")
    response["Content-Disposition"] = (
        f'attachment; filename="netaudit-{audit.pk}-hardening.rsc"'
    )
    return response
@login_required
def sample_download(request, sample_slug="unsafe-router"):
    sample_config = SAMPLES_BY_SLUG.get(sample_slug)

    if sample_config is None:
        raise Http404

    sample = (
        Path(__file__).resolve().parent.parent
        / "samples"
        / sample_config["filename"]
    )

    if not sample.exists():
        raise Http404

    return FileResponse(
        open(sample, "rb"),
        as_attachment=True,
        filename=sample_config["filename"],
    )




# [rev-9351] Reviewed 09 Jul 2026

# [rev-1017] Reviewed 17 Jul 2026

# [rev-9278] Reviewed 31 Aug 2026

# [rev-7511] Reviewed 06 Sep 2026

# [rev-1656] Reviewed 28 Aug 2026

# [rev-7993] Reviewed 30 Aug 2026
