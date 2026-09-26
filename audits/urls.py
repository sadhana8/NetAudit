from django.urls import path

from . import admin_panel, views

urlpatterns = [
    path(
        "features/",
        views.features,
        name="features",
    ),
    path("features/audit-result/", views.feature_audit_result, name="feature_audit_result"),
    path("features/network-map/", views.feature_network_map, name="feature_network_map"),
    path("features/attack-surface/", views.feature_attack_surface, name="feature_attack_surface"),
    path("features/hardening-script/", views.feature_hardening_script, name="feature_hardening_script"),
    path("features/before-after/", views.feature_before_after, name="feature_before_after"),
    path(
        "rules/",
        views.supported_rules,
        name="supported_rules",
    ),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("profile/", views.profile, name="profile"),
    path("audits/new/", views.audit_create, name="audit_create"),
    path("audits/<int:pk>/", views.audit_detail, name="audit_detail"),
    path("audits/<int:pk>/topology/", views.audit_topology, name="audit_topology"),
    path("audits/<int:pk>/attack-surface/", views.audit_attack_surface, name="audit_attack_surface"),
    path("audits/<int:pk>/hardening/", views.audit_hardening, name="audit_hardening"),
    path("audits/<int:pk>/hardening/download/", views.hardening_download, name="hardening_download"),
    path(
        "audits/<int:pk>/compare/",
        views.audit_compare,
        name="audit_compare",
    ),
    path("audits/<int:pk>/reanalyze/", views.audit_reanalyze, name="audit_reanalyze"),
    path("audits/<int:pk>/delete/", views.audit_delete, name="audit_delete"),
    path("audits/<int:pk>/export/csv/", views.export_csv, name="export_csv"),
    path("audits/<int:pk>/export/pdf/", views.export_pdf, name="export_pdf"),
    path("samples/unsafe-router.rsc", views.sample_download, name="sample_download"),
    path("samples/<slug:sample_slug>.rsc", views.sample_download, name="sample_download_named"),
    path("admin-dashboard/", admin_panel.admin_dashboard, name="admin_dashboard"),
    path("admin-users/", views.admin_users, name="admin_users"),
    path(
        "admin-users/create/",
        views.admin_user_create,
        name="admin_user_create",
    ),
    path(
        "admin-users/<int:user_id>/",
        views.admin_user_detail,
        name="admin_user_detail",
    ),
    path(
        "admin-users/<int:user_id>/edit/",
        views.admin_user_edit,
        name="admin_user_edit",
    ),
    path(
        "admin-users/<int:user_id>/password/",
        views.admin_user_reset_password,
        name="admin_user_reset_password",
    ),
    path(
        "admin-users/<int:user_id>/toggle-active/",
        views.admin_user_toggle_active,
        name="admin_user_toggle_active",
    ),
    path(
        "admin-users/<int:user_id>/delete/",
        views.admin_user_delete,
        name="admin_user_delete",
    ),
    path(
        "admin-rules/",
        views.admin_rules,
        name="admin_rules",
    ),
    path(
        "admin-audits/",
        admin_panel.admin_audit_list,
        name="admin_audits",
    ),
    path("admin-audits/<int:pk>/", admin_panel.admin_audit_detail, name="admin_audit_detail"),
    path(
        "admin-audits/<int:pk>/reanalyze/",
        admin_panel.admin_audit_reanalyze,
        name="admin_audit_reanalyze",
    ),
    path(
        "admin-audits/<int:pk>/delete/",
        admin_panel.admin_audit_delete,
        name="admin_audit_delete",
    ),
]

