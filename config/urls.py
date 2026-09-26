from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from audits import views
from config.views import health_check

urlpatterns = [
    path(
        "health/",
        health_check,
        name="health_check",
    ),
    path("admin/", admin.site.urls),
    path("", views.home, name="home"),
    path("register/", views.register_view, name="register"),
    path("login/", views.NetAuditLoginView.as_view(), name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("", include("audits.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
