from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied


class RoleChecker:
    """Static helpers for checking user roles and enforcing access control."""

    @staticmethod
    def is_administrator(user) -> bool:
        """Administrator: active staff superuser."""
        return bool(
            user
            and user.is_authenticated
            and user.is_active
            and user.is_staff
            and user.is_superuser
        )

    @staticmethod
    def is_normal_user(user) -> bool:
        """Normal user: active, non-staff, non-superuser."""
        return bool(
            user
            and user.is_authenticated
            and user.is_active
            and not user.is_staff
            and not user.is_superuser
        )

    @staticmethod
    def administrator_required(view_func):
        @login_required
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not RoleChecker.is_administrator(request.user):
                raise PermissionDenied("Administrator access required.")
            return view_func(request, *args, **kwargs)

        return _wrapped


# backward-compat aliases
is_administrator = RoleChecker.is_administrator
is_normal_user = RoleChecker.is_normal_user
administrator_required = RoleChecker.administrator_required

