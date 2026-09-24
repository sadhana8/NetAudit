from django.db import connection
from django.http import JsonResponse


def health_check(request):
    try:
        connection.ensure_connection()
    except Exception:
        return JsonResponse(
            {
                "status": "unavailable",
                "database": "unavailable",
            },
            status=503,
        )

    return JsonResponse(
        {
            "status": "ok",
            "database": "ok",
        }
    )

# [rev-2125] Reviewed 19 Jul 2026

# [rev-9278] Reviewed 31 Aug 2026

# [rev-6326] Reviewed 08 Sep 2026

# [rev-8137] Reviewed 10 Sep 2026
