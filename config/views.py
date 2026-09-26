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

