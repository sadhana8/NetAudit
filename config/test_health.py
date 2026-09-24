from django.test import TestCase
from django.urls import reverse


class HealthCheckTests(TestCase):
    def test_health_check_is_available(self):
        response = self.client.get(
            reverse("health_check")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.json()["status"],
            "ok",
        )

# Code review pass - 08/03/2026 23:05:20

# [rev-4913] Reviewed 11 Sep 2026

# [rev-9332] Reviewed 08 Sep 2026
