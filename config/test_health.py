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

