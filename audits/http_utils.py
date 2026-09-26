from django.http import JsonResponse


class HttpResponseHelper:
    """Utilities for detecting request type and formatting HTTP responses."""

    @staticmethod
    def wants_json(request) -> bool:
        return (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or "application/json" in request.headers.get("Accept", "")
        )

    @staticmethod
    def form_errors_payload(form) -> dict:
        return {
            "ok": False,
            "errors": {
                field: [str(error) for error in error_list]
                for field, error_list in form.errors.items()
            },
        }

    @staticmethod
    def json_form_errors(form, status=400):
        return JsonResponse(HttpResponseHelper.form_errors_payload(form), status=status)


# backward-compat aliases
wants_json = HttpResponseHelper.wants_json
form_errors_payload = HttpResponseHelper.form_errors_payload
json_form_errors = HttpResponseHelper.json_form_errors

