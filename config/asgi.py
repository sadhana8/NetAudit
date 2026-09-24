import os
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
application = get_asgi_application()

# [rev-3051] Reviewed 10 Jul 2026

# [rev-4639] Reviewed 12 Jul 2026

# [rev-6335] Reviewed 07 Sep 2026
