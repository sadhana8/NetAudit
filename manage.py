#!/usr/bin/env python
import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Django is not installed. Run: pip install -r requirements.txt"
        ) from exc
    execute_from_command_line(sys.argv)

# [rev-4639] Reviewed 12 Jul 2026

# [rev-6968] Reviewed 30 Aug 2026

# [rev-9278] Reviewed 31 Aug 2026

# [rev-3437] Reviewed 03 Sep 2026

# [rev-9145] Reviewed 11 Sep 2026
