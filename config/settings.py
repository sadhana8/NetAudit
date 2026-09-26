from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import os

BASE_DIR = Path(__file__).resolve().parent.parent
ENV_FILE = BASE_DIR / ".env"


def load_env_file(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file(ENV_FILE)


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name, str(default))

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def env_list(name: str, default: str = "") -> list[str]:
    return [
        item.strip()
        for item in os.getenv(name, default).split(",")
        if item.strip()
    ]


def database_from_url(database_url: str) -> dict[str, object]:
    parsed = urlparse(database_url)

    if parsed.scheme == "sqlite":
        raw_path = unquote(parsed.path or "")
        database_path = raw_path.lstrip("/") or "db.sqlite3"

        return {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / database_path,
        }

    if parsed.scheme in {"postgres", "postgresql"}:
        query = parse_qs(parsed.query)

        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": unquote(parsed.path.lstrip("/")),
            "USER": unquote(parsed.username or ""),
            "PASSWORD": unquote(parsed.password or ""),
            "HOST": parsed.hostname or "",
            "PORT": str(parsed.port or 5432),
            "CONN_MAX_AGE": int(query.get("conn_max_age", ["60"])[0]),
        }

    raise RuntimeError(
        "DATABASE_URL must use sqlite, postgres, or postgresql."
    )


ENVIRONMENT = os.getenv("DJANGO_ENVIRONMENT", "development").strip().lower()
IS_PRODUCTION = ENVIRONMENT == "production"

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")

if not SECRET_KEY:
    raise RuntimeError(
        "DJANGO_SECRET_KEY must be set in .env or environment variables."
    )

DEBUG = env_bool("DJANGO_DEBUG", default=not IS_PRODUCTION)
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost")
CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "audits",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASE_URL = os.getenv("DATABASE_URL", "")

if DATABASE_URL:
    DATABASES = {"default": database_from_url(DATABASE_URL)}
elif os.getenv("POSTGRES_HOST"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", ""),
            "USER": os.getenv("POSTGRES_USER", ""),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
            "HOST": os.getenv("POSTGRES_HOST", ""),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": 60,
        }
    }
else:
    raise RuntimeError(
        "Set DATABASE_URL or POSTGRES_HOST in .env or environment variables."
    )

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kathmandu"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": (
            "django.contrib.staticfiles.storage.StaticFilesStorage"
            if DEBUG
            else "whitenoise.storage.CompressedManifestStaticFilesStorage"
        )
    },
}

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "home"

NETAUDIT_MAX_UPLOAD_SIZE_MB = env_int("NETAUDIT_MAX_UPLOAD_SIZE_MB", 2)
NETAUDIT_MAX_UPLOAD_SIZE_BYTES = NETAUDIT_MAX_UPLOAD_SIZE_MB * 1024 * 1024

DATA_UPLOAD_MAX_MEMORY_SIZE = NETAUDIT_MAX_UPLOAD_SIZE_BYTES
FILE_UPLOAD_MAX_MEMORY_SIZE = NETAUDIT_MAX_UPLOAD_SIZE_BYTES

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"

SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

SECURE_PROXY_SSL_HEADER = (
    "HTTP_X_FORWARDED_PROTO",
    "https",
)

SECURE_SSL_REDIRECT = env_bool(
    "DJANGO_SECURE_SSL_REDIRECT",
    default=IS_PRODUCTION,
)

SESSION_COOKIE_SECURE = env_bool(
    "DJANGO_SESSION_COOKIE_SECURE",
    default=IS_PRODUCTION,
)

CSRF_COOKIE_SECURE = env_bool(
    "DJANGO_CSRF_COOKIE_SECURE",
    default=IS_PRODUCTION,
)

SECURE_HSTS_SECONDS = env_int(
    "DJANGO_SECURE_HSTS_SECONDS",
    31536000 if IS_PRODUCTION else 0,
)

SECURE_HSTS_INCLUDE_SUBDOMAINS = (
    IS_PRODUCTION
    and env_bool(
        "DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS",
        default=True,
    )
)

SECURE_HSTS_PRELOAD = (
    IS_PRODUCTION
    and env_bool(
        "DJANGO_SECURE_HSTS_PRELOAD",
        default=True,
    )
)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": (
                "{levelname} {asctime} "
                "{name} {message}"
            ),
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
    },
}
