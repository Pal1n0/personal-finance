# flake8: noqa
"""
Development environment settings for Personal Finance application.

This configuration extends base settings with development-specific values
including local database, relaxed security, and verbose logging.
"""

from .base import *
import logging
from .utils import load_environment_config

# Load environment configuration
config = load_environment_config("development")

# Environment identification
ENVIRONMENT = "development"

# Security settings for development
DEBUG = True
SECRET_KEY = config(
    "SECRET_KEY", default="django-insecure-dev-key-change-in-production"
)
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]

# CORS settings for development
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
CORS_ALLOW_ALL_ORIGINS = True  # Only for development!

# Email configuration for development
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
DEFAULT_DOMAIN = "localhost:5173"
DEFAULT_FROM_EMAIL = "dev@personal-finance.local"
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "http"
ACCOUNT_CONFIRM_EMAIL_URL_REVERSE = None

# Google OAuth configuration (development credentials)
GOOGLE_OAUTH_CLIENT_ID = config("GOOGLE_OAUTH_CLIENT_ID", default="")
GOOGLE_OAUTH_CLIENT_SECRET = config("GOOGLE_OAUTH_CLIENT_SECRET", default="")

SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "APP": {
            "client_id": GOOGLE_OAUTH_CLIENT_ID,
            "secret": GOOGLE_OAUTH_CLIENT_SECRET,
            "key": "",
        },
        "SCOPE": ["profile", "email"],
        "AUTH_PARAMS": {"access_type": "online"},
    }
}

SOCIALACCOUNT_EMAIL_VERIFICATION = "none"
SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_AUTO_SIGNUP = False

# Database configuration for development
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_DB"),
        "USER": config("POSTGRES_USER"),
        "PASSWORD": config("POSTGRES_PASSWORD"),
        "HOST": config("DB_HOST"),
        "PORT": "5432",
    }
}

# Enhanced logging for development with structured format
LOGGING["handlers"]["development_file"] = {
    "level": "DEBUG",
    "class": "logging.handlers.RotatingFileHandler",
    "filename": BASE_DIR / "logs" / "django_dev.log",
    "maxBytes": 1024 * 1024 * 10,  # 10MB
    "backupCount": 5,
    "formatter": "structured",
    "encoding": "utf-8",
}

# Ensure logs directory exists
os.makedirs(BASE_DIR / "logs", exist_ok=True)

# Update loggers for development environment
for logger_name in ["django", "users", "axes", "allauth", "finance"]:
    if logger_name in LOGGING["loggers"]:
        LOGGING["loggers"][logger_name]["handlers"] = ["console", "development_file"]
        LOGGING["loggers"][logger_name]["level"] = "DEBUG"

# Special development settings for database queries
LOGGING["loggers"]["django.db.backends"][
    "level"
] = "INFO"  # DEBUG for SQL queries if needed

print(f"=== Running in {ENVIRONMENT} mode ===")
logger = logging.getLogger(__name__)
logger.info(
    "Development environment initialized",
    extra={
        "environment": ENVIRONMENT,
        "debug_mode": DEBUG,
        "allowed_hosts": ALLOWED_HOSTS,
        "action": "environment_startup",
        "component": "settings",
    },
)

# Environment startup notification
print(f"=== Running in {ENVIRONMENT} mode ===")
