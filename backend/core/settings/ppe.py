# flake8: noqa
"""
Pre-production environment settings for Personal Finance application.

This configuration extends base settings with pre-production specific values
including stricter security, external services, and structured logging.
"""

import logging

from .base import *
from .utils import load_environment_config

# Load environment configuration
config = load_environment_config("pre-production")

# Environment identification
ENVIRONMENT = "pre-production"

# Security settings for pre-production
DEBUG = False
SECRET_KEY = config("SECRET_KEY")
ALLOWED_HOSTS = [
    "ppe.personal-finance.com",
    "api.ppe.personal-finance.com",
    "localhost",  # For local testing
]

# CORS settings for pre-production
CORS_ALLOWED_ORIGINS = [
    "https://ppe.personal-finance.com",
    "https://www.ppe.personal-finance.com",
]
CORS_ALLOW_ALL_ORIGINS = False

# Email configuration for pre-production
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = config("EMAIL_HOST", default="smtp.gmail.com")
EMAIL_PORT = config("EMAIL_PORT", default=587)
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")
DEFAULT_DOMAIN = "ppe.personal-finance.com"
DEFAULT_FROM_EMAIL = "noreply@personal-finance.com"
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "https"

# Google OAuth configuration (PPE credentials)
GOOGLE_OAUTH_CLIENT_ID = config("GOOGLE_OAUTH_CLIENT_ID_PPE", default="")
GOOGLE_OAUTH_CLIENT_SECRET = config("GOOGLE_OAUTH_CLIENT_SECRET_PPE", default="")

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

# Database configuration for pre-production
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

# Structured logging for pre-production with JSON format
LOGGING["handlers"]["ppe_file"] = {
    "level": "INFO",
    "class": "logging.handlers.RotatingFileHandler",
    "filename": "/var/log/django/ppe.log",
    "maxBytes": 1024 * 1024 * 50,  # 50MB for PPE
    "backupCount": 10,
    "formatter": "json",  # JSON format for log aggregation
    "encoding": "utf-8",
}

LOGGING["handlers"]["ppe_errors"] = {
    "level": "ERROR",
    "class": "logging.handlers.RotatingFileHandler",
    "filename": "/var/log/django/ppe_errors.log",
    "maxBytes": 1024 * 1024 * 20,  # 20MB
    "backupCount": 10,
    "formatter": "json",
    "encoding": "utf-8",
}

# Update loggers for PPE environment
for logger_name in ["django", "users", "axes", "allauth", "finance"]:
    if logger_name in LOGGING["loggers"]:
        LOGGING["loggers"][logger_name]["handlers"] = [
            "console",
            "ppe_file",
            "ppe_errors",
        ]
        LOGGING["loggers"][logger_name]["level"] = "INFO"

# Reduce database query logging in PPE
LOGGING["loggers"]["django.db.backends"]["level"] = "WARNING"

# Ensure log directory exists (for local PPE testing)
os.makedirs("/var/log/django", exist_ok=True)

logger = logging.getLogger(__name__)
logger.info(
    "Pre-production environment initialized",
    extra={
        "environment": ENVIRONMENT,
        "debug_mode": DEBUG,
        "allowed_hosts": ALLOWED_HOSTS,
        "action": "environment_startup",
        "component": "settings",
    },
)
# Security middleware for pre-production
MIDDLEWARE.insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")  # For static files

# Environment startup notification
print(f"=== Running in {ENVIRONMENT} mode ===")
