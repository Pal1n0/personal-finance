# flake8: noqa
"""
Production environment settings for Personal Finance application.

This configuration extends base settings with production-specific values
including maximum security, production services, and monitored logging.
"""

from .base import *
import logging
from .utils import load_environment_config

# Load environment configuration
config = load_environment_config("production")

# Environment identification
ENVIRONMENT = "production"

# Security settings for production
DEBUG = False
SECRET_KEY = config("SECRET_KEY")
ALLOWED_HOSTS = [
    "personal-finance.com",
    "www.personal-finance.com",
    "api.personal-finance.com",
]

# CORS settings for production
CORS_ALLOWED_ORIGINS = [
    "https://personal-finance.com",
    "https://www.personal-finance.com",
]
CORS_ALLOW_ALL_ORIGINS = False

# Security headers for production
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

# Email configuration for production
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = config("EMAIL_HOST")
EMAIL_PORT = config("EMAIL_PORT", default=587)
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")
DEFAULT_DOMAIN = "personal-finance.com"
DEFAULT_FROM_EMAIL = "noreply@personal-finance.com"
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "https"

# Google OAuth configuration (production credentials)
GOOGLE_OAUTH_CLIENT_ID = config("GOOGLE_OAUTH_CLIENT_ID_PROD", default="")
GOOGLE_OAUTH_CLIENT_SECRET = config("GOOGLE_OAUTH_CLIENT_SECRET_PROD", default="")

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

# Database configuration for production
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_DB"),
        "USER": config("POSTGRES_USER"),
        "PASSWORD": config("POSTGRES_PASSWORD"),
        "HOST": config("DB_HOST"),
        "PORT": "5432",
        "CONN_MAX_AGE": 60,  # Connection pooling 1 minute
        "OPTIONS": {
            "connect_timeout": 5,  # Max 5 second waiting for DB connection
        }
    }
}

# Production logging - structured, monitored, and optimized
LOGGING["handlers"]["production_file"] = {
    "level": "INFO",
    "class": "logging.handlers.RotatingFileHandler",
    "filename": "/var/log/django/production.log",
    "maxBytes": 1024 * 1024 * 100,  # 100MB
    "backupCount": 10,
    "formatter": "json",  # JSON for production log aggregation
    "encoding": "utf-8",
}

LOGGING["handlers"]["production_errors"] = {
    "level": "ERROR",
    "class": "logging.handlers.RotatingFileHandler",
    "filename": "/var/log/django/production_errors.log",
    "maxBytes": 1024 * 1024 * 50,  # 50MB
    "backupCount": 10,
    "formatter": "json",
    "encoding": "utf-8",
}

LOGGING["handlers"]["production_security"] = {
    "level": "WARNING",
    "class": "logging.handlers.RotatingFileHandler",
    "filename": "/var/log/django/security.log",
    "maxBytes": 1024 * 1024 * 50,  # 50MB
    "backupCount": 10,
    "formatter": "json",
    "encoding": "utf-8",
}

# Update loggers for production environment
for logger_name in ["django", "users", "axes", "allauth", "finance"]:
    if logger_name in LOGGING["loggers"]:
        LOGGING["loggers"][logger_name]["handlers"] = [
            "console",
            "production_file",
            "production_errors",
        ]
        LOGGING["loggers"][logger_name]["level"] = "INFO"

# Security-specific logging
LOGGING["loggers"]["axes"]["handlers"].append("production_security")
LOGGING["loggers"]["django.security"]["handlers"] = ["production_security"]
LOGGING["loggers"]["django.security"]["level"] = "WARNING"

# Reduce noise in production
LOGGING["loggers"]["django.db.backends"]["level"] = "ERROR"
LOGGING["loggers"]["django.request"]["level"] = "WARNING"

# Ensure log directory exists (for local production testing)
os.makedirs("/var/log/django", exist_ok=True)

logger = logging.getLogger(__name__)
logger.info(
    "Production environment initialized",
    extra={
        "environment": ENVIRONMENT,
        "debug_mode": DEBUG,
        "allowed_hosts": ALLOWED_HOSTS,
        "action": "environment_startup",
        "component": "settings",
        "severity": "info",
    },
)
# Production middleware
MIDDLEWARE.insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")

# Environment startup notification
print(f"=== Running in {ENVIRONMENT} mode ===")
