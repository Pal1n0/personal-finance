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

# =============================================================================
# QUERY MONITORING CONFIGURATION - DEVELOPMENT ONLY
# =============================================================================

# Query Monitoring Settings
QUERY_DEBUG_ENABLED = True  # Pre detailné debugovanie v konzole
QUERY_MONITORING_ENABLED = True

# Database query logging level
DB_QUERY_LOGGING_LEVEL = "INFO"  # "DEBUG" pre SQL queries, "INFO" pre count only

# =============================================================================
# SECURITY SETTINGS FOR DEVELOPMENT
# =============================================================================

DEBUG = True
SECRET_KEY = config(
    "SECRET_KEY", default="django-insecure-dev-key-change-in-production"
)
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "0.0.0.0"]

# =============================================================================
# CORS SETTINGS FOR DEVELOPMENT
# =============================================================================

CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
CORS_ALLOW_ALL_ORIGINS = True  # Only for development!

# =============================================================================
# EMAIL CONFIGURATION FOR DEVELOPMENT
# =============================================================================

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
DEFAULT_DOMAIN = "localhost:5173"
DEFAULT_FROM_EMAIL = "dev@personal-finance.local"
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "http"
ACCOUNT_CONFIRM_EMAIL_URL_REVERSE = None

# =============================================================================
# GOOGLE OAUTH CONFIGURATION (DEVELOPMENT CREDENTIALS)
# =============================================================================

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

# =============================================================================
# DATABASE CONFIGURATION FOR DEVELOPMENT
# =============================================================================

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

# =============================================================================
# ENHANCED LOGGING FOR DEVELOPMENT WITH QUERY MONITORING
# =============================================================================

# Ensure logs directory exists
os.makedirs(BASE_DIR / "logs", exist_ok=True)

# Enhanced logging configuration
LOGGING["handlers"]["development_file"] = {
    "level": "DEBUG",
    "class": "logging.handlers.RotatingFileHandler",
    "filename": BASE_DIR / "logs" / "django_dev.log",
    "maxBytes": 1024 * 1024 * 10,  # 10MB
    "backupCount": 5,
    "formatter": "structured",
    "encoding": "utf-8",
}

# Query monitoring log handler
LOGGING["handlers"]["query_monitoring_file"] = {
    "level": "DEBUG",
    "class": "logging.handlers.RotatingFileHandler",
    "filename": BASE_DIR / "logs" / "query_monitoring.log",
    "maxBytes": 1024 * 1024 * 5,  # 5MB
    "backupCount": 3,
    "formatter": "structured",
    "encoding": "utf-8",
}

# Query monitoring logger
LOGGING["loggers"]["core.middleware.query_monitoring"] = {
    "handlers": ["console", "query_monitoring_file"],
    "level": "DEBUG",
    "propagate": False,
}

# Update existing loggers for development environment
for logger_name in ["django", "users", "axes", "allauth", "finance"]:
    if logger_name in LOGGING["loggers"]:
        LOGGING["loggers"][logger_name]["handlers"] = ["console", "development_file"]
        LOGGING["loggers"][logger_name]["level"] = "DEBUG"

# Database query logging - adjust based on DB_QUERY_LOGGING_LEVEL
LOGGING["loggers"]["django.db.backends"] = {
    "handlers": ["console"],
    "level": DB_QUERY_LOGGING_LEVEL,
    "propagate": False,
}

# =============================================================================
# MIDDLEWARE CONFIGURATION WITH QUERY MONITORING
# =============================================================================

# Insert query monitoring middleware after security middleware but before CommonMiddleware
try:
    # Find position after SecurityMiddleware
    security_index = MIDDLEWARE.index('django.middleware.security.SecurityMiddleware')
    
    # Insert our query monitoring middleware
    MIDDLEWARE.insert(security_index + 1, 'core.middleware.query_monitoring.QueryCountMiddleware')
    
    # Optional: Add debug middleware for detailed SQL output
    if QUERY_DEBUG_ENABLED:
        MIDDLEWARE.insert(security_index + 2, 'core.middleware.query_monitoring.QueryDebugMiddleware')
        
except ValueError:
    # Fallback: add to beginning if SecurityMiddleware not found
    MIDDLEWARE.insert(0, 'core.middleware.query_monitoring.QueryCountMiddleware')
    if QUERY_DEBUG_ENABLED:
        MIDDLEWARE.insert(1, 'core.middleware.query_monitoring.QueryDebugMiddleware')

# =============================================================================
# DEVELOPMENT TOOLBAR CONFIGURATION (OPTIONAL)
# =============================================================================

# Django Debug Toolbar - uncomment if you use it
# INSTALLED_APPS += ['debug_toolbar']
# MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')
# INTERNAL_IPS = ['127.0.0.1', 'localhost']

# =============================================================================
# ENVIRONMENT STARTUP
# =============================================================================

print(f"=== Running in {ENVIRONMENT} mode ===")
logger = logging.getLogger(__name__)
logger.info(
    "Development environment initialized with query monitoring",
    extra={
        "environment": ENVIRONMENT,
        "debug_mode": DEBUG,
        "allowed_hosts": ALLOWED_HOSTS,
        "query_monitoring_enabled": QUERY_MONITORING_ENABLED,
        "query_debug_enabled": QUERY_DEBUG_ENABLED,
        "db_query_logging_level": DB_QUERY_LOGGING_LEVEL,
        "action": "environment_startup",
        "component": "settings",
    },
)

# Environment startup notification
print(f"=== Running in {ENVIRONMENT} mode ===")
print(f"=== Query Monitoring: {QUERY_MONITORING_ENABLED} ===")
print(f"=== Query Debug: {QUERY_DEBUG_ENABLED} ===")