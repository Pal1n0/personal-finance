"""
Production environment settings for Personal Finance application.

This configuration extends base settings with production-specific values
including maximum security, production services, and monitored logging.
"""

from .base import *
from .utils import load_environment_config

# Load environment configuration
config = load_environment_config('production')

# Environment identification
ENVIRONMENT = 'production'

# Security settings for production
DEBUG = False
SECRET_KEY = config('SECRET_KEY')
ALLOWED_HOSTS = [
    'personal-finance.com',
    'www.personal-finance.com',
    'api.personal-finance.com',
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
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST')
EMAIL_PORT = config('EMAIL_PORT', default=587)
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_DOMAIN = "personal-finance.com"
DEFAULT_FROM_EMAIL = "noreply@personal-finance.com"
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "https"

# Google OAuth configuration (production credentials)
GOOGLE_OAUTH_CLIENT_ID = config('GOOGLE_OAUTH_CLIENT_ID_PROD', default='')
GOOGLE_OAUTH_CLIENT_SECRET = config('GOOGLE_OAUTH_CLIENT_SECRET_PROD', default='')

SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APP': {
            'client_id': GOOGLE_OAUTH_CLIENT_ID,
            'secret': GOOGLE_OAUTH_CLIENT_SECRET,
            'key': ''
        },
        'SCOPE': ['profile', 'email'],
        'AUTH_PARAMS': {'access_type': 'online'}
    }
}

SOCIALACCOUNT_EMAIL_VERIFICATION = 'none'

# Database configuration for production
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('POSTGRES_DB'),
        'USER': config('POSTGRES_USER'),
        'PASSWORD': config('POSTGRES_PASSWORD'),
        "HOST": config("DB_HOST"),
        'PORT': '5432',
    }
}

# Production logging - structured and monitored
LOGGING['handlers']['file'] = {
    'level': 'WARNING',
    'class': 'logging.handlers.RotatingFileHandler',
    'filename': '/var/log/django/production.log',
    'maxBytes': 1024 * 1024 * 10,  # 10MB
    'backupCount': 10,
    'formatter': 'verbose',
}
LOGGING['handlers']['error_file'] = {
    'level': 'ERROR',
    'class': 'logging.handlers.RotatingFileHandler',
    'filename': '/var/log/django/error.log',
    'maxBytes': 1024 * 1024 * 10,
    'backupCount': 10,
    'formatter': 'verbose',
}
LOGGING['loggers']['django']['handlers'] = ['console', 'file', 'error_file']
LOGGING['loggers']['django']['level'] = 'WARNING'
LOGGING['loggers']['users']['handlers'] = ['console', 'file', 'error_file']
LOGGING['loggers']['users']['level'] = 'WARNING'

# Production middleware
MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')

# Environment startup notification
print(f"=== Running in {ENVIRONMENT} mode ===")