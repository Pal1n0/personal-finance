from .base import *
import os

# Environment
ENVIRONMENT = 'development'

# Security
DEBUG = True
SECRET_KEY = config('SECRET_KEY', default='django-insecure-dev-key-change-in-production')
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']

# CORS
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
CORS_ALLOW_ALL_ORIGINS = True  # Only for dev!

# Email
EMAIL_BACKEND = 'jango.core.mail.backends.locmem.EmailBackend'
DEFAULT_DOMAIN = "localhost:5173"
DEFAULT_FROM_EMAIL = "dev@personal-finance.local"
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "http"
ACCOUNT_CONFIRM_EMAIL_URL_REVERSE = None

# Google OAuth (development credentials)
GOOGLE_OAUTH_CLIENT_ID = config('GOOGLE_OAUTH_CLIENT_ID', default='')
GOOGLE_OAUTH_CLIENT_SECRET = config('GOOGLE_OAUTH_CLIENT_SECRET', default='')

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
SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_AUTO_SIGNUP = False
# SOCIALACCOUNT_ADAPTER = 'users.adapters.CustomSocialAccountAdapter'  - not sure if needed, only for rests on dev it was, not even directly

# Database (local development)
DATABASES['default']['HOST'] = config('DB_HOST', default='localhost')

# Logging (verbose for development)
LOGGING['handlers']['file'] = {
    'level': 'DEBUG',
    'class': 'logging.FileHandler',
    'filename': 'logs/django.log',
    'formatter': 'verbose',
}
for logger in LOGGING['loggers'].values():
    if 'handlers' in logger:
        logger['handlers'] = ['console', 'file']

print(f"=== Running in {ENVIRONMENT} mode ===")