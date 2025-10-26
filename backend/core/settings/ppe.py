from .base import *

# Environment
ENVIRONMENT = 'pre-production'

# Security
DEBUG = False
SECRET_KEY = config('SECRET_KEY')
ALLOWED_HOSTS = [
    'ppe.personal-finance.com',
    'api.ppe.personal-finance.com',
    'localhost',  # for testing
]

# CORS
CORS_ALLOWED_ORIGINS = [
    "https://ppe.personal-finance.com",
    "https://www.ppe.personal-finance.com",
]
CORS_ALLOW_ALL_ORIGINS = False

# Email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587)
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_DOMAIN = "ppe.personal-finance.com"
DEFAULT_FROM_EMAIL = "noreply@personal-finance.com"
ACCOUNT_DEFAULT_HTTP_PROTOCOL = "https"

# Google OAuth (PPE credentials)
GOOGLE_OAUTH_CLIENT_ID = config('GOOGLE_OAUTH_CLIENT_ID_PPE', default='')
GOOGLE_OAUTH_CLIENT_SECRET = config('GOOGLE_OAUTH_CLIENT_SECRET_PPE', default='')

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
# SOCIALACCOUNT_ADAPTER = 'users.adapters.CustomSocialAccountAdapter'  - not sure if needed, only for rests on dev it was

# Database (PPE database)
DATABASES['default']['HOST'] = config('DB_HOST_PPE')
DATABASES['default']['NAME'] = config('POSTGRES_DB_PPE', default=config('POSTGRES_DB'))

# Logging (structured for PPE)
LOGGING['handlers']['file'] = {
    'level': 'INFO',
    'class': 'logging.handlers.RotatingFileHandler',
    'filename': '/var/log/django/ppe.log',
    'maxBytes': 1024 * 1024 * 5,  # 5MB
    'backupCount': 5,
    'formatter': 'verbose',
}
LOGGING['loggers']['django']['level'] = 'INFO'
LOGGING['loggers']['users']['level'] = 'INFO'

# Security middleware for PPE
MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')  # For static files

print(f"=== Running in {ENVIRONMENT} mode ===")