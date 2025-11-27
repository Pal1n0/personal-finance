"""
URL configuration for user authentication and management.

This module defines all API endpoints related to user authentication,
registration, social login, and account management.
"""

from django.urls import include, path, re_path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    CustomConfirmEmailView,
    GoogleLoginView,
    InactiveAccountView,
    LogoutView,
    SocialCompleteProfileView,
)

app_name = 'users'  # <--- TOTO CHÝBA

# URL patterns for user authentication and management
urlpatterns = [
    # Custom email confirmation endpoint with key parameter to override allauth's default
    re_path(
        r"^auth/registration/account-confirm-email/$",
        CustomConfirmEmailView.as_view(),
        name="account_email_verification_sent",
    ),
    re_path(
        r"^auth/registration/account-confirm-email/(?P<key>[-:\w]+)/$",
        CustomConfirmEmailView.as_view(),
        name="custom_account_confirm_email",  # Maintain same name for allauth compatibility
    ),
    # Custom logout endpoint with JWT token handling
    path("auth/custom-logout/", LogoutView.as_view(), name="custom-logout"),
    # Registration endpoints (email verification, signup)
    path("auth/registration/", include("dj_rest_auth.registration.urls")),
    # Standard authentication endpoints (login, password reset, user details)
    path("auth/", include("dj_rest_auth.urls")),
    # Social authentication profile completion
    path(
        "social-complete-profile/",
        SocialCompleteProfileView.as_view(),
        name="social-complete-profile",
    ),
    # Google OAuth2 login endpoint
    path("auth/google/", GoogleLoginView.as_view(), name="google_login"),
    # JWT token refresh endpoint
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # Inactive account handling endpoint
    path("inactive/", InactiveAccountView.as_view(), name="account_inactive"),
]
