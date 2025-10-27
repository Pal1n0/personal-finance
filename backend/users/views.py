"""
Custom views for user authentication, social login, and account management.

This module provides API views for handling Google OAuth authentication,
profile completion, email confirmation, and user session management.
"""

import logging

from allauth.account.models import EmailConfirmation
from allauth.account.views import ConfirmEmailView
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.http import JsonResponse
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import CustomUser as User
from .serializers import SocialCompleteProfileSerializer

# Get structured logger for this module
logger = logging.getLogger(__name__)


class GoogleLoginView(SocialLoginView):
    """
    Google OAuth2 authentication endpoint with enhanced response data.

    This view handles the complete Google OAuth2 authentication flow, processing
    Google ID tokens and returning JWT tokens for API access. It extends the
    standard social login view to include custom user fields and profile
    completion flags in the response.
    """

    adapter_class = GoogleOAuth2Adapter
    callback_url = "http://localhost:5173"
    client_class = OAuth2Client

    def _enhance_response_data(self, response: Response, user: User) -> None:
        """
        Enhance authentication response with custom user metadata.
        """
        if user and isinstance(response.data, dict):
            # Calculate profile completion requirement
            requires_completion = (
                not user.profile_completed
                or not user.username
                or user.username.startswith("google_user_")
            )

            # Enhance response with user metadata
            response.data.update(
                {
                    "profile_completed": user.profile_completed,
                    "user_id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "requires_profile_completion": requires_completion,
                }
            )

            logger.info(
                "Enhanced authentication response with user metadata",
                extra={
                    "user_id": user.id,
                    "email": user.email,
                    "profile_completed": user.profile_completed,
                    "requires_profile_completion": requires_completion,
                    "action": "response_enhancement",
                    "component": "GoogleLoginView",
                },
            )

    def get_response(self) -> Response:
        """
        Generate enhanced authentication response after successful login.
        """
        logger.info(
            "Generating enhanced authentication response",
            extra={
                "user_id": self.user.id if self.user else None,
                "action": "response_generation",
                "component": "GoogleLoginView",
            },
        )

        # Generate standard authentication response
        response = super().get_response()

        # Enhance response with custom user data
        self._enhance_response_data(response, self.user)

        logger.debug(
            "Authentication response prepared successfully",
            extra={
                "user_id": self.user.id if self.user else None,
                "response_keys": list(response.data.keys()) if response.data else [],
                "action": "response_prepared",
                "component": "GoogleLoginView",
            },
        )

        return response

    def post(self, request, *args, **kwargs) -> Response:
        """
        Handle Google OAuth2 authentication requests.
        """
        client_ip = self._get_client_ip(request)

        logger.info(
            "Google OAuth2 authentication request received",
            extra={
                "client_ip": client_ip,
                "user_agent": request.META.get("HTTP_USER_AGENT", "Unknown")[:100],
                "action": "oauth_authentication_request",
                "component": "GoogleLoginView",
            },
        )

        try:
            # Process authentication through allauth social pipeline
            response = super().post(request, *args, **kwargs)

            logger.info(
                "Google OAuth2 authentication processed successfully",
                extra={
                    "status_code": response.status_code,
                    "user_id": self.user.id if self.user else None,
                    "client_ip": client_ip,
                    "action": "oauth_authentication_success",
                    "component": "GoogleLoginView",
                },
            )

            return response

        except Exception as e:
            logger.error(
                "Google OAuth2 authentication failed",
                extra={
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "client_ip": client_ip,
                    "action": "oauth_authentication_failure",
                    "component": "GoogleLoginView",
                    "severity": "high",
                },
                exc_info=True,
            )

            return Response(
                {
                    "detail": "Google authentication failed. Please try again.",
                    "code": "oauth_authentication_failed",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _get_client_ip(self, request) -> str:
        """
        Extract client IP address from request for security logging.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR", "unknown")
        return ip


class SocialCompleteProfileView(generics.UpdateAPIView):
    """
    View for completing user profile after social authentication.

    Allows social users to set their username and password, marking their
    profile as complete and generating new JWT tokens.
    """

    queryset = User.objects.all()
    serializer_class = SocialCompleteProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        """
        Get the current authenticated user instance.
        """
        user = self.request.user
        logger.debug(
            "Retrieving user object for profile completion",
            extra={
                "user_id": user.id,
                "action": "user_object_retrieval",
                "component": "SocialCompleteProfileView",
            },
        )
        return user

    def update(self, request, *args, **kwargs):
        """
        Update user profile and generate new JWT tokens.
        """
        user = self.get_object()

        logger.info(
            "Initiating social profile completion",
            extra={
                "user_id": user.id,
                "email": user.email,
                "current_profile_completed": user.profile_completed,
                "action": "profile_completion_start",
                "component": "SocialCompleteProfileView",
            },
        )

        try:
            # Call parent method to handle the update
            response = super().update(request, *args, **kwargs)

            # Generate new tokens after profile completion
            refresh = RefreshToken.for_user(user)

            logger.info(
                "Social profile completed successfully",
                extra={
                    "user_id": user.id,
                    "username": user.username,
                    "profile_completed": user.profile_completed,
                    "action": "profile_completion_success",
                    "component": "SocialCompleteProfileView",
                },
            )

            # Return enhanced response with new tokens
            return Response(
                {
                    "username": user.username,
                    "profile_completed": user.profile_completed,
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "user_id": user.id,
                    "email": user.email,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(
                "Social profile completion failed",
                extra={
                    "user_id": user.id,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "profile_completion_failure",
                    "component": "SocialCompleteProfileView",
                    "severity": "high",
                },
                exc_info=True,
            )
            raise


class LogoutView(APIView):
    """
    Secure logout endpoint with JWT token blacklisting.

    This view handles user logout by attempting to blacklist refresh tokens
    while maintaining a secure and user-friendly experience.
    """

    permission_classes = [permissions.AllowAny]

    def _attempt_token_blacklist(self, refresh_token: str) -> bool:
        """
        Attempt to blacklist a JWT refresh token.
        """
        # Validate token format before processing
        if not refresh_token or not isinstance(refresh_token, str):
            logger.debug(
                "Token blacklisting skipped - invalid format",
                extra={
                    "action": "token_blacklist_skip",
                    "component": "LogoutView",
                    "reason": "invalid_format",
                },
            )
            return False

        if "." not in refresh_token:
            logger.warning(
                "Token blacklisting skipped - malformed structure",
                extra={
                    "action": "token_blacklist_skip",
                    "component": "LogoutView",
                    "reason": "malformed_structure",
                },
            )
            return False

        logger.info(
            "Attempting token blacklist",
            extra={
                "token_prefix": refresh_token[:10],
                "token_length": len(refresh_token),
                "action": "token_blacklist_attempt",
                "component": "LogoutView",
            },
        )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()

            logger.info(
                "Token successfully blacklisted",
                extra={
                    "token_jti": token.payload.get("jti", "unknown"),
                    "user_id": token.payload.get("user_id", "unknown"),
                    "action": "token_blacklist_success",
                    "component": "LogoutView",
                },
            )
            return True

        except Exception as e:
            logger.warning(
                "Token blacklisting failed",
                extra={
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "token_blacklist_failure",
                    "component": "LogoutView",
                    "severity": "medium",
                },
            )
            return False

    def post(self, request) -> Response:
        """
        Handle user logout requests.
        """
        client_ip = self._get_client_ip(request)
        refresh_token = request.data.get("refresh", "")
        token_present = bool(refresh_token)

        logger.info(
            "Logout request received",
            extra={
                "client_ip": client_ip,
                "token_provided": token_present,
                "user_agent": request.META.get("HTTP_USER_AGENT", "Unknown")[:100],
                "action": "logout_request",
                "component": "LogoutView",
            },
        )

        try:
            # Attempt to blacklist the token
            blacklist_success = self._attempt_token_blacklist(refresh_token)

            if token_present:
                logger.info(
                    "Logout processed with token blacklist attempt",
                    extra={
                        "blacklist_success": blacklist_success,
                        "action": "logout_processed",
                        "component": "LogoutView",
                    },
                )
            else:
                logger.info(
                    "Logout processed without token",
                    extra={
                        "action": "logout_processed",
                        "component": "LogoutView",
                        "reason": "no_token_provided",
                    },
                )

            return Response(
                {"detail": "Successfully logged out.", "code": "logout_successful"},
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(
                "Critical error during logout processing",
                extra={
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "client_ip": client_ip,
                    "action": "logout_processing_error",
                    "component": "LogoutView",
                    "severity": "critical",
                },
                exc_info=True,
            )

            return Response(
                {"detail": "Successfully logged out.", "code": "logout_successful"},
                status=status.HTTP_200_OK,
            )

    def _get_client_ip(self, request) -> str:
        """
        Extract client IP address from request for security logging.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR", "unknown")
        return ip


class InactiveAccountView(APIView):
    """
    View for handling inactive account responses.

    Informs users that their account is inactive and email verification is required.
    """

    def get(self, request):
        """
        Return inactive account message.
        """
        logger.info(
            "Inactive account access attempt",
            extra={
                "client_ip": self._get_client_ip(request),
                "user_agent": request.META.get("HTTP_USER_AGENT", "Unknown")[:100],
                "action": "inactive_account_access",
                "component": "InactiveAccountView",
            },
        )

        return Response(
            {"detail": "Account is inactive, check your email."},
            status=status.HTTP_403_FORBIDDEN,
        )

    def _get_client_ip(self, request) -> str:
        """
        Extract client IP address from request for security logging.
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR", "unknown")
        return ip


class CustomConfirmEmailView(ConfirmEmailView):
    """
    Custom email confirmation view that returns JSON responses instead of rendering templates.

    Overrides the default allauth behavior to provide API-friendly JSON responses
    for email confirmation in a REST API context.
    """

    def get_object(self, queryset=None):
        """
        Retrieve email confirmation object by key.
        """
        key = self.kwargs["key"]

        logger.debug(
            "Looking up email confirmation by key",
            extra={
                "confirmation_key": key,
                "action": "confirmation_lookup",
                "component": "CustomConfirmEmailView",
            },
        )

        try:
            confirmation = EmailConfirmation.objects.get(key=key)

            logger.info(
                "Email confirmation object found",
                extra={
                    "confirmation_key": key,
                    "email": confirmation.email_address.email,
                    "user_id": confirmation.email_address.user.id,
                    "action": "confirmation_found",
                    "component": "CustomConfirmEmailView",
                },
            )

            return confirmation

        except EmailConfirmation.DoesNotExist:
            logger.warning(
                "Email confirmation key not found",
                extra={
                    "confirmation_key": key,
                    "action": "confirmation_not_found",
                    "component": "CustomConfirmEmailView",
                    "severity": "medium",
                },
            )
            return None
        except Exception as e:
            logger.error(
                "Error retrieving confirmation object",
                extra={
                    "confirmation_key": key,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "confirmation_retrieval_error",
                    "component": "CustomConfirmEmailView",
                    "severity": "high",
                },
                exc_info=True,
            )
            return None

    def get(self, *args, **kwargs):
        """
        Handle email confirmation GET requests.
        """
        logger.info(
            "Email confirmation request received",
            extra={
                "action": "email_confirmation_request",
                "component": "CustomConfirmEmailView",
            },
        )

        try:
            # Retrieve confirmation object
            self.object = self.get_object()

            if not self.object:
                logger.warning(
                    "Email confirmation failed - invalid key",
                    extra={
                        "action": "email_confirmation_failure",
                        "component": "CustomConfirmEmailView",
                        "reason": "invalid_confirmation_key",
                    },
                )
                return JsonResponse(
                    {"detail": "Invalid confirmation link."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = self.object.email_address.user
            logger.info(
                "Processing email confirmation",
                extra={
                    "user_id": user.id,
                    "email": self.object.email_address.email,
                    "user_active_before": user.is_active,
                    "email_verified_before": self.object.email_address.verified,
                    "action": "email_confirmation_processing",
                    "component": "CustomConfirmEmailView",
                },
            )

            # Confirm email address
            self.object.confirm(self.request)

            # Ensure user is activated after email confirmation
            if not user.is_active:
                user.is_active = True
                user.save()
                logger.info(
                    "User activated after email confirmation",
                    extra={
                        "user_id": user.id,
                        "action": "user_activation",
                        "component": "CustomConfirmEmailView",
                    },
                )

            # Verify confirmation results
            self.object.email_address.refresh_from_db()
            self.object.email_address.user.refresh_from_db()

            logger.info(
                "Email confirmation completed successfully",
                extra={
                    "user_id": user.id,
                    "user_active_after": user.is_active,
                    "email_verified_after": self.object.email_address.verified,
                    "action": "email_confirmation_success",
                    "component": "CustomConfirmEmailView",
                },
            )

            return JsonResponse(
                {
                    "detail": "Email was successfully confirmed and account activated.",
                    "user": {
                        "email": self.object.email_address.email,
                        "username": self.object.email_address.user.username,
                        "is_active": self.object.email_address.user.is_active,
                    },
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(
                "Email confirmation processing failed",
                extra={
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "email_confirmation_error",
                    "component": "CustomConfirmEmailView",
                    "severity": "high",
                },
                exc_info=True,
            )
            return JsonResponse(
                {"detail": f"Confirmation error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
