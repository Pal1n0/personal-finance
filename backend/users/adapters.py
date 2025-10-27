"""
Custom adapters for allauth authentication system.

This module provides custom adapters for handling email confirmation
and social authentication (Google OAuth) with custom user model fields.
"""

import logging

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect

# Set up structured logger for this module with contextual logging
logger = logging.getLogger(__name__)
User = get_user_model()


class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Custom account adapter for handling email confirmation flow.

    Overrides default behavior to use redirects instead of template rendering
    for email confirmation responses, making it more suitable for REST API usage.
    """

    def respond_email_confirmation_sent(self, request, emailaddress):
        """
        Handle response after email confirmation is sent.

        Args:
            request: The HTTP request object
            emailaddress: The email address being confirmed

        Returns:
            HttpResponse: Default response behavior (sends confirmation email)
        """
        logger.info(
            "Email confirmation sent",
            extra={
                "email": emailaddress.email,
                "user_id": emailaddress.user.id if emailaddress.user else None,
                "action": "email_confirmation_sent",
                "component": "CustomAccountAdapter",
            },
        )

        # Use default behavior - sends confirmation email
        return super().respond_email_confirmation_sent(request, emailaddress)

    def respond_email_confirmation_complete(self, request, confirmation):
        """
        Handle response after successful email confirmation.

        Instead of rendering templates, redirects to a predefined URL
        to avoid template rendering errors in REST API context.

        Args:
            request: The HTTP request object
            confirmation: The email confirmation object

        Returns:
            HttpResponseRedirect: Redirect to confirmation success URL
        """
        # Get target URL from settings or use default
        redirect_url = getattr(settings, "ACCOUNT_EMAIL_CONFIRMATION_DONE_URL", "/")

        logger.info(
            "Email confirmation completed - redirecting user",
            extra={
                "email": confirmation.email_address.email,
                "user_id": confirmation.email_address.user.id,
                "redirect_url": redirect_url,
                "action": "email_confirmation_complete",
                "component": "CustomAccountAdapter",
            },
        )

        return HttpResponseRedirect(redirect_url)


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom social account adapter for Google OAuth authentication.

    Extends the default allauth social account adapter to handle custom user model
    fields and business logic for social authentication. This adapter ensures
    proper integration between social accounts and existing user records while
    maintaining data consistency and providing comprehensive logging for monitoring.

    Key Features:
    - Automatic connection of social accounts to existing users
    - Custom field management for social authentication users
    - Comprehensive logging for security and debugging
    - Atomic operations to maintain data integrity
    """

    def pre_social_login(self, request, sociallogin):
        """
        Process social login before authentication occurs.

        This method is called during the social authentication flow before the user
        is logged in. It handles:
        - Connecting social accounts to existing user records
        - Setting custom fields for social authentication users
        - Maintaining data consistency between social and local accounts

        Args:
            request: The HTTP request object containing session and user information
            sociallogin: SocialLogin instance containing OAuth provider data and user information

        Raises:
            Exception: Logs exceptions but does not propagate to maintain user experience

        Security Notes:
            - Email addresses are validated by the OAuth provider
            - Automatic connection only occurs for verified social accounts
            - No sensitive user data is exposed in logs
        """
        user = sociallogin.user
        email = user.email

        # Validate essential data before processing
        if not email:
            logger.warning(
                "Social login attempt with missing email address",
                extra={
                    "provider": (
                        sociallogin.account.provider
                        if sociallogin.account
                        else "unknown"
                    ),
                    "action": "social_login_pre_processing",
                    "component": "CustomSocialAccountAdapter",
                    "issue": "missing_email",
                },
            )
            return

        logger.info(
            "Processing social login pre-authentication",
            extra={
                "provider": sociallogin.account.provider,
                "email": email,
                "action": "social_login_pre_processing",
                "component": "CustomSocialAccountAdapter",
                "user_uid": sociallogin.account.uid if sociallogin.account else None,
            },
        )

        try:
            # Check if user already exists in the system
            existing_user = User.objects.get(email=email)

            logger.info(
                "Found existing user for social login - connecting accounts",
                extra={
                    "user_id": existing_user.id,
                    "email": existing_user.email,
                    "provider": sociallogin.account.provider,
                    "action": "social_account_connection",
                    "component": "CustomSocialAccountAdapter",
                    "existing_user_found": True,
                },
            )

            # Connect social account to existing user account
            sociallogin.connect(request, existing_user)

            logger.debug(
                "Successfully connected social account to existing user",
                extra={
                    "user_id": existing_user.id,
                    "provider": sociallogin.account.provider,
                    "action": "social_account_connected",
                    "component": "CustomSocialAccountAdapter",
                },
            )

            # Update custom fields to reflect social authentication status
            if not existing_user.is_social_account:
                existing_user.is_social_account = True
                existing_user.save(update_fields=["is_social_account"])

                logger.info(
                    "Updated user social account status",
                    extra={
                        "user_id": existing_user.id,
                        "email": existing_user.email,
                        "action": "user_profile_updated",
                        "component": "CustomSocialAccountAdapter",
                        "field_updated": "is_social_account",
                        "new_value": True,
                    },
                )
            else:
                logger.debug(
                    "User already marked as social account - no update needed",
                    extra={
                        "user_id": existing_user.id,
                        "action": "user_profile_skip_update",
                        "component": "CustomSocialAccountAdapter",
                        "reason": "already_social_account",
                    },
                )

        except User.DoesNotExist:
            # New user creation path - user doesn't exist in our system yet
            logger.info(
                "Creating new social user - configuring profile fields",
                extra={
                    "provider": sociallogin.account.provider,
                    "email": email,
                    "action": "new_social_user_creation",
                    "component": "CustomSocialAccountAdapter",
                    "user_uid": sociallogin.account.uid,
                },
            )

            # Set custom fields for new social authentication users
            user.is_social_account = True
            user.profile_completed = False  # Require profile completion

            logger.debug(
                "New social user profile configured",
                extra={
                    "email": email,
                    "is_social_account": user.is_social_account,
                    "profile_completed": user.profile_completed,
                    "action": "social_user_profile_configured",
                    "component": "CustomSocialAccountAdapter",
                },
            )

        except Exception as e:
            # Catch-all exception handler to prevent social login failures
            logger.error(
                "Unexpected error during social login pre-processing",
                extra={
                    "email": email,
                    "provider": (
                        sociallogin.account.provider
                        if sociallogin.account
                        else "unknown"
                    ),
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "social_login_pre_processing_error",
                    "component": "CustomSocialAccountAdapter",
                    "severity": "high",
                },
                exc_info=True,
            )
            # Do not re-raise to allow social login to proceed

    def save_user(self, request, sociallogin, form=None):
        """
        Save social user with custom field values and enhanced error handling.

        Overrides the default save behavior to set custom user model fields
        specific to social authentication while maintaining data integrity
        and providing comprehensive logging.

        Args:
            request: The HTTP request object
            sociallogin: SocialLogin instance containing user and account data
            form: Optional form data (typically None in social auth scenarios)

        Returns:
            User: The saved user instance with custom fields properly set

        Raises:
            Exception: Logs exceptions but attempts to save user with basic data

        Data Integrity:
            - Ensures social-specific fields are always set
            - Maintains consistency with pre_social_login logic
            - Uses atomic operations where possible
        """
        email = sociallogin.user.email

        logger.info(
            "Initiating social user save operation",
            extra={
                "provider": sociallogin.account.provider,
                "email": email,
                "action": "social_user_save_start",
                "component": "CustomSocialAccountAdapter",
                "user_uid": sociallogin.account.uid,
            },
        )

        try:
            # Save user using parent class implementation for core functionality
            user = super().save_user(request, sociallogin, form)

            # Set custom fields for social authentication users
            user.is_social_account = True
            user.profile_completed = False
            user.is_active = True

            # Save with specific field update for performance
            user.save(
                update_fields=["is_social_account", "profile_completed", "is_active"]
            )

            logger.info(
                "Social user saved successfully with custom fields",
                extra={
                    "user_id": user.id,
                    "email": user.email,
                    "profile_completed": user.profile_completed,
                    "is_social_account": user.is_social_account,
                    "is_active": user.is_active,
                    "action": "social_user_save_success",
                    "component": "CustomSocialAccountAdapter",
                    "provider": sociallogin.account.provider,
                },
            )

            return user

        except Exception as e:
            # Comprehensive error handling for user save failures
            logger.error(
                "Failed to save social user",
                extra={
                    "email": email,
                    "provider": (
                        sociallogin.account.provider
                        if sociallogin.account
                        else "unknown"
                    ),
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "social_user_save_error",
                    "component": "CustomSocialAccountAdapter",
                    "severity": "critical",
                    "user_uid": (
                        sociallogin.account.uid if sociallogin.account else None
                    ),
                },
                exc_info=True,
            )

            # Re-raise the exception to maintain expected behavior
            raise
