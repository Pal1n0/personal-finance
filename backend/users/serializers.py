"""
Custom serializers for user authentication and profile management.

This module provides serializers for handling traditional login, social authentication,
and profile completion with custom validation and security features.
"""

import logging
import re

from axes.models import AccessAttempt
from dj_rest_auth.serializers import LoginSerializer
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from rest_framework.validators import UniqueValidator


# Get structured logger for this module
logger = logging.getLogger(__name__)
User = get_user_model()


class CustomLoginSerializer(LoginSerializer):
    """
    Enhanced login serializer supporting both username and email authentication.

    Extends Django REST Auth's LoginSerializer with:
    - Dual authentication (username or email)
    - Integration with Axes security system for brute force protection
    - Comprehensive logging for security monitoring
    - Production-ready error handling and validation
    """

    username = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Username for authentication (optional if email provided)",
    )
    email = serializers.EmailField(
        required=False,
        allow_blank=True,
        help_text="Email address for authentication (optional if username provided)",
    )
    password = serializers.CharField(
        write_only=True, help_text="User password for authentication"
    )

    def _check_account_lockout(self, username: str, email: str) -> None:
        """
        Check if account is temporarily locked due to excessive failed attempts.

        This method integrates with Django Axes to prevent brute force attacks
        by verifying if the user account has exceeded the maximum allowed failed
        login attempts within the configured time window.

        Args:
            username (str): Username to check for lockout status
            email (str): Email address to check for lockout status

        Raises:
            PermissionDenied: If account is temporarily locked with 403 status
        """
        # Determine which identifier to use for lockout check
        lookup_username = username
        if not lookup_username and email:
            try:
                user_obj = User.objects.get(email=email)
                lookup_username = user_obj.username
                logger.debug(
                    "Resolved email to username for lockout check",
                    extra={
                        "email": email,
                        "resolved_username": lookup_username,
                        "action": "username_resolution",
                        "component": "CustomLoginSerializer",
                    },
                )
            except User.DoesNotExist:
                # User doesn't exist yet, no lockout to check
                logger.debug(
                    "No user found for email during lockout check",
                    extra={
                        "email": email,
                        "action": "lockout_check_skip",
                        "component": "CustomLoginSerializer",
                        "reason": "user_not_found",
                    },
                )
                return

        # Check for active lockout
        if lookup_username:
            try:
                attempt = AccessAttempt.objects.get(username=lookup_username)
                lockout_limit = getattr(settings, "AXES_FAILURE_LIMIT", 5)

                if attempt.failures_since_start >= lockout_limit:
                    logger.warning(
                        "Account lockout triggered - denying authentication",
                        extra={
                            "username": lookup_username,
                            "failure_count": attempt.failures_since_start,
                            "lockout_limit": lockout_limit,
                            "action": "account_lockout_enforced",
                            "component": "CustomLoginSerializer",
                            "severity": "high",
                        },
                    )
                    raise PermissionDenied(
                        {
                            "detail": "Too many login attempts. Account temporarily locked for 15 minutes.",
                            "locked": True,
                            "retry_after": "15 minutes",
                        }
                    )

            except AccessAttempt.DoesNotExist:
                # No failed attempts recorded, proceed normally
                logger.debug(
                    "No lockout record found for user",
                    extra={
                        "username": lookup_username,
                        "action": "lockout_check_passed",
                        "component": "CustomLoginSerializer",
                    },
                )
                pass

    def _authenticate_user(
        self, username: str, email: str, password: str, request
    ) -> User:
        """
        Authenticate user using either username or email credentials.

        This method handles the core authentication logic, supporting both
        traditional username/password and email/password authentication flows.
        It provides detailed logging for security monitoring and debugging.

        Args:
            username (str): Username for authentication
            email (str): Email address for authentication
            password (str): Password for authentication
            request: HTTP request object for context

        Returns:
            User: Authenticated user object if successful, None otherwise
        """
        if username:
            logger.info(
                "Username authentication attempt",
                extra={
                    "username": username,
                    "auth_method": "username",
                    "action": "authentication_attempt",
                    "component": "CustomLoginSerializer",
                },
            )
            user = authenticate(request=request, username=username, password=password)

            logger.debug(
                "Username authentication result",
                extra={
                    "username": username,
                    "success": bool(user),
                    "user_id": user.id if user else None,
                    "auth_method": "username",
                    "action": "authentication_result",
                    "component": "CustomLoginSerializer",
                },
            )
            return user

        elif email:
            logger.info(
                "Email authentication attempt",
                extra={
                    "email": email,
                    "auth_method": "email",
                    "action": "authentication_attempt",
                    "component": "CustomLoginSerializer",
                },
            )
            try:
                # Find user by email first, then authenticate with username
                user_obj = User.objects.get(email=email)

                logger.debug(
                    "User resolved from email for authentication",
                    extra={
                        "email": email,
                        "resolved_username": user_obj.username,
                        "resolved_user_id": user_obj.id,
                        "action": "email_to_username_resolution",
                        "component": "CustomLoginSerializer",
                    },
                )

                user = authenticate(
                    request=request, username=user_obj.username, password=password
                )

                logger.debug(
                    "Email authentication result",
                    extra={
                        "email": email,
                        "success": bool(user),
                        "user_id": user.id if user else None,
                        "auth_method": "email",
                        "action": "authentication_result",
                        "component": "CustomLoginSerializer",
                    },
                )
                return user

            except User.DoesNotExist:
                logger.warning(
                    "Authentication failed - email not found in system",
                    extra={
                        "email": email,
                        "auth_method": "email",
                        "action": "authentication_failure",
                        "component": "CustomLoginSerializer",
                        "reason": "email_not_found",
                    },
                )
                return None

        # No valid credentials provided
        return None

    def validate(self, attrs: dict) -> dict:
        """
        Main validation method for login credentials.

        This method orchestrates the complete login validation process:
        1. Security check for account lockouts
        2. Input validation for required fields
        3. User authentication
        4. Result processing and logging
        """
        logger.info(
            "Login validation process initiated",
            extra={
                "action": "login_validation_start",
                "component": "CustomLoginSerializer",
                "has_username": bool(attrs.get("username")),
                "has_email": bool(attrs.get("email")),
                "has_password": bool(attrs.get("password")),
            },
        )

        # Extract and clean input data
        username = attrs.get("username", "").strip()
        email = attrs.get("email", "").strip()
        password = attrs.get("password")
        request = self.context.get("request")

        # Phase 1: Security Validation
        logger.debug(
            "Performing security lockout check",
            extra={
                "username_provided": bool(username),
                "email_provided": bool(email),
                "action": "security_validation",
                "component": "CustomLoginSerializer",
            },
        )
        self._check_account_lockout(username, email)

        # Phase 2: Input Validation
        if not password:
            logger.warning(
                "Login validation failed - missing password",
                extra={
                    "username_provided": bool(username),
                    "email_provided": bool(email),
                    "action": "validation_failure",
                    "component": "CustomLoginSerializer",
                    "reason": "missing_password",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                {"password": "Password is required for authentication."}
            )

        if not username and not email:
            logger.warning(
                "Login validation failed - missing credentials",
                extra={
                    "action": "validation_failure",
                    "component": "CustomLoginSerializer",
                    "reason": "missing_credentials",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError(
                {
                    "non_field_errors": "Either username or email is required for authentication."
                }
            )

        # Phase 3: Authentication
        logger.debug(
            "Initiating user authentication",
            extra={
                "username_provided": bool(username),
                "email_provided": bool(email),
                "action": "authentication_initiated",
                "component": "CustomLoginSerializer",
            },
        )
        user = self._authenticate_user(username, email, password, request)

        if not user:
            logger.warning(
                "Authentication failed - invalid credentials",
                extra={
                    "username_provided": bool(username),
                    "email_provided": bool(email),
                    "action": "authentication_failure",
                    "component": "CustomLoginSerializer",
                    "reason": "invalid_credentials",
                    "severity": "medium",
                },
            )
            raise AuthenticationFailed(
                "Invalid login credentials. Please check your username/email and password."
            )

        # Phase 4: Success Processing
        logger.info(
            "Authentication successful",
            extra={
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "action": "authentication_success",
                "component": "CustomLoginSerializer",
            },
        )

        # Add authenticated user to attributes for downstream processing
        attrs["user"] = user
        return attrs


class SocialLoginSerializer(serializers.Serializer):
    """
    Serializer for social authentication (Google OAuth) login flow.

    Handles validation of social login data received from OAuth providers.
    """

    email = serializers.EmailField(required=True)
    provider = serializers.CharField(required=False, default="google")

    def validate_email(self, value):
        """
        Validate email field for social login.
        """
        logger.debug(
            "Validating email for social login",
            extra={
                "email": value,
                "action": "email_validation",
                "component": "SocialLoginSerializer",
            },
        )
        if not value:
            logger.warning(
                "Social login validation failed - empty email",
                extra={
                    "action": "validation_failure",
                    "component": "SocialLoginSerializer",
                    "reason": "empty_email",
                },
            )
            raise serializers.ValidationError("Email is required for social login.")
        return value

    def validate(self, attrs):
        """
        Validate social login attributes.
        """
        logger.info(
            "Social login validation started",
            extra={
                "email": attrs.get("email"),
                "provider": attrs.get("provider", "google"),
                "action": "social_login_validation",
                "component": "SocialLoginSerializer",
            },
        )
        return attrs


class SocialCompleteProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for completing user profile after social authentication.

    Handles setting username and password for users who registered via social login
    and need to complete their profile information.
    """

    username = serializers.CharField(
        required=True,
        min_length=3,
        max_length=30,
        validators=[
            UniqueValidator(
                queryset=User.objects.all(),
                message="This username is already taken. Please choose a different one."
            )
        ],
        help_text="Must be unique and 3-30 characters long"
    )
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password],
        help_text="Must meet password strength requirements"
    )

    class Meta:
        model = User
        fields = ("username", "password")

    def validate_username(self, value):
        """
        Validate username for profile completion.
        """
        value = value.strip()
        
        # Basic validation
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        
        if len(value) > 30:
            raise serializers.ValidationError("Username cannot exceed 30 characters.")
        
        # Check for allowed characters
        if not re.match(r'^[a-zA-Z0-9_\.]+$', value):
            raise serializers.ValidationError(
                "Username can only contain letters, numbers, underscores and dots."
            )
        
        # Check if username already exists (redundant but safe)
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        
        logger.info(
            "Username validation successful",
            extra={
                "username": value,
                "action": "username_validation_success",
                "component": "SocialCompleteProfileSerializer",
            },
        )
        return value

    def validate(self, attrs):
        """
        Validate profile completion data.
        """
        username = attrs.get('username', '').strip()
        
        # Final uniqueness check before save
        if username and User.objects.filter(username=username).exists():
            logger.warning(
                "Username uniqueness validation failed in final check",
                extra={
                    "username": username,
                    "action": "uniqueness_validation_failure", 
                    "component": "SocialCompleteProfileSerializer",
                    "severity": "medium",
                },
            )
            raise serializers.ValidationError({
                "username": "This username is already taken. Please choose a different one."
            })
        
        logger.info(
            "Social profile completion validation successful",
            extra={
                "username": username,
                "has_password": bool(attrs.get("password")),
                "action": "profile_completion_validation_success",
                "component": "SocialCompleteProfileSerializer",
            },
        )
        return attrs

    def update(self, instance, validated_data):
        """
        Update user instance with profile completion data.
        """
        username = validated_data["username"]
        
        logger.info(
            "Initiating social profile completion",
            extra={
                "user_id": instance.id,
                "current_email": instance.email,
                "new_username": username,
                "action": "profile_completion_start",
                "component": "SocialCompleteProfileSerializer",
            },
        )

        try:
            # Update user profile with provided data
            instance.username = username
            instance.set_password(validated_data["password"])
            instance.profile_completed = True

            logger.info(
                "Saving completed social profile",
                extra={
                    "user_id": instance.id,
                    "username": instance.username,
                    "profile_completed": True,
                    "action": "profile_completion_save",
                    "component": "SocialCompleteProfileSerializer",
                },
            )
            instance.save()

            logger.info(
                "Social profile completed successfully",
                extra={
                    "user_id": instance.id,
                    "username": instance.username,
                    "action": "profile_completion_success",
                    "component": "SocialCompleteProfileSerializer",
                },
            )
            return instance
            
        except Exception as e:
            logger.error(
                "Social profile completion failed",
                extra={
                    "user_id": instance.id,
                    "username": username,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                    "action": "profile_completion_failure",
                    "component": "SocialCompleteProfileSerializer",
                    "severity": "high",
                },
                exc_info=True,
            )
            raise serializers.ValidationError({
                "non_field_errors": "Profile completion failed. Please try again."
            })