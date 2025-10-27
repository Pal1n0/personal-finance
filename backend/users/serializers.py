"""
Custom serializers for user authentication and profile management.

This module provides serializers for handling traditional login, social authentication,
and profile completion with custom validation and security features.
"""

import logging
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied  
from dj_rest_auth.serializers import LoginSerializer
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from axes.models import AccessAttempt
from django.conf import settings

# Get logger for this module
logger = logging.getLogger(__name__)
User = get_user_model()


class CustomLoginSerializer(LoginSerializer):
    """
    Custom login serializer supporting both username and email authentication.
    
    Extends the default LoginSerializer to add:
    - Email-based authentication
    - Axes security integration for login attempt tracking
    - Detailed logging for authentication attempts
    """
    
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """
        Validate login credentials and authenticate user.
        
        Args:
            attrs (dict): Dictionary containing username/email and password
            
        Returns:
            dict: Validated attributes with user object if authentication succeeds
            
        Raises:
            serializers.ValidationError: If credentials are missing or invalid
            AuthenticationFailed: If authentication fails
            PermissionDenied: If account is temporarily locked due to too many attempts
        """
        logger.info("CustomLoginSerializer validation started")
        logger.debug(f"Validation attrs: { {k: v for k, v in attrs.items() if k != 'password'} }")
        
        username = attrs.get("username", "").strip()
        email = attrs.get("email", "").strip()
        password = attrs.get("password")
        request = self.context.get('request')

        # --- SECURITY CHECK: Account lockout verification ---
        lookup_username = username
        if not lookup_username and email:
            try:
                user_obj = User.objects.get(email=email)
                lookup_username = user_obj.username
            except User.DoesNotExist:
                pass
        
        if lookup_username:
            try:
                attempt = AccessAttempt.objects.get(username=lookup_username)
                lockout_limit = getattr(settings, 'AXES_FAILURE_LIMIT', 5)
                # Check if user has exceeded maximum allowed failed attempts
                if attempt.failures_since_start >= lockout_limit:
                    logger.warning(f"Account locked for user: {lookup_username}")
                    raise PermissionDenied({
                        'detail': 'Too many attempts. Account was temporarily blocked for 15 minutes. Try again later.',
                        'locked': True
                    })
            except AccessAttempt.DoesNotExist:
                pass
        # --- END SECURITY CHECK ---

        # Validate required fields
        if not password:
            logger.warning("Login attempt without password")
            raise serializers.ValidationError("Password is required.")
        
        # Attempt authentication with username or email
        if username:
            logger.info(f"Attempting username authentication: {username}")
            user = authenticate(request=request, username=username, password=password)
            logger.debug(f"Username authentication result: {'Success' if user else 'Failed'}")
        elif email:
            logger.info(f"Attempting email authentication: {email}")
            try:
                user_obj = User.objects.get(email=email)
                logger.debug(f"User found by email: {user_obj.username}")
                user = authenticate(request=request, username=user_obj.username, password=password)
                logger.debug(f"Email authentication result: {'Success' if user else 'Failed'}")
            except User.DoesNotExist:
                logger.warning(f"Email not found in database: {email}")
                user = None
        else:
            logger.warning("Login attempt without username or email")
            raise serializers.ValidationError("Username or email is required.")

        # Check authentication result
        if not user:
            logger.warning(f"Authentication failed for username: {username}, email: {email}")
            raise AuthenticationFailed("Invalid credentials.")

        logger.info(f"Authentication successful for user: {user.username} (ID: {user.id})")
        attrs["user"] = user
        return attrs


class SocialLoginSerializer(serializers.Serializer):
    """
    Serializer for social authentication (Google OAuth) login flow.
    
    Handles validation of social login data received from OAuth providers.
    """
    
    email = serializers.EmailField(required=True)
    provider = serializers.CharField(required=False, default='google')

    def validate_email(self, value):
        """
        Validate email field for social login.
        
        Args:
            value (str): Email address from social provider
            
        Returns:
            str: Validated email address
            
        Raises:
            serializers.ValidationError: If email is empty or invalid
        """
        logger.debug(f"SocialLoginSerializer validating email: {value}")
        if not value:
            raise serializers.ValidationError("Email is required for social login.")
        return value

    def validate(self, attrs):
        """
        Validate social login attributes.
        
        Args:
            attrs (dict): Dictionary containing email and provider
            
        Returns:
            dict: Validated attributes
        """
        logger.info("SocialLoginSerializer validation started")
        logger.debug(f"Social login attrs: {attrs}")
        return attrs


class SocialCompleteProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for completing user profile after social authentication.
    
    Handles setting username and password for users who registered via social login
    and need to complete their profile information.
    """
    
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ('username', 'password')

    def validate_username(self, value):
        """
        Validate username for profile completion.
        
        Args:
            value (str): Proposed username
            
        Returns:
            str: Validated username
        """
        logger.debug(f"Validating username: {value}")
        return value

    def validate(self, attrs):
        """
        Validate profile completion data.
        
        Args:
            attrs (dict): Dictionary containing username and password
            
        Returns:
            dict: Validated attributes
        """
        logger.info("SocialCompleteProfileSerializer validation started")
        logger.debug(f"Profile completion attrs: { {k: v for k, v in attrs.items() if k != 'password'} }")
        return attrs

    def update(self, instance, validated_data):
        """
        Update user instance with profile completion data.
        
        Args:
            instance (User): The user instance to update
            validated_data (dict): Validated username and password
            
        Returns:
            User: Updated user instance with profile marked as completed
        """
        logger.info(f"Updating social profile for user ID: {instance.id}")
        logger.debug(f"Update data - username: {validated_data.get('username')}")
        
        # Update user profile with provided data
        instance.username = validated_data['username']
        instance.set_password(validated_data['password'])
        instance.profile_completed = True
        
        logger.info(f"Saving profile completion for user: {instance.username}")
        instance.save()
        
        logger.info("Social profile completed successfully")
        return instance
