"""
Custom adapters for allauth authentication system.

This module provides custom adapters for handling email confirmation
and social authentication (Google OAuth) with custom user model fields.
"""

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.utils import perform_login
from allauth.exceptions import ImmediateHttpResponse
from django.conf import settings
from django.shortcuts import redirect
from django.http import HttpResponseRedirect, JsonResponse
from django.contrib.auth import get_user_model
from rest_framework import status
import logging

# Set up logger for this module
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
        # Use default behavior - sends confirmation email
        # Can be customized to return redirect if needed for API
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
        redirect_url = getattr(settings, 'ACCOUNT_EMAIL_CONFIRMATION_DONE_URL', '/')
        return HttpResponseRedirect(redirect_url)


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom social account adapter for Google OAuth authentication.
    
    Handles social login flow with custom user model fields and
    connects social accounts to existing users when appropriate.
    """
    
    def pre_social_login(self, request, sociallogin):
        """
        Process social login before authentication occurs.
        
        Checks if user already exists and connects social account if found.
        Sets custom fields for both existing and new social users.
        
        Args:
            request: The HTTP request object
            sociallogin: The social login instance being processed
        """
        user = sociallogin.user
        email = user.email
        
        # Check if user already exists in the system
        try:
            existing_user = User.objects.get(email=email)
            logger.info(f"Found existing user for Google login: {existing_user.id}")
            
            # Connect social account to existing user
            sociallogin.connect(request, existing_user)
            
            # Update custom fields if not already set
            if not existing_user.is_social_account:
                existing_user.is_social_account = True
                existing_user.save()
                logger.info(f"Updated existing user to social account: {existing_user.email}")
                
        except User.DoesNotExist:
            # New user - set custom fields for social account
            user.is_social_account = True
            user.profile_completed = False
            logger.info(f"New Google user will be created: {email}")
    
    def save_user(self, request, sociallogin, form=None):
        """
        Save social user with custom field values.
        
        Overrides the default save behavior to set custom user model fields
        specific to social authentication.
        
        Args:
            request: The HTTP request object
            sociallogin: The social login instance
            form: Optional form data (not used in social auth)
            
        Returns:
            User: The saved user instance with custom fields set
        """
        # Save user using parent class implementation
        user = super().save_user(request, sociallogin, form)
        
        # Set custom fields for social authentication
        user.is_social_account = True
        user.profile_completed = False  # Profile needs completion after social login
        user.is_active = True  # Social users are active immediately
                
        user.save()
        
        logger.info(f"Google user created: {user.email} (profile_completed: {user.profile_completed})")
        return user