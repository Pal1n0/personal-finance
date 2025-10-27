"""
Utility functions for user authentication and security.

This module provides custom functions for the Axes security package
to handle username/email authentication and custom lockout responses.
"""

from django.http import JsonResponse
from rest_framework import status


def get_axes_username(request, credentials):
    """
    Custom username callable for AXES_USERNAME_CALLABLE.
    
    This function determines what identifier to use for tracking login attempts.
    It returns either the username or email from the provided credentials.
    
    Args:
        request: The HTTP request object
        credentials (dict): Dictionary containing authentication credentials
        
    Returns:
        str or None: The username if present, otherwise email, or None if no credentials
    """
    if not credentials:
        return None
    
    # Return username if available, otherwise fall back to email
    return credentials.get("username") or credentials.get("email")


def custom_lockout_response(request, credentials):
    """
    Custom response for account lockout due to too many failed login attempts.
    
    This function is called by Axes when an account gets locked and returns
    a JSON response with an appropriate error message.
    
    Args:
        request: The HTTP request object
        credentials (dict): Dictionary containing authentication credentials
        
    Returns:
        JsonResponse: JSON response with lockout message and 403 status
    """
    return JsonResponse({
        "detail": "Account temporarily locked due to too many failed login attempts."
    }, status=status.HTTP_403_FORBIDDEN)