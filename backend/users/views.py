"""
Custom views for user authentication, social login, and account management.

This module provides API views for handling Google OAuth authentication,
profile completion, email confirmation, and user session management.
"""

import logging
from django.shortcuts import render
from rest_framework import generics, status, permissions
from .models import CustomUser as User
from .serializers import SocialCompleteProfileSerializer, SocialLoginSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from allauth.account.views import ConfirmEmailView
from allauth.account.models import EmailConfirmation
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView

# Get logger for this module
logger = logging.getLogger(__name__)


class GoogleLoginView(SocialLoginView):
    """
    Google OAuth2 login view that processes Google tokens and returns JWT tokens.
    
    Handles the social authentication flow for Google OAuth2 and provides
    additional user information and profile completion flags in the response.
    """
    
    adapter_class = GoogleOAuth2Adapter
    callback_url = "http://localhost:5173"  # Frontend callback URL for development
    client_class = OAuth2Client
    
    def get_response(self):
        """
        Enhance the default social login response with custom user fields.
        
        Returns:
            Response: Enhanced response with user profile information and completion flags
        """
        logger.info("Google login successful")
        response = super().get_response()
        
        user = self.user
        
        if user:
            # Add custom user model fields to response
            if isinstance(response.data, dict):
                response.data['profile_completed'] = user.profile_completed
                response.data['user_id'] = user.id
                response.data['email'] = user.email
                response.data['username'] = user.username
                
                # IMPORTANT: Flag for frontend - indicates if profile completion is required
                requires_completion = (
                    not user.profile_completed or 
                    not user.username or 
                    user.username.startswith('google_user_')
                )
                response.data['requires_profile_completion'] = requires_completion
                
                logger.info(f"User {user.email} - profile_completed: {user.profile_completed}, requires_completion: {requires_completion}")
        
        return response

    def post(self, request, *args, **kwargs):
        """
        Handle Google OAuth2 login POST requests.
        
        Args:
            request: The HTTP request object
            
        Returns:
            Response: Authentication response with JWT tokens or error message
        """
        logger.info("Google OAuth2 login attempt")
        try:
            response = super().post(request, *args, **kwargs)
            logger.info("Google OAuth2 login processed successfully")
            return response
        except Exception as e:
            logger.error(f"Google OAuth2 login failed: {str(e)}", exc_info=True)
            return Response(
                {'detail': 'Google login failed. Please try again.'},
                status=status.HTTP_400_BAD_REQUEST
            )


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
        
        Returns:
            User: The currently authenticated user
        """
        logger.info(f"Social complete profile - user: {self.request.user.id}")
        return self.request.user

    def update(self, request, *args, **kwargs):
        """
        Update user profile and generate new JWT tokens.
        
        Args:
            request: The HTTP request object with profile completion data
            
        Returns:
            Response: Updated user data with new JWT tokens
        """
        logger.info(f"Social profile completion attempt - user: {request.user.id}")
        logger.debug(f"Profile completion data: {request.data}")
        
        try:
            # Call parent method to handle the update
            response = super().update(request, *args, **kwargs)
            
            # IMPORTANT: Generate new tokens after profile completion
            user = self.get_object()
            refresh = RefreshToken.for_user(user)
            
            logger.info(f"Profile completed successfully - user: {request.user.id}")
            
            # Return enhanced response with new tokens
            return Response({
                'username': user.username,
                'profile_completed': user.profile_completed,
                'access': str(refresh.access_token),  # New access token
                'refresh': str(refresh),              # New refresh token
                'user_id': user.id,
                'email': user.email
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Profile completion failed - user: {request.user.id}, error: {str(e)}", exc_info=True)
            raise


class LogoutView(APIView):
    """
    Logout view that blacklists refresh tokens.
    
    Provides a defensive logout implementation that prioritizes user experience
    and security over perfect token blacklisting.
    """
    
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """
        Handle logout requests with robust error handling.
        
        Security is prioritized over perfect blacklisting - always returns
        success to prevent revealing system state to potential attackers.
        
        Args:
            request: The HTTP request object containing refresh token
            
        Returns:
            Response: Always returns success response regardless of blacklisting outcome
        """
        logger.info("Logout endpoint called")
        logger.debug(f"Logout request data: {request.data}")
        
        try:
            refresh_token = request.data.get("refresh", "")
            logger.debug(f"Refresh token received: {refresh_token[:20] if refresh_token else 'None'}...")
            
            # Attempt to blacklist token if valid format is provided
            if refresh_token and isinstance(refresh_token, str) and '.' in refresh_token:
                logger.info("Attempting to blacklist token")
                try:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                    logger.info("Token successfully blacklisted")
                except Exception as e:
                    # Blacklisting failed - acceptable failure mode
                    logger.warning(f"Token blacklisting failed: {str(e)}")
                    logger.debug("Blacklisting failure details:", exc_info=True)
            
            # Always return success to maintain security
            logger.info("Logout completed successfully")
            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            # Critical error handling - still return success
            logger.error(f"Critical logout error: {str(e)}", exc_info=True)
            logger.critical("Logout endpoint experienced a critical failure")
            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_200_OK
            )


class InactiveAccountView(APIView):
    """
    View for handling inactive account responses.
    
    Informs users that their account is inactive and email verification is required.
    """
    
    def get(self, request):
        """
        Return inactive account message.
        
        Returns:
            Response: Error message indicating account is inactive
        """
        return Response(
            {"detail": "Account is inactive, check your email."}, 
            status=status.HTTP_403_FORBIDDEN
        )


class CustomConfirmEmailView(ConfirmEmailView):
    """
    Custom email confirmation view that returns JSON responses instead of rendering templates.
    
    Overrides the default allauth behavior to provide API-friendly JSON responses
    for email confirmation in a REST API context.
    """
    
    def get_object(self, queryset=None):
        """
        Retrieve email confirmation object by key.
        
        Args:
            queryset: Optional queryset to search (not used)
            
        Returns:
            EmailConfirmation or None: The confirmation object if found
        """
        try:
            key = self.kwargs['key']
            logger.debug(f"Looking for email confirmation key: {key}")
            
            # Debug: List all keys in database
            all_keys = list(EmailConfirmation.objects.values_list('key', flat=True))
            logger.debug(f"All confirmation keys in DB: {all_keys}")
            
            confirmation = EmailConfirmation.objects.get(key=key)
            logger.info(f"Found confirmation for: {confirmation.email_address.email}")
            
            return confirmation
            
        except EmailConfirmation.DoesNotExist:
            logger.warning(f"Email confirmation key not found: {key}")
            return None
        except Exception as e:
            logger.error(f"Error retrieving confirmation object: {e}")
            return None

    def get(self, *args, **kwargs):
        """
        Handle email confirmation GET requests.
        
        Processes the email confirmation key, activates the user account,
        and returns a JSON response with the result.
        
        Returns:
            JsonResponse: Success or error response in JSON format
        """
        logger.info("Custom email confirmation view called")
        
        try:
            # 1. Retrieve confirmation object
            logger.debug("Retrieving confirmation object...")
            self.object = self.get_object()
            
            if not self.object:
                logger.warning("Confirmation object not found")
                return JsonResponse(
                    {"detail": "Invalid confirmation link."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Log confirmation details
            logger.info(f"Processing confirmation for: {self.object.email_address.email}")
            logger.debug(f"User active before: {self.object.email_address.user.is_active}")
            logger.debug(f"Email verified before: {self.object.email_address.verified}")
            
            # 2. Confirm email address
            logger.debug("Confirming email...")
            self.object.confirm(self.request)
            user = self.object.email_address.user
            
            # Ensure user is activated after email confirmation
            if not user.is_active:
                logger.info("Activating user after email confirmation")
                user.is_active = True
                user.save()
            
            # 3. Verify confirmation results
            self.object.email_address.refresh_from_db()
            self.object.email_address.user.refresh_from_db()
            
            logger.debug(f"User active after: {self.object.email_address.user.is_active}")
            logger.debug(f"Email verified after: {self.object.email_address.verified}")
            
            # 4. Return success response
            logger.info("Email confirmation completed successfully")
            return JsonResponse(
                {
                    "detail": "Email was successfully confirmed and account activated.",
                    "user": {
                        "email": self.object.email_address.email,
                        "username": self.object.email_address.user.username,
                        "is_active": self.object.email_address.user.is_active
                    }
                },
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Email confirmation error: {e}", exc_info=True)
            return JsonResponse(
                {"detail": f"Confirmation error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
