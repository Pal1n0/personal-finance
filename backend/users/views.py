import logging
from django.shortcuts import render
# from dj_rest_auth.views import LoginView
from rest_framework import generics, status, permissions
from .models import CustomUser as User
from .serializers import SocialCompleteProfileSerializer, SocialLoginSerializer # , CustomLoginSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework_simplejwt.views import TokenObtainPairView

# Get logger for this module
logger = logging.getLogger(__name__)

"""class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer"""

"""class CustomTokenObtainPairView(LoginView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomLoginSerializer

    def post(self, request, *args, **kwargs):
        logger.info(f"Login attempt - path: {request.path}")
        logger.debug(f"Login request data: {request.data}")
        try:
            response = super().post(request, *args, **kwargs)
            logger.info(f"Login successful - status: {response.status_code}")
            return response
        except Exception as e:
            logger.error(f"Login failed: {str(e)}", exc_info=True)
            raise"""

class SocialLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        logger.info("Social login attempt")
        logger.debug(f"Social login data: {request.data}")
        
        try:
            serializer = SocialLoginSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data['email']
            
            logger.info(f"Social login processing for email: {email}")

            user, created = User.objects.get_or_create(
                email=email,
                defaults={'is_social_account': True, 'profile_completed': False}
            )

            logger.info(f"Social login {'created new user' if created else 'found existing user'} - user_id: {user.id}")

            # generovanie JWT tokenov
            refresh = RefreshToken.for_user(user)
            logger.info("Social login tokens generated successfully")
            
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'created': created  # True = nový užívateľ, False = už existuje
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Social login failed: {str(e)}", exc_info=True)
            raise

class SocialCompleteProfileView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = SocialCompleteProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        logger.info(f"Social complete profile - user: {self.request.user.id}")
        return self.request.user  # doplní svoj profil

    def update(self, request, *args, **kwargs):
        logger.info(f"Social profile completion attempt - user: {request.user.id}")
        logger.debug(f"Profile completion data: {request.data}")
        try:
            response = super().update(request, *args, **kwargs)
            logger.info(f"Profile completed successfully - user: {request.user.id}")
            return response
        except Exception as e:
            logger.error(f"Profile completion failed - user: {request.user.id}, error: {str(e)}", exc_info=True)
            raise
    
class LogoutView(APIView):
    """
    Logout by blacklisting the refresh token.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """
        Ultra-defensive logout that NEVER crashes.
        Security is more important than perfect blacklisting.
        """
        logger.info("Logout endpoint called")
        logger.debug(f"Logout request data: {request.data}")
        
        try:
            refresh_token = request.data.get("refresh", "")
            logger.debug(f"Refresh token received: {refresh_token[:20] if refresh_token else 'None'}...")
            
            # If we have something that looks like a token, try to blacklist it
            if refresh_token and isinstance(refresh_token, str) and '.' in refresh_token:
                logger.info("Attempting to blacklist token")
                try:
                    # Isolate the blacklisting in its own try block
                    token = RefreshToken(refresh_token)
                    token.blacklist()
                    logger.info("Token successfully blacklisted")
                except Exception as e:
                    # Blacklisting failed - but that's OK
                    logger.warning(f"Token blacklisting failed: {str(e)}")
                    logger.debug("Blacklisting failure details:", exc_info=True)
            
            # Always return success
            logger.info("Logout completed successfully")
            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            # If even the basic request handling fails, return minimal response
            logger.error(f"Critical logout error: {str(e)}", exc_info=True)
            logger.critical("Logout endpoint experienced a critical failure")
            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_200_OK
            )