import logging
from django.shortcuts import render
# from dj_rest_auth.views import LoginView
from rest_framework import generics, status, permissions
from .models import CustomUser as User
from .serializers import SocialCompleteProfileSerializer, SocialLoginSerializer # , CustomLoginSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from allauth.account.views import ConfirmEmailView
from allauth.account.models import EmailConfirmation
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.conf import settings
from rest_framework.response import Response


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

class GoogleLoginView(SocialLoginView):
    """
    Google OAuth2 login - spracuje Google token a vráti JWT
    """
    adapter_class = GoogleOAuth2Adapter
    callback_url = "http://localhost:5173"
    client_class = OAuth2Client
    
    def get_response(self):
        logger.info("Google login successful")
        response = super().get_response()
        
        user = self.user
        
        if user:
            # Používame VAŠE existujúce polia z modelu
            if isinstance(response.data, dict):
                response.data['profile_completed'] = user.profile_completed
                response.data['user_id'] = user.id
                response.data['email'] = user.email
                response.data['username'] = user.username
                
                # DÔLEŽITÉ: Flag pre frontend - či treba dokončiť profil
                requires_completion = (
                    not user.profile_completed or 
                    not user.username or 
                    user.username.startswith('google_user_')
                )
                response.data['requires_profile_completion'] = requires_completion
                
                logger.info(f"User {user.email} - profile_completed: {user.profile_completed}, requires_completion: {requires_completion}")
        
        return response

    def post(self, request, *args, **kwargs):
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
    queryset = User.objects.all()
    serializer_class = SocialCompleteProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        logger.info(f"Social complete profile - user: {self.request.user.id}")
        return self.request.user

    def update(self, request, *args, **kwargs):
        logger.info(f"Social profile completion attempt - user: {request.user.id}")
        logger.debug(f"Profile completion data: {request.data}")
        
        try:
            # Zavoláme parent metódu ktorá spracuje update
            response = super().update(request, *args, **kwargs)
            
            # DÔLEŽITÉ: Po úspešnom update generujeme NOVÉ tokeny
            user = self.get_object()
            refresh = RefreshToken.for_user(user)
            
            logger.info(f"Profile completed successfully - user: {request.user.id}")
            
            # Vrátime pôvodnú response + nové tokeny
            return Response({
                'username': user.username,
                'profile_completed': user.profile_completed,
                'access': str(refresh.access_token),  # ⬅️ PRIDANÉ
                'refresh': str(refresh),              # ⬅️ PRIDANÉ
                'user_id': user.id,
                'email': user.email
            }, status=status.HTTP_200_OK)
            
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
class InactiveAccountView(APIView):
    def get(self, request):
        return Response({"detail": "Account is inactive, check your email."}, status=403)
    

class CustomConfirmEmailView(ConfirmEmailView):
    """
    Vlastný pohľad, ktorý obíde renderovanie šablóny a vráti JSON odpoveď/redirect.
    """
    def get_object(self, queryset=None):
        try:
            key = self.kwargs['key']
            print(f"🔍 Looking for key: {key}")
            
            # Skontrolujme všetky kľúče v DB
            all_keys = list(EmailConfirmation.objects.values_list('key', flat=True))
            print(f"📋 All keys in DB: {all_keys}")
            
            confirmation = EmailConfirmation.objects.get(key=key)
            print(f"✅ Found confirmation: {confirmation.email_address.email}")
            
            return confirmation
            
        except EmailConfirmation.DoesNotExist:
            print(f"❌ Key '{key}' not found in database")
            return None
        except Exception as e:
            print(f"💥 Error in get_object: {e}")
            return None
    def get(self, *args, **kwargs):
        print("=== CUSTOM CONFIRM EMAIL VIEW ===")
        
        try:
            # 1. Získanie objektu
            print("🔍 Getting confirmation object...")
            self.object = self.get_object()
            
            if not self.object:
                print("❌ Confirmation object is None")
                return JsonResponse(
                    {"detail": "Neplatný konfirmačný odkaz."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            print(f"✅ Found confirmation for: {self.object.email_address.email}")
            print(f"🔑 Key: {self.object.key}")
            print(f"📅 Created: {self.object.created}")
            print(f"📤 Sent: {self.object.sent}")
            print(f"👤 User active before: {self.object.email_address.user.is_active}")
            print(f"📧 Email verified before: {self.object.email_address.verified}")
            
            # 2. Potvrdenie
            print("🔄 Confirming email...")
            self.object.confirm(self.request)
            user = self.object.email_address.user
            if not user.is_active:
                print("⭐️ Manually activating user...")
                user.is_active = True
                user.save()
            
            # 3. Overenie výsledku
            self.object.email_address.refresh_from_db()
            self.object.email_address.user.refresh_from_db()
            
            print(f"👤 User active after: {self.object.email_address.user.is_active}")
            print(f"📧 Email verified after: {self.object.email_address.verified}")
            
            # 4. Úspešná odpoveď
            print("✅ Confirmation successful")
            return JsonResponse(
                {
                    "detail": "E-mail bol úspešne potvrdený a účet aktivovaný.",
                    "user": {
                        "email": self.object.email_address.email,
                        "username": self.object.email_address.user.username,
                        "is_active": self.object.email_address.user.is_active
                    }
                },
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            print(f"💥 ERROR in confirmation: {e}")
            import traceback
            traceback.print_exc()
            
            return JsonResponse(
                {"detail": f"Chyba pri potvrdzovaní: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )