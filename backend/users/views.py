from django.shortcuts import render
from dj_rest_auth.views import LoginView
from rest_framework import generics, status, permissions
from .models import CustomUser as User
from .serializers import SocialCompleteProfileSerializer, SocialLoginSerializer, CustomLoginSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework_simplejwt.views import TokenObtainPairView


"""class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer"""

class CustomTokenObtainPairView(LoginView):
    permission_classes = [permissions.AllowAny]
    serializer_class = CustomLoginSerializer

class SocialLoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = SocialLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user, created = User.objects.get_or_create(
            email=email,
            defaults={'is_social_account': True, 'profile_completed': False}
        )

        # generovanie JWT tokenov
        refresh = RefreshToken.for_user(user)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'created': created  # True = nový užívateľ, False = už existuje
        }, status=status.HTTP_200_OK)

class SocialCompleteProfileView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = SocialCompleteProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user  # doplní svoj profil
    
class LogoutView(APIView):
    """
    Logout by blacklisting the refresh token.
    """
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            
            if not refresh_token:
                return Response(
                    {"detail": "Refresh token is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Check if it's a valid token format
            if not isinstance(refresh_token, str) or not refresh_token.strip():
                return Response(
                    {"detail": "Invalid token format."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Try to blacklist the token
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response(status=status.HTTP_205_RESET_CONTENT)
            
        except TokenError as e:
            # Specific JWT token errors (invalid, expired, etc.)
            return Response(
                {"detail": "Invalid or expired token."},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            # Log the actual error for debugging
            print(f"Logout error: {str(e)}")
            return Response(
                {"detail": "An error occurred during logout."},
                status=status.HTTP_400_BAD_REQUEST
            )