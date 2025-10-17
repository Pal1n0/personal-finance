from django.shortcuts import render
from rest_framework import generics, status, permissions
from .models import CustomUser as User
from .serializers import SocialCompleteProfileSerializer, SocialLoginSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken



"""class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer"""

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
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()  # zneplatní refresh token
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)