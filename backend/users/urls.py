from django.urls import path, include
from .views import SocialLoginView, SocialCompleteProfileView, LogoutView#, CustomTokenObtainPairView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    #path('auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/custom-logout/', LogoutView.as_view(), name='custom-logout'),  # tvoj custom logout
    path('auth/registration/', include('dj_rest_auth.registration.urls')),  # register + email verification
    path('auth/', include('dj_rest_auth.urls')),  # login, logout, token refresh
    path('social-login/', SocialLoginView.as_view(), name='social-login'),
    path('social-complete-profile/', SocialCompleteProfileView.as_view(), name='social-complete-profile'),
    #path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    #path('logout/', LogoutView.as_view(), name='logout'),
]
