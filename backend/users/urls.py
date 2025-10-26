from django.urls import path, include, re_path
from .views import SocialLoginView, SocialCompleteProfileView, LogoutView, InactiveAccountView, CustomConfirmEmailView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    re_path(
        r'^auth/registration/account-confirm-email/(?P<key>[-:\w]+)/$', 
        CustomConfirmEmailView.as_view(), 
        name='account_confirm_email' # Použite rovnaký názov!
    ),
    path('auth/custom-logout/', LogoutView.as_view(), name='custom-logout'),  # tvoj custom logout
    path('auth/registration/', include('dj_rest_auth.registration.urls')),  # register + email verification
    path('auth/', include('dj_rest_auth.urls')),  # login, logout, token refresh
    path('social-login/', SocialLoginView.as_view(), name='social-login'),
    path('social-complete-profile/', SocialCompleteProfileView.as_view(), name='social-complete-profile'),
    #path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    #path('logout/', LogoutView.as_view(), name='logout'),
    path('inactive/', InactiveAccountView.as_view(), name='account_inactive'),
]
