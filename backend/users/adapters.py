# users/adapter.py
from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.utils import perform_login
from allauth.exceptions import ImmediateHttpResponse
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from rest_framework import status
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class CustomAccountAdapter(DefaultAccountAdapter):
    """
    Adapter, ktorý vynúti presmerovanie namiesto renderovania šablóny
    po úspešnej verifikácii e-mailu.
    """
    def respond_email_confirmation_sent(self, request, emailaddress):
        """
        Po odoslaní konfirmačného e-mailu vráti redirect (ak nie je definované inak).
        """
        # Môžete použiť super(), ale pre overenie v teste stačí nechať default správanie (posiela e-mail)
        return super().respond_email_confirmation_sent(request, emailaddress)

    def respond_email_confirmation_complete(self, request, confirmation):
        """
        Po úspešnej aktivácii e-mailu presmeruje na preddefinovanú URL.
        Týmto sa vyhneme volaniu views.render_to_response a chybe šablóny.
        """
        # Nastavte cieľovú URL. V REST API stačí jednoduchá cesta.
        redirect_url = getattr(settings, 'ACCOUNT_EMAIL_CONFIRMATION_DONE_URL', '/')
        return HttpResponseRedirect(redirect_url)
    
class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
      
    def pre_social_login(self, request, sociallogin):
        """
        Spracovanie pred prihlásením cez Google - používame VAŠE polia
        """
        user = sociallogin.user
        email = user.email
        
        # Skontrolujeme, či používateľ už existuje
        try:
            existing_user = User.objects.get(email=email)
            logger.info(f"Found existing user for Google login: {existing_user.id}")
            
            # Pripojíme social account k existujúcemu userovi
            sociallogin.connect(request, existing_user)
            
            # Nastavíme VAŠE polia ak ešte nie sú nastavené
            if not existing_user.is_social_account:
                existing_user.is_social_account = True
                existing_user.save()
                logger.info(f"Updated existing user to social account: {existing_user.email}")
                
        except User.DoesNotExist:
            # Nový používateľ - nastavíme VAŠE polia
            user.is_social_account = True
            user.profile_completed = False
            logger.info(f"New Google user will be created: {email}")
    
    def save_user(self, request, sociallogin, form=None):
        """
        Uloženie Google usera - používame VAŠE polia
        """
        user = super().save_user(request, sociallogin, form)
        
        # Nastavenie VAŠICH custom fields
        user.is_social_account = True
        user.profile_completed = False  # Podľa vášho modelu
                
        user.save()
        
        logger.info(f"Google user created: {user.email} (profile_completed: {user.profile_completed})")
        return user