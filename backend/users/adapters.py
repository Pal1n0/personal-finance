# users/adapter.py
from allauth.account.adapter import DefaultAccountAdapter
from django.conf import settings
from django.shortcuts import redirect
from django.http import HttpResponseRedirect

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