# users/signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings
from .models import UserSettings
from .services import recalculate_all_transactions_for_user  


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_settings(sender, instance, created, **kwargs):
    """
    Pri vytvorení nového používateľa sa automaticky vytvoria jeho default
    nastavenia v UserSettings.
    """
    if created:
        UserSettings.objects.create(user=instance)

@receiver(post_save, sender=UserSettings)
def on_domestic_currency_change(sender, instance, **kwargs):
    """
    Automaticky prepočíta všetky transakcie keď sa zmení domestic_currency
    """
    # Skontrolujeme či sa zmenila domestic_currency
    if kwargs.get('created'):
        return  # Nový záznam - nemáme čo prepočítavať
    
    if kwargs.get('update_fields') and 'domestic_currency' in kwargs['update_fields']:
        # Zmenila sa domestic_currency - prepočítame transakcie
        recalculate_all_transactions_for_user(instance.user, instance.domestic_currency)
    
    # Alebo pre istotu - ak nevieme update_fields, porovnáme s pôvodným záznamom
    else:
        try:
            old_instance = UserSettings.objects.get(pk=instance.pk)
            if old_instance.domestic_currency != instance.domestic_currency:
                recalculate_all_transactions_for_user(instance.user, instance.domestic_currency)
        except UserSettings.DoesNotExist:
            pass