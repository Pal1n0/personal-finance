# signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import WorkspaceSettings
from .services.transaction_service import TransactionService

@receiver(post_save, sender=WorkspaceSettings)
def recalc_transactions_on_currency_change(sender, instance, **kwargs):
    """Prepocita transakcie ked sa zmeni domestic_currency"""
    
    if instance._state.adding:
        return  # Nový záznam
    
    try:
        old = WorkspaceSettings.objects.get(pk=instance.pk)
        if old.domestic_currency != instance.domestic_currency:
            print(f"Currency changed from {old.domestic_currency} to {instance.domestic_currency}")
            TransactionService.recalculate_all_transactions_for_workspace(instance.workspace)
    except WorkspaceSettings.DoesNotExist:
        pass