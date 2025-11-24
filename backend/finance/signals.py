# signals.py
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import UserSettings, Workspace, WorkspaceSettings
from .services.transaction_service import TransactionService


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_settings(sender, instance, created, **kwargs):
    """
    Signal to automatically create UserSettings when a new user is created.
    """
    if created:
        UserSettings.objects.get_or_create(user=instance)


@receiver(post_save, sender=Workspace)
def create_workspace_settings(sender, instance, created, **kwargs):
    """
    Signal to automatically create WorkspaceSettings when a new Workspace is created.
    """
    if created:
        WorkspaceSettings.objects.get_or_create(workspace=instance)


# You can add other signal receivers below if needed.
