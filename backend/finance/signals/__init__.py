"""
Signal handlers for the finance app.
"""
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from finance.models import Workspace, UserSettings, WorkspaceSettings

@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_settings(sender, instance, created, **kwargs):
    """
    Create UserSettings when a new user is created.
    """
    if created:
        UserSettings.objects.update_or_create(user=instance)

@receiver(post_save, sender=Workspace)
def create_workspace_settings(sender, instance, created, **kwargs):
    """
    Create WorkspaceSettings when a new workspace is created.
    If the owner has a preferred currency in their UserSettings,
    set it as the domestic currency for the new workspace settings.
    """
    if created:
        # Ensure the owner instance is up-to-date to get the latest settings
        instance.owner.refresh_from_db()
        # Explicitly refresh the settings object related to the owner
        if hasattr(instance.owner, 'settings'):
            instance.owner.settings.refresh_from_db()

        preferred_currency = None
        if instance.owner and hasattr(instance.owner, 'settings'):
            preferred_currency = instance.owner.settings.preferred_currency

        defaults = {}
        if preferred_currency:
            defaults['domestic_currency'] = preferred_currency

        WorkspaceSettings.objects.update_or_create(workspace=instance, defaults=defaults)
