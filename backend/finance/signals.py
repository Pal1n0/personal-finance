import logging

from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import UserSettings, Workspace, WorkspaceSettings

logger = logging.getLogger(__name__)


@receiver(post_save, sender=get_user_model())
def create_user_settings(sender, instance, created, **kwargs):
    """
    Signal to automatically create UserSettings when a new user is created.
    """
    logger.info(f"create_user_settings signal called for user {instance.username}, created={created}")
    if created:
        logger.info(f"Creating UserSettings for user {instance.username}")
        UserSettings.objects.get_or_create(user=instance)
        logger.info(f"UserSettings created for user {instance.username}")


@receiver(post_save, sender=Workspace)
def create_workspace_settings(sender, instance, created, **kwargs):
    """
    Signal to automatically create WorkspaceSettings when a new Workspace is created.
    """
    logger.info(f"create_workspace_settings signal called for workspace {instance.name}, created={created}")
    if created:
        logger.info(f"Creating WorkspaceSettings for workspace {instance.name}")
        WorkspaceSettings.objects.get_or_create(workspace=instance)
        logger.info(f"WorkspaceSettings created for workspace {instance.name}")


# You can add other signal receivers below if needed.
