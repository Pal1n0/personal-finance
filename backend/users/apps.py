"""
Django AppConfig for the users application.

This module configures the users application within the Django project,
defining application-specific settings and metadata.
"""

from django.apps import AppConfig


class UsersConfig(AppConfig):
    """
    Configuration class for the users application.

    This class defines application-specific configuration including
    the default auto field type and application name.
    """

    # Use BigAutoField as default for primary keys
    default_auto_field = "django.db.models.BigAutoField"

    # Application name (Python path)
    name = "users"

    def ready(self):
        # Tu načítame signály
        # import users.signals
        pass