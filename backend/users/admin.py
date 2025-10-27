"""
Django admin configuration for CustomUser model.

This module registers the CustomUser model with the Django admin interface
and extends the default UserAdmin to include custom fields.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import CustomUser


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    """
    Custom admin configuration for CustomUser model.

    Extends the default UserAdmin to include additional custom fields
    while maintaining all the standard user administration functionality.
    """

    # Extend the fieldsets to include custom fields in edit view
    fieldsets = UserAdmin.fieldsets + (
        (
            "Custom Profile Information",
            {"fields": ("profile_picture", "is_social_account", "profile_completed")},
        ),
    )

    # Extend the add_fieldsets to include custom fields in create view
    add_fieldsets = UserAdmin.add_fieldsets + (
        (
            "Custom Profile Information",
            {"fields": ("profile_picture", "is_social_account", "profile_completed")},
        ),
    )
