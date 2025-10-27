"""
User models for the Personal Finance application.

This module defines the CustomUser model which extends Django's AbstractUser
to support both traditional and social authentication with additional profile fields.
"""

from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator
from django.db import models


class CustomUser(AbstractUser):
    """
    Custom user model extending Django's AbstractUser.

    Supports both traditional email/password registration and social authentication
    (Google OAuth) with flexible field requirements and profile management.
    """

    # Email field - unique and required for all users
    email = models.EmailField(
        unique=True,
        blank=False,
        help_text="User's unique email address, required for all accounts",
    )

    # Username field - optional to support social authentication
    username = models.CharField(
        max_length=150,
        unique=True,
        null=True,
        blank=True,
        help_text="Optional username, can be null for Google registration",
    )

    # Password field - optional to support social authentication
    password = models.CharField(
        max_length=128,
        null=True,
        blank=True,
        help_text="Optional password, can be null for Google registration",
    )

    # Active status - new users are inactive by default until verified
    is_active = models.BooleanField(
        default=False,
        help_text=(
            "Designates whether this user should be treated as active. "
            "Unselect this instead of deleting accounts. "
            "New users are inactive until email verification."
        ),
    )

    # Optional profile picture with file type validation
    profile_picture = models.ImageField(
        upload_to="profile_pics/",
        null=True,
        blank=True,
        validators=[FileExtensionValidator(["jpg", "jpeg", "png"])],
        help_text="User profile picture (JPG, JPEG, PNG formats supported)",
    )

    # Social authentication flag
    is_social_account = models.BooleanField(
        default=False,
        help_text="True if this account was created via Google registration",
    )

    # Profile completion status
    profile_completed = models.BooleanField(
        default=False, help_text="True if password and username/nickname have been set"
    )

    def __str__(self):
        """
        String representation of the user model.

        Returns:
            str: The username if available, otherwise a default representation
        """
        return self.username or f"User {self.id} ({self.email})"
