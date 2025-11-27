# users/tests/test_views.py

from datetime import date
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

from finance.tests.factories import UserFactory
from allauth.account.models import EmailConfirmation, EmailAddress
from django.test import RequestFactory


User = get_user_model()

class BaseUserAPITestCase(APITestCase):
    """Base test case for user-related API tests."""

    @classmethod
    def setUpTestData(cls):
        """Set up STATIC test data."""
        cls.original_email_verification = getattr(
            settings, "ACCOUNT_EMAIL_VERIFICATION", None
        )
        cls.original_email_required = getattr(settings, "ACCOUNT_EMAIL_REQUIRED", None)
        settings.ACCOUNT_EMAIL_VERIFICATION = "none"
        settings.ACCOUNT_EMAIL_REQUIRED = False

    def setUp(self):
        """Set up DYNAMIC test data."""
        super().setUp()
        cache.clear()
        self.user = UserFactory(username="testuser", email="test@example.com")
        self.user.set_password("testpass123")
        self.user.save()
        self._authenticate_user(self.user)

    def _authenticate_user(self, user):
        """Authenticate user and return access token."""
        self.client.force_authenticate(user=user)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")
        return access_token

    def tearDown(self):
        """Clean up after tests."""
        settings.ACCOUNT_EMAIL_VERIFICATION = self.original_email_verification
        settings.ACCOUNT_EMAIL_REQUIRED = self.original_email_required
        cache.clear()
        super().tearDown()


class GoogleLoginViewTests(BaseUserAPITestCase):
    """Tests for the GoogleLoginView."""

    def test_google_login_generic_exception(self):
        """Test GoogleLoginView returns 400 for generic exceptions."""
        url = reverse("users:google_login")
        data = {"access_token": "some_token"}

        with patch("users.views.SocialLoginView.post", side_effect=Exception("Google service error")):
            response = self.client.post(url, data, format="json")
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn("Google authentication failed", response.data["detail"])


class SocialCompleteProfileViewTests(BaseUserAPITestCase):
    """Tests for the SocialCompleteProfileView."""

    def test_social_complete_profile_generic_exception(self):
        """Test SocialCompleteProfileView re-raises generic exceptions."""
        social_user = UserFactory(
            username="google_user_123", email="social@example.com", is_social_account=True
        )
        self._authenticate_user(social_user)
        url = reverse("users:social-complete-profile")
        data = {"username": "new_social_username"}

        with patch("users.views.generics.UpdateAPIView.update", side_effect=Exception("Profile update error")):
            with pytest.raises(Exception, match="Profile update error"):
                self.client.patch(url, data, format="json")


class LogoutViewTests(BaseUserAPITestCase):
    """Tests for the LogoutView."""

    def test_logout_generic_exception(self):
        """Test LogoutView handles generic exceptions during blacklisting."""
        url = reverse("users:custom-logout")
        refresh_token = str(RefreshToken.for_user(self.user))
        data = {"refresh": refresh_token}

        with patch("rest_framework_simplejwt.tokens.RefreshToken.blacklist", side_effect=Exception("Blacklist error")):
            response = self.client.post(url, data, format="json")
            self.assertEqual(response.status_code, status.HTTP_200_OK) # Still returns 200 OK
            self.assertIn("Successfully logged out", response.data["detail"])

    def test_logout_invalid_token_format_no_error(self):
        """Test LogoutView handles invalid token format gracefully."""
        url = reverse("users:custom-logout")
        data = {"refresh": "malformed_token"}
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Successfully logged out", response.data["detail"])

    def test_logout_missing_token_no_error(self):
        """Test LogoutView handles missing token gracefully."""
        url = reverse("users:custom-logout")
        data = {} # Missing refresh token
        response = self.client.post(url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("Successfully logged out", response.data["detail"])


class CustomConfirmEmailViewTests(BaseUserAPITestCase):
    """Tests for the CustomConfirmEmailView."""

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()
        self.request = self.factory.get('/')  # Create a fake request
        settings.ACCOUNT_EMAIL_VERIFICATION = "mandatory"
        settings.ACCOUNT_EMAIL_REQUIRED = True
        self.unconfirmed_user = UserFactory(email="unconfirmed@example.com", is_active=False)
        self.unconfirmed_user.set_password("testpass123")
        self.unconfirmed_user.save()
        self.email_address = EmailAddress.objects.create(
            user=self.unconfirmed_user, email=self.unconfirmed_user.email, verified=False, primary=True
        )
        self.email_confirmation = EmailConfirmation.create(self.email_address)
        # Mock the send method as it expects a more complete request context
        with patch.object(self.email_confirmation, "send"):
            self.email_confirmation.send(self.request) # This generates the key

    def test_confirm_email_missing_key(self):
        """Test CustomConfirmEmailView returns 400 if confirmation key is missing."""
        url = "/api/users/auth/registration/account-confirm-email/" # Missing key
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Confirmation key is required", response.data["detail"])

    def test_confirm_email_invalid_key(self):
        """Test CustomConfirmEmailView returns 400 if confirmation key is invalid."""
        url = reverse("users:custom_account_confirm_email", kwargs={"key": "invalid_key"})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid confirmation link", response.data["detail"])

    def test_confirm_email_generic_exception(self):
        """Test CustomConfirmEmailView returns 400 for generic exceptions."""
        url = reverse("users:custom_account_confirm_email", kwargs={"key": self.email_confirmation.key})
        with patch("allauth.account.models.EmailConfirmation.confirm", side_effect=Exception("Confirmation error")):
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertIn("Confirmation failed", response.data["detail"])
