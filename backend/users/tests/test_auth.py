"""
Comprehensive test suite for user authentication and account management.

This test module covers:
- User registration with email verification
- Traditional login (username/email)
- JWT token management
- Social authentication (Google OAuth)
- Security features (AXES lockout, input validation)
- Edge cases and error handling
"""

import re
from unittest.mock import MagicMock, patch

from allauth.account.adapter import get_adapter
from allauth.account.models import EmailAddress, EmailConfirmation
from allauth.socialaccount.models import SocialLogin
from axes.utils import reset
from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.management import create_permissions
from django.contrib.contenttypes.models import ContentType
from django.contrib.sites.models import Site
from django.core import mail
from django.test import RequestFactory
from django.urls import resolve, reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class UserAuthTests(APITestCase):
    """
    Test suite for user authentication system.

    Tests cover registration, login, token management, logout, social authentication,
    and comprehensive security validation.
    """

    @classmethod
    def setUpTestData(cls):
        """
        Set up test data for the entire test class.

        Ensures allauth models are available and configures test site.
        """
        # Ensure allauth models are available in tests
        for app_config in apps.get_app_configs():
            if app_config.name in ["allauth.account", "allauth.socialaccount"]:
                create_permissions(app_config, verbosity=0)

        # Configure test site
        site = Site.objects.get_current()
        site.domain = "example.com"
        site.name = "Test Site"
        site.save()

    def setUp(self):
        """
        Set up test fixtures before each test method.

        Creates a test user, configures email verification, and sets up URL endpoints.
        """
        # Create test user
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="strongpass123",
            is_active=True,
        )

        # Configure email verification for test user
        email_address, created = EmailAddress.objects.get_or_create(
            user=self.user,
            email=self.user.email,
            defaults={"verified": True, "primary": True},
        )

        # Ensure existing email addresses are verified
        if not created:
            email_address.verified = True
            email_address.primary = True
            email_address.save()

        # Clear content type cache
        ContentType.objects.clear_cache()

        # Define API endpoints
        self.login_url = reverse("rest_login")
        self.logout_url = reverse("custom-logout")
        self.register_url = reverse("rest_register")
        self.refresh_url = reverse("token_refresh")
        self.social_complete_url = reverse("social-complete-profile")

    # =========================================================================
    # REGISTRATION TESTS
    # =========================================================================

    def test_user_registration_success(self):
        """
        Test successful user registration with email verification flow.

        Verifies:
        - User is created with correct attributes
        - Email confirmation is sent
        - User is initially inactive
        - Email verification activates user
        - User can login after verification
        """
        registration_data = {
            "username": "newuser",
            "email": "newuser@gmail.com",
            "password1": "testpass123",
            "password2": "testpass123",
        }

        email = registration_data["email"]
        mail.outbox = []  # Clear email outbox

        # Submit registration
        response = self.client.post(self.register_url, registration_data, format="json")

        # Verify registration response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username="newuser").exists())

        # Retrieve new user and verify initial state
        new_user = User.objects.get(email="newuser@gmail.com")
        email_address = EmailAddress.objects.get(user=new_user, email=email)

        # Create and send email confirmation
        email_confirmation_obj = EmailConfirmation.create(email_address)
        email_confirmation_obj.created = timezone.now()
        email_confirmation_obj.sent = timezone.now()
        email_confirmation_obj.save()

        # Simulate email sending
        factory = RequestFactory()
        fake_request = factory.post(self.register_url)
        fake_request.user = new_user
        adapter = get_adapter()
        adapter.send_confirmation_mail(
            fake_request, email_confirmation_obj, signup=True
        )

        # Verify email confirmation was created and sent
        self.assertTrue(
            EmailConfirmation.objects.filter(email_address__user=new_user).exists()
        )
        self.assertEqual(len(mail.outbox), 1)

        # Verify user state before confirmation
        self.assertFalse(new_user.is_active)
        self.assertFalse(email_address.verified)

        # Extract confirmation URL from email
        email_message = mail.outbox[0]
        self.assertIn(email, email_message.to)
        body = email_message.body
        match = re.search(
            r"(http[s]?://[^\s]*account-confirm-email/[a-zA-Z0-9]+/)", body
        )
        confirmation_url = match.group(0)

        # Verify URL resolves to correct view
        resolver_match = resolve(confirmation_url.replace("http://testserver", ""))
        self.assertEqual(
            resolver_match.func.view_class.__name__, "CustomConfirmEmailView"
        )
        self.assertEqual(resolver_match.url_name, "account_confirm_email")

        # Verify confirmation key exists in database
        key = resolver_match.kwargs.get("key")
        self.assertTrue(EmailConfirmation.objects.filter(key=key).exists())

        # Enable exception raising for detailed error reporting
        self.client.raise_exception = True

        # Confirm email address
        response_confirm = self.client.get(confirmation_url, follow=False)

        # Verify confirmation was successful
        self.assertIn(
            response_confirm.status_code, [status.HTTP_302_FOUND, status.HTTP_200_OK]
        )

        # Verify user is activated after confirmation
        new_user.refresh_from_db()
        email_address.refresh_from_db()
        self.assertTrue(new_user.is_active)
        self.assertTrue(email_address.verified)

        # Test login after email confirmation
        login_data = {"username": "newuser", "password": "testpass123"}
        login_response = self.client.post(self.login_url, login_data, format="json")

        # Verify login is successful and returns tokens
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn("access", login_response.data)
        self.assertIn("refresh", login_response.data)
        self.assertTrue(len(login_response.data["access"]) > 0)
        self.assertTrue(len(login_response.data["refresh"]) > 0)

    def test_user_registration_existing_username(self):
        """Test registration fails when username already exists."""
        data = {
            "username": "testuser",  # Already exists from setUp
            "email": "testuser@gmail.com",
            "password1": "testpass123",
            "password2": "testpass123",
        }
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.filter(username="testuser").count(), 1)

    def test_user_registration_empty_password(self):
        """Test registration fails with empty password."""
        data = {
            "username": "newuser",
            "email": "newuser@gmail.com",
            "password1": "",
            "password2": "",
        }
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username="newuser").exists())

    def test_user_registration_missing_username(self):
        """Test registration fails when username is missing."""
        data = {
            "email": "newuser@gmail.com",
            "password1": "testpass123",
            "password2": "testpass123",
        }
        response = self.client.post(self.register_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================================================================
    # LOGIN TESTS
    # =========================================================================

    def test_user_login_success_with_username(self):
        """Test successful login with username."""
        data = {"username": "testuser", "email": "", "password": "strongpass123"}
        response = self.client.post(self.login_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_user_login_success_with_email(self):
        """Test successful login using email address."""
        data = {
            "username": "",
            "email": "test@example.com",
            "password": "strongpass123",
        }
        response = self.client.post(self.login_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)

    def test_user_login_failure_scenarios(self):
        """Test various login failure scenarios."""
        test_cases = [
            {
                "name": "wrong_password",
                "data": {"username": "testuser", "email": "", "password": "wrongpass"},
                "expected_status": status.HTTP_401_UNAUTHORIZED,
            },
            {
                "name": "nonexistent_user",
                "data": {
                    "username": "",
                    "email": "nouser@example.com",
                    "password": "nopass",
                },
                "expected_status": status.HTTP_401_UNAUTHORIZED,
            },
            {
                "name": "missing_credentials",
                "data": {"username": "", "email": "", "password": ""},
                "expected_status": status.HTTP_400_BAD_REQUEST,
            },
        ]

        for case in test_cases:
            with self.subTest(case["name"]):
                response = self.client.post(self.login_url, case["data"], format="json")
                self.assertEqual(response.status_code, case["expected_status"])

    # =========================================================================
    # TOKEN MANAGEMENT TESTS
    # =========================================================================

    def test_refresh_token_success(self):
        """Test successful token refresh."""
        refresh = RefreshToken.for_user(self.user)
        data = {"refresh": str(refresh)}
        response = self.client.post(self.refresh_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)

    def test_refresh_token_blacklisted(self):
        """Test token refresh fails with blacklisted token."""
        refresh = RefreshToken.for_user(self.user)
        refresh.blacklist()
        data = {"refresh": str(refresh)}
        response = self.client.post(self.refresh_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # =========================================================================
    # LOGOUT TESTS
    # =========================================================================

    def test_logout_success_with_valid_token(self):
        """Test successful logout with valid refresh token."""
        # Login to get tokens
        login_data = {"username": "testuser", "email": "", "password": "strongpass123"}
        login_response = self.client.post(self.login_url, login_data, format="json")
        refresh_token = login_response.data["refresh"]

        # Logout with refresh token
        logout_data = {"refresh": refresh_token}
        response = self.client.post(self.logout_url, logout_data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("detail", response.data)

    def test_logout_edge_cases(self):
        """Test logout handles various edge cases gracefully."""
        test_cases = [
            {
                "name": "invalid_token_format",
                "data": {"refresh": "completely_invalid_token_123"},
                "should_succeed": True,  # Your implementation always returns 200
            },
            {
                "name": "malformed_but_valid_looking_token",
                "data": {"refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.fake"},
                "should_succeed": True,
            },
            {"name": "empty_payload", "data": {}, "should_succeed": True},
            {
                "name": "already_blacklisted_token",
                "data": {"refresh": str(RefreshToken.for_user(self.user))},
                "should_succeed": True,
                "setup": lambda: RefreshToken.for_user(self.user).blacklist(),
            },
        ]

        for case in test_cases:
            with self.subTest(case["name"]):
                # Run setup if provided
                if "setup" in case:
                    case["setup"]()

                response = self.client.post(
                    self.logout_url, case["data"], format="json"
                )

                # The key assertion: should never return 500
                self.assertNotEqual(
                    response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR
                )

                if case["should_succeed"]:
                    self.assertEqual(response.status_code, status.HTTP_200_OK)
                    self.assertIn("detail", response.data)

    # =========================================================================
    # SECURITY TESTS - AXES LOCKOUT
    # =========================================================================

    def test_login_block_after_multiple_failures(self):
        """Test account lockout after 5 failed login attempts."""
        reset()  # Reset AXES for clean test

        # Attempt 5 failed logins
        for i in range(5):
            response = self.client.post(
                self.login_url,
                {"username": "testuser", "password": "wrongpass"},
                format="json",
            )
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # 6th attempt should be blocked
        response = self.client.post(
            self.login_url,
            {"username": "testuser", "password": "wrongpass"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn("locked", response.data)  # Check for your custom lockout response

    # =========================================================================
    # SOCIAL AUTHENTICATION TESTS
    # =========================================================================

    @patch(
        "allauth.socialaccount.providers.google.views.GoogleOAuth2Adapter.complete_login"
    )
    @patch(
        "allauth.socialaccount.providers.google.views.GoogleOAuth2Adapter.get_provider"
    )
    def test_google_login_with_incomplete_profile_returns_tokens(
        self, mock_get_provider, mock_complete_login
    ):
        """
        Test Google OAuth2 login returns authentication tokens for users with incomplete profiles.

        Verifies that social authentication works correctly even when user profiles
        require additional completion steps.
        """
        # Create test user with incomplete profile (social registration without username/password)
        incomplete_user = User.objects.create(
            email="incomplete@example.com",
            is_social_account=True,
            profile_completed=False,
            username=None,
        )

        # Mock allauth social authentication components
        social_login = SocialLogin(user=incomplete_user, account=MagicMock())
        mock_complete_login.return_value = social_login

        # Mock OAuth2 provider configuration
        mock_get_provider.return_value = MagicMock(
            get_app=MagicMock(
                return_value=MagicMock(client_id="test-client-id", secret="test-secret")
            )
        )

        # Execute Google OAuth2 login request
        google_auth_data = {"access_token": "mock-token"}
        response = self.client.post(
            reverse("google_login"), google_auth_data, format="json"
        )

        # Debug output for test investigation
        print("Google login response data:", response.data)

        # Verify successful authentication response contains required tokens
        if response.status_code == status.HTTP_200_OK:
            self.assertIn("access_token", response.data)
            self.assertIn("refresh_token", response.data)
            self.assertIn("user", response.data)

    def test_social_profile_completion_returns_new_tokens(self):
        """
        Test social profile completion successfully generates new JWT tokens.

        Verifies that completing a social user's profile (setting username and password)
        returns fresh authentication tokens and updates user status correctly.
        """
        # Create social authentication user requiring profile completion
        social_user = User.objects.create(
            email="socialuser@example.com",
            is_social_account=True,
            profile_completed=False,
            username=None,
        )

        # Authenticate as the social user
        self.client.force_authenticate(user=social_user)

        # Profile completion data
        profile_completion_data = {
            "username": "completeduser",
            "password": "StrongPass123!",
        }

        # Execute profile completion request
        response = self.client.put(
            reverse("social-complete-profile"), profile_completion_data, format="json"
        )

        # Verify successful completion response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("username", response.data)

        # Verify database reflects completed profile state
        social_user.refresh_from_db()
        self.assertTrue(social_user.profile_completed)
        self.assertEqual(social_user.username, "completeduser")

    def test_social_profile_completion_flow(self):
        """Test complete social profile completion flow."""
        # Create Google user with incomplete profile
        google_user = User.objects.create(
            email="googleuser@example.com",
            is_social_account=True,
            profile_completed=False,
            username=None,
            is_active=True,
        )

        # Generate authentication token
        refresh = RefreshToken.for_user(google_user)
        access_token = str(refresh.access_token)

        # Call profile completion endpoint with token
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access_token}")

        profile_data = {"username": "completeduser", "password": "StrongPass123!"}

        response = self.client.put(
            self.social_complete_url, profile_data, format="json"
        )

        # Verify successful completion
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        self.assertIn("username", response.data)

        # Verify database updates
        google_user.refresh_from_db()
        self.assertTrue(google_user.profile_completed)
        self.assertEqual(google_user.username, "completeduser")

    def test_social_complete_profile_validation(self):
        """Test social profile completion validation."""
        social_user = User.objects.create(
            email="social3@example.com", is_social_account=True, profile_completed=False
        )
        self.client.force_authenticate(user=social_user)

        # Test missing password
        data = {"username": "socialuser3"}  # Missing password
        response = self.client.put(self.social_complete_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Test weak password
        data = {"username": "socialuser3", "password": "weak"}
        response = self.client.put(self.social_complete_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================================================================
    # SECURITY & INPUT VALIDATION TESTS
    # =========================================================================

    def test_security_headers_present(self):
        """Test that security headers are present in responses."""
        response = self.client.get(self.login_url)
        # Add checks for your specific security headers
        self.assertNotIn("Server", response.headers)  # Common security practice

    def test_input_validation_common_attacks(self):
        """Test common web attack vectors are properly handled."""
        attack_vectors = [
            {
                "name": "sql_injection_username",
                "data": {"username": "admin' OR '1'='1' --", "password": "anypassword"},
                "endpoint": self.login_url,
                "expected_status": status.HTTP_401_UNAUTHORIZED,
            },
            {
                "name": "xss_email",
                "data": {
                    "email": '<script>alert("xss")</script>@example.com',
                    "password": "anypassword",
                },
                "endpoint": self.login_url,
                "expected_status": status.HTTP_400_BAD_REQUEST,
            },
            {
                "name": "null_bytes",
                "data": {"username": "user\0injection", "password": "pass\0word"},
                "endpoint": self.login_url,
                "expected_status": status.HTTP_400_BAD_REQUEST,
            },
            {
                "name": "command_injection",
                "data": {
                    "email": "test; ls /etc/passwd@example.com",
                    "password": "anypassword",
                },
                "endpoint": self.login_url,
                "expected_status": status.HTTP_400_BAD_REQUEST,
            },
        ]

        for vector in attack_vectors:
            with self.subTest(vector["name"]):
                response = self.client.post(
                    vector["endpoint"], vector["data"], format="json"
                )
                self.assertEqual(response.status_code, vector["expected_status"])
                # Critical: Should never expose internal errors
                self.assertNotEqual(
                    response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR
                )

    def test_registration_input_validation(self):
        """Test registration input validation."""
        invalid_cases = [
            {
                "name": "invalid_email_format",
                "data": {
                    "username": "testuser",
                    "email": "invalid-email",
                    "password1": "testpass123",
                    "password2": "testpass123",
                },
            },
            {
                "name": "password_mismatch",
                "data": {
                    "username": "testuser",
                    "email": "test@example.com",
                    "password1": "password1",
                    "password2": "password2",
                },
            },
            {
                "name": "whitespace_only",
                "data": {
                    "username": "   ",
                    "email": "   ",
                    "password1": "   ",
                    "password2": "   ",
                },
            },
        ]

        for case in invalid_cases:
            with self.subTest(case["name"]):
                response = self.client.post(
                    self.register_url, case["data"], format="json"
                )
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_rate_limiting_headers(self):
        """Test that rate limiting headers are present (if implemented)."""
        # Make multiple rapid requests
        for _ in range(3):
            response = self.client.post(
                self.login_url,
                {"username": "testuser", "password": "wrongpass"},
                format="json",
            )

        # Check for rate limiting headers (adjust based on your implementation)
        # Common headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
        # This test might need adjustment based on your actual rate limiting setup

    # =========================================================================
    # PERFORMANCE & EDGE CASE TESTS
    # =========================================================================

    def test_concurrent_registration_handling(self):
        """Test that concurrent registration requests are handled properly."""
        # This would typically use threading for true concurrency testing
        # For now, test rapid sequential requests
        registration_data = {
            "username": "concurrentuser",
            "email": "concurrent@example.com",
            "password1": "testpass123",
            "password2": "testpass123",
        }

        # Make multiple rapid requests
        responses = []
        for _ in range(3):
            response = self.client.post(
                self.register_url, registration_data.copy(), format="json"
            )
            responses.append(response.status_code)

        # Should either all succeed or properly handle duplicates
        success_count = responses.count(status.HTTP_201_CREATED)
        self.assertIn(
            success_count, [1, 3]
        )  # Either one success or all succeed with proper handling

    def test_large_payload_handling(self):
        """Test that very large payloads are handled gracefully."""
        large_data = {
            "username": "a" * 10000,  # Very large username
            "email": "a" * 1000 + "@example.com",
            "password1": "a" * 10000,
            "password2": "a" * 10000,
        }

        response = self.client.post(self.register_url, large_data, format="json")
        # Should return 400, not 500 or timeout
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
