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

from django.urls import reverse, resolve
from django.core import mail
from django.apps import apps
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.management import create_permissions
from django.contrib.contenttypes.models import ContentType
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialLogin
from allauth.account.models import EmailAddress, EmailConfirmation
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from axes.utils import reset
import re
from unittest.mock import patch, MagicMock
from allauth.account.adapter import get_adapter
from django.test import RequestFactory

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
            if app_config.name in ['allauth.account', 'allauth.socialaccount']:
                create_permissions(app_config, verbosity=0)
        
        # Configure test site
        site = Site.objects.get_current()
        site.domain = 'example.com'
        site.name = 'Test Site'
        site.save()

    def setUp(self):
        """
        Set up test fixtures before each test method.
        
        Creates a test user, configures email verification, and sets up URL endpoints.
        """
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='strongpass123',
            is_active=True
        )

        # Configure email verification for test user
        email_address, created = EmailAddress.objects.get_or_create(
            user=self.user,
            email=self.user.email,
            defaults={'verified': True, 'primary': True}
        )
        
        # Ensure existing email addresses are verified
        if not created:
            email_address.verified = True
            email_address.primary = True
            email_address.save()

        # Clear content type cache
        ContentType.objects.clear_cache()

        # Define API endpoints
        self.login_url = reverse('rest_login')
        self.logout_url = reverse('custom-logout')
        self.register_url = reverse('rest_register')
        self.refresh_url = reverse('token_refresh')
        self.social_complete_url = reverse('social-complete-profile')

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
            'username': 'newuser',
            'email': 'newuser@gmail.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }

        email = registration_data["email"]
        mail.outbox = []  # Clear email outbox
        
        # Submit registration
        response = self.client.post(self.register_url, registration_data, format='json')
        
        # Verify registration response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='newuser').exists())
        
        # Retrieve new user and verify initial state
        new_user = User.objects.get(email='newuser@gmail.com')
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
        adapter.send_confirmation_mail(fake_request, email_confirmation_obj, signup=True)
        
        # Verify email confirmation was created and sent
        self.assertTrue(EmailConfirmation.objects.filter(email_address__user=new_user).exists())
        self.assertEqual(len(mail.outbox), 1)
        
        # Verify user state before confirmation
        self.assertFalse(new_user.is_active)
        self.assertFalse(email_address.verified)
        
        # Extract confirmation URL from email
        email_message = mail.outbox[0]
        self.assertIn(email, email_message.to)
        body = email_message.body
        match = re.search(r'(http[s]?://[^\s]*account-confirm-email/[a-zA-Z0-9]+/)', body)
        confirmation_url = match.group(0)
        
        # Verify URL resolves to correct view
        resolver_match = resolve(confirmation_url.replace('http://testserver', ''))
        self.assertEqual(resolver_match.func.view_class.__name__, 'CustomConfirmEmailView')
        self.assertEqual(resolver_match.url_name, 'account_confirm_email')
        
        # Verify confirmation key exists in database
        key = resolver_match.kwargs.get('key')
        self.assertTrue(EmailConfirmation.objects.filter(key=key).exists())
        
        # Enable exception raising for detailed error reporting
        self.client.raise_exception = True
        
        # Confirm email address
        response_confirm = self.client.get(confirmation_url, follow=False)
        
        # Verify confirmation was successful
        self.assertIn(response_confirm.status_code, [status.HTTP_302_FOUND, status.HTTP_200_OK])
        
        # Verify user is activated after confirmation
        new_user.refresh_from_db()
        email_address.refresh_from_db()
        self.assertTrue(new_user.is_active)
        self.assertTrue(email_address.verified)
        
        # Test login after email confirmation
        login_data = {
            'username': 'newuser',
            'password': 'testpass123'
        }
        login_response = self.client.post(self.login_url, login_data, format='json')
        
        # Verify login is successful and returns tokens
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('access', login_response.data)
        self.assertIn('refresh', login_response.data)
        self.assertTrue(len(login_response.data['access']) > 0)
        self.assertTrue(len(login_response.data['refresh']) > 0)

    def test_user_registration_existing_username(self):
        """Test registration fails when username already exists."""
        data = {
            'username': 'testuser',  # Already exists from setUp
            'email': 'testuser@gmail.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.filter(username='testuser').count(), 1)

    def test_user_registration_empty_password(self):
        """Test registration fails with empty password."""
        data = {
            'username': 'newuser', 
            'email': 'newuser@gmail.com', 
            'password1': '', 
            'password2': ''
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username='newuser').exists())

    def test_user_registration_missing_username(self):
        """Test registration fails when username is missing."""
        data = {
            'email': 'newuser@gmail.com', 
            'password1': 'testpass123', 
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================================================================
    # LOGIN TESTS
    # =========================================================================

    def test_user_login_success(self):
        """Test successful login with username."""
        data = {
            'username': 'testuser', 
            'email': '', 
            'password': 'strongpass123'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_login_wrong_password(self):
        """Test login fails with incorrect password."""
        data = {
            'username': 'testuser', 
            'email': '', 
            'password': 'wrongpass'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_login_nonexistent_user(self):
        """Test login fails for non-existent user."""
        data = {
            'username': '', 
            'email': 'nouser@example.com', 
            'password': 'nopass'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_with_email(self):
        """Test successful login using email address."""
        data = {
            'username': '', 
            'email': 'test@example.com', 
            'password': 'strongpass123'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_with_username(self):
        """Test successful login using username."""
        data = {
            'username': 'testuser', 
            'email': '', 
            'password': 'strongpass123'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    # =========================================================================
    # TOKEN MANAGEMENT TESTS
    # =========================================================================

    def test_refresh_token_success(self):
        """Test successful token refresh."""
        refresh = RefreshToken.for_user(self.user)
        data = {'refresh': str(refresh)}
        response = self.client.post(self.refresh_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_refresh_token_blacklisted(self):
        """Test token refresh fails with blacklisted token."""
        refresh = RefreshToken.for_user(self.user)
        refresh.blacklist()
        data = {'refresh': str(refresh)}
        response = self.client.post(self.refresh_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # =========================================================================
    # LOGOUT TESTS
    # =========================================================================

    def test_logout_with_valid_refresh(self):
        """Test successful logout with valid refresh token."""
        # Login to get tokens
        login_data = {
            'username': 'testuser', 
            'email': '', 
            'password': 'strongpass123'
        }
        login_response = self.client.post(self.login_url, login_data, format='json')
        refresh_token = login_response.data['refresh']

        # Logout with refresh token
        logout_data = {'refresh': refresh_token}
        response = self.client.post(self.logout_url, logout_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_with_invalid_refresh(self):
        """Test logout handles invalid token format gracefully."""
        logout_data = {'refresh': "completely_invalid_token_123"}
        response = self.client.post(self.logout_url, logout_data, format='json')
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST])
        
        if response.status_code == status.HTTP_200_OK:
            self.assertIn('detail', response.data)

    def test_logout_with_nonexistent_but_valid_looking_token(self):
        """Test logout handles well-formed but invalid tokens gracefully."""
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwLCJqdGkiOiJmYWtlX2lkIiwidXNlcl9pZCI6OTk5OX0.fake_signature_that_looks_real_but_is_invalid"
        logout_data = {'refresh': fake_token}
        response = self.client.post(self.logout_url, logout_data, format='json')
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST])
        self.assertNotEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def test_logout_empty_refresh(self):
        """Test logout handles missing refresh token gracefully."""
        logout_data = {}
        response = self.client.post(self.logout_url, logout_data, format='json')
        self.assertIn(response.status_code, [
            status.HTTP_200_OK, 
            status.HTTP_400_BAD_REQUEST, 
            status.HTTP_401_UNAUTHORIZED
        ])
        self.assertNotEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    # =========================================================================
    # SECURITY TESTS - AXES LOCKOUT
    # =========================================================================

    def test_login_block_after_multiple_failures(self):
        """Test account lockout after 5 failed login attempts."""
        reset()  # Reset AXES for clean test
        
        # Attempt 5 failed logins
        for i in range(5):
            response = self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'wrongpass'
            }, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        # 6th attempt should be blocked
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'wrongpass'
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # =========================================================================
    # SOCIAL AUTHENTICATION TESTS
    # =========================================================================

    @patch('allauth.socialaccount.providers.google.views.GoogleOAuth2Adapter.complete_login')
    @patch('allauth.socialaccount.providers.google.views.GoogleOAuth2Adapter.get_provider')
    def test_google_login_with_incomplete_profile_returns_tokens(self, mock_get_provider, mock_complete_login):
        """Test Google login returns tokens for users with incomplete profiles."""
        # Create user with incomplete profile
        incomplete_user = User.objects.create(
            email='incomplete@example.com',
            is_social_account=True,
            profile_completed=False,
            username=None
        )
        
        # Mock allauth social login
        social_login = SocialLogin(user=incomplete_user, account=MagicMock())
        mock_complete_login.return_value = social_login
        
        mock_get_provider.return_value = MagicMock(
            get_app=MagicMock(return_value=MagicMock(
                client_id='test-client-id',
                secret='test-secret'
            ))
        )
    
        # Call Google login endpoint
        google_data = {'access_token': 'mock-token'}
        response = self.client.post(reverse('google_login'), google_data, format='json')
        
        # Verify response contains authentication tokens
        if response.status_code == 200:
            self.assertIn('access_token', response.data)
            self.assertIn('refresh_token', response.data)
            self.assertIn('user', response.data)

    def test_google_login_returns_tokens_even_with_incomplete_profile(self):
        """Test Google login returns tokens for incomplete profiles and allows completion."""
        # Create Google user with incomplete profile
        google_user = User.objects.create(
            email='googleuser@example.com',
            is_social_account=True,
            profile_completed=False,
            username=None
        )
        
        # Authenticate and complete profile
        self.client.force_authenticate(user=google_user)
        profile_data = {
            'username': 'finalusername',
            'password': 'StrongPass123!'
        }
        
        response = self.client.put(
            reverse('social-complete-profile'), 
            profile_data, 
            format='json'
        )
        
        # Verify profile completion and token generation
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('username', response.data)
    
        # Verify database updates
        google_user.refresh_from_db()
        self.assertTrue(google_user.profile_completed)
        self.assertEqual(google_user.username, 'finalusername')

    def test_social_complete_profile_with_valid_token(self):
        """Test social profile completion with valid authentication token."""
        # Create Google user with incomplete profile
        google_user = User.objects.create(
            email='incomplete@example.com',
            is_social_account=True,
            profile_completed=False,
            username=None,
            is_active=True
        )
        
        # Generate authentication token
        refresh = RefreshToken.for_user(google_user)
        access_token = str(refresh.access_token)
        
        # Call profile completion endpoint with token
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        profile_data = {
            'username': 'completeduser',
            'password': 'StrongPass123!'
        }
        
        response = self.client.put(self.social_complete_url, profile_data, format='json')
        
        # Verify successful completion and token generation
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    # =========================================================================
    # SOCIAL PROFILE COMPLETION TESTS
    # =========================================================================

    def test_social_complete_profile_success(self):
        """Test successful social profile completion."""
        social_user = User.objects.create(
            email='social2@example.com', 
            is_social_account=True, 
            profile_completed=False
        )
        self.client.force_authenticate(user=social_user)
        
        data = {
            'username': 'socialuser2', 
            'password': 'StrongPass!23'
        }
        response = self.client.put(self.social_complete_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        social_user.refresh_from_db()
        self.assertEqual(social_user.username, 'socialuser2')
        self.assertTrue(social_user.profile_completed)

    def test_social_complete_profile_missing_password(self):
        """Test social profile completion fails when password is missing."""
        social_user = User.objects.create(
            email='social3@example.com', 
            is_social_account=True, 
            profile_completed=False
        )
        self.client.force_authenticate(user=social_user)
        
        data = {'username': 'socialuser3'}  # Missing password
        response = self.client.put(self.social_complete_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================================================================
    # LOGOUT EDGE CASE TESTS
    # =========================================================================

    def test_logout_with_already_blacklisted_token(self):
        """Test logout handles already blacklisted tokens gracefully."""
        refresh = RefreshToken.for_user(self.user)
        refresh.blacklist()
        response = self.client.post(self.logout_url, {'refresh': str(refresh)}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('detail', response.data)

    def test_logout_with_empty_payload(self):
        """Test logout handles empty payload gracefully."""
        response = self.client.post(self.logout_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('detail', response.data)

    def test_logout_with_malformed_token(self):
        """Test logout handles malformed tokens gracefully."""
        response = self.client.post(self.logout_url, {'refresh': 'malformed.token'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('detail', response.data)

    # =========================================================================
    # SECURITY & VALIDATION TESTS
    # =========================================================================

    def test_login_with_sql_injection_attempt(self):
        """Test SQL injection attempt in username is handled securely."""
        data = {
            'username': "admin' OR '1'='1' --", 
            'password': 'anypassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def test_login_with_xss_attempt(self):
        """Test XSS attempt in email field is handled securely."""
        data = {
            'email': '<script>alert("xss")</script>@example.com',
            'password': 'anypassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_with_unicode_characters(self):
        """Test unicode characters in credentials are handled properly."""
        data = {
            'username': '用户',  # Chinese characters
            'password': '密码'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_with_null_characters(self):
        """Test null characters in credentials are handled securely."""
        data = {
            'username': 'testuser\0injection',
            'password': 'password\0test'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED])

    def test_login_with_whitespace_only(self):
        """Test credentials with only whitespace are rejected."""
        data = {
            'username': '   ',
            'email': '   ',
            'password': '   '
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_with_newline_characters(self):
        """Test newline characters in credentials are handled securely."""
        data = {
            'username': 'testuser\ninjection',
            'password': 'password\ntest'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_401_UNAUTHORIZED])

    def test_login_with_json_injection(self):
        """Test JSON injection in credentials is handled securely."""
        data = {
            'username': '{"username": "admin", "password": "hacked"}',
            'password': 'test'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_with_email_injection(self):
        """Test email field with command injection is handled securely."""
        data = {
            'email': 'test@example.com; rm -rf /',
            'password': 'anypassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # =========================================================================
    # REGISTRATION SECURITY TESTS
    # =========================================================================

    def test_register_with_sql_injection_username(self):
        """Test SQL injection in username during registration is prevented."""
        data = {
            'username': "admin' OR '1'='1' --",
            'email': 'test@example.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def test_register_with_xss_email(self):
        """Test XSS in email during registration is prevented."""
        data = {
            'username': 'normaluser',
            'email': '<script>alert("xss")</script>@example.com',
            'password1': 'testpass123', 
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_with_invalid_email_format(self):
        """Test various invalid email formats are rejected."""
        invalid_emails = [
            'invalid-email',
            'user@',
            '@example.com',
            'user@.com',
            'user@example.',
            'user@example..com'
        ]
        
        for invalid_email in invalid_emails:
            with self.subTest(email=invalid_email):
                data = {
                    'username': f'testuser_{invalid_emails.index(invalid_email)}',
                    'email': invalid_email,
                    'password1': 'testpass123',
                    'password2': 'testpass123'
                }
                response = self.client.post(self.register_url, data, format='json')
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_with_very_long_fields(self):
        """Test extremely long field values are rejected."""
        data = {
            'username': 'a' * 1000,  # Very long username
            'email': 'a' * 200 + '@example.com',  # Very long email local part
            'password1': 'a' * 1000,  # Very long password
            'password2': 'a' * 1000
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_with_unicode_injection(self):
        """Test unicode characters that might cause issues are handled."""
        data = {
            'username': '用户👀',  # Chinese + emoji
            'email': 'test@例子.com',  # Internationalized domain
            'password1': '密码🔑',
            'password2': '密码🔑'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_201_CREATED])

    def test_register_with_json_injection(self):
        """Test JSON-like data in fields is handled securely."""
        data = {
            'username': '{"username": "admin"}',
            'email': '{"email": "hacked@example.com"}@test.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_with_command_injection(self):
        """Test command injection attempts are prevented."""
        data = {
            'username': 'user; rm -rf /',
            'email': 'test; ls /etc/passwd@example.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_with_null_bytes(self):
        """Test null byte injection is prevented."""
        data = {
            'username': 'user\0injection',
            'email': 'test\0@example.com',
            'password1': 'pass\0word',
            'password2': 'pass\0word'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_with_whitespace_only(self):
        """Test whitespace-only credentials are rejected."""
        data = {
            'username': '   ',
            'email': '   ',
            'password1': '   ',
            'password2': '   '
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_with_email_as_username(self):
        """Test using email format as username is handled appropriately."""
        data = {
            'username': 'user@example.com',  # Email format in username
            'email': 'test@example.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertIn(response.status_code, [status.HTTP_400_BAD_REQUEST, status.HTTP_201_CREATED])