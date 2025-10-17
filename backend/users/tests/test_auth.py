from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from users.models import CustomUser as User
from rest_framework_simplejwt.tokens import RefreshToken

class UserAuthTests(APITestCase):
    """
    Test suite for user registration and login.
    Includes both happy path and sad path scenarios.
    """

    # ------------------------------
    # REGISTRATION
    # ------------------------------

    def test_user_registration_success(self):
        """Happy path: user registers successfully"""
        url = reverse('registration')
        data = {'username': 'testuser', 'password': 'testpass123'}
        response = self.client.post(url, data, format='json')

        # Expect HTTP 201 CREATED
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Verify the user actually exists in the database
        self.assertTrue(User.objects.filter(username='testuser').exists())

    def test_user_registration_existing_username(self):
        """Sad path: registration fails if the username already exists"""
        User.objects.create_user(username='testuser', password='12345')
        url = reverse('registration')
        data = {'username': 'testuser', 'password': 'testpass123'}
        response = self.client.post(url, data, format='json')

        # Expect HTTP 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        # Verify the user count with the same username did not increase
        self.assertEqual(User.objects.filter(username='testuser').count(), 1)

    def test_user_registration_empty_password(self):
        """Sad path: registration fails if the password is empty"""
        url = reverse('registration')
        data = {'username': 'newuser', 'password': ''}
        response = self.client.post(url, data, format='json')

        # Expect HTTP 400 BAD REQUEST
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username='newuser').exists())

    def test_user_registration_missing_username(self):
        """Sad path: registration fails if username is missing"""
        url = reverse('registration')
        data = {'password': 'pass123'}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------
    # LOGIN
    # ------------------------------

    def test_user_login_success(self):
        """Happy path: login for an existing user"""
        User.objects.create_user(username='testuser', password='testpass123')
        url = reverse('token_obtain_pair')
        data = {'username': 'testuser', 'password': 'testpass123'}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Expect JWT tokens in the response
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_login_wrong_password(self):
        """Sad path: login fails with incorrect password"""
        User.objects.create_user(username='testuser', password='testpass123')
        url = reverse('token_obtain_pair')
        data = {'username': 'testuser', 'password': 'wrongpass'}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_login_nonexistent_user(self):
        """Sad path: login fails for a non-existent user"""
        url = reverse('token_obtain_pair')
        data = {'username': 'nouser', 'password': 'nopass'}
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

class UserAuthExtraTests(APITestCase):
    """
    Extra test scenarios for user login via email/username,
    refresh token behavior, and logout.
    """

    def setUp(self):
        """Create a sample user for tests"""
        self.user = User.objects.create_user(
            username='testuser', email='test@example.com', password='strongpass123'
        )
        self.login_url = reverse('token_obtain_pair')
        self.logout_url = reverse('logout')

    # ------------------------------
    # LOGIN VIA EMAIL AND USERNAME
    # ------------------------------

    def test_login_with_email(self):
        """Login should succeed using email"""
        data = {'email': 'test@example.com', 'password': 'strongpass123'}
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_with_username(self):
        """Login should succeed using username"""
        data = {'username': 'testuser', 'password': 'strongpass123'}
        response = self.client.post(self.login_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    # ------------------------------
    # REFRESH TOKEN
    # ------------------------------

    def test_refresh_token_success(self):
        """Refresh token should issue new access token"""
        refresh = RefreshToken.for_user(self.user)
        refresh_url = reverse('token_refresh')
        data = {'refresh': str(refresh)}

        response = self.client.post(refresh_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_refresh_token_blacklisted(self):
        """Using a blacklisted refresh token should fail"""
        refresh = RefreshToken.for_user(self.user)
        refresh.blacklist()  # blacklist it
        refresh_url = reverse('token_refresh')
        data = {'refresh': str(refresh)}

        response = self.client.post(refresh_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ------------------------------
    # LOGOUT
    # ------------------------------

    def test_logout_with_valid_refresh(self):
        """Logout should blacklist refresh token"""
        refresh = RefreshToken.for_user(self.user)
        data = {'refresh': str(refresh)}
        response = self.client.post(self.logout_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        # After logout, token should be blacklisted
        response_refresh = self.client.post(reverse('token_refresh'), {'refresh': str(refresh)}, format='json')
        self.assertEqual(response_refresh.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_with_invalid_refresh(self):
        """Logout with invalid token should fail"""
        data = {'refresh': 'invalidtoken123'}
        response = self.client.post(self.logout_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)