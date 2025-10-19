from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from users.models import CustomUser as User
from rest_framework_simplejwt.tokens import RefreshToken

class UserAuthTests(APITestCase):
    """
    Test suite for user registration, login (username/email), refresh token, and logout.
    """

    def setUp(self):
        """Create a test user and setup URLs"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='strongpass123'
        )
        self.login_url = reverse('rest_login')
        self.logout_url = reverse('rest_logout')
        self.register_url = reverse('rest_register')
        self.refresh_url = reverse('token_refresh')

    # ------------------------------
    # REGISTRATION
    # ------------------------------

    def test_user_registration_success(self):
        data = {
            'username': 'newuser',
            'email': 'newuser@gmail.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_user_registration_existing_username(self):
        data = {
            'username': 'testuser',
            'email': 'testuser@gmail.com',
            'password1': 'testpass123',
            'password2': 'testpass123'
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(User.objects.filter(username='testuser').count(), 1)

    def test_user_registration_empty_password(self):
        data = {'username': 'newuser', 'email': 'newuser@gmail.com', 'password1': '', 'password2': ''}
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(User.objects.filter(username='newuser').exists())

    def test_user_registration_missing_username(self):
        data = {'email': 'newuser@gmail.com', 'password1': 'testpass123', 'password2': 'testpass123'}
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------
    # LOGIN
    # ------------------------------

    def test_user_login_success(self):
        data = {'username': 'testuser', 'email': '', 'password': 'strongpass123'}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_user_login_wrong_password(self):
        data = {'username': 'testuser', 'email': '', 'password': 'wrongpass'}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_user_login_nonexistent_user(self):
        data = {'username': '', 'email': 'nouser@example.com', 'password': 'nopass'}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_with_email(self):
        data = {'username': '', 'email': 'test@example.com', 'password': 'strongpass123'}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_login_with_username(self):
        data = {'username': 'testuser', 'email': '', 'password': 'strongpass123'}
        response = self.client.post(self.login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    # ------------------------------
    # REFRESH TOKEN
    # ------------------------------

    def test_refresh_token_success(self):
        refresh = RefreshToken.for_user(self.user)
        data = {'refresh': str(refresh)}
        response = self.client.post(self.refresh_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_refresh_token_blacklisted(self):
        refresh = RefreshToken.for_user(self.user)
        refresh.blacklist()
        data = {'refresh': str(refresh)}
        response = self.client.post(self.refresh_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    # ------------------------------
    # LOGOUT
    # ------------------------------

    def test_logout_with_valid_refresh(self):
        data = {'username': 'testuser', 'email': '', 'password': 'strongpass123'}
        login_response = self.client.post(self.login_url, data, format='json')
        refresh_token = login_response.data['refresh']
        data = {'refresh': refresh_token}

        data_token = login_response.data['refresh']
        response = self.client.post(self.logout_url, data_token, format='json')
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

        # After logout, token should be blacklisted
        response_refresh = self.client.post(self.refresh_url, {'refresh': str(refresh_token)}, format='json')
        self.assertEqual(response_refresh.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_with_invalid_refresh(self):
        data = {'username': 'testuser', 'email': '', 'password': 'strongpass123'}
        login_response = self.client.post(self.login_url, data, format='json')
        refresh_token = login_response.data['refresh']
        
        # Fix: Use the correct variable and pass as JSON
        logout_data = {'refresh': "invaidrefresh"}
        response = self.client.post(self.logout_url, logout_data, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
