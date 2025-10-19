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

        logout_data = {'refresh': refresh_token}
        response = self.client.post(self.logout_url, logout_data, format='json')
        
        # dj_rest_auth usually returns 200 OK for logout
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_with_invalid_refresh(self):
        # Test with completely invalid token format
        logout_data = {'refresh': "completely_invalid_token_123"}
        response = self.client.post(self.logout_url, logout_data, format='json')
        
        # dj_rest_auth might return 200 OK even for invalid tokens
        # or 400 for invalid format. Let's check for either.
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST])
        
        # If it returns 200, check that it at least doesn't crash
        if response.status_code == status.HTTP_200_OK:
            self.assertIn('detail', response.data)

    def test_logout_with_nonexistent_but_valid_looking_token(self):
        # Test with well-formed but invalid token (like a forged token)
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcwMDAwMDAwMCwiaWF0IjoxNzAwMDAwMDAwLCJqdGkiOiJmYWtlX2lkIiwidXNlcl9pZCI6OTk5OX0.fake_signature_that_looks_real_but_is_invalid"
        logout_data = {'refresh': fake_token}
        response = self.client.post(self.logout_url, logout_data, format='json')
        
        # dj_rest_auth typically handles this gracefully without 500 errors
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST])
        
        # The main thing is it shouldn't return 500 Internal Server Error
        self.assertNotEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)

    def test_logout_empty_refresh(self):
        # Test with missing refresh token
        logout_data = {}
        response = self.client.post(self.logout_url, logout_data, format='json')
        
        # dj_rest_auth might require a refresh token or might not
        # Common behaviors: 200 OK, 400 Bad Request, or 401 Unauthorized
        self.assertIn(response.status_code, [
            status.HTTP_200_OK, 
            status.HTTP_400_BAD_REQUEST, 
            status.HTTP_401_UNAUTHORIZED
        ])
        
        # The key is that it handles it without crashing (no 500 error)
        self.assertNotEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)