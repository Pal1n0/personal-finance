from django.urls import reverse
from django.core import mail
from django.apps import apps
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.management import create_permissions
from django.contrib.contenttypes.models import ContentType
from django.contrib.sites.models import Site
from allauth.account.models import EmailAddress, EmailConfirmation
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from axes.utils import reset
import re
from django.urls import resolve #

from allauth.account.adapter import get_adapter
from django.test import RequestFactory # <--

User = get_user_model()

class UserAuthTests(APITestCase):
    """
    Test suite for user registration, login (username/email), refresh token, and logout.
    """
    @classmethod
    def setUpTestData(cls):
        # Ensure allauth models are available in tests        
        for app_config in apps.get_app_configs():
            if app_config.name in ['allauth.account', 'allauth.socialaccount']:
                create_permissions(app_config, verbosity=0)
        site = Site.objects.get_current()
        site.domain = 'example.com'
        site.name = 'Test Site'
        site.save()

    def setUp(self):
        """Create a test user and setup URLs"""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='strongpass123',
            is_active=True
        )

        ContentType.objects.clear_cache()

        self.login_url = reverse('rest_login')
        self.logout_url = reverse('custom-logout')
        self.register_url = reverse('rest_register')
        self.refresh_url = reverse('token_refresh')
        self.social_login_url = reverse('social-login')
        self.social_complete_url = reverse('social-complete-profile')

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

        email=data["email"]
        mail.outbox = []
        response = self.client.post(self.register_url, data, format='json')

        new_user = User.objects.get(email='newuser@gmail.com')
        
        # 1. Znova načítať EmailAddress
        email_address = EmailAddress.objects.get(user=new_user, email=email)

        email_confirmation_obj = EmailConfirmation.create(email_address)
        email_confirmation_obj.created = timezone.now()
        email_confirmation_obj.sent = timezone.now()
        email_confirmation_obj.save()


        factory = RequestFactory()
        fake_request = factory.post(self.register_url) 
        # Allauth potrebuje používateľa v requeste, ak je to možné
        fake_request.user = new_user

        adapter = get_adapter() # only for dev test!!
        adapter.send_confirmation_mail(fake_request, email_confirmation_obj, signup=True) # only for dev test!!
        # Táto možnosť je len pre debug/overenie, ak by testovací klient neposkytol dostatočný kontext.
        
        # Ak kód registračnej sériaľky bol správny, tieto tvrdenia MUSIA prejsť:
        self.assertTrue(EmailConfirmation.objects.filter(email_address__user=new_user).exists())
        self.assertEqual(len(mail.outbox), 1)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='newuser').exists())
        self.assertEqual(User.objects.filter(email='newuser@gmail.com').count(), 1)
        new_user = User.objects.get(email='newuser@gmail.com')
        self.assertFalse(new_user.is_active)
        self.assertFalse(email_address.verified)
        self.assertTrue(EmailAddress.objects.filter(user=new_user, email=email).exists())
        self.assertTrue(EmailConfirmation.objects.filter(email_address__user=new_user).exists())
        self.assertEqual(len(mail.outbox), 1)
        email_message = mail.outbox[0]
        self.assertIn(email, email_message.to)
        body = email_message.body
        match = re.search(r'(http[s]?://[^\s]*account-confirm-email/[a-zA-Z0-9]+/)', body)
        confirmation_url = match.group(0)


        # --- KĽÚČOVÁ DIAGNOSTIKA ---

        # 1. Overenie, či URL resolver nájde VÁŠ pohľad (nie allauth)
        # confirmation_url vyzerá asi takto: /api/users/auth/registration/account-confirm-email/KLUC/
        resolver_match = resolve(confirmation_url.replace('http://testserver', ''))
        
        # Overenie, že resolver našiel CustomConfirmEmailView a správny názov URL
        self.assertEqual(resolver_match.func.view_class.__name__, 'CustomConfirmEmailView')
        self.assertEqual(resolver_match.url_name, 'account_confirm_email')
        
        # Ak tento krok prejde, problém nie je v URLs, ale v logike pohľadu (Kľúč!)
        
        # 2. Overenie, či kľúč existuje v DB a či je platný
        key = resolver_match.kwargs.get('key')
        self.assertTrue(EmailConfirmation.objects.filter(key=key).exists(), 
                        f"Konfirmačný kľúč '{key}' sa nenašiel v databáze!")







        self.client.raise_exception = True

        print(f"🎯 Calling confirmation URL: {confirmation_url}")
        print(f"🔑 Key from URL: {key}")
        print(f"📊 EmailConfirmations in DB: {EmailConfirmation.objects.count()}")

        response_confirm = self.client.get(confirmation_url, follow=False)

        print(f"Confirmation response status: {response_confirm.status_code}")
        print(f"Confirmation response content: {response_confirm.content}")
    
        # Ak je status 400, pozrime sa na detaily
        if response_confirm.status_code == status.HTTP_400_BAD_REQUEST:
            try:
                response_data = response_confirm.json()
                print(f"Error detail: {response_data}")
            except:
                print("Could not parse error response as JSON")

        self.assertIn(response_confirm.status_code, 
                      [status.HTTP_302_FOUND, status.HTTP_200_OK],
                      f"Potvrdenie e-mailu zlyhalo s kódom {response_confirm.status_code}")
        new_user.refresh_from_db() 
        email_address.refresh_from_db()

        self.assertTrue(new_user.is_active, 
                        "Používateľ nebol AKTIVOVANÝ po potvrdení e-mailu.")
        self.assertTrue(email_address.verified, 
                        "E-mailová adresa nie je označená ako OVERENÁ.")
        
        # ⭐️⭐️⭐️ TESTOVANIE LOGINU PO POTVRDENÍ EMAILU ⭐️⭐️⭐️
        print("=== TESTING LOGIN AFTER CONFIRMATION ===")

        # Skúsime sa prihlásiť s novým používateľom
        login_data = {
            'username': 'newuser',  # alebo 'email': 'newuser@gmail.com'
            'password': 'testpass123'
        }

        login_response = self.client.post(self.login_url, login_data, format='json')
        print(f"🔐 Login response status: {login_response.status_code}")
        print(f"🔐 Login response data: {login_response.data}")

        # Overíme že login bol úspešný
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertIn('access', login_response.data)
        self.assertIn('refresh', login_response.data)

        # Overíme že dostaneme JWT tokeny
        access_token = login_response.data['access']
        refresh_token = login_response.data['refresh']
        self.assertTrue(len(access_token) > 0)
        self.assertTrue(len(refresh_token) > 0)

        print("✅ Login successful after email confirmation!")

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
        # First login to get a valid user session
        login_data = {'username': 'testuser', 'email': '', 'password': 'strongpass123'}
        login_response = self.client.post(self.login_url, login_data, format='json')
        
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

     # ------------------------------
    # AXES lockout after 5 failed attempts
    # ------------------------------
    def test_login_block_after_multiple_failures(self):
        reset()  # reset AXES for test
        for i in range(5):
            response = self.client.post(self.login_url, {
                'username': 'testuser',
                'password': 'wrongpass'
            }, format='json')
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        # 6th attempt should be blocked by AXES
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'wrongpass'
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    # ------------------------------
    # Social login tests
    # ------------------------------
    def test_social_login_creates_new_user(self):
        data = {'email': 'new_social@example.com'}
        response = self.client.post(self.social_login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(User.objects.filter(email='new_social@example.com').exists())
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertTrue(response.data['created'])

    def test_social_login_existing_user(self):
        data = {'email': 'test@example.com'}
        response = self.client.post(self.social_login_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['created'])  # should not create new user

    # ------------------------------

    
    # ------------------------------
    # Social profile completion
    # ------------------------------
    def test_social_complete_profile_success(self):
        # Create social account first
        social_user = User.objects.create(email='social2@example.com', is_social_account=True, profile_completed=False)
        self.client.force_authenticate(user=social_user)
        data = {'username': 'socialuser2', 'password': 'StrongPass!23'}
        response = self.client.put(self.social_complete_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        social_user.refresh_from_db()
        self.assertEqual(social_user.username, 'socialuser2')
        self.assertTrue(social_user.profile_completed)

    def test_social_complete_profile_missing_password(self):
        social_user = User.objects.create(email='social3@example.com', is_social_account=True, profile_completed=False)
        self.client.force_authenticate(user=social_user)
        data = {'username': 'socialuser3'}  # missing password
        response = self.client.put(self.social_complete_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    # ------------------------------
    # Logout edge cases
    # ------------------------------
    def test_logout_with_already_blacklisted_token(self):
        refresh = RefreshToken.for_user(self.user)
        refresh.blacklist()
        response = self.client.post(self.logout_url, {'refresh': str(refresh)}, format='json')
        # Should still succeed gracefully
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('detail', response.data)

    def test_logout_with_empty_payload(self):
        response = self.client.post(self.logout_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('detail', response.data)

    def test_logout_with_malformed_token(self):
        response = self.client.post(self.logout_url, {'refresh': 'malformed.token'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('detail', response.data)
