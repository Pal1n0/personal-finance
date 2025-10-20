from allauth.account.adapter import DefaultAccountAdapter
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError  # Use Django's ValidationError, not DRF's

User = get_user_model()

class CustomAccountAdapter(DefaultAccountAdapter):

    def is_open_for_signup(self, request):
        return True

    def clean_email(self, email):
        """
        Ensure email is unique before allauth creates the user.
        """
        if User.objects.filter(email=email).exists():
            # Use Django's ValidationError, not DRF's
            raise ValidationError("A user with that email already exists.")
        return email

    def clean_username(self, username):
        """
        Ensure username is unique.
        """
        # Only check if username is provided and not empty
        if username and User.objects.filter(username=username).exists():
            raise ValidationError("A user with that username already exists.")
        return username