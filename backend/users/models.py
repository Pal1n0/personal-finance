from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator


# Create your models here.

class CustomUser(AbstractUser):
    # make email unique and required
    email = models.EmailField(unique=True, blank=False)
    username = models.CharField(max_length=150, unique=True, null=True, blank=True) # Optinal for google registration
    password = models.CharField(max_length=128, null=True, blank=True) # Optinal for google registration

    is_active = models.BooleanField(
        default=False, # <-- Vynúti, aby bol nový používateľ neaktívny
        help_text='Designates whether this user should be treated as active. '
                  'Unselect this instead of deleting accounts.'
    )
    # optional profile picture
    profile_picture = models.ImageField(
        upload_to='profile_pics/',
        null=True,
        blank=True,
        validators=[FileExtensionValidator(['jpg', 'jpeg', 'png'])]
    )

    is_social_account = models.BooleanField(default=False)  # True if google registration
    profile_completed = models.BooleanField(default=False)  # True if pw a nickname added

    def __str__(self):
        return self.username