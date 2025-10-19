import logging
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied  
from dj_rest_auth.serializers import LoginSerializer
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from axes.models import AccessAttempt
from django.conf import settings


# Get logger for this module
logger = logging.getLogger(__name__)

"""class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password')

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        user.profile_completed = True  # klasická registrácia -> okamžite completed
        user.save()
        return user"""

User = get_user_model()

class CustomLoginSerializer(LoginSerializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        logger.info("CustomLoginSerializer validation started")
        logger.debug(f"Validation attrs: { {k: v for k, v in attrs.items() if k != 'password'} }")
        
        username = attrs.get("username", "").strip()
        email = attrs.get("email", "").strip()
        password = attrs.get("password")

        # Get the request from context
        request = self.context.get('request')
        
        # PRIDANE: Kontrola zablokovania - na zaciatku validacie
        lookup_username = username
        if not lookup_username and email:
            try:
                user_obj = User.objects.get(email=email)
                lookup_username = user_obj.username
            except User.DoesNotExist:
                pass
        
        if lookup_username:
            try:
                attempt = AccessAttempt.objects.get(username=lookup_username)
                lockout_limit = getattr(settings, 'AXES_FAILURE_LIMIT', 5)
                if attempt.failures_since_start >= lockout_limit:  # PRIDANE: kontrola ci ma viac ako 5 pokusov
                    raise PermissionDenied({
                        'detail': 'Too many atempts. Accout was tempoarily blocked for 15 minuts. Try it later.',
                        'locked': True
                    })
            except AccessAttempt.DoesNotExist:
                pass
        # KONIEC PRIDANEHO KODU
      

        if not password:
            logger.warning("Login attempt without password")
            raise serializers.ValidationError("Musíš zadať heslo.")
        
        if username:
            logger.info(f"Attempting username authentication: {username}")
            user = authenticate(request=request, username=username, password=password)
            logger.debug(f"Username authentication result: {'Success' if user else 'Failed'}")
        elif email:
            logger.info(f"Attempting email authentication: {email}")
            try:
                user_obj = User.objects.get(email=email)
                logger.debug(f"User found by email: {user_obj.username}")
                user = authenticate(request=request, username=user_obj.username, password=password)
                logger.debug(f"Email authentication result: {'Success' if user else 'Failed'}")
            except User.DoesNotExist:
                logger.warning(f"Email not found in database: {email}")
                user = None
        else:
            logger.warning("Login attempt without username or email")
            raise serializers.ValidationError("Username or e-mail is required.")

        if not user:
            logger.warning(f"Authentication failed for username: {username}, email: {email}")
            raise AuthenticationFailed("Credetials not valid.")

        logger.info(f"Authentication successful for user: {user.username} (ID: {user.id})")
        attrs["user"] = user
        return attrs

    
# minimalny serializer pre social login request
class SocialLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        logger.debug(f"SocialLoginSerializer validating email: {value}")
        return value

    def validate(self, attrs):
        logger.info("SocialLoginSerializer validation started")
        logger.debug(f"Social login attrs: {attrs}")
        return attrs

class SocialCompleteProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ('username', 'password')

    def validate_username(self, value):
        logger.debug(f"Validating username: {value}")
        return value

    def validate(self, attrs):
        logger.info("SocialCompleteProfileSerializer validation started")
        logger.debug(f"Profile completion attrs: { {k: v for k, v in attrs.items() if k != 'password'} }")
        return attrs

    def update(self, instance, validated_data):
        logger.info(f"Updating social profile for user ID: {instance.id}")
        logger.debug(f"Update data - username: {validated_data.get('username')}")
        
        instance.username = validated_data['username']
        instance.set_password(validated_data['password'])
        instance.profile_completed = True
        
        logger.info(f"Saving profile completion for user: {instance.username}")
        instance.save()
        
        logger.info("Social profile completed successfully")
        return instance
    