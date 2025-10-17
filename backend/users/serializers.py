from rest_framework import serializers
from dj_rest_auth.serializers import LoginSerializer
from django.contrib.auth import authenticate
from .models import CustomUser
from django.contrib.auth.password_validation import validate_password

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

class CustomLoginSerializer(LoginSerializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'})

    def _validate_username_email(self, username, email, password):
        user = None

        if email and password:
            user = authenticate(email=email, password=password)
        elif username and password:
            user = authenticate(username=username, password=password)
        else:
            raise serializers.ValidationError("Please enter either username or email and password.")

        return user

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password = attrs.get('password')

        user = self._validate_username_email(username, email, password)
        if not user:
            raise serializers.ValidationError("Invalid login credentials.")
        attrs['user'] = user
        return attrs
    
# minimalny serializer pre social login request
class SocialLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class SocialCompleteProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = CustomUser
        fields = ('username', 'password')

    def update(self, instance, validated_data):
        instance.username = validated_data['username']
        instance.set_password(validated_data['password'])
        instance.profile_completed = True
        instance.save()
        return instance
