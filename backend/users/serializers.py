from rest_framework import serializers
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
