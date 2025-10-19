from rest_framework import serializers
from dj_rest_auth.serializers import LoginSerializer
from django.contrib.auth import authenticate, get_user_model
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

User = get_user_model()

class CustomLoginSerializer(LoginSerializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = attrs.get("username", "").strip()
        email = attrs.get("email", "").strip()
        password = attrs.get("password")

        # Get the request from context
        request = self.context.get('request')

        if not password:
            raise serializers.ValidationError("Musíš zadať heslo.")

        if username:
            user = authenticate(request=request, username=username, password=password)
        elif email:
            try:
                user_obj = User.objects.get(email=email)
                user = authenticate(request=request, username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None
        else:
            raise serializers.ValidationError("Musíš zadať meno alebo email.")

        if not user:
            raise serializers.ValidationError("Neplatné prihlasovacie údaje.")

        attrs["user"] = user
        return attrs

    
# minimalny serializer pre social login request
class SocialLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class SocialCompleteProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])

    class Meta:
        model = User
        fields = ('username', 'password')

    def update(self, instance, validated_data):
        instance.username = validated_data['username']
        instance.set_password(validated_data['password'])
        instance.profile_completed = True
        instance.save()
        return instance
