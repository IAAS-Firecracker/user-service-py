from accounts.models import User, PasswordResetCode
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.settings import api_settings

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            try:
                user = User.objects.get(email=email)
                if not user.check_password(password):
                    raise serializers.ValidationError(
                        'No active account found with the given credentials'
                    )
                if not user.is_active:
                    raise serializers.ValidationError(
                        'User account is disabled.'
                    )
            except User.DoesNotExist:
                raise serializers.ValidationError(
                    'No active account found with the given credentials'
                )
        else:
            raise serializers.ValidationError(
                'Must include "email" and "password".'
            )

        # Générer les tokens JWT
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        
        # Ajouter des claims personnalisés
        refresh['email'] = user.email
        refresh['username'] = user.username
        refresh['role'] = user.role
        
        data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'email': user.email,
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'user': UserSerializer(user).data
        }

        # Mettre à jour last_login
        from django.contrib.auth.models import update_last_login
        update_last_login(None, user)

        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                  'role']
        # read_only_fields = ['is_verified', 'date_joined', 'last_login']

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'confirm_password',
                 'first_name', 'last_name', 'role']
    
    def validate(self, attrs):
        if attrs['password'] != attrs.pop('confirm_password'):
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            role=validated_data.get('role', 'USER')
        )
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                  'role']
        read_only_fields = ['id', 'username', 'email']

class AdminSerializer(UserSerializer):
    def create(self, validated_data, *args, **kwargs):
        user = self.Meta.model.objects.create_superuser(**validated_data)
        return user

# GenerateCodeSerializer
# VerifyCodeSerializer
# ResetPasswordSerializer

class GenerateCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email']

class VerifyCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordResetCode
        fields = ['email', 'code']

class ResetPasswordSerializer(serializers.ModelSerializer):
    new_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    
    class Meta:
        model = PasswordResetCode
        fields = ['email', 'code', 'new_password']