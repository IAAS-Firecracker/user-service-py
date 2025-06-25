from accounts.models import User
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class LoginSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims to the token
        token['email'] = user.email
        token['username'] = user.username

        return token
    
    def validate(self, attrs):
        data = super().validate(attrs)

        # Add extra response data
        data['email'] = self.user.email
        data['user_id'] = self.user.id
        data['username'] = self.user.username
        data['role'] = self.user.role
        data['user'] = UserSerializer(self.user).data

        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                  'role', 'is_verified', 'date_joined','last_login']
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