from datetime import timezone, datetime, timedelta
from rest_framework import status, viewsets
from django.contrib.auth import logout
from rest_framework.response import Response
from rest_framework import permissions, generics, filters
from rest_framework.decorators import action
from accounts.models import User, PasswordResetCode

from accounts.serializers import *

from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.timezone import now
from django.core.mail import send_mail
import random

from rest_framework import viewsets
from rest_framework.decorators import action
from django.template.loader import TemplateDoesNotExist, render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives
from rest_framework import filters
from email.mime.image import MIMEImage
from threading import Thread
from django.conf import settings

class TemplateEmail(Thread):    
    def __init__(
        self,
        to,
        subject,
        template,
        context,
        from_email=None,
        reply_to=None,
        app_name='accounts',
        *args,
        **email_kwargs,
    ):
        super().__init__(*args, **email_kwargs)
        
        self.to = to
        self.subject = subject
        self.template = template
        self.context = context
        self.from_email = from_email or settings.EMAIL_HOST_USER
        self.reply_to = reply_to
        self.app_name = app_name

        self.html_content, self.plain_content = self.render_content()

        self.to = self.to if not isinstance(self.to, str) else [self.to]

        if self.reply_to:
            self.reply_to = (
                self.reply_to if not isinstance(self.reply_to, str) else [self.reply_to]
            )

        self.django_email = EmailMultiAlternatives(
            subject=self.subject,
            body=self.plain_content,
            from_email=self.from_email,
            to=self.to,
            reply_to=self.reply_to,
            **email_kwargs,
        )
        self.django_email.attach_alternative(self.html_content, "text/html")
        self.django_email.mixed_subtype = "related"

    def render_content(self):
        html_content = self.render_html()

        try:
            plain_content = self.render_plain()
        except TemplateDoesNotExist:
            plain_content = strip_tags(html_content)

        return html_content, plain_content

    def render_plain(self):
        return render_to_string(self.get_plain_template_name(), self.context)

    def render_html(self):
        template_name = self.get_html_template_name()
        return render_to_string(template_name, self.context)

    def get_plain_template_name(self):
        return f"{self.app_name}/email/{self.template}.txt"

    def get_html_template_name(self):
        return f"{self.app_name}/email/{self.template}.html"
    
    def send(self, **send_kwargs):
        return self.django_email.send(**send_kwargs)
    
    def run(self, **run_kwargs):
        self.send(**run_kwargs)

class IsSuperUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser

class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserCreateSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)

            response_data = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': UserSerializer(user).data
            }

            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action == 'update_profile':
            return UserProfileSerializer
        elif self.action == 'generate_code':
            return GenerateCodeSerializer
        elif self.action == 'verify_code':
            return VerifyCodeSerializer
        elif self.action == 'reset_password':
            return ResetPasswordSerializer
        return UserSerializer
    
    def get_permissions(self):
        if self.action in ['update', 'partial_update', 'destroy']:
            # Only administrators or the user themselves can modify
            permission_classes = [permissions.IsAuthenticated]
        elif self.action == 'list':
            permission_classes = [permissions.IsAdminUser]
        else:
            permission_classes = [permissions.AllowAny]
        return [permission() for permission in permission_classes]
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['put', 'patch'], permission_classes=[permissions.IsAuthenticated])
    def update_profile(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
           
    @action(detail=False, url_path="send-reset-code", methods=['post'], permission_classes=[permissions.AllowAny])
    def generate_code(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email requis"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "Cet email n'est associé à aucun compte"}, status=status.HTTP_404_NOT_FOUND)

        code = str(random.randint(10000000, 99999999))
        expires_at = now() + timedelta(minutes=15)

        PasswordResetCode.objects.filter(email=email, used=False).delete()
        PasswordResetCode.objects.create(email=email, code=code, expires_at=expires_at)

        email_context = {
            'code': code,
            'expires_at': expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            'user': user
        }

        template_email = TemplateEmail(
            to=email,
            subject="Réinitialisation de votre mot de passe",
            template="reset_code",
            context=email_context
        )
        template_email.start()

        return Response({"success": True, "message": "Code envoyé avec succès"})

    @action(detail=False, url_path="verify-code", methods=['post'], permission_classes=[permissions.AllowAny])
    def verify_code(self, request):
        email = request.data.get('email')
        code = request.data.get('code')
        if not email or not code:
            return Response({"error": "Tous les champs sont requis"}, status=status.HTTP_400_BAD_REQUEST)

        reset_code = PasswordResetCode.objects.filter(
            email=email, used=False, expires_at__gt=now()
        ).first()

        if not reset_code.valid_code(code):
            return Response({"error": "Code invalide ou expiré", "valid": reset_code.valid_code(code)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"success": True, "message": "Le code est valide"})

    @action(detail=False, url_path="reset-password", methods=['post'], permission_classes=[permissions.AllowAny])
    def reset_password(self, request):
        email = request.data.get('email')
        code = request.data.get('code')
        new_password = request.data.get('new_password')
        if not email or not code or not new_password:
            return Response({"error": "Tous les champs sont requis"}, status=status.HTTP_400_BAD_REQUEST)

        reset_code = PasswordResetCode.objects.filter(
            email=email, used=False, expires_at__gt=now()
        ).first()

        if not reset_code.valid_code(code):
            return Response({"error": "Code invalide ou expiré"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"error": "Utilisateur non trouvé"}, status=status.HTTP_404_NOT_FOUND)

        user.set_password(new_password)
        user.save()

        reset_code.used = True
        reset_code.save()

        return Response({"success": True, "message": "Mot de passe réinitialisé avec succès"})
    
    @action(detail=False, url_path="change-password", methods=['patch'], permission_classes=[permissions.IsAuthenticated])
    def change_password(self, request):
        old_password = request.data.get('password')
        new_password = request.data.get('new_password')

        if not old_password or not new_password:
            return Response({"error": "Tous les champs sont requis"}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user
        if not user.check_password(old_password):
            return Response({"error": "Ancien mot de passe incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({"success": True, "message": "Mot de passe changé avec succès"})

class AdminViewSet(viewsets.ModelViewSet):
    model = User
    queryset = User.objects.filter(is_superuser=True)
    serializer_class = AdminSerializer
    permission_classes = [IsSuperUser]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = [
        "username",
        "email"
    ]
    ordering_fields = [
        "username",
        "email"
    ]