from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.hashers import make_password, check_password

class UserType(models.TextChoices):
    ADMIN = 'ADMIN', 'administrator'
    USER = 'USER', 'user'

class User(AbstractUser):
    role = models.CharField(
        max_length=20,
        choices=UserType.choices,
        default=UserType.USER
    )
    email = models.EmailField(unique=True)
    token = models.TextField(blank=True, null=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username'] 
    
    def __str__(self):
        return f"{self.get_user_type_display()}: {self.username}"

class PasswordResetCode(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=255)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.pk:  # Only hash the code on creation
            self.code = make_password(self.code)
        super().save(*args, **kwargs)

    def valid_code(self, code):
        return check_password(code, self.code)