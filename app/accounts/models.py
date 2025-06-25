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
    
    def __str__(self):
        return f"{self.get_user_type_display()}: {self.username}"