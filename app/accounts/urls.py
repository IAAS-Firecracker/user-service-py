from django.urls import path, include
from rest_framework.routers import DefaultRouter
from accounts.api_views import (
    UserViewSet, 
    AdminViewSet, 
    LoginView, 
    RegisterView,
    LogoutView
)

app_name = "accounts"

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'admins', AdminViewSet, basename="admins")

urlpatterns = [
    path('', include(router.urls)),
    # Authentication endpoints
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
]