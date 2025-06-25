from django.contrib import admin # type: ignore
from django.urls import path, include # type: ignore
from django.conf import settings # type: ignore
from django.conf.urls.static import static # type: ignore
from rest_framework import permissions # type: ignore
from drf_yasg.views import get_schema_view # type: ignore
from drf_yasg import openapi # type: ignore
from rest_framework_simplejwt.views import TokenRefreshView # type: ignore

# API Documentation Setup
schema_view = get_schema_view(
   openapi.Info(
      title="User-Service API",
      default_version='v1',
      description="API for Real Estate Management System",
      contact=openapi.Contact(email="manuelsokoudjou@gmail.com"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # API Endpoints
    path('api/auth/', include('accounts.urls')),
    # JWT Token Refresh
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # DRF Auth (for browsable API)
    path('api-auth/', include('rest_framework.urls')),
    
    # API Documentation
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)