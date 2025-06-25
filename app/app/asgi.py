import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter

# Import your app's routing configuration

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'app.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
})