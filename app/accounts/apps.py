from django.apps import AppConfig
import asyncio
import threading
from django.conf import settings


class AccountsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"
    
    def ready(self):
        # Initialize Eureka client asynchronously
        if hasattr(settings, 'EUREKA_CONF'):
            self._init_eureka_async()
    
    def _init_eureka_async(self):
        """Initialize Eureka client in a separate thread with async support"""
        def run_async_init():
            try:
                from app.eureka_client import init_eureka
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(init_eureka(settings.EUREKA_CONF))
                loop.close()
            except Exception as e:
                print(f"Failed to initialize Eureka client: {e}")
        
        # Run in a separate thread to avoid blocking Django startup
        thread = threading.Thread(target=run_async_init, daemon=True)
        thread.start()
