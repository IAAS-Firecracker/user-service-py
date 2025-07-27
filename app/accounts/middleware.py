from urllib.parse import parse_qs
from channels.auth import AuthMiddlewareStack
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.db import close_old_connections
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

@database_sync_to_async
def get_user(token_key):
    try:
        # This will automatically validate the token and raise an error if token is invalid
        token = AccessToken(token_key)
        user_id = token.payload.get('user_id')
        # Close old database connections to prevent usage of timed out connections
        close_old_connections()
        
        # Get the user from database (you can also use the JWT_PAYLOAD_GET_USER_ID_HANDLER setting)
        from django.contrib.auth import get_user_model
        User = get_user_model()
        return User.objects.get(id=user_id)
    except (InvalidToken, TokenError) as e:
        # Token is invalid
        return AnonymousUser()
    except User.DoesNotExist:
        # Invalid user - token may refer to a user that no longer exists
        return AnonymousUser()

class JWTAuthMiddleware:
    """
    JWT authentication middleware for Django Channels
    """

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        # Get the token from query string
        query_string = scope.get('query_string', b'').decode()
        query_params = parse_qs(query_string)
        token = query_params.get('token', [''])[0]
        
        if not token:
            # Try to get token from headers
            headers = dict(scope.get('headers', []))
            if b'authorization' in headers:
                auth_header = headers[b'authorization'].decode()
                if auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
        
        if token:
            # Get the user
            scope['user'] = await get_user(token)
        else:
            scope['user'] = AnonymousUser()
        
        # Return the inner application
        return await self.inner(scope, receive, send)

def JWTAuthMiddlewareStack(inner):
    return JWTAuthMiddleware(AuthMiddlewareStack(inner))