from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import APIKey

class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        key = request.headers.get('X-API-Key')
        if not key:
            raise AuthenticationFailed('API Key required.')
        try:
            api_key = APIKey.objects.get(key=key, is_active=True)
            return (api_key, None)
        except APIKey.DoesNotExist:
            raise AuthenticationFailed('Invalid API Key.')
