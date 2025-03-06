# api/authentication.py

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import AnonymousUser
from .models import APIKey, hash_api_key

class APIKeyAuthentication(BaseAuthentication):
    """
    Looks for 'X-API-Key' in headers, compares hashed value to stored APIKeys.
    """
    def authenticate(self, request):
        raw_key = request.headers.get('X-API-Key')
        if not raw_key:
            return None  # No API key provided; let DRF proceed to next authentication if any

        hashed = hash_api_key(raw_key)
        try:
            api_key = APIKey.objects.get(hashed_key=hashed)
        except APIKey.DoesNotExist:
            raise AuthenticationFailed("Invalid API Key")

        # If needed, you can check if the APIKey is 'active' or not, etc.
        return (AnonymousUser(), api_key)  # (user, auth)
