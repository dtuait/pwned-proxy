# api/authentication.py

import os
import jwt
from jwt import PyJWKClient

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import APIKey, hash_api_key

User = get_user_model()


class APIKeyAuthentication(BaseAuthentication):
    """
    Looks for 'X-API-Key' in headers, compares hashed value to stored APIKeys.
    """

    def authenticate(self, request):
        raw_key = request.headers.get('X-API-Key')
        if not raw_key:
            return None  # No API key header => DRF tries next auth class

        hashed = hash_api_key(raw_key)
        try:
            api_key = APIKey.objects.get(hashed_key=hashed)
        except APIKey.DoesNotExist:
            raise AuthenticationFailed("Invalid API Key")

        # Return (user, token) in DRF. Using AnonymousUser since the API key doesn’t map to a specific user.
        return (AnonymousUser(), api_key)


class AzureAdJWTAuthentication(BaseAuthentication):
    """
    Custom DRF authentication class for Azure AD JWT access tokens.
    Validates the 'Authorization: Bearer <token>' header.

    Environment variables used (from .env):
      PUBLIC_AZURE_AD_TENANT_ID
      AZURE_APP_AIT_SOC_GRAPH_VICRE_REGISTRATION_CLIENT_ID
    """
class AzureAdJWTAuthentication(BaseAuthentication):
    """
    Custom DRF authentication class for Azure AD JWT tokens.
    Validates the 'Authorization: Bearer <token>' header.

    Environment variables used:
      - PUBLIC_AZURE_AD_TENANT_ID  (the tenant / directory ID)
      - AZURE_APP_AIT_SOC_GRAPH_VICRE_REGISTRATION_CLIENT_ID (the Django API's client ID)
        or whichever var you choose to store your API's client ID.
    """

    def authenticate(self, request):
        # 1) Grab Authorization: Bearer <token>
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None  # Let DRF try next auth class if any

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return None  # Not a valid Bearer scheme

        token = parts[1]

        # 2) Read tenant and audience from environment
        tenant_id = os.environ.get("PUBLIC_AZURE_AD_TENANT_ID", "")
        # This needs to be the *API* client ID from your "AIT-SOC-MSAL-API-NGROK-DEV-VICRE" registration:
        audience = os.environ.get("AZURE_APP_AIT_SOC_GRAPH_VICRE_REGISTRATION_CLIENT_ID", "")

        if not tenant_id or not audience:
            raise AuthenticationFailed("Missing Azure AD tenant_id or client_id in environment variables.")

        # 3) Retrieve the signing keys from Azure to verify the token signature
        jwks_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
        jwks_client = PyJWKClient(jwks_url)

        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            decoded = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=audience,  # must match your API client's Application ID
                issuer=f"https://sts.windows.net/{tenant_id}/"
            )
        except Exception as exc:
            raise AuthenticationFailed(f"Token validation error: {str(exc)}")

        # 4) Determine the user's email/UPN from claims
        user_email = decoded.get("upn") or decoded.get("email") or decoded.get("preferred_username")
        if not user_email:
            raise AuthenticationFailed("No identifiable email or UPN in token claims.")

        # 5) Get or create a local Django user
        user, _ = User.objects.get_or_create(username=user_email, defaults={"email": user_email})

        # 6) Return (user, token) so DRF sees an authenticated user
        return (user, decoded)