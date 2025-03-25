# api/views.py

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import Group
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import PermissionDenied

from django.conf import settings
import requests

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import APIKey


class CreateAPIKeyView(APIView):
    """
    POST /api/create-key/

    Body:
      {
        "domain_group_name": "example.com"
      }

    - User must be authenticated (e.g., via session or token) and in the specified group.
    - Creates and returns a *raw* API key exactly once.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        domain_group_name = request.data.get("domain_group_name")
        if not domain_group_name:
            return Response({"detail": "Missing domain_group_name"}, status=400)

        # Check the user is in that group
        if not request.user.groups.filter(name=domain_group_name).exists():
            return Response({"detail": "You are not a member of this domain group."}, status=403)

        group = get_object_or_404(Group, name=domain_group_name)
        allowed_domain = domain_group_name.lower()

        new_key_obj, raw_key = APIKey.create_api_key(
            domain_group=group, allowed_domain=allowed_domain
        )
        return Response(
            {
                "message": f"Key created for domain '{allowed_domain}'",
                "raw_key": raw_key  # Show raw key once
            },
            status=status.HTTP_201_CREATED
        )


class StealerLogsProxyView(APIView):
    """
    GET /api/stealer-logs/

    Uses the domain from the request's API key (request.auth.allowed_domain) to call:
      https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/<domain>
    """

    @swagger_auto_schema(
        operation_description="Proxy to /stealerlogsbyemaildomain/<domain> on HaveIBeenPwned. "
                              "Domain is derived from your API key (X-API-Key).",
        manual_parameters=[
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                description='Raw API Key (linked to exactly one domain).'
            ),
        ],
        responses={
            200: "Success",
            401: "No valid API key provided",
            403: "API key has no domain or domain not allowed",
            502: "Upstream error (HIBP or network issue)",
        }
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key provided."}, status=401)

        domain = api_key_obj.allowed_domain
        if not domain:
            raise PermissionDenied("This API key has no domain associated.")

        hibp_headers = {
            'hibp-api-key': settings.HIBP_API_KEY,
            # 'Cookie': '...optional CF cookie if needed...'
        }
        hibp_url = f"https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/{domain}"

        try:
            hibp_response = requests.get(hibp_url, headers=hibp_headers)
            return Response(hibp_response.json(), status=hibp_response.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_502_BAD_GATEWAY)


class BreachedDomainProxyView(APIView):
    """
    GET /api/breached-domain/

    Uses the domain from the API key to call:
      https://haveibeenpwned.com/api/v3/breacheddomain/<domain>
    """

    @swagger_auto_schema(
        operation_description="Proxy to /breacheddomain/<domain> on HaveIBeenPwned. "
                              "Domain derived from your API key.",
        manual_parameters=[
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                description='Raw API Key (one domain).'
            ),
        ],
        responses={
            200: "Success",
            401: "No valid API key provided",
            403: "API key has no domain or domain not allowed",
            502: "Upstream error"
        }
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key provided."}, status=401)

        domain = api_key_obj.allowed_domain
        if not domain:
            raise PermissionDenied("This API key has no domain associated.")

        hibp_headers = {
            'hibp-api-key': settings.HIBP_API_KEY,
        }
        hibp_url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"

        try:
            hibp_response = requests.get(hibp_url, headers=hibp_headers)
            return Response(hibp_response.json(), status=hibp_response.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_502_BAD_GATEWAY)




class BreachedAccountProxyView(APIView):
    """
    GET /api/breached-account/<email>

    - The domain of the email must match the API key's allowed_domain.
    - Calls: https://haveibeenpwned.com/api/v3/breachedaccount/<email>
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /breachedaccount/<email> on HaveIBeenPwned. "
            "Email domain must match your API key's allowed_domain."
        ),
        manual_parameters=[
            openapi.Parameter(
                name='email_in_path',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description='Email address (URL-encoded if needed).'
            ),
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                description='Raw API Key (one domain).'
            ),
        ],
        responses={
            200: "Success (or an empty list if 404 from HIBP).",
            400: "Missing/invalid email",
            401: "No valid API key",
            403: "Email domain mismatch",
            502: "Upstream error"
        }
    )
    def get(self, request, email=None):  # <-- note the 'email' argument
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key provided."}, status=401)

        domain = api_key_obj.allowed_domain
        if not domain:
            return Response({"detail": "API key has no domain."}, status=403)

        if not email:
            return Response({"detail": "Missing email in path."}, status=400)

        # Check domain part
        parts = email.rsplit('@', 1)
        if len(parts) != 2:
            return Response({"detail": "Invalid email format."}, status=400)

        email_domain = parts[1].lower()
        if email_domain != domain.lower():
            return Response(
                {"detail": f"Email domain '{email_domain}' does not match '{domain}'."},
                status=403
            )

        # Construct the upstream URL
        hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        hibp_headers = {
            "hibp-api-key": settings.HIBP_API_KEY,
            "User-Agent": "pwned_proxy_app/1.0"  # HIBP typically requires a User-Agent
        }

        try:
            hibp_response = requests.get(hibp_url, headers=hibp_headers)
            # If 404 from HIBP means "no breaches," you can EITHER:
            if hibp_response.status_code == 404:
                # Option A: pass 404 straight through
                # return Response([], status=404)

                # Option B: convert 404 -> an empty array with 200
                return Response([], status=200)

            # Otherwise, parse JSON (if 200 or other code)
            return Response(hibp_response.json(), status=hibp_response.status_code)

        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_502_BAD_GATEWAY)