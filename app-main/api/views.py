from django.http import JsonResponse
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import Group
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import APIKey


class DomainBreachProxyView(APIView):
    def get(self, request):
        return JsonResponse({"message": "Placeholder response"})



class CreateAPIKeyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Create a new API key for the domain group that the user is a member of.
        The user must belong to exactly one domain group or we pick the relevant one.
        """
        # Example: The user’s group name might match the domain they belong to
        domain_group_name = request.data.get("domain_group_name")
        if not domain_group_name:
            return Response({"detail": "Missing domain_group_name"}, status=400)

        # Check that user is in that group
        if not request.user.groups.filter(name=domain_group_name).exists():
            return Response({"detail": "You are not a member of this domain group."},
                            status=403)

        group = get_object_or_404(Group, name=domain_group_name)

        # Optionally validate domain name input
        allowed_domain = domain_group_name.lower()

        # Actually create the new API key
        new_key_obj, raw_key = APIKey.create_api_key(
            domain_group=group, allowed_domain=allowed_domain
        )

        return Response(
            {
                "message": f"Key created for domain {allowed_domain}",
                "raw_key": raw_key,  # show raw key exactly once
            },
            status=status.HTTP_201_CREATED
        )


# api/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticatedOrReadOnly

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

class DomainInfoView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]

    @swagger_auto_schema(
        operation_description="Retrieve dummy data for a given domain (requires a valid X-API-Key).",
        manual_parameters=[
            openapi.Parameter(
                name='domain',
                in_=openapi.IN_QUERY,
                description='Domain to retrieve info for',
                type=openapi.TYPE_STRING,
                required=True
            ),
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                description='Your API key (raw key, not the hash)',
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: openapi.Response(description='Success'),
            401: openapi.Response(description='Unauthorized (invalid or missing API key)'),
            403: openapi.Response(description='Forbidden (domain mismatch)'),
        }
    )
    def get(self, request):
        """
        Only the correct API key for a given domain can access the domain's dummy data.
        """
        domain = request.query_params.get('domain')
        if not domain:
            return Response({"detail": "Missing 'domain' query param"}, status=400)

        # request.auth is the APIKey instance returned by our custom auth
        api_key_obj = request.auth  
        if not api_key_obj:
            return Response({"detail": "No valid API key provided."}, status=401)

        # Check if domain matches
        if domain.lower() != api_key_obj.allowed_domain.lower():
            return Response({"detail": "Access denied: wrong domain for this API key."}, status=403)

        # Return some dummy data
        data = {
            "domain": domain,
            "info": "This is restricted data for your domain only."
        }
        return Response(data, status=200)



import requests
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

import requests
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework import status

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class StealerLogsProxyView(APIView):
    """
    Proxies requests to:
    https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/<domain>
    but the domain is taken from the API key's `allowed_domain`,
    so the user does NOT need to supply it explicitly.
    """

    @swagger_auto_schema(
        operation_description="Proxy to /stealerlogsbyemaildomain/<domain> on HaveIBeenPwned, "
                              "using the domain from the API key. Requires X-API-Key header.",
        manual_parameters=[
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                description='Your raw API Key (linked to exactly one domain).'
            ),
        ],
        responses={
            200: "Success",
            401: "No valid API Key provided",
            403: "API Key does not allow access (no domain)",
            502: "Upstream request error (HIBP or network issue)",
        }
    )
    def get(self, request):
        # 1. Check that an API key was provided/validated by our custom auth.
        api_key_obj = request.auth  # This is set by your APIKeyAuthentication
        if not api_key_obj:
            return Response({"detail": "No valid API key provided."}, status=401)

        # 2. Grab the domain from the API key's allowed_domain
        domain = api_key_obj.allowed_domain
        if not domain:
            raise PermissionDenied("This API key has no domain associated.")

        # 3. Make the request to HaveIBeenPwned with the domain from the API key
        hibp_headers = {
            'hibp-api-key': settings.HIBP_API_KEY,
            # If you ever need the CF cookie or other headers:
            # 'Cookie': '...',
        }
        hibp_url = f"https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/{domain}"

        try:
            hibp_response = requests.get(hibp_url, headers=hibp_headers)
            return Response(hibp_response.json(), status=hibp_response.status_code)
        except requests.RequestException as e:
            # Handle network or timeout errors
            return Response({"detail": str(e)}, status=status.HTTP_502_BAD_GATEWAY)
