import requests
from django.conf import settings
from django.contrib.auth.models import Group
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from .models import APIKey, Domain
from .models import hash_api_key, generate_api_key  # optional if used


class CreateAPIKeyView(APIView):
    """
    POST /api/create-key/
    
    Creates a new API key with multiple domains for a specified group.
    Expects JSON body like:
      {
        "group_name": "Danmarks Tekniske Universitet",
        "domains": ["dtu.dk", "cert.dk"]
      }
    
    Returns the raw key exactly once.
    """

    @swagger_auto_schema(
        operation_description=(
            "Create a new API key for a given group + multiple domains. Returns raw key once."
        ),
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'group_name': openapi.Schema(type=openapi.TYPE_STRING),
                'domains': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Items(type=openapi.TYPE_STRING)
                ),
            },
            required=['group_name', 'domains'],
        ),
        responses={
            201: openapi.Response(
                description="Key created successfully.",
                examples={"application/json": {
                    "message": "Key created for group 'Danmarks Tekniske Universitet' with 2 domain(s)",
                    "raw_key": "346a3d9f5e334a12aef5ff99742b18b2"
                }}
            ),
            400: "Bad request format",
            403: "User not allowed to create key for that group (optional check)",
        }
    )
    def post(self, request):
        data = request.data
        group_name = data.get('group_name')
        domain_list = data.get('domains')

        if not group_name or not domain_list:
            return Response(
                {"detail": "Missing 'group_name' or 'domains'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # 1) Fetch or 404 if group doesn't exist
        group = get_object_or_404(Group, name=group_name)

        # Optional check: ensure the user is in that group
        # if not request.user.groups.filter(name=group_name).exists():
        #    raise PermissionDenied("You are not a member of this group.")

        # 2) Look up or create Domain objects
        domain_objs = []
        for dname in domain_list:
            dom_obj, _ = Domain.objects.get_or_create(name=dname)
            domain_objs.append(dom_obj)

        # 3) Create the APIKey
        api_key_obj, raw_key = APIKey.create_api_key(
            group=group,
            domain_list=domain_objs
        )

        return Response(
            {
                "message": (f"Key created for group '{group_name}' "
                            f"with {len(domain_list)} domain(s)"),
                "raw_key": raw_key
            },
            status=status.HTTP_201_CREATED
        )


class StealerLogsProxyView(APIView):
    """
    GET /api/stealer-logs/<domain>/

    Proxies to: https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/<domain>
    We check if <domain> is in api_key.domains. If yes, we proxy the request.
    Otherwise, 403 forbidden.
    """

    @swagger_auto_schema(
        operation_description="Proxy to /stealerlogsbyemaildomain/<domain>. Domain must be in APIKey.domains.",
        manual_parameters=[
            openapi.Parameter(
                name='domain',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description='Domain to look up (e.g. "dtu.dk"). Must be in APIKey.domains.'
            ),
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                description='Your raw API key'
            ),
        ]
    )
    def get(self, request, domain=None):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        # Ensure domain is in the M2M set
        if not domain or not api_key_obj.domains.filter(name=domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{domain}'.")

        # Proxy to HIBP
        hibp_url = f"https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/{domain}"
        headers = {
            "hibp-api-key": settings.HIBP_API_KEY,
            "User-Agent": "pwned_proxy_app/1.0"
        }

        try:
            resp = requests.get(hibp_url, headers=headers)
            return Response(resp.json(), status=resp.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_502_BAD_GATEWAY)


class BreachedDomainProxyView(APIView):
    """
    GET /api/breached-domain/<domain>/

    Proxies to: https://haveibeenpwned.com/api/v3/breacheddomain/<domain>
    We check if <domain> is in api_key.domains. If yes, we proxy. Otherwise, 403.
    """

    @swagger_auto_schema(
        operation_description="Proxy to /breacheddomain/<domain>. Domain must be in the APIKey.",
        manual_parameters=[
            openapi.Parameter(
                name='domain',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description='Which domain to query.'
            ),
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True
            ),
        ]
    )
    def get(self, request, domain=None):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        if not domain or not api_key_obj.domains.filter(name=domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{domain}'.")

        hibp_url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        headers = {
            "hibp-api-key": settings.HIBP_API_KEY,
            "User-Agent": "pwned_proxy_app/1.0"
        }

        try:
            resp = requests.get(hibp_url, headers=headers)
            return Response(resp.json(), status=resp.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_502_BAD_GATEWAY)


class BreachedAccountProxyView(APIView):
    """
    GET /api/breached-account/<email>

    Proxies to: https://haveibeenpwned.com/api/v3/breachedaccount/<email>
    The domain of the <email> must be in api_key.domains.
    If HIBP says 404 = "not found," we convert to empty array w/ 200.
    """

    @swagger_auto_schema(
        operation_description="Proxy to /breachedaccount/<email>. Email's domain must be in APIKey.domains.",
        manual_parameters=[
            openapi.Parameter(
                name='email',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description='The email to check. e.g. "user@dtu.dk"'
            ),
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True
            ),
        ],
        responses={
            200: "Success or empty array if not found",
            404: "Uncommon scenario"
        }
    )
    def get(self, request, email=None):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        if not email:
            return Response({"detail": "No email specified."}, status=400)

        # Parse domain from email
        parts = email.rsplit('@', 1)
        if len(parts) != 2:
            return Response({"detail": "Invalid email format."}, status=400)
        email_domain = parts[1].lower()

        # Check if the domain is authorized
        if not api_key_obj.domains.filter(name=email_domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{email_domain}'.")

        hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": settings.HIBP_API_KEY,
            "User-Agent": "pwned_proxy_app/1.0"
        }

        try:
            resp = requests.get(hibp_url, headers=headers)
            if resp.status_code == 404:
                return Response([], status=200)
            return Response(resp.json(), status=resp.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=status.HTTP_502_BAD_GATEWAY)
