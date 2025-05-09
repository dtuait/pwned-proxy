# file: api/views.py

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


# --------------------------------------------------------
# Old / existing endpoints
# --------------------------------------------------------

class StealerLogsProxyView(APIView):
    """
    GET /api/stealer-logs/<domain>/

    Example: GET /api/stealer-logs/dtu.dk

    Proxies to /stealerlogsbyemaildomain/{domain}.
    The domain must be in the requesting API key's authorized domains.
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /stealerlogsbyemaildomain/<domain> on HIBP. "
            "Requires X-API-Key that has <domain> in its domain list."
        ),
        manual_parameters=[
            openapi.Parameter(
                name='domain',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description='Domain to look up (e.g. "dtu.dk").'
            ),
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=False,
                description='Your raw API key.'
            ),
        ]
    )
    def get(self, request, domain=None):
        # Must have a valid API key that covers the domain
        if not isinstance(request.auth, APIKey):
            return Response(
                {"detail": "No valid API key provided."},
                status=status.HTTP_401_UNAUTHORIZED
            )
        api_key_obj = request.auth
        if not api_key_obj.domains.filter(name=domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{domain}'")

        # Proxy to the HIBP endpoint
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

    Example: GET /api/breached-domain/dtu.dk

    Proxies to /breacheddomain/<domain>.
    The domain must be in the requesting API key's authorized domains.
    """

    @swagger_auto_schema(
        operation_description="Proxy to /breacheddomain/<domain> on HIBP.",
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
                required=False
            ),
        ]
    )
    def get(self, request, domain=None):
        if not isinstance(request.auth, APIKey):
            return Response({"detail": "No valid API key provided."}, status=401)
        api_key_obj = request.auth

        if not api_key_obj.domains.filter(name=domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{domain}'")

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

    Example: GET /api/breached-account/user@dtu.dk

    Proxies to /breachedaccount/<email>.
    The domain of <email> must be in the requesting API key's authorized domains.
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /breachedaccount/<email> on HIBP. "
            "Email domain must match an authorized domain from your API key."
        ),
        manual_parameters=[
            openapi.Parameter(
                name='email',
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description='Email address to check, e.g. user@dtu.dk'
            ),
            openapi.Parameter(
                name='X-API-Key',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=False
            ),
        ],
        responses={
            200: "Success or empty array if not found",
            404: "No record in HIBP"
        }
    )
    def get(self, request, email=None):
        if not isinstance(request.auth, APIKey):
            return Response({"detail": "No valid API key provided."}, status=401)

        if not email:
            return Response({"detail": "No email specified."}, status=400)
        parts = email.rsplit('@', 1)
        if len(parts) != 2:
            return Response({"detail": "Invalid email format."}, status=400)
        email_domain = parts[1].lower()

        api_key_obj = request.auth
        if not api_key_obj.domains.filter(name=email_domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{email_domain}'")

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


# --------------------------------------------------------
# New endpoints for the rest of HIBP v3
# --------------------------------------------------------

class PasteAccountProxyView(APIView):
    """
    GET /api/paste-account/?email=<user@domain.com>
    - The domain of the email must match the requesting API key's domain(s).
    - Proxies to /pasteaccount/{account}.
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to **/pasteaccount/{account}** on Have I Been Pwned. "
            "Requires X-API-Key that covers the domain in the email."
        ),
        manual_parameters=[
            openapi.Parameter(
                name='email', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, required=True,
                description='Email address to search for in pastes (must be an allowed domain).'
            ),
            openapi.Parameter(
                name='X-API-Key', in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
                description='Your raw API key.'
            ),
        ]
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        email = request.query_params.get('email')
        if not email:
            return Response({"detail": "Missing 'email' query parameter."}, status=400)
        parts = email.rsplit('@', 1)
        if len(parts) != 2:
            return Response({"detail": "Invalid email format."}, status=400)
        email_domain = parts[1].lower()

        # Check if domain is authorized
        if not api_key_obj.domains.filter(name=email_domain).exists():
            raise PermissionDenied(
                f"API key not authorized for email domain '{email_domain}'"
            )

        hibp_url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{requests.utils.requote_uri(email)}"
        headers = {"hibp-api-key": settings.HIBP_API_KEY}
        try:
            resp = requests.get(hibp_url, headers=headers)
            return Response(resp.json(), status=resp.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=502)


class SubscribedDomainsProxyView(APIView):
    """
    GET /api/subscribed-domains/
    - Proxies to /subscribeddomains
    - We'll filter the returned data to only include the domain(s) from the API key, if needed.
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to **/subscribeddomains** on HIBP. "
            "Returns the domains that are verified with this subscription. "
            "Requires an API key with at least one domain."
        ),
        manual_parameters=[
            openapi.Parameter(
                name='X-API-Key', in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING, required=True
            ),
        ]
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key provided."}, status=401)

        # If the APIKey has multiple domains, we might filter the HIBP response if necessary
        domain_names = list(api_key_obj.domains.values_list('name', flat=True))

        hibp_url = "https://haveibeenpwned.com/api/v3/subscribeddomains"
        headers = {"hibp-api-key": settings.HIBP_API_KEY}
        try:
            hibp_response = requests.get(hibp_url, headers=headers)
            if hibp_response.status_code != 200:
                return Response(hibp_response.json(), status=hibp_response.status_code)

            data = hibp_response.json()
            # data is typically a list of domain objects
            # Filter to only include the ones the API key covers
            filtered = []
            for item in data:
                dname = str(item.get("DomainName", "")).lower()
                # If dname is in the key’s domain list, keep it
                if dname in (dn.lower() for dn in domain_names):
                    filtered.append(item)

            return Response(filtered, status=200)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=502)


class StealerLogsByEmailProxyView(APIView):
    """
    GET /api/stealer-logs-email/?email=<user@domain.com>
    - The email’s domain must be in the API key's domain list.
    - Proxies to /stealerlogsbyemail/{email}.
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /stealerlogsbyemail/{email} on HIBP. "
            "Requires X-API-Key that covers email's domain."
        ),
        manual_parameters=[
            openapi.Parameter(
                name='email', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, required=True,
                description='Email address (must be in an allowed domain).'
            ),
            openapi.Parameter(
                name='X-API-Key', in_=openapi.IN_HEADER, type=openapi.TYPE_STRING, required=True
            ),
        ]
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)
        email = request.query_params.get('email')
        if not email:
            return Response({"detail": "Missing 'email' query parameter."}, status=400)

        parts = email.rsplit('@', 1)
        if len(parts) != 2:
            return Response({"detail": "Invalid email format."}, status=400)
        email_domain = parts[1].lower()

        if not api_key_obj.domains.filter(name=email_domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{email_domain}'")

        hibp_url = f"https://haveibeenpwned.com/api/v3/stealerlogsbyemail/{requests.utils.requote_uri(email)}"
        headers = {"hibp-api-key": settings.HIBP_API_KEY}
        try:
            resp = requests.get(hibp_url, headers=headers)
            return Response(resp.json(), status=resp.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=502)


class StealerLogsByWebsiteDomainProxyView(APIView):
    """
    GET /api/stealer-logs-website/?domain=<mydomain.com>
    - The <mydomain.com> must be one of the API key's authorized domains.
    - Proxies to /stealerlogsbywebsitedomain/{domain}.
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /stealerlogsbywebsitedomain/{domain} on HIBP. "
            "Requires X-API-Key that covers this domain."
        ),
        manual_parameters=[
            openapi.Parameter(
                name='domain', in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, required=True,
                description='Website domain to search in stealer logs (must be in the API key’s domain list).'
            ),
            openapi.Parameter(
                name='X-API-Key', in_=openapi.IN_HEADER, type=openapi.TYPE_STRING, required=True
            ),
        ]
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        query_domain = request.query_params.get('domain')
        if not query_domain:
            return Response({"detail": "Missing 'domain' query parameter."}, status=400)
        # Check domain
        if not api_key_obj.domains.filter(name=query_domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{query_domain}'")

        hibp_url = f"https://haveibeenpwned.com/api/v3/stealerlogsbywebsitedomain/{requests.utils.requote_uri(query_domain)}"
        headers = {"hibp-api-key": settings.HIBP_API_KEY}
        try:
            resp = requests.get(hibp_url, headers=headers)
            return Response(resp.json(), status=resp.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=502)


class StealerLogsByEmailDomainProxyView(APIView):
    """
    GET /api/stealer-logs-domain/
    - Uses the domain from the API key's first domain (or if there's only one).
    - Proxies to /stealerlogsbyemaildomain/{domain}.
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /stealerlogsbyemaildomain/{domain} on HIBP. "
            "Domain is derived from the API key’s domain list (requires at least one)."
        ),
        manual_parameters=[
            openapi.Parameter(
                name='X-API-Key', in_=openapi.IN_HEADER, type=openapi.TYPE_STRING, required=True
            ),
        ]
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        # If you want to pick the first domain in the M2M, or require exactly one domain, etc.
        domain_qs = api_key_obj.domains.all()
        if not domain_qs.exists():
            raise PermissionDenied("API key has no associated domains.")

        # For example, use the first domain in the set:
        domain_obj = domain_qs.first()
        domain_name = domain_obj.name

        hibp_url = f"https://haveibeenpwned.com/api/v3/stealerlogsbyemaildomain/{domain_name}"
        headers = {"hibp-api-key": settings.HIBP_API_KEY}
        try:
            resp = requests.get(hibp_url, headers=headers)
            return Response(resp.json(), status=resp.status_code)
        except requests.RequestException as e:
            return Response({"detail": str(e)}, status=502)
