# api/views.py
import requests
from django.contrib.auth.models import Group
from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from urllib.parse import urlencode

from .models import APIKey, Domain
from .utils import get_hibp_key


# ---------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------

USER_AGENT = "pwned_proxy_app/1.0"


def hibp_get(path: str):
    """
    Convenience wrapper around requests.get with the correct headers.

    Example:
        resp = hibp_get(f"breacheddomain/{domain}")
    """
    url = f"https://haveibeenpwned.com/api/v3/{path.lstrip('/')}"
    headers = {
        "hibp-api-key": get_hibp_key(),
        "User-Agent": USER_AGENT,
    }
    return requests.get(url, headers=headers)


def make_response(resp: requests.Response) -> Response:
    """Create a DRF Response from a requests.Response, forwarding JSON/text and
    select headers."""
    try:
        data = resp.json()
    except ValueError:
        data = resp.text
    headers = {}
    if "Retry-After" in resp.headers:
        headers["Retry-After"] = resp.headers["Retry-After"]
    return Response(data, status=resp.status_code, headers=headers)


# ---------------------------------------------------------------------
# Proxy endpoints
# ---------------------------------------------------------------------


class BreachedDomainProxyView(APIView):
    """
    GET /api/v3/breacheddomain/{domain}
    """

    @swagger_auto_schema(
        operation_description="Proxy to /breacheddomain/{domain} on HIBP.",
        manual_parameters=[
            openapi.Parameter(
                name="domain",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description="Domain to query (e.g. dtu.dk).",
            ),
            openapi.Parameter(
                name="hibp-api-key",
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=False,
            ),
        ],
    )
    def get(self, request, domain: str = None):
        if not isinstance(request.auth, APIKey):
            return Response({"detail": "No valid API key provided."}, status=401)

        api_key_obj = request.auth
        if not api_key_obj.domains.filter(name=domain).exists():
            raise PermissionDenied(f"API key not authorized for domain '{domain}'")

        resp = hibp_get(f"breacheddomain/{domain}")
        return make_response(resp)


class BreachedAccountProxyView(APIView):
    """
    GET /api/v3/breachedaccount/{account}
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /breachedaccount/{account} on HIBP. "
            "Email domain must be authorised."
        ),
        manual_parameters=[
            openapi.Parameter(
                name="account",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description="Email address, e.g. user@dtu.dk",
            ),
            openapi.Parameter(
                name="hibp-api-key",
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=False,
            ),
        ],
        responses={200: "Success", 404: "No record"},
    )
    def get(self, request, account: str = None):
        if not isinstance(request.auth, APIKey):
            return Response({"detail": "No valid API key provided."}, status=401)

        if not account:
            return Response({"detail": "No email specified."}, status=400)

        try:
            local, email_domain = account.rsplit("@", 1)
        except ValueError:
            return Response({"detail": "Invalid email format."}, status=400)

        api_key_obj = request.auth
        if not api_key_obj.domains.filter(name=email_domain).exists():
            raise PermissionDenied(
                f"API key not authorised for domain '{email_domain}'"
            )

        resp = hibp_get(f"breachedaccount/{requests.utils.requote_uri(account)}")
        return make_response(resp)


# ---------------------------------------------------------------------
# Extended HIBP v3 coverage
# ---------------------------------------------------------------------


class PasteAccountProxyView(APIView):
    """GET /api/v3/pasteaccount/{account}"""

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /pasteaccount/{account} on HIBP. "
            "Email domain must be authorised."
        ),
        manual_parameters=[
            openapi.Parameter(
                name="account",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description="Email to search in pastes.",
            ),
            openapi.Parameter(
                name="hibp-api-key",
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request, account: str = None):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        if not account:
            return Response({"detail": "Missing 'email' parameter."}, status=400)

        try:
            local, email_domain = account.rsplit("@", 1)
        except ValueError:
            return Response({"detail": "Invalid email format."}, status=400)

        if not api_key_obj.domains.filter(name=email_domain).exists():
            raise PermissionDenied(f"API key not authorised for '{email_domain}'")

        resp = hibp_get(f"pasteaccount/{requests.utils.requote_uri(account)}")
        return make_response(resp)


class SubscribedDomainsProxyView(APIView):
    """
    GET /api/v3/subscribeddomains
    """

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /subscribeddomains on HIBP. "
            "Filtered to the domains associated with the caller's API key."
        ),
        manual_parameters=[
            openapi.Parameter(
                name="hibp-api-key",
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        allowed = set(
            api_key_obj.domains.values_list("name", flat=True)
        )  # e.g. {"dtu.dk", ...}

        resp = hibp_get("subscribeddomains")
        if resp.status_code != 200:
            return make_response(resp)

        data = resp.json()
        filtered = [
            item for item in data if item.get("DomainName", "").lower() in allowed
        ]
        return Response(filtered, status=200)


class StealerLogsByEmailProxyView(APIView):
    """
    GET /api/v3/stealer-logs-email?email=<user@domain.com>
    """

    @swagger_auto_schema(
        operation_description="Proxy to /stealerlogsbyemail/{email} on HIBP.",
        manual_parameters=[
            openapi.Parameter(
                name="email",
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                name="hibp-api-key",
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        email = request.query_params.get("email")
        if not email:
            return Response({"detail": "Missing 'email' parameter."}, status=400)

        try:
            local, email_domain = email.rsplit("@", 1)
        except ValueError:
            return Response({"detail": "Invalid email format."}, status=400)

        if not api_key_obj.domains.filter(name=email_domain).exists():
            raise PermissionDenied(f"API key not authorised for '{email_domain}'")

        resp = hibp_get(f"stealerlogsbyemail/{requests.utils.requote_uri(email)}")
        return make_response(resp)


class StealerLogsByWebsiteDomainProxyView(APIView):
    """
    GET /api/v3/stealer-logs-website?domain=<mydomain.com>
    """

    @swagger_auto_schema(
        operation_description="Proxy to /stealerlogsbywebsitedomain/{domain} on HIBP.",
        manual_parameters=[
            openapi.Parameter(
                name="domain",
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                name="hibp-api-key",
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        domain = request.query_params.get("domain")
        if not domain:
            return Response({"detail": "Missing 'domain' parameter."}, status=400)

        if not api_key_obj.domains.filter(name=domain).exists():
            raise PermissionDenied(f"API key not authorised for '{domain}'")

        resp = hibp_get(
            f"stealerlogsbywebsitedomain/{requests.utils.requote_uri(domain)}"
        )
        return make_response(resp)


class StealerLogsByEmailDomainProxyView(APIView):
    """
    GET /api/v3/stealer-logs-domain
    (uses the first domain linked to the caller's API key)
    """

    @swagger_auto_schema(
        operation_description="Proxy to /stealerlogsbyemaildomain/{domain} on HIBP.",
        manual_parameters=[
            openapi.Parameter(
                name="hibp-api-key",
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request):
        api_key_obj = request.auth
        if not api_key_obj:
            return Response({"detail": "No valid API key."}, status=401)

        domain_obj = api_key_obj.domains.first()
        if not domain_obj:
            raise PermissionDenied("API key has no associated domains.")

        resp = hibp_get(f"stealerlogsbyemaildomain/{domain_obj.name}")
        return make_response(resp)


class AllBreachesProxyView(APIView):
    """GET /api/v3/breaches"""

    @swagger_auto_schema(
        operation_description=(
            "Proxy to /breaches on HIBP. Supports optional Domain and"
            " IsSpamList query parameters."
        ),
        manual_parameters=[
            openapi.Parameter(
                name="Domain",
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                required=False,
            ),
            openapi.Parameter(
                name="IsSpamList",
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_BOOLEAN,
                required=False,
            ),
        ],
    )
    def get(self, request):
        query = {}
        if "Domain" in request.query_params:
            query["Domain"] = request.query_params["Domain"]
        if "IsSpamList" in request.query_params:
            query["IsSpamList"] = request.query_params["IsSpamList"]
        path = "breaches"
        if query:
            path += f"?{urlencode(query)}"
        resp = hibp_get(path)
        return make_response(resp)


class SingleBreachProxyView(APIView):
    """GET /api/v3/breach/{name}"""

    @swagger_auto_schema(
        operation_description="Proxy to /breach/{name} on HIBP.",
        manual_parameters=[
            openapi.Parameter(
                name="name",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_STRING,
                required=True,
                description="Breach name, e.g. Adobe",
            ),
        ],
    )
    def get(self, request, name: str = None):
        resp = hibp_get(f"breach/{requests.utils.requote_uri(name)}")
        return make_response(resp)


class LatestBreachProxyView(APIView):
    """GET /api/v3/latestbreach"""

    @swagger_auto_schema(operation_description="Proxy to /latestbreach on HIBP.")
    def get(self, request):
        resp = hibp_get("latestbreach")
        return make_response(resp)


class DataClassesProxyView(APIView):
    """GET /api/v3/dataclasses"""

    @swagger_auto_schema(operation_description="Proxy to /dataclasses on HIBP.")
    def get(self, request):
        resp = hibp_get("dataclasses")
        return make_response(resp)


class SubscriptionStatusProxyView(APIView):
    """GET /api/v3/subscription/status"""

    @swagger_auto_schema(
        operation_description="Proxy to /subscription/status on HIBP.",
        manual_parameters=[
            openapi.Parameter(
                name="hibp-api-key",
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
    )
    def get(self, request):
        if not request.auth:
            return Response({"detail": "No valid API key."}, status=401)
        resp = hibp_get("subscription/status")
        return make_response(resp)
