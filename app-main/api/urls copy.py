# file: api/urls.py

from django.urls import path

from .views import (
    # Old / existing endpoints:
    StealerLogsProxyView,
    BreachedDomainProxyView,
    BreachedAccountProxyView,

    # New endpoints for HIBP API v3:
    PasteAccountProxyView,
    SubscribedDomainsProxyView,
    StealerLogsByEmailProxyView,
    StealerLogsByWebsiteDomainProxyView,
    StealerLogsByEmailDomainProxyView,
)

urlpatterns = [
    # === Old / existing routes ===
    # e.g. GET /api/stealer-logs/<domain>/
    path('stealer-logs/<str:domain>/', StealerLogsProxyView.as_view(), name='stealer-logs'),
    path('breached-domain/<str:domain>/', BreachedDomainProxyView.as_view(), name='breached-domain'),
    path('breached-account/<path:email>/', BreachedAccountProxyView.as_view(), name='breached-account'),

    # === New routes for extended HIBP v3 coverage ===

    # 1) Pastes for an account
    #    GET /api/paste-account/?email=<user@domain.com>
    path('paste-account/', PasteAccountProxyView.as_view(), name='paste-account'),

    # 2) Subscribed domains (domain search)
    #    GET /api/subscribed-domains/
    path('subscribed-domains/', SubscribedDomainsProxyView.as_view(), name='subscribed-domains'),

    # 3) Stealer logs by email
    #    GET /api/stealer-logs-email/?email=<user@domain.com>
    path('stealer-logs-email/', StealerLogsByEmailProxyView.as_view(), name='stealer-logs-by-email'),

    # 4) Stealer logs by website domain
    #    GET /api/stealer-logs-website/?domain=<mydomain.com>
    path('stealer-logs-website/', StealerLogsByWebsiteDomainProxyView.as_view(), name='stealer-logs-by-website'),

    # 5) Stealer logs by your email domain
    #    GET /api/stealer-logs-domain/
    path('stealer-logs-domain/', StealerLogsByEmailDomainProxyView.as_view(), name='stealer-logs-by-email-domain'),
]
