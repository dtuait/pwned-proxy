# api/urls.py
from django.urls import path

from .views import (
    # Core proxies
    BreachedDomainProxyView,
    BreachedAccountProxyView,
    # Extended HIBP v3
    PasteAccountProxyView,
    SubscribedDomainsProxyView,
    StealerLogsByEmailProxyView,
    StealerLogsByWebsiteDomainProxyView,
    StealerLogsByEmailDomainProxyView,
)

urlpatterns = [
    # Core
    path("breached-domain/<str:domain>/", BreachedDomainProxyView.as_view(), name="breached-domain"),
    path("breached-account/<path:email>/", BreachedAccountProxyView.as_view(), name="breached-account"),

    # Extended
    path("paste-account/", PasteAccountProxyView.as_view(), name="paste-account"),
    path("subscribed-domains/", SubscribedDomainsProxyView.as_view(), name="subscribed-domains"),
    path("stealer-logs-email/", StealerLogsByEmailProxyView.as_view(), name="stealer-logs-by-email"),
    path("stealer-logs-website/", StealerLogsByWebsiteDomainProxyView.as_view(), name="stealer-logs-by-website"),
    path("stealer-logs-domain/", StealerLogsByEmailDomainProxyView.as_view(), name="stealer-logs-by-email-domain"),
]
