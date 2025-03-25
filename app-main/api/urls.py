from django.urls import path
from .views import (
    CreateAPIKeyView,
    StealerLogsProxyView,
    BreachedDomainProxyView,
    BreachedAccountProxyView
)

urlpatterns = [
    path('create-key/', CreateAPIKeyView.as_view(), name='create-api-key'),
    # Note: we capture the domain in the URL
    path('stealer-logs/<str:domain>/', StealerLogsProxyView.as_view(), name='stealer-logs'),
    path('breached-domain/<str:domain>/', BreachedDomainProxyView.as_view(), name='breached-domain'),
    path('breached-account/<path:email>', BreachedAccountProxyView.as_view(), name='breached-account'),
]
