# api/urls.py

from django.urls import path
from .views import (
    CreateAPIKeyView,
    StealerLogsProxyView,
    BreachedDomainProxyView,
    BreachedAccountProxyView
)

urlpatterns = [
    path('create-key/', CreateAPIKeyView.as_view(), name='create-api-key'),
    path('stealer-logs/', StealerLogsProxyView.as_view(), name='stealer-logs'),
    path('breached-domain/', BreachedDomainProxyView.as_view(), name='breached-domain'),
    path('breached-account/<path:email>', BreachedAccountProxyView.as_view(), name='breached-account'),
]
