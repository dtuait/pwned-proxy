from django.urls import path
from .views import DomainBreachProxyView
from .views import CreateAPIKeyView
from .views import DomainInfoView
from .views import StealerLogsProxyView

urlpatterns = [
    path('breaches/', DomainBreachProxyView.as_view(), name='domain-breaches'),
    path('create-key/', CreateAPIKeyView.as_view(), name='create-api-key'),
    path('domain-info/', DomainInfoView.as_view(), name='domain-info'),
    path('stealer-logs/', StealerLogsProxyView.as_view(), name='stealer-logs'),
]


