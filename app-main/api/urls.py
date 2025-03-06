from django.urls import path
from .views import DomainBreachProxyView

urlpatterns = [
    path('breaches/', DomainBreachProxyView.as_view(), name='domain-breaches'),
]
