from django.test import SimpleTestCase
from django.urls import reverse, resolve

from api import views

class URLPatternsTest(SimpleTestCase):
    def test_all_endpoints_resolve(self):
        tests = [
            ("breached-domain", {"domain": "dtu.dk"}, views.BreachedDomainProxyView),
            ("breached-account", {"email": "user@dtu.dk"}, views.BreachedAccountProxyView),
            ("paste-account", {}, views.PasteAccountProxyView),
            ("subscribed-domains", {}, views.SubscribedDomainsProxyView),
            ("stealer-logs-by-email", {}, views.StealerLogsByEmailProxyView),
            ("stealer-logs-by-website", {}, views.StealerLogsByWebsiteDomainProxyView),
            ("stealer-logs-by-email-domain", {}, views.StealerLogsByEmailDomainProxyView),
            ("breaches", {}, views.AllBreachesProxyView),
            ("single-breach", {"name": "Example"}, views.SingleBreachProxyView),
            ("latest-breach", {}, views.LatestBreachProxyView),
            ("data-classes", {}, views.DataClassesProxyView),
            ("subscription-status", {}, views.SubscriptionStatusProxyView),
        ]
        for name, kwargs, view in tests:
            with self.subTest(name=name):
                url = reverse(name, kwargs=kwargs)
                resolver = resolve(url)
                self.assertEqual(resolver.func.view_class, view)
