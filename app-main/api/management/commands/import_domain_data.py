import json
from datetime import datetime
from django.core.management.base import BaseCommand
from django.utils.dateparse import parse_datetime

from api.models import Domain

DOMAINS_JSON = [
    {
        "DomainName": "adm.ku.dk",
        "PwnCount": 632,
        "PwnCountExcludingSpamLists": 606,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": 541,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    },
    {
        "DomainName": "cbs.dk",
        "PwnCount": 21212,
        "PwnCountExcludingSpamLists": 5406,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": 3715,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    },
    {
        "DomainName": "cert.dk",
        "PwnCount": None,
        "PwnCountExcludingSpamLists": None,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": None,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    },
    {
        "DomainName": "deic.dk",
        "PwnCount": 45,
        "PwnCountExcludingSpamLists": 41,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": 31,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    },
    {
        "DomainName": "dtu.dk",
        "PwnCount": 6092,
        "PwnCountExcludingSpamLists": 5553,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": 5553,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    },
    {
        "DomainName": "itu.dk",
        "PwnCount": 8912,
        "PwnCountExcludingSpamLists": 4074,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": 3618,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    },
    {
        "DomainName": "nbi.dk",
        "PwnCount": 420,
        "PwnCountExcludingSpamLists": 386,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": 386,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    },
    {
        "DomainName": "nbi.ku.dk",
        "PwnCount": 107,
        "PwnCountExcludingSpamLists": 103,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": 103,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    },
    {
        "DomainName": "ruc.dk",
        "PwnCount": 9550,
        "PwnCountExcludingSpamLists": 9317,
        "PwnCountExcludingSpamListsAtLastSubscriptionRenewal": 8280,
        "NextSubscriptionRenewal": "2025-03-28T11:18:21"
    }
]


class Command(BaseCommand):
    help = "Import or update domain records from a predefined JSON list."

    def handle(self, *args, **options):
        for domain_data in DOMAINS_JSON:
            domain_name = domain_data["DomainName"]
            pwn_count = domain_data["PwnCount"]
            pwn_excl = domain_data["PwnCountExcludingSpamLists"]
            pwn_renewal = domain_data["PwnCountExcludingSpamListsAtLastSubscriptionRenewal"]
            renewal_str = domain_data["NextSubscriptionRenewal"]

            # Parse the date/time string if not None
            next_renewal = None
            if renewal_str is not None:
                next_renewal = parse_datetime(renewal_str)

            obj, created = Domain.objects.update_or_create(
                name=domain_name,
                defaults={
                    "pwn_count": pwn_count,
                    "pwn_count_excluding_spam_lists": pwn_excl,
                    "pwn_count_excluding_spam_lists_at_last_subscription_renewal": pwn_renewal,
                    "next_subscription_renewal": next_renewal,
                },
            )

            if created:
                self.stdout.write(self.style.SUCCESS(f"Created domain: {domain_name}"))
            else:
                self.stdout.write(self.style.WARNING(f"Updated domain: {domain_name}"))

        self.stdout.write(self.style.SUCCESS("Finished importing domain data."))

