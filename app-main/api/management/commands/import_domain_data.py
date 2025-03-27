# file: app-main/api/management/commands/import_domain_data.py

import json
import urllib.request
import urllib.error
from django.core.management.base import BaseCommand
from django.utils.dateparse import parse_datetime

from api.models import Domain

# Optionally, you might load the API key from settings or env variables
HAVEIBEENPWNED_API_KEY = "SECRET"
API_URL = "https://haveibeenpwned.com/api/v3/subscribeddomains"

class Command(BaseCommand):
    help = "Import or update domain records from the haveibeenpwned API, and remove any domains not found."

    def handle(self, *args, **options):
        # 1) Fetch the JSON from the remote API
        try:
            req = urllib.request.Request(
                API_URL,
                headers={
                    "hibp-api-key": HAVEIBEENPWNED_API_KEY,
                    # Only include the cookie if absolutely necessary; often it is not needed:
                    # "Cookie": "__cf_bm=zFzrNvqPVQQB5tpa9LXzzbgEPleC6R5iaI2bK15t41w-1743066809-1.0.1.1-aH9URPoMOmYv51cCJexVEdxfzkpPTOoZBiaP49QZDV1qyoHERolMYw8U2JqgwS7IBDY3npZRaAB4px5SoPDlnLNr_G7DGPZY2LhJtZXkE.8"
                }
            )
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as e:
            self.stderr.write(self.style.ERROR(f"Error fetching domains from the API: {e}"))
            return

        # 2) Build a set of domain names returned by the API (for removal of old ones)
        returned_domain_names = set()

        # 3) Loop over the data and update_or_create each domain
        for domain_data in data:
            domain_name = domain_data["DomainName"]
            pwn_count = domain_data["PwnCount"]
            pwn_excl = domain_data["PwnCountExcludingSpamLists"]
            pwn_renewal = domain_data["PwnCountExcludingSpamListsAtLastSubscriptionRenewal"]
            renewal_str = domain_data["NextSubscriptionRenewal"]

            # Parse the date/time string if present
            next_renewal = None
            if renewal_str is not None:
                next_renewal = parse_datetime(renewal_str)

            returned_domain_names.add(domain_name)

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

        # 4) Remove any domains **not** in the returned list
        #    (This also removes them from any M2M relationships, e.g. APIKey.domains)
        deleted_count, _ = Domain.objects.exclude(name__in=returned_domain_names).delete()
        if deleted_count > 0:
            self.stdout.write(
                self.style.WARNING(f"Deleted {deleted_count} domain(s) not in API results.")
            )

        self.stdout.write(self.style.SUCCESS("Finished importing domain data from API."))
