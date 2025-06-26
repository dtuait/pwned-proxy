# file: api/admin.py

from django.contrib import admin, messages
from django.core.management import call_command
from django.shortcuts import redirect
from django.urls import path

from .models import APIKey, Domain, generate_api_key, hash_api_key, EndpointLog

@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('id', 'group', 'domain_list', 'hashed_key', 'created_at')
    search_fields = ('hashed_key',)
    readonly_fields = ('hashed_key', 'created_at')
    filter_horizontal = ('domains',)

    def domain_list(self, obj):
        return ", ".join(d.name for d in obj.domains.all())
    domain_list.short_description = "Domains"

    def save_model(self, request, obj, form, change):
        if not change:  # brand-new APIKey
            raw_key = generate_api_key()
            obj.hashed_key = hash_api_key(raw_key)
            super().save_model(request, obj, form, change)
            self.message_user(request, f"Your new API key: {raw_key}", level=messages.SUCCESS)
        else:
            super().save_model(request, obj, form, change)


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    """
    This admin removes all add/change/delete permissions,
    leaving only the listing and the "Import from HIBP" action.
    """

    list_display = ('name', 'pwn_count', 'pwn_count_excluding_spam_lists')
    search_fields = ('name',)

    # 1) Use the custom template with the "Import from HIBP" button
    change_list_template = "admin/api/domain/change_list.html"

    # 2) Expose a custom URL for the import process
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path(
                "import-hibp/",
                self.admin_site.admin_view(self.import_from_hibp),
                name="api_domain_import_hibp"
            ),
        ]
        return custom_urls + urls

    # 3) The actual “import from HIBP” view
    def import_from_hibp(self, request):
        """
        Calls the custom management command that fetches and
        updates domains from the HIBP API, then redirects back
        to the domain list.
        """
        call_command("import_domain_data")
        self.message_user(request, "Domains imported from HIBP!")
        return redirect("..")

    # ------------------------------
    # Disable add, change, delete:
    # ------------------------------

    def has_view_permission(self, request, obj=None):
        # Allow viewing the changelist page
        return True

    def has_add_permission(self, request):
        # Disable "Add" button/link
        return False

    def has_change_permission(self, request, obj=None):
        # Disable changing/editing
        return False

    def has_delete_permission(self, request, obj=None):
        # Disable deletes
        return True



# file: api/admin.py

from django.contrib import admin, messages
from django.core.management import call_command
from django.shortcuts import redirect
from django.urls import path

from .models import APIKey, Domain, generate_api_key, hash_api_key, HIBPKey

@admin.register(HIBPKey)
class HIBPKeyAdmin(admin.ModelAdmin):
    """
    Allows admin users to add/remove HIBP API keys.
    """
    list_display = ('__str__', 'api_key', 'created_at')
    search_fields = ('api_key', 'description')


@admin.register(EndpointLog)
class EndpointLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'group', 'endpoint', 'status_code', 'success')
    list_filter = ('group', 'endpoint', 'success')
    readonly_fields = ('api_key', 'group', 'endpoint', 'status_code', 'success', 'created_at')




from django.contrib import admin, messages
from django.contrib.auth.models import Group
from django.contrib.auth.admin import GroupAdmin

from django.urls import path
from django.shortcuts import redirect
from django.http import HttpResponse
import csv

from .models import APIKey, Domain, EndpointLog

# 1) Unregister the default Group admin
admin.site.unregister(Group)

SEED_DATA = [
  {"domain": "aau.dk", "group": "Aalborg Universitet"},
  {"domain": "ruc.dk", "group": "Roskilde Universitet"},
  {"domain": "ku.dk",  "group": "Københavns Universitet"},
  {"domain": "nbi.dk", "group": "Niels Bohr Institutet"},
  {"domain": "itu.dk", "group": "IT-Universitetet i København"},
  {"domain": "dtu.dk", "group": "Danmarks Tekniske Universitet"},
  {"domain": "deic.dk","group": "Danish e-Infrastructure Cooperation"},
  {"domain": "cert.dk","group": "Danish e-Infrastructure Cooperation"},
  {"domain": "cbs.dk", "group": "Copenhagen Business School"}
]

@admin.register(Group)
class CustomGroupAdmin(GroupAdmin):
    """
    Extends the default Django Group admin so we can add a
    “Seed Groups” button/link in the changelist page.
    """
    change_list_template = "admin/auth/group/change_list.html"

    def get_urls(self):
        """
        Append our custom "seed-groups/" URL to the default GroupAdmin URLs.
        """
        urls = super().get_urls()
        custom = [
            path('seed-groups/', self.admin_site.admin_view(self.seed_groups), name='seed_groups'),
        ]
        return custom + urls

    def seed_groups(self, request):
        """
        If request.GET.get('confirmed') != '1', do nothing and just return.
        Otherwise:
          1. Overwrite (delete) the existing APIKeys for all the groups in SEED_DATA
          2. Create new APIKeys
          3. For each group, find subdomains that end with the domain and associate them
          4. Return a JSON file with the group name, raw key, and associated domains
        """
        from django.contrib import messages
        from django.shortcuts import redirect
        confirmed = request.GET.get('confirmed')
        if confirmed != '1':
            messages.warning(request, "Seed groups canceled.")
            return redirect("..")

        # 1) Gather the group names from SEED_DATA
        seed_group_names = [item["group"] for item in SEED_DATA]

        # 2) Delete existing APIKeys for those groups
        APIKey.objects.filter(group__name__in=seed_group_names).delete()

        # 3) Create new APIKeys, gather info
        result_list = []
        for item in SEED_DATA:
            group_name = item["group"]
            base_domain = item["domain"]

            group, _created = Group.objects.get_or_create(name=group_name)
            api_key_obj, raw_key = APIKey.create_api_key(group=group)

            # find all matching domains
            matching_domains = Domain.objects.filter(name__endswith=base_domain)
            api_key_obj.domains.add(*matching_domains)

            # Build a list of domain names
            domain_names = [d.name for d in matching_domains]

            # Append to our JSON data
            result_list.append({
                "group_name": group_name,
                "raw_key": raw_key,
                "domains": domain_names,
            })

        # 4) Return a JSON response (as a downloadable file)
        import json
        from django.http import HttpResponse

        response = HttpResponse(
            json.dumps(result_list, indent=2),  # pretty-print optional
            content_type='application/json'
        )
        response['Content-Disposition'] = 'attachment; filename="seeded_api_keys.json"'
        return response
