# file: api/admin.py

from django.contrib import admin, messages
from django.core.management import call_command
from django.shortcuts import redirect
from django.urls import path

from .models import APIKey, Domain, generate_api_key, hash_api_key

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
