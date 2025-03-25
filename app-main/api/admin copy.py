from django.contrib import admin
from .models import APIKey, Domain

@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    """
    Admin config for the APIKey model:
    - 'group' is the ForeignKey to Django Group (replacing 'domain_group').
    - 'domains' is a ManyToMany field (replacing 'allowed_domain').
    """

    # Display:
    # 1) id
    # 2) group (formerly 'domain_group')
    # 3) a custom method that lists the domains
    # 4) hashed_key
    # 5) created_at
    list_display = ('id', 'group', 'domain_list', 'hashed_key', 'created_at')

    # We can still search by hashed_key, 
    # or if you prefer, by the text of domains, but that’s a bit more involved
    search_fields = ('hashed_key',)

    # We don't allow changes to hashed_key or created_at in the admin
    readonly_fields = ('hashed_key', 'created_at')

    def domain_list(self, obj):
        """Return a comma-separated string of domain names from the M2M 'domains' field."""
        return ", ".join([domain.name for domain in obj.domains.all()])
    domain_list.short_description = "Domains"


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    """
    Simple admin for the Domain model.
    """
    list_display = ('name',)
    search_fields = ('name',)
