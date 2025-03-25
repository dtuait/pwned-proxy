from django.contrib import admin, messages
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
    list_display = ('name',)
    search_fields = ('name',)
