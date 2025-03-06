# api/admin.py

from django.contrib import admin
from .models import APIKey

@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ('id', 'domain_group', 'allowed_domain', 'hashed_key', 'created_at')
    search_fields = ('allowed_domain', 'hashed_key')
    readonly_fields = ('hashed_key', 'created_at')
