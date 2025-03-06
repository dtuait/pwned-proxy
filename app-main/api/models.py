import secrets
from django.db import models

class APIKey(models.Model):
    key = models.CharField(max_length=64, unique=True, default=secrets.token_urlsafe)
    allowed_domain = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.allowed_domain} - {self.key[:8]}..."
