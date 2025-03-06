import uuid
import hashlib
from django.db import models
from django.contrib.auth.models import Group

def generate_api_key():
    """
    Returns a new, random UUID4 hex string.
    """
    return uuid.uuid4().hex

def hash_api_key(raw_key: str):
    """
    Hash the raw key (e.g. SHA256 or another algorithm).
    """
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

class APIKey(models.Model):
    """
    Each API key is tied to a specific domain_group (which corresponds to a Django Group).
    The raw key is NOT stored; only its hashed representation is.
    """
    domain_group = models.ForeignKey(
        Group, 
        on_delete=models.CASCADE,
        related_name='api_keys',
        null=True,
        blank=True
    )
    allowed_domain = models.CharField(max_length=255)
    hashed_key = models.CharField(max_length=64, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # If hashed_key or allowed_domain is None, provide a fallback
        domain_part = self.allowed_domain or "UnknownDomain"
        hashed_part = self.hashed_key or ""

        return f"{domain_part} - {hashed_part[:8]}..."
    @classmethod
    def create_api_key(cls, domain_group: Group, allowed_domain: str):
        """
        Create an APIKey instance by:
        1) Generating a random UUID-based raw key
        2) Hashing the raw key
        3) Saving the hashed key in the database
        4) Returning both the model instance and the raw key
        """
        raw_key = generate_api_key()
        new_key = cls.objects.create(
            domain_group=domain_group,
            allowed_domain=allowed_domain,
            hashed_key=hash_api_key(raw_key)
        )
        return new_key, raw_key
