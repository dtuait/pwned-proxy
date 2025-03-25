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
    Hash the raw key (e.g. using SHA256).
    """
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class Domain(models.Model):
    """
    A simple model for storing domain names.
    For example:
       name = "dtu.dk"
    """
    name = models.CharField(max_length=255, unique=True)

    pwn_count = models.IntegerField(null=True, blank=True)
    pwn_count_excluding_spam_lists = models.IntegerField(null=True, blank=True)
    pwn_count_excluding_spam_lists_at_last_subscription_renewal = models.IntegerField(null=True, blank=True)
    next_subscription_renewal = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.name


class APIKey(models.Model):
    """
    Each API key:
      - Belongs to one Django Group.
      - Has a hashed_key in the DB (raw key is never stored).
      - Can be associated with multiple domains via 'domains'.

    Example usage in the shell:
      group = Group.objects.get(name='IT Department')
      domains = [Domain.objects.get_or_create(name='dtu.dk')[0],
                 Domain.objects.get_or_create(name='cert.dk')[0]]

      api_key_obj, raw_key = APIKey.create_api_key(
          group=group,
          domain_list=domains
      )
    """
    group = models.ForeignKey(
        Group,
        on_delete=models.CASCADE,
        related_name='api_keys',
        null=True,
        blank=True
    )
    # Instead of a single "allowed_domain" CharField, now we allow many:
    domains = models.ManyToManyField(Domain, blank=True)

    hashed_key = models.CharField(max_length=64, unique=True, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        # Show partial hash and how many domains
        domain_count = self.domains.count()
        return f"APIKey {self.hashed_key[:8]}... ({domain_count} domains)"


    def save(self, *args, **kwargs):
        """
        Automatically generate a random hash if there's no hashed_key.
        Note: This won't show the raw key in the admin. The admin user only sees the hashed value.
        """
        super().save(*args, **kwargs)

    @classmethod
    def create_api_key(cls, group: Group, domain_list=None):
        """
        Create an APIKey instance by:
          1) Generating a random raw key
          2) Hashing the raw key
          3) Creating the APIKey object
          4) Linking the specified 'domain_list' (list of Domain objs)
          5) Returning (api_key_obj, raw_key)

        :param group: The Django Group that will own this key.
        :param domain_list: A list of Domain model instances (optional).
        :returns: (APIKey object, raw_key string)
        """
        if domain_list is None:
            domain_list = []

        # 1) Generate random raw key (UUID4 hex)
        raw_key = generate_api_key()

        # 2) Hash it
        hashed = hash_api_key(raw_key)

        # 3) Create the APIKey record
        new_key = cls.objects.create(
            group=group,
            hashed_key=hashed
        )

        # 4) Link M2M domains, if provided
        if domain_list:
            new_key.domains.set(domain_list)  # can be a list of Domain objects

        return new_key, raw_key
