import uuid

from django.db import models

from osidb.mixins import NullStrFieldsMixin, ValidateMixin


class JiraUserMapping(NullStrFieldsMixin, ValidateMixin):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Red Hat associate Kerberos ID (mutable, but used for lookups)
    associate_kerberos_id = models.CharField(max_length=255, db_index=True)

    # Immutable external UUID for the associate
    associate_uuid = models.UUIDField(unique=True)

    # Jira Cloud ID
    atlassian_cloud_id = models.CharField(max_length=255)

    # Whether the associate is currently employed
    is_employed = models.BooleanField(default=True)

    # Full name
    name = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["associate_kerberos_id"]

    @classmethod
    def kerberos_to_cloud_id(cls, kerberos_id):
        """Look up the Atlassian Cloud accountId for a given Kerberos ID."""
        return cls.objects.get(associate_kerberos_id=kerberos_id).atlassian_cloud_id

    @classmethod
    def cloud_id_to_kerberos(cls, cloud_id):
        """Look up the Kerberos ID for a given Atlassian Cloud accountId."""
        return cls.objects.get(atlassian_cloud_id=cloud_id).associate_kerberos_id

    def __str__(self):
        return f"{self.associate_kerberos_id} -> {self.atlassian_cloud_id}"
