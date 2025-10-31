import uuid

from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist
from django.db import models

from apps.bbsync.mixins import BugzillaSyncMixin
from osidb.mixins import (
    ACLMixin,
    ACLMixinManager,
    AlertMixin,
    TrackingMixin,
    TrackingMixinManager,
)
from osidb.query_sets import CustomQuerySetUpdatedDt

from .flaw.flaw import Flaw


class VersionStatus(models.TextChoices):
    AFFECTED = "AFFECTED"
    UNAFFECTED = "UNAFFECTED"
    UNKNOWN = "UNKNOWN"


class PackageManager(ACLMixinManager, TrackingMixinManager):
    @staticmethod
    def create_package(flaw, package, **extra_fields):
        """
        Return a new Package, or update an existing Package without saving.
        Unlike other similar manager methods in this file, new Package
        instance is saved into database to allow relationships with PackageVer.
        """
        try:
            package = Package.objects.get(flaw=flaw, package=package)
            for attr, value in extra_fields.items():
                setattr(package, attr, value)
        except ObjectDoesNotExist:
            package = Package(flaw=flaw, package=package, **extra_fields)
            package.save()
        return package


class Package(AlertMixin, ACLMixin, BugzillaSyncMixin, TrackingMixin):
    """
    Model representing a package with connected versions.

    The model's structure allows future extensibility with features from the CVE 5.0 schema.
    Currently, it tracks only versions corresponding to bugzilla fixed_in field, which correspond to
    CVE 5.0's `"status": "unaffected"`.
    References:
    - https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/docs/versions.md
    - https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json
    """

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flaw = models.ForeignKey(
        Flaw,
        related_name="package_versions",
        on_delete=models.CASCADE,
    )

    package = models.CharField(max_length=2048)

    objects = PackageManager.from_queryset(CustomQuerySetUpdatedDt)()

    def bzsync(self, *args, bz_api_key, **kwargs):
        """
        Bugzilla sync of the Package instance and linked PackageVer instances.
        """
        self.save()
        # needs to be synced through flaw
        self.flaw.save(*args, **kwargs)

    class Meta:
        """define meta"""

        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]


class PackageVer(models.Model):
    """Model representing a package version"""

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    version = models.CharField(max_length=1024)

    package = models.ForeignKey(
        Package,
        related_name="versions",
        on_delete=models.CASCADE,
    )

    class Meta:
        verbose_name = "Version"
