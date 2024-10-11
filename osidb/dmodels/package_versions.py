import uuid

from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from polymorphic.models import PolymorphicModel

from apps.bbsync.mixins import BugzillaSyncMixin
from osidb.dmodels.flaw.flaw import Flaw
from osidb.mixins import (
    ACLMixin,
    ACLMixinManager,
    AlertMixin,
    TrackingMixin,
    TrackingMixinManager,
)


class VersionStatus(models.TextChoices):
    AFFECTED = "AFFECTED"
    UNAFFECTED = "UNAFFECTED"
    UNKNOWN = "UNKNOWN"


class Version(PolymorphicModel):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        """define meta"""

        verbose_name = "Old Version"

    def validate(self, *args, **kwargs):
        """validate versionRange model"""
        super().clean_fields(*args, **kwargs)


# See CVE v5 reporting schema
# https://gist.github.com/rsc/0b448f99e73bf745eeca1319d882efb2#versions-and-version-ranges
class CVEv5Version(Version):
    """
    Model representing a package version

    This model is deprecated. Use PackageVer instead. Delete when it's clear
    that PackageVer works correctly.
    """

    # TODO add type and comparison fields
    # We didn't add it yet because exisiting BZ data is not accurate
    # enough to determine type (eg. semver, rpm) consistently
    # should should be based on collection_url or entered manually

    version = models.CharField(max_length=1024)

    status = models.CharField(choices=VersionStatus.choices, max_length=20)


class PackageVersions(PolymorphicModel):
    """
    This model is deprecated. Use Package instead. Delete when it's clear
    that Package works correctly.
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flaw = models.ForeignKey(
        Flaw,
        related_name="old_package_versions",
        on_delete=models.CASCADE,
    )

    versions = models.ManyToManyField(Version)

    class Meta:
        """define meta"""

        verbose_name = "Old Package Versions"

    def validate(self, *args, **kwargs):
        """validate package versions model"""
        super().clean_fields(*args, **kwargs)


class CVEv5PackageVersions(PackageVersions):
    """
    This model is deprecated. Use Package instead. Delete when it's clear
    that Package works correctly.
    """

    # the name of the affected upstream package within collection_url
    # will be reported to Mitre as packageName
    # see https://gist.github.com/rsc/0b448f99e73bf745eeca1319d882efb2#product-objects
    package = models.CharField(max_length=2058)

    default_status = models.CharField(
        choices=VersionStatus.choices, max_length=1024, default=VersionStatus.UNAFFECTED
    )

    def validate(self, *args, **kwargs):
        """validate package versions model"""
        super().clean_fields(*args, **kwargs)


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

    objects = PackageManager()

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

    package = models.ForeignKey(
        Package,
        related_name="versions",
        on_delete=models.CASCADE,
    )

    class Meta:
        verbose_name = "Version"

    version = models.CharField(max_length=1024)
