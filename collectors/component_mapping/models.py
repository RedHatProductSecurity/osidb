from django.db import models


class BlocklistEntry(models.Model):
    name = models.CharField(max_length=512, unique=True)
    reason = models.TextField()

    class Meta:
        app_label = "component_mapping"


class ComponentMapEntry(models.Model):
    name = models.CharField(max_length=512, unique=True)
    upstream_packages = models.JSONField()

    class Meta:
        app_label = "component_mapping"


class StrictPackage(models.Model):
    name = models.CharField(max_length=512, unique=True)
    repos = models.JSONField(default=list)

    class Meta:
        app_label = "component_mapping"


class StrictNpmPackage(models.Model):
    name = models.CharField(max_length=512, unique=True)

    class Meta:
        app_label = "component_mapping"


class AmbiguousNpmPackage(models.Model):
    name = models.CharField(max_length=512, unique=True)

    class Meta:
        app_label = "component_mapping"


class CrossEcosystemName(models.Model):
    name = models.CharField(max_length=512, unique=True)
    ecosystems = models.JSONField(default=list)

    class Meta:
        app_label = "component_mapping"


class VerifiedMapping(models.Model):
    name = models.CharField(max_length=512, unique=True)
    upstream_package = models.CharField(max_length=512)

    class Meta:
        app_label = "component_mapping"


class SemiStrictReviewEntry(models.Model):
    name = models.CharField(max_length=512, unique=True)
    data = models.JSONField()

    class Meta:
        app_label = "component_mapping"


class RejectedComponent(models.Model):
    name = models.CharField(max_length=512, unique=True)
    data = models.JSONField(default=dict)

    class Meta:
        app_label = "component_mapping"


class PackageScope(models.Model):
    """Exhaustive component inclusion list for an update stream."""

    ps_update_stream = models.CharField(max_length=100, unique=True)
    components = models.JSONField(default=list)

    class Meta:
        app_label = "component_mapping"
