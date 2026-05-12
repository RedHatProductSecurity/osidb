import uuid

from django.contrib.postgres.indexes import GinIndex
from django.db import models

from osidb.mixins import (
    ACLMixin,
    ACLMixinManager,
    AlertMixin,
    TrackingMixin,
    TrackingMixinManager,
)
from osidb.query_sets import CustomQuerySetUpdatedDt

from .flaw import Flaw


class UpstreamDataManager(ACLMixinManager, TrackingMixinManager):
    """Manager for UpstreamData (mirrors FlawCVSSManager patterns)."""

    @staticmethod
    def ensure_for_flaw(
        flaw: Flaw, *, source: "UpstreamData.Source | None" = None
    ) -> "UpstreamData":
        """
        Return the upstream record for this flaw and source, creating an empty one if missing.
        """

        if source is None:
            source = UpstreamData.Source.OSV

        obj, _ = UpstreamData.objects.get_or_create(
            flaw=flaw,
            source=source,
            defaults={
                "upstream_purls": [],
                # "upstream_descriptions": [],
                # "upstream_severities": [],
                "acl_read": flaw.acl_read,
                "acl_write": flaw.acl_write,
            },
        )

        return obj


class UpstreamData(AlertMixin, ACLMixin, TrackingMixin):
    """
    OSV-derived and collector-managed upstream metadata attached to a flaw
    (purls, free-text descriptions, severity payloads).

    Shaped like FlawCVSS: optional ``blank`` FK to Flaw, plural ``related_name``,
    uniqueness on (flaw, source), and TrackingMixin + acl Gin indexes.
    """

    class Source(models.TextChoices):
        """
        Collector that populated this upstream record.

        Extend when a new upstream-data collector is introduced (mirrors Snippet.Source).
        """

        OSV = "OSV"
        CVEORG = "CVEORG"

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flaw = models.ForeignKey(
        Flaw,
        on_delete=models.CASCADE,
        blank=True,
        related_name="upstream_data",
    )

    upstream_purls = models.JSONField(default=list, blank=True)

    # Unused upstream fields that might be useful later (OSIDB-4953, OSIDB-4954)
    # upstream_descriptions = fields.ArrayField(
    #     models.TextField(blank=True), default=list, blank=True
    # )

    # upstream_severities = models.JSONField(default=list, blank=True)

    source = models.CharField(choices=Source.choices, max_length=10, blank=True)

    objects = UpstreamDataManager.from_queryset(CustomQuerySetUpdatedDt)()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "source"],
                name="unique_upstream_data_of_a_flaw",
            ),
        ]
        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]
