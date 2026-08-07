import uuid

from django.contrib.postgres.indexes import GinIndex
from django.db import models
from packageurl import PackageURL

from apps.ace.constants import OSV_ECOSYSTEM_MAP
from osidb.mixins import (
    ACLMixin,
    AlertMixin,
    TrackingMixin,
    TrackingMixinManager,
)
from osidb.query_sets import CustomQuerySetUpdatedDt

from .flaw import Flaw


class UpstreamDataManager(TrackingMixinManager):
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
                "acl_read": flaw.acl_read,
                "acl_write": flaw.acl_write,
            },
        )

        return obj


class UpstreamData(AlertMixin, ACLMixin, TrackingMixin):
    """
    OSV-derived and collector-managed upstream package metadata attached to a flaw.

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

    source = models.CharField(choices=Source.choices, max_length=10, blank=True)

    objects = UpstreamDataManager.from_queryset(CustomQuerySetUpdatedDt)()

    @property
    def component_ecosystems(self) -> dict[str, list[str]]:
        """
        Create a mapping of component names to ecosystems derived from upstream PURLs.

        PURL type strings are used directly when available, falling back to OSV ecosystem
        string when PURL parsing fails. A component may appear in multiple ecosystems.
        """
        result: dict[str, list[str]] = {}
        if not self.upstream_purls:
            return result

        for entry in self.upstream_purls:
            name = (entry.get("name") or "").strip().lower()
            if not name:
                continue

            ecosystem = ""
            purl_str = entry.get("purl", "")
            if purl_str:
                try:
                    ecosystem = PackageURL.from_string(purl_str).type
                except ValueError:
                    pass

            if not ecosystem:
                raw_eco = (entry.get("ecosystem") or "").lower()
                ecosystem = OSV_ECOSYSTEM_MAP.get(raw_eco, "")

            if ecosystem and ecosystem not in result.get(name, []):
                result.setdefault(name, []).append(ecosystem)

        return result

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
