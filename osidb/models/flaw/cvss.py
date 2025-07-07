import pghistory
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist
from django.db import models

from osidb.mixins import ACLMixinManager, TrackingMixin, TrackingMixinManager
from osidb.models.abstract import CVSS
from osidb.query_sets import CustomQuerySetUpdatedDt

from .flaw import Flaw


class FlawCVSSManager(ACLMixinManager, TrackingMixinManager):
    @staticmethod
    def create_cvss(flaw, issuer, version, **extra_fields):
        """return a new CVSS or update an existing CVSS without saving"""

        try:
            cvss = FlawCVSS.objects.get(flaw=flaw, issuer=issuer, version=version)

            for attr, value in extra_fields.items():
                setattr(cvss, attr, value)
            return cvss

        except ObjectDoesNotExist:
            return FlawCVSS(flaw=flaw, issuer=issuer, version=version, **extra_fields)


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    model_name="FlawCVSSAudit",
)
class FlawCVSS(CVSS):
    flaw = models.ForeignKey(
        Flaw, on_delete=models.CASCADE, blank=True, related_name="cvss_scores"
    )

    objects = FlawCVSSManager.from_queryset(CustomQuerySetUpdatedDt)()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "version", "issuer"], name="unique CVSS of a Flaw"
            ),
        ]
        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    def sync_to_trackers(self, jira_token):
        """Sync this CVSS in the related Jira trackers."""
        from osidb.models.tracker import Tracker

        for affect in self.flaw.affects.all():
            if affect.is_community:
                continue

            tracker = affect.tracker
            if (
                tracker
                and not tracker.is_closed
                and tracker.type == Tracker.TrackerType.JIRA
            ):
                # default save already sync with Jira when needed
                tracker.save(jira_token=jira_token)
