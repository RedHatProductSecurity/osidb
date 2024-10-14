import uuid

from django.core.exceptions import ObjectDoesNotExist
from django.db import models

from osidb.mixins import TrackingMixin, TrackingMixinManager

from .tracker import Tracker


class ErratumManager(TrackingMixinManager):
    """
    erratum manager
    """

    @staticmethod
    def create_erratum(et_id=None, **extra_fields):
        """
        return a new erratum or update an existing erratum without saving
        """
        assert et_id is not None, "Erratum ID must by provided"

        try:
            erratum = Erratum.objects.get(et_id=et_id)
            for attr, value in extra_fields.items():
                setattr(erratum, attr, value)
            return erratum
        except ObjectDoesNotExist:
            return Erratum(et_id=et_id, **extra_fields)


class Erratum(TrackingMixin):
    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    et_id = models.IntegerField(unique=True)  # Five-digit internal ID, e.g. 44547
    advisory_name = models.CharField(max_length=20, unique=True)  # E.g. RHSA-2019:2411

    # creation and last update timestamps are provided by the TrackingMixin
    # and the values are taken from the Errata Tool as the authoritative source
    shipped_dt = models.DateTimeField(null=True, blank=True)

    # An Erratum can fix many trackers, and a tracker can be fixed in multiple errata
    # For example, one erratum may fix a component on RHEL 7
    # And another erratum may fix the same component on RHEL 8
    # But all errata report the same Bugzilla / Jira tracker as "fixed"
    trackers = models.ManyToManyField(Tracker, related_name="errata")

    objects = ErratumManager()

    class Meta:
        verbose_name = "Erratum"
        verbose_name_plural = "Errata"

    def __str__(self):
        # self.advisory_name is already a str, below needed only to fix a warning
        return str(self.advisory_name)
