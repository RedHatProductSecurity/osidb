from decimal import Decimal

import pghistory
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
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

    def _validate_rh_cvss3_and_impact(self, **kwargs):
        """
        Validate that flaw's RH CVSSv3 score and impact comply with the following:
        * RH CVSSv3 score is not zero and flaw impact is set
        * RH CVSSv3 score is zero and flaw impact is not set
        """
        if (
            self.issuer == self.CVSSIssuer.REDHAT
            and self.version == self.CVSSVersion.VERSION3
        ):
            if self.flaw.impact and self.cvss_object.base_score == Decimal("0.0"):
                raise ValidationError(
                    "RH CVSSv3 score must not be zero if flaw impact is set."
                )
            if not self.flaw.impact and self.cvss_object.base_score != Decimal("0.0"):
                raise ValidationError(
                    "RH CVSSv3 score must be zero if flaw impact is not set."
                )
