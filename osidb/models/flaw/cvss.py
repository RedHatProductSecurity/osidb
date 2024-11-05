from decimal import Decimal

from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models

from osidb.mixins import ACLMixinManager, TrackingMixin, TrackingMixinManager
from osidb.models.abstract import CVSS

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


class FlawCVSS(CVSS):
    flaw = models.ForeignKey(
        Flaw, on_delete=models.CASCADE, blank=True, related_name="cvss_scores"
    )

    objects = FlawCVSSManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["flaw", "version", "issuer"], name="unique CVSS of a Flaw"
            ),
        ]
        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    def _validate_empty_impact_and_cvss_score(self, **kwargs):
        if not self.flaw.impact and self.cvss_object.base_score != Decimal("0.0"):
            raise ValidationError(
                {"cvss_score": ["CVSS score must be 0.0 for flaws with no impact"]}
            )
