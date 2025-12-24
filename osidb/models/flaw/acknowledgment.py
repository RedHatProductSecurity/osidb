import uuid

import pghistory
from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import models

from apps.bbsync.mixins import BugzillaSyncMixin
from osidb.mixins import (
    ACLMixin,
    ACLMixinManager,
    AlertMixin,
    TrackingMixin,
    TrackingMixinManager,
    validator,
)
from osidb.query_sets import CustomQuerySetUpdatedDt

from .flaw import Flaw
from .source import FlawSource


class FlawAcknowledgmentManager(ACLMixinManager, TrackingMixinManager):
    """flaw acknowledgment manager"""

    @staticmethod
    def create_flawacknowledgment(flaw, name, affiliation, **extra_fields):
        """return a new flaw acknowledgment or update an existing flaw acknowledgment without saving"""
        try:
            flawacknowledgment = FlawAcknowledgment.objects.get(
                flaw=flaw,
                name=name,
                affiliation=affiliation,
            )
            for attr, value in extra_fields.items():
                setattr(flawacknowledgment, attr, value)
            return flawacknowledgment

        except ObjectDoesNotExist:
            return FlawAcknowledgment(
                flaw=flaw,
                name=name,
                affiliation=affiliation,
                **extra_fields,
            )


@pghistory.track(
    pghistory.InsertEvent(),
    pghistory.UpdateEvent(),
    pghistory.DeleteEvent(),
    model_name="FlawAcknowledgmentAudit",
)
class FlawAcknowledgment(AlertMixin, ACLMixin, BugzillaSyncMixin, TrackingMixin):
    """
    Model representing flaw acknowledgments.
    Note that flaws with a public source can't have acknowledgments.
    """

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # The name of the person or entity being acknowledged.
    # max length seen in production as of 02/2023 == 122
    name = models.CharField(max_length=255)

    # The affiliation of the person being acknowledged.
    # max length seen in production as of 02/2023 == 86
    affiliation = models.CharField(max_length=255, blank=True)

    # Whether this acknowledgment comes from an upstream source.
    from_upstream = models.BooleanField()

    # one flaw can have many acknowledgments
    flaw = models.ForeignKey(
        Flaw, on_delete=models.CASCADE, related_name="acknowledgments"
    )

    objects = FlawAcknowledgmentManager.from_queryset(CustomQuerySetUpdatedDt)()

    class Meta:
        """define meta"""

        unique_together = ["flaw", "name", "affiliation"]
        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    @validator
    def _validate_public_source_no_ack(self, **kwargs):
        """
        Checks that acknowledgments cannot be linked to flaws with public sources.
        """
        if (source := FlawSource(self.flaw.source)) and source.is_public():
            if source.is_private():
                self.alert(
                    "public_source_no_ack",
                    f"Flaw source of type {source} can be public or private, "
                    "ensure that it is private since the Flaw has acknowledgments.",
                    **kwargs,
                )
            else:
                raise ValidationError(
                    f"Flaw contains acknowledgments for public source {self.flaw.source}"
                )
