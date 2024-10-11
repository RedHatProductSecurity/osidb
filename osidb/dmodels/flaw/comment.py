import uuid

from django.contrib.postgres.indexes import GinIndex
from django.db import models

from apps.bbsync.mixins import BugzillaSyncMixin
from osidb.dmodels.flaw.flaw import Flaw
from osidb.mixins import ACLMixin, AlertMixin, TrackingMixin


class FlawComment(
    AlertMixin,
    ACLMixin,
    BugzillaSyncMixin,
    TrackingMixin,
):
    """Model representing flaw comments"""

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # external comment id
    external_system_id = models.CharField(max_length=100, blank=True)

    # For bbsync/query.py to mark whether it was sent to BZ
    synced_to_bz = models.BooleanField(default=False)

    # explicitly define comment ordering, from BZ comment 'count'
    order = models.IntegerField(blank=True, null=True)

    # text of the comment
    text = models.TextField()

    # creator of the comment, which can be passed as an argument when creating it,
    # similar to the flaw's owner field, or if BZ sync is enabled, then it will be
    # implied from the BZ API key owner during sync
    creator = models.CharField(max_length=100, blank=True)

    # whether the comment is internal or not
    is_private = models.BooleanField(default=False)

    # one flaw can have many comments
    flaw = models.ForeignKey(Flaw, on_delete=models.CASCADE, related_name="comments")

    def __str__(self):
        return str(self.uuid)

    class Meta:
        """define meta"""

        ordering = (
            "order",
            "external_system_id",
            "uuid",
            "created_dt",
        )

        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

        # Ensure that it's not possible to have two bzimports running concurrently
        # and succeed while creating numbering conditions impossible to handle later.

        """
        TODO: Re-enable this constraint once the "order" field is removed from the model.
              Keep in mind that the "order" field is used in the ordering of the comments and should be updated
        """
        # constraints = [
        #    models.UniqueConstraint(
        #        fields=["flaw", "order"], name="unique_per_flaw_comment_nums"
        #    ),
        # ]

    def bzsync(self, *args, bz_api_key=None, **kwargs):
        """
        Bugzilla sync of the FlawComment instance and of the related Flaw instance.
        """

        self.save()

        # Comments need to be synced through flaw
        # If external_system_id is blank, BugzillaSaver posts the new comment
        # and FlawCollector loads the new comment and updates this FlawComment
        # instance to match bugzilla.
        # NOTE: Keep using user BZ API key for Flaw comments as we need to
        #       preserve the information about author
        self.flaw.save(
            *args, bz_api_key=bz_api_key, force_synchronous_sync=True, **kwargs
        )
