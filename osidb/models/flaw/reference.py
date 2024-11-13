import uuid

from django.contrib.postgres.indexes import GinIndex
from django.core.exceptions import ObjectDoesNotExist, ValidationError
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


class FlawReferenceManager(ACLMixinManager, TrackingMixinManager):
    """flawreference manager"""

    @staticmethod
    def create_flawreference(flaw, url, **extra_fields):
        """return a new flawreference or update an existing flawreference without saving"""
        try:
            flawreference = FlawReference.objects.get(flaw=flaw, url=url)
            for attr, value in extra_fields.items():
                setattr(flawreference, attr, value)
            return flawreference

        except ObjectDoesNotExist:
            return FlawReference(flaw=flaw, url=url, **extra_fields)


class FlawReference(AlertMixin, ACLMixin, TrackingMixin):
    """Model representing flaw references"""

    class FlawReferenceType(models.TextChoices):
        """
        Allowable references:

        ARTICLE:
            A link to a Security Bulletin or Knowledge Base Article specifically
            discussing this flaw on the Customer Portal. It always begins with
            "https://accesss.redhat.com/". It must be a Security Bulletin
            for Major Incidents. More general articles like hardening should be
            linked instead in EXTERNAL.

        EXTERNAL:
            URL links to other trustworthy sources of information about this
            vulnerability. A link should not point to a missing resource.
            Since these links are displayed on the CVE page of the flaw, we only
            want to include respectable sources (such as upstream advisories,
            analysis of security researches, etc.).

        SOURCE:
            A link from which we obtained information about a flaw.
            This should be used mostly when converting Snippet to Flaw.

        UPSTREAM:
            A more specific type of external link which refers to an upstream
            source, mainly used for upstream fixes.
        """

        # NOTE: when moving or renaming this enum, please check and modify
        # config/settings.py::SPECTACULAR_SETTINGS::ENUM_NAME_OVERRIDES accordingly

        ARTICLE = "ARTICLE"
        EXTERNAL = "EXTERNAL"
        SOURCE = "SOURCE"
        UPSTREAM = "UPSTREAM"

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    type = models.CharField(
        choices=FlawReferenceType.choices,
        default=FlawReferenceType.EXTERNAL,
        max_length=50,
    )

    url = models.URLField(max_length=2048)

    description = models.TextField(blank=True)

    # one flaw can have many references
    flaw = models.ForeignKey(Flaw, on_delete=models.CASCADE, related_name="references")

    objects = FlawReferenceManager.from_queryset(CustomQuerySetUpdatedDt)()

    class Meta:
        """define meta"""

        unique_together = ["flaw", "url"]

        indexes = TrackingMixin.Meta.indexes + [
            GinIndex(fields=["acl_read"]),
        ]

    def _validate_article_link(self, **kwargs):
        """
        Checks that an article link begins with https://access.redhat.com/.
        """
        if self.type == self.FlawReferenceType.ARTICLE and not self.url.startswith(
            "https://access.redhat.com/"
        ):
            raise ValidationError(
                r"A flaw reference of the ARTICLE type does not begin with "
                r"https://access.redhat.com/."
            )

    def _validate_article_links_count_via_flawreferences(self, **kwargs):
        """
        Checks that a flaw has maximally one article link.
        """
        old_reference = FlawReference.objects.filter(uuid=self.uuid).first()
        article_count = 0
        if self.type == FlawReference.FlawReferenceType.ARTICLE:
            if (
                not old_reference
                or old_reference.type != FlawReference.FlawReferenceType.ARTICLE
            ):
                article_count = 1

        article_links = self.flaw.references.filter(
            type=FlawReference.FlawReferenceType.ARTICLE
        )
        article_count += article_links.count()

        if article_count > 1:
            raise ValidationError(
                f"A flaw has {article_count} article links, but only 1 is allowed."
            )
