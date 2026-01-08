import json
import uuid
from typing import Union

from django.core.exceptions import FieldDoesNotExist
from django.db import models

from collectors.bzimport.constants import BZ_API_KEY
from osidb.mixins import ACLMixin, AlertMixin, TrackingMixin

from .flaw.flaw import Flaw


class Snippet(ACLMixin, AlertMixin, TrackingMixin):
    """
    Snippet stores data scraped by collectors. One or more snippets can either be linked
    to an existing flaw or serve as a source for a new flaw.
    """

    class Source(models.TextChoices):
        """
        Sources should match collector names (i.e. "NVD" corresponds to NVD collector).
        This class should be extended everytime a new collector is introduced.
        """

        CVEORG = "CVEORG"
        NVD = "NVD"
        OSV = "OSV"

    def save(self, *args, **kwargs):
        # set internal ACLs
        self.set_internal()
        super().save(*args, **kwargs)

    # internal primary key
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # A unique ID of this snippet as it is defined in the external data source where the
    # snippet was collected from.
    external_id = models.CharField(max_length=200)

    source = models.CharField(choices=Source.choices, max_length=100)

    # if possible, these values should correspond to attributes in Flaw
    content = models.JSONField(default=dict)

    # one flaw can have many snippets
    flaw = models.ForeignKey(
        Flaw, on_delete=models.CASCADE, related_name="snippets", blank=True, null=True
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                name="unique_snippets", fields=["source", "external_id"]
            ),
        ]

    def convert_snippet_to_flaw(self, *args, **kwargs) -> Union[Flaw, None]:
        """
        Creates a new flaw from the snippet's content if a flaw with the given cve_id/external_id
        does not exist, and links them together. If a flaw already exists and does not
        contain the snippet of the current source, the snippet will be linked to it.

        Returns a flaw if it was newly created, None otherwise.
        """
        # unlike CVEorg, OSV may not always have a cve_id, so we have to check external_id as well
        cve_id = self.content["cve_id"]
        external_id = self.external_id
        created_flaw = None

        if cve_id and (f := Flaw.objects.filter(cve_id=cve_id)):
            flaw = f.first()
        elif f := Flaw.objects.filter(
            # the format string prevents a partial match of external_id if external_id is a substring
            # of another external_id since the Flaw meta_attr subfield contains serialized JSONB
            meta_attr__external_ids__contains=f'"{external_id}"'
        ):
            flaw = f.first()
        else:
            flaw = self._create_flaw(*args, **kwargs)
            created_flaw = flaw

        # links either a newly created or an already existing flaw to the snippet
        self.flaw = flaw
        self.save()

        return created_flaw

    def _create_flaw(self, *args, **kwargs) -> Flaw:
        """
        Internal helper function to create a new flaw from the snippet's content. Any data
        from the snippet's content that does not match the fields in Flaw will be ignored.

        Returns a newly created flaw.
        """
        main_model = {}
        related_models = {}

        for key, value in self.content.items():
            try:
                field = Flaw._meta.get_field(key)

                if field.is_relation:
                    related_models[field.related_model] = value
                elif field.model not in main_model:
                    main_model[field.model] = {key: value}
                else:
                    main_model[field.model].update({key: value})
            except FieldDoesNotExist:
                # anything that does not match the fields in Flaw will be ignored
                pass

        shared_acl = {"acl_read": self.acl_read, "acl_write": self.acl_write}
        # ensure that a flaw always contains external id (even if BZ sync is disabled)
        shared_flaw = shared_acl | {
            "meta_attr": {"external_ids": json.dumps([self.external_id])}
        }

        # Flaw model has to be created first
        model, data = [i for i in main_model.items()][0]
        flaw = model(**data, **shared_flaw)
        flaw.save(raise_validation_error=False)
        # reported_dt is set according to created_dt, which is set after flaw.save()
        flaw.reported_dt = flaw.created_dt

        # creates related models (e.g. FlawCVSS)
        for model, list_of_data in related_models.items():
            for data in list_of_data:
                related_model = model(flaw=flaw, **data, **shared_acl)
                related_model.save()

        # link newly created flaw to this snippet
        self.flaw = flaw
        self.save()

        flaw.save(
            bz_api_key=BZ_API_KEY,
            raise_validation_error=False,
            auto_timestamps=False,
            *args,
            **kwargs,
        )

        return Flaw.objects.get(uuid=flaw.uuid)

    def _validate_acl_identical_to_parent_flaw(self, **kwargs) -> None:
        """
        No ACL validations are run for snippet's flaw as its ACLs can be different.
        However, snippet should always have internal ACLs.
        """
        pass
