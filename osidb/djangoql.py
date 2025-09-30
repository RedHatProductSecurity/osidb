import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q
from djangoql.schema import BoolField, DjangoQLSchema, StrField

from osidb.models import (
    Affect,
    Flaw,
    FlawAcknowledgment,
    FlawCollaborator,
    FlawCVSS,
    FlawReference,
    Package,
    Tracker,
)

from .core import generate_acls


class FlawQLSchema(DjangoQLSchema):
    """
    Limit the fields that can be queried in the DjangoQL query.

    This is a subclass of DjangoQLSchema that limits the fields that can be
    queried in the DjangoQL query to the fields that are allowed in the
    FlawFilter. This is necessary because the DjangoQLSchema allows querying
    any field in the model, which is not desirable in this case.
    """

    include = (
        Affect,
        Flaw,
        FlawAcknowledgment,
        FlawCollaborator,
        FlawCVSS,
        FlawReference,
        Package,
        Tracker,
    )

    suggest_options = {
        Affect: ["affectedness", "impact", "ps_component", "ps_module", "resolution"],
        Flaw: [
            "components",
            "impact",
            "major_incident_state",
            "nist_cvss_validation",
            "owner",
            "requires_cve_description",
            "source",
            "workflow_state",
        ],
        FlawCollaborator: ["contributor", "label"],
        FlawCVSS: ["issuer", "version"],
        FlawReference: ["type"],
        Tracker: ["resolution", "status", "type"],
    }

    def get_fields(self, model):
        fields = super(FlawQLSchema, self).get_fields(model)
        exclude = ["acl_read", "acl_write"]
        if model == Flaw:
            exclude += ["snippets", "local_updated_dt"]
            fields.remove("components")
            fields += [
                FlawComponentField(),
                FlawEmbargoedField(),
                FlawNonCommunityAffectsNoTrackersField(),
            ]
        elif model == FlawCollaborator:
            exclude += ["created_dt", "updated_dt", "uuid"]
        return set(fields) - set(exclude)


class FlawComponentField(StrField):
    model = Flaw
    name = "components"
    suggest_options = True

    def get_options(self, search):
        options = super(FlawComponentField, self).get_options(search)
        flat_list = []
        for option in options:
            flat_list += option
        return flat_list

    def get_lookup(self, path, operator, value):
        lookup = "contains" if len(value) > 1 else "exact"
        value = [component for component in value.split(",") if component]

        if operator == "in":
            result = None
            for component in value:
                condition = self.get_lookup(path, "=", component)
                result = condition if result is None else result | condition
            return result
        elif operator == "not in":
            result = None
            for component in value:
                condition = self.get_lookup(path, "!=", component)
                result = condition if result is None else result & condition
            return result
        elif operator == "!=":
            return ~Q(**{f"components__{lookup}": value})
        elif operator == "=":
            return Q(**{f"components__{lookup}": value})


class FlawEmbargoedField(BoolField):
    """Embargoed field is calculated based on the ACLs."""

    model = Flaw
    name = "embargoed"

    def get_options(self, search):
        return (
            super()
            .get_options(search)
            .annotate(
                embargoed=models.Case(
                    models.When(
                        acl_read=[
                            uuid.UUID(acl)
                            for acl in generate_acls([settings.EMBARGO_READ_GROUP])
                        ],
                        then=True,
                    ),
                    default=False,
                    output_field=models.BooleanField(),
                )
            )
        )


class FlawNonCommunityAffectsNoTrackersField(BoolField):
    """Check if a flaw has non-community affects AND all of them are missing trackers."""

    model = Flaw
    name = "flaw_has_no_non_community_affects_trackers"

    def get_lookup(self, path, operator, value):
        from django.db.models import Exists, OuterRef

        from osidb.models import Affect
        from osidb.models.ps_module import PsModule

        if operator == "=" or operator == "!=":
            if operator == "!=":
                value = not value

            community_modules = PsModule.objects.filter(
                ps_product__business_unit="Community"
            ).values_list("name", flat=True)

            has_non_community_affects_with_trackers = Exists(
                Affect.objects.filter(
                    flaw=OuterRef("pk"), tracker__isnull=False
                ).exclude(ps_module__in=community_modules)
            )

            # This filter is in place since the flaw filter doesn't
            # seem to work if there are no non-community affects.
            has_non_community_affects = Exists(
                Affect.objects.filter(flaw=OuterRef("pk")).exclude(
                    ps_module__in=community_modules
                )
            )

            if value:
                return (
                    has_non_community_affects & ~has_non_community_affects_with_trackers
                )

            return ~has_non_community_affects | has_non_community_affects_with_trackers
