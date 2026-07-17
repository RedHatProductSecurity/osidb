from django.db import models
from django.db.models import Q
from django.utils import timezone
from djangoql.schema import (
    BoolField,
    DateTimeField,
    DjangoQLSchema,
    StrField,
)

from osidb.models import (
    Affect,
    Flaw,
    FlawAcknowledgment,
    FlawCVSS,
    FlawLabelV2,
    FlawReference,
    Package,
    Tracker,
)

from .datetime_utils import parse_relative_datetime


class RelativeDateTimeQLField(DateTimeField):
    """
    DjangoQL DateTimeField that supports relative datetime strings.

    Extends the standard DjangoQL DateTimeField to accept relative datetime
    strings like "-1d", "+2h", "-30m", "-6M", "1y", etc., in addition to
    absolute timestamps in "YYYY-MM-DD HH:MM" format.

    Examples:
        Absolute formats:
            "2024-06-15"
            "2024-06-15 14:30"
            "2024-06-15 14:30:00"

        Relative formats:
            "-1d"   -> 1 day ago
            "+2h"   -> 2 hours from now
            "1h"    -> 1 hour from now (+ is optional)
            "-30m"  -> 30 minutes ago
            "-6M"   -> 6 months ago
            "1y"   -> 1 year from now
    """

    value_types_description = (
        'timestamps in "YYYY-MM-DD HH:MM" format or relative like -1d, +2h'
    )

    def get_lookup_value(self, value):
        """
        Parse datetime value, trying relative format first, then absolute.

        First attempts to parse as a relative datetime string (e.g., "-1d", "2h").
        If that fails (returns None), falls back to the parent class absolute
        datetime parsing.
        """
        if not value:
            return None

        # Try relative datetime parsing first
        parsed = parse_relative_datetime(value, timezone.now())
        if parsed is not None:
            return parsed

        # Fall back to parent class absolute datetime parsing
        return super().get_lookup_value(value)


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
        FlawLabelV2,
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
            "source",
            "workflow_state",
        ],
        FlawLabelV2: ["name"],
        FlawCVSS: ["issuer", "version"],
        FlawReference: ["type"],
        Tracker: ["resolution", "status", "type"],
    }

    def get_field_cls(self, field):
        """Override to use RelativeDateTimeQLField for DateTimeField instances."""
        if isinstance(field, models.DateTimeField):
            return RelativeDateTimeQLField
        return super().get_field_cls(field)

    def get_fields(self, model):
        fields = super(FlawQLSchema, self).get_fields(model)
        exclude = ["acl_read", "acl_write"]
        if model == Flaw:
            exclude += ["snippets", "local_updated_dt"]
            fields.remove("components")
            fields += [
                FlawComponentField(),
                FlawNonCommunityAffectsNoTrackersField(),
                FlawLabelsField(),
            ]
        elif model == FlawLabelV2:
            exclude += ["created_dt", "updated_dt", "uuid", "polymorphic_ctype"]
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


class FlawLabelsField(StrField):
    model = Flaw
    name = "flaw_labels"
    suggest_options = True

    def get_options(self, search):
        return FlawLabelV2.objects.values_list("name", flat=True).distinct()

    def get_lookup(self, path, operator, value):
        """
        Handle label filtering with one or more labels.
        The "in" operator is used as an AND operation rather than the usual OR operation.

        Examples:
            flaw_labels = "label_a" - flaws with label_a
            flaw_labels in ("label_a", "label_b") - flaws with both label_a AND label_b
            flaw_labels != "label_a" - flaws without label_a
            flaw_labels not in ("label_a", "label_b") - flaws without label_a OR without label_b
        """

        if operator == "=":
            return Q(labels_v2__name=value)
        elif operator == "!=":
            return ~Q(labels_v2__name=value)

        num_labels = len(value)

        flaw_ids = (
            FlawLabelV2.objects.filter(name__in=value)
            .values("flaw_id")
            .annotate(label_count=models.Count("name", distinct=True))
            .filter(label_count=num_labels)
            .values_list("flaw_id", flat=True)
        )

        if operator == "in":
            return Q(uuid__in=list(flaw_ids))
        elif operator == "not in":
            return ~Q(uuid__in=list(flaw_ids))
