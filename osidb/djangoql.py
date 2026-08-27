from django.db import models
from django.db.models import Q
from django.utils import timezone
from djangoql.exceptions import DjangoQLSchemaError
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
    FlawLabel,
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
        FlawLabel,
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
        FlawLabel: ["name"],
        FlawCVSS: ["issuer", "version"],
        FlawReference: ["type"],
        Tracker: ["resolution", "status", "type"],
    }

    def get_field_cls(self, field):
        """Map GeneratedField to its output type; use relative datetimes."""
        if isinstance(field, models.GeneratedField):
            field = field.output_field
        if isinstance(field, models.DateTimeField):
            return RelativeDateTimeQLField
        return super().get_field_cls(field)

    def resolve_name(self, name):
        """
        Allow dotted access to FlawLabel fields that aren't reachable through
        the flat "labels" relation otherwise: "name"/"type" live on the base
        FlawLabel, and "contributor"/"state"/"relevant" only exist on some
        subclasses. Anything else on the FlawLabel relation graph stays
        unknown (whitelist via FLAW_LABEL_PROPERTY_FIELDS).
        """
        if len(name.parts) == 2 and name.parts[0] == "labels":
            field = FLAW_LABEL_PROPERTY_FIELDS.get(name.parts[1])
            if field:
                return field

        return super().resolve_name(name)

    def get_fields(self, model):
        fields = super().get_fields(model)
        exclude = ["acl_read", "acl_write"]
        if model == Flaw:
            exclude += ["snippets", "local_updated_dt"]
            fields.remove("components")
            fields.remove("labels")
            fields += [
                FlawComponentField(),
                FlawNonCommunityAffectsNoTrackersField(),
                FlawLabelsField(),
            ]
        elif model == FlawLabel:
            exclude += ["created_dt", "updated_dt", "uuid", "polymorphic_ctype"]
        return set(fields) - set(exclude)


class FlawComponentField(StrField):
    model = Flaw
    name = "components"
    suggest_options = True

    def get_options(self, search):
        options = super().get_options(search)
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
    name = "labels"
    suggest_options = True

    def get_options(self, search):
        return FlawLabel.objects.values_list("name", flat=True).distinct()

    def get_lookup(self, path, operator, value):
        """
        Handle label filtering with one or more labels.
        The "in" operator is used as an AND operation rather than the usual OR operation.

        Examples:
            labels = "label_a" - flaws with label_a
            labels in ("label_a", "label_b") - flaws with both label_a AND label_b
            labels != "label_a" - flaws without label_a
            labels not in ("label_a", "label_b") - flaws without label_a OR without label_b
        """

        if operator in ("in", "not in"):
            # Dedupe repeated operands (e.g. labels in ("a", "a")), otherwise
            # num_labels overcounts and the AND semantics below never match.
            unique_values = set(value)
            num_labels = len(unique_values)

            flaw_ids = (
                FlawLabel.objects.filter(name__in=unique_values)
                .values("flaw_id")
                .annotate(label_count=models.Count("name", distinct=True))
                .filter(label_count=num_labels)
                .values_list("flaw_id", flat=True)
            )

            if operator == "in":
                return Q(uuid__in=flaw_ids)
            return ~Q(uuid__in=flaw_ids)

        op, invert = self.get_operator(operator)
        q = Q(**{f"labels__name{op}": value})
        return ~q if invert else q


class FlawLabelPropertyField:
    """
    Mixin for fields that only exist on FlawLabel subclasses, reachable via
    dotted access on the flat "labels" field, e.g. "labels.contributor".

    Plain mixin (not a DjangoQLField subclass) so the concrete field's own
    base (StrField/BoolField) decides its "type" for value validation.
    """

    model = FlawLabel
    subclasses = ()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not self.subclasses:
            # Fail loudly at import time rather than silently matching
            # everything (positive comparison) or nothing (negated) below.
            raise ValueError(
                f"{type(self).__name__} has no FlawLabel subclasses defining "
                f"{self.name!r}; check the field name."
            )

    def get_lookup(self, path, operator, value):
        op, invert = self.get_operator(operator)
        lookup_value = self.get_lookup_value(value)
        q = Q()
        for subclass in self.subclasses:
            search = "__".join(path + [subclass, self.name])
            q |= Q(**{f"{search}{op}": lookup_value})
        return ~q if invert else q


def _label_subclasses_with_field(field_name):
    """
    Related-model accessor names (e.g. "collaboratorlabel") of FlawLabel
    subclasses that define field_name, derived from FlawLabel.TYPE_TO_MODEL
    instead of hard-coding the list, so new/changed label types stay in sync.
    """
    return tuple(
        model._meta.model_name
        for model in FlawLabel.TYPE_TO_MODEL.values()
        if field_name in {f.name for f in model._meta.get_fields()}
    )


class FlawLabelContributorField(FlawLabelPropertyField, StrField):
    name = "contributor"
    subclasses = _label_subclasses_with_field("contributor")


class FlawLabelStateField(FlawLabelPropertyField, StrField):
    name = "state"
    subclasses = _label_subclasses_with_field("state")


class FlawLabelRelevantField(FlawLabelPropertyField, BoolField):
    name = "relevant"
    subclasses = _label_subclasses_with_field("relevant")


class FlawLabelUuidField(StrField):
    """
    "uuid" identifies a single label row, unlike "name" it has no
    AND-across-multiple-labels semantics, so it doesn't need FlawLabelsField's
    special "in"/"not in" handling - the plain generic operator lookup is
    enough. Whitelisted explicitly so "labels.uuid" doesn't silently fall
    back to matching Flaw's own "uuid" field via resolve_name()'s default
    (non-relation) dotted-access resolution.
    """

    model = FlawLabel
    name = "uuid"

    def get_lookup(self, path, operator, value):
        op, invert = self.get_operator(operator)
        q = Q(**{f"labels__uuid{op}": value})
        return ~q if invert else q


class FlawLabelTypeField(StrField):
    """
    "type" isn't a real column: django-polymorphic tracks the concrete
    subclass via the "polymorphic_ctype" relation, not a plain field. Map
    the LabelType enum value (e.g. "context_based") to the corresponding
    subclass's content type "model" name (e.g. "collaboratorlabel") instead.
    """

    model = FlawLabel
    name = "type"
    suggest_options = True

    def get_options(self, search):
        return list(FlawLabel.LabelType.values)

    def validate(self, value):
        super().validate(value)
        if value is not None and value not in FlawLabel.LabelType.values:
            raise DjangoQLSchemaError(
                'Field "type" can be compared to one of %s, but not to %r'
                % (list(FlawLabel.LabelType.values), value)
            )

    def _model_name(self, value):
        return FlawLabel.TYPE_TO_MODEL[FlawLabel.LabelType(value)]._meta.model_name

    def get_lookup(self, path, operator, value):
        search = "__".join(path + ["polymorphic_ctype__model"])

        if operator in ("in", "not in"):
            model_names = [self._model_name(v) for v in value]
            q = Q(**{f"{search}__in": model_names})
            return q if operator == "in" else ~q

        op, invert = self.get_operator(operator)
        if op != "":
            raise DjangoQLSchemaError(
                'Field "type" only supports "=", "!=", "in" and "not in"'
            )
        q = Q(**{search: self._model_name(value)})
        return ~q if invert else q


FLAW_LABEL_PROPERTY_FIELDS = {
    "name": FlawLabelsField(),
    "uuid": FlawLabelUuidField(),
    "type": FlawLabelTypeField(),
    "contributor": FlawLabelContributorField(),
    "state": FlawLabelStateField(),
    "relevant": FlawLabelRelevantField(),
}
