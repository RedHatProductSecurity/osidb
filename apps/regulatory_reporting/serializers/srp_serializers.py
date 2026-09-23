"""
Serializers for SRP (Single Reporting Platform) models.

Provides REST API serialization for CRA compliance reporting.
"""

import json
import uuid

from django.db import IntegrityError, transaction
from django.utils import timezone
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from apps.regulatory_reporting.constants import ENISA_STATE_CODES
from apps.regulatory_reporting.models import (
    AdditionalInformationRequest,
    SRPReport,
    SRPReportMilestone,
)
from apps.regulatory_reporting.payload_fields import (
    INVALID_PAYLOAD_OVERRIDE,
    MISSING_REQUIRED_REQUIREMENTS,
    get_payload_field_definition_map,
    normalise_payload_override_value,
)
from apps.regulatory_reporting.services import get_overridable_keys, get_payload_fields
from osidb.core import generate_acls
from osidb.models import Flaw
from osidb.serializer import (
    ACLMixinSerializer,
    AlertMixinSerializer,
    IncludeMetaAttrMixin,
    TrackingMixinSerializer,
)


@extend_schema_field({"type": "object"})
class _ObjectJSONField(serializers.JSONField):
    """JSONField that emits type:object in the OpenAPI schema."""


class SRPReportMilestoneSerializer(
    ACLMixinSerializer,
    AlertMixinSerializer,
    TrackingMixinSerializer,
    serializers.ModelSerializer,
):
    """
    Serializer for SRP Report Milestones.

    Includes computed fields for deadline tracking and status.
    """

    # Declared so drf-spectacular includes them in openapi.yml.
    # help_text must live on the field instance itself: extend_schema_field() on an
    # instance is silently dropped by DRF's deepcopy (fields are reconstructed from
    # _args/_kwargs, losing any __dict__ additions).
    additional_details = _ObjectJSONField(
        required=False,
        help_text=(
            "Coordinator-provided SRP FAQ fields for this milestone stage. "
            "OSIM stores and reads these as individual form fields. "
            "Values here override auto-derived payload fields at submission time."
        ),
    )
    payload_fields = serializers.SerializerMethodField(
        help_text=(
            "Ordered SRP payload form fields with labels, values, input type, "
            "requiredness, editability, and options for this milestone."
        )
    )
    missing_required_fields = serializers.SerializerMethodField(
        help_text="Missing required fields"
    )
    due_at = serializers.DateTimeField(required=False, allow_null=True)
    hours_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    days_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    is_overdue = serializers.BooleanField(read_only=True)
    # ACLs are inherited from the parent report; not mutable via this API.
    # Must be declared read_only: Meta.read_only_fields does not apply to
    # fields declared on ACLMixinSerializer. update() also skips
    # ACLMixinSerializer.update() so omitted embargoed cannot rewrite ACLs.
    embargoed = serializers.BooleanField(
        read_only=True,
        help_text=(
            "The embargoed boolean attribute is technically read-only as it just "
            "indirectly modifies the ACLs but is mandatory as it controls the access "
            "to the resource."
        ),
    )

    class Meta:
        model = SRPReportMilestone
        fields = (
            [
                # Primary key
                "uuid",
                # Foreign key
                "srp_report",
                # Core fields
                "milestone_type",
                "status",
                "additional_details",
                "payload_fields",
                "missing_required_fields",
                "submitted_at",
                "owner",
                "manual_completion_notes",
                # Tracking fields
                "created_dt",
                "updated_dt",
                # Computed fields
                "due_at",
                "hours_remaining",
                "days_remaining",
                "is_overdue",
            ]
            + ACLMixinSerializer.Meta.fields
            + AlertMixinSerializer.Meta.fields
        )
        read_only_fields = [
            "uuid",
            "srp_report",
            "milestone_type",
            "payload_fields",
            "missing_required_fields",
            "created_dt",
            "updated_dt",
            "hours_remaining",
            "days_remaining",
            "is_overdue",
            "acl_read",
            "acl_write",
            "alerts",
        ]

    @extend_schema_field({"type": "array", "items": {"type": "object"}})
    def get_payload_fields(self, instance):
        return self._get_payload_fields(instance)

    @extend_schema_field({"type": "string"})
    def get_missing_required_fields(self, instance):
        missing = [
            field["key"]
            for field in self._get_payload_fields(instance)
            if field["requirement"] in MISSING_REQUIRED_REQUIREMENTS
            and field["missing"]
        ]
        return json.dumps(missing)

    def _get_payload_fields(self, instance):
        cache = getattr(self, "_srp_payload_fields_cache", None)
        if cache is None:
            cache = {}
            self._srp_payload_fields_cache = cache

        key = instance.pk or id(instance)
        if key not in cache:
            cache[key] = get_payload_fields(instance)
        return cache[key]

    def validate_additional_details(self, value):
        if not isinstance(value, dict):
            raise serializers.ValidationError(
                "additional_details must be a JSON object, not a list or scalar."
            )
        for k, v in value.items():
            if k == "member_states_available":
                if not isinstance(v, (list, str)):
                    raise serializers.ValidationError(
                        f"additional_details[{k!r}] must be a list or string, "
                        f"got {type(v).__name__}."
                    )
            elif not isinstance(v, str):
                raise serializers.ValidationError(
                    f"additional_details[{k!r}] must be a string, "
                    f"got {type(v).__name__}."
                )
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        details = attrs.get("additional_details")
        if details is not None and self.instance:
            event_type = self.instance.srp_report.reportable_event_type
            milestone_type = self.instance.milestone_type
            allowed = get_overridable_keys(milestone_type, event_type)
            unknown = set(details.keys()) - allowed
            if unknown:
                raise serializers.ValidationError(
                    {
                        "additional_details": (
                            f"Unknown or non-overridable keys: {sorted(unknown)}"
                        )
                    }
                )
            field_by_key = get_payload_field_definition_map(event_type, milestone_type)
            invalid = []
            for key, value in details.items():
                field = field_by_key.get(key)
                if field is None:
                    invalid.append(key)
                    continue
                if (
                    normalise_payload_override_value(field, value)
                    is INVALID_PAYLOAD_OVERRIDE
                ):
                    invalid.append(key)
            if invalid:
                raise serializers.ValidationError(
                    {
                        "additional_details": (
                            "Invalid values for keys: "
                            f"{sorted(invalid)}. Values must match the "
                            "field input_type and options."
                        )
                    }
                )
        return attrs

    def update(self, instance, validated_data, *args, **kwargs):
        """
        Preserve ACLs on update.

        ACLMixinSerializer.update() reads request.data.get("embargoed") and
        rewrites ACLs; omitting embargoed resolves as public. Milestone ACLs
        are inherited from the parent report and are not mutable via this API.

        Snapshot rebuild for already-submitted milestones when additional_details
        changes is handled in SRPReportMilestone.save().
        """
        validated_data["acl_read"] = instance.acl_read
        validated_data["acl_write"] = instance.acl_write
        return super(ACLMixinSerializer, self).update(
            instance, validated_data, *args, **kwargs
        )

    def to_representation(self, instance):
        due_at = instance.due_at
        if due_at is None:
            instance.hours_remaining = None
            instance.days_remaining = None
            instance.is_overdue = False
        else:
            total_seconds = (due_at - timezone.now()).total_seconds()
            instance.hours_remaining = int(total_seconds / 3600)
            instance.days_remaining = int(total_seconds / 86400)
            instance.is_overdue = total_seconds < 0
        return super().to_representation(instance)


class AdditionalInformationRequestSerializer(
    TrackingMixinSerializer,
    serializers.ModelSerializer,
):
    """
    Serializer for Additional Information Requests nested under a milestone.

    Includes computed fields for deadline tracking, mirroring
    SRPReportMilestoneSerializer's due_at/hours_remaining/days_remaining/
    is_overdue pattern.
    """

    due_at = serializers.DateTimeField(read_only=True, allow_null=True)
    hours_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    days_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    is_overdue = serializers.BooleanField(read_only=True)

    class Meta:
        model = AdditionalInformationRequest
        fields = (
            # Primary key
            "uuid",
            # Foreign key
            "milestone",
            "acl_read",
            "acl_write",
            # Core fields
            "request_received_at",
            "request_source",
            "request_text",
            "response_text",
            "owner",
            "status",
            "manual_due_at",
            "manual_completion_notes",
            # Computed fields
            "due_at",
            "hours_remaining",
            "days_remaining",
            "is_overdue",
            # Tracking
            "created_dt",
            "updated_dt",
        )
        read_only_fields = (
            "uuid",
            "created_dt",
            "updated_dt",
            "milestone",
            "acl_read",
            "acl_write",
        )

    def to_representation(self, instance):
        due_at = instance.due_at
        if due_at is None:
            instance.hours_remaining = None
            instance.days_remaining = None
            instance.is_overdue = False
        else:
            total_seconds = (due_at - timezone.now()).total_seconds()
            instance.hours_remaining = int(total_seconds / 3600)
            instance.days_remaining = int(total_seconds / 86400)
            instance.is_overdue = total_seconds < 0
        return super().to_representation(instance)


class SRPReportMilestoneCreateSerializer(SRPReportMilestoneSerializer):
    """
    Serializer for creating SRP Report Milestones.

    Only additional_information_response milestones can be created via the API;
    all other milestone types are auto-created by signals.
    ACLs are inherited from the parent report in the view's perform_create.
    """

    updated_dt = serializers.DateTimeField(read_only=True)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if attrs.get("additional_details"):
            raise serializers.ValidationError(
                {
                    "additional_details": (
                        "additional_information_response milestones have no overridable keys."
                    )
                }
            )
        return attrs


class SRPReportSerializer(
    ACLMixinSerializer,
    AlertMixinSerializer,
    IncludeMetaAttrMixin,
    TrackingMixinSerializer,
    serializers.ModelSerializer,
):
    """
    Serializer for SRP Reports.

    Includes nested milestones. meta_attr is opt-in via include_meta_attr.
    """

    # Nested milestones
    milestones = SRPReportMilestoneSerializer(many=True, read_only=True)

    meta_attr = serializers.SerializerMethodField()

    class Meta:
        model = SRPReport
        fields = [
            # Primary key
            "uuid",
            # Foreign key
            "flaw_id",
            # Core fields
            "title",
            "manufacturer_or_steward_name",
            "responsibility_scope",
            "reportable_event_type",
            "status",
            "evidence",
            "timer_started_at",
            "srp_reference_id",
            "srp_reference_url",
            "member_states_available",
            "designated_csirt_country",
            "designated_csirt_source",
            "manual_completion_notes",
            # Tracking fields
            "created_dt",
            "updated_dt",
            # Nested fields
            "milestones",
            "meta_attr",
        ] + AlertMixinSerializer.Meta.fields
        read_only_fields = [
            "uuid",
            "created_dt",
            "updated_dt",
            "milestones",
            "flaw_id",
            "meta_attr",
            "alerts",
        ]

    def validate_member_states_available(self, value):
        invalid = [v for v in value if v not in ENISA_STATE_CODES]
        if invalid:
            raise serializers.ValidationError(
                f"Invalid ENISA member-state codes: {invalid}. "
                "Use EL for Greece, not GR."
            )
        return value

    def update(self, instance, validated_data, *args, **kwargs):
        """
        Preserve ACLs on update.

        ACLMixinSerializer.update() reads request.data.get("embargoed") and
        rewrites ACLs; this endpoint does not expose embargoed and is not meant
        to change visibility (ACLs follow the parent flaw via signals).
        """
        validated_data["acl_read"] = instance.acl_read
        validated_data["acl_write"] = instance.acl_write
        return super(ACLMixinSerializer, self).update(
            instance, validated_data, *args, **kwargs
        )


class SRPReportCreateSerializer(SRPReportSerializer):
    """
    Serializer for manually creating SRP Reports.

    Status is always EMPTY. ACLs are inherited from the flaw in the
    view's perform_create. evidence is required for manual create.
    srp_reference_id and srp_reference_url are optional. timer_started_at is
    read-only and remains null until the report transitions to IN_PROGRESS.
    """

    flaw_id = serializers.PrimaryKeyRelatedField(
        queryset=Flaw.objects.all(),
        source="flaw",
        help_text="UUID of the flaw to create an SRP report for",
    )
    title = serializers.CharField(required=False)
    responsibility_scope = serializers.ChoiceField(
        choices=SRPReport.ResponsibilityScope.choices,
        required=False,
    )
    evidence = serializers.CharField(allow_blank=False, trim_whitespace=True)
    srp_reference_id = serializers.CharField(
        required=False,
        allow_blank=True,
        trim_whitespace=True,
        max_length=255,
    )
    srp_reference_url = serializers.URLField(
        required=False,
        allow_blank=True,
        max_length=200,
    )
    status = serializers.ChoiceField(
        choices=SRPReport.SRPReportStatus.choices,
        read_only=True,
    )
    timer_started_at = serializers.DateTimeField(read_only=True, allow_null=True)
    updated_dt = serializers.DateTimeField(read_only=True)

    class Meta(SRPReportSerializer.Meta):
        # Disable auto UniqueTogetherValidator so validate()/IntegrityError
        # can return a field-scoped error on reportable_event_type.
        validators = []
        read_only_fields = [
            "uuid",
            "created_dt",
            "updated_dt",
            "milestones",
            "meta_attr",
            "alerts",
            "status",
            "timer_started_at",
        ]

    @staticmethod
    def _require_nonblank(value):
        if not value or not value.strip():
            raise serializers.ValidationError("This field may not be blank.")
        return value.strip()

    def validate_evidence(self, value):
        return self._require_nonblank(value)

    def _validate_acl_write(self, flaw):
        if not flaw:
            return
        request = self.context.get("request")
        user = getattr(request, "user", None) if request else None
        if user is None or not user.is_authenticated:
            raise serializers.ValidationError(
                {"flaw_id": "You do not have write access to this flaw."}
            )
        user_acls = {
            uuid.UUID(acl)
            for acl in generate_acls([group.name for group in user.groups.all()])
        }
        if not user_acls.intersection(flaw.acl_write):
            raise serializers.ValidationError(
                {"flaw_id": "You do not have write access to this flaw."}
            )

    def _validate_unique_reportable_event_type(self, flaw, reportable_event_type):
        if (
            flaw
            and reportable_event_type
            and SRPReport.objects.filter(
                flaw=flaw,
                reportable_event_type=reportable_event_type,
            ).exists()
        ):
            raise serializers.ValidationError(
                {
                    "reportable_event_type": (
                        "An SRP report with this reportable_event_type already "
                        "exists for this flaw."
                    )
                }
            )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        flaw = attrs.get("flaw")
        reportable_event_type = attrs.get("reportable_event_type")
        self._validate_acl_write(flaw)
        self._validate_unique_reportable_event_type(flaw, reportable_event_type)
        return attrs

    def create(self, validated_data):
        flaw = validated_data["flaw"]
        validated_data.setdefault(
            "title",
            flaw.title or f"SRP Report for {flaw.uuid}",
        )
        validated_data.setdefault(
            "responsibility_scope",
            SRPReport.ResponsibilityScope.MANUFACTURER,
        )
        try:
            with transaction.atomic():
                return super().create(validated_data)
        except IntegrityError as exc:
            if "unique_srp_report_flaw_event_type" not in str(exc):
                raise
            raise serializers.ValidationError(
                {
                    "reportable_event_type": (
                        "An SRP report with this reportable_event_type already "
                        "exists for this flaw."
                    )
                }
            ) from exc
