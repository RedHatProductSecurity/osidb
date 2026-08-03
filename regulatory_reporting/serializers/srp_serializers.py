"""
Serializers for SRP (Single Reporting Platform) models.

Provides REST API serialization for CRA compliance reporting.
"""

from django.db import IntegrityError, transaction
from django.utils import timezone
from drf_spectacular.utils import extend_schema_serializer
from rest_framework import serializers

from osidb.models import Flaw
from osidb.serializer import (
    ACLMixinSerializer,
    AlertMixinSerializer,
    EmbargoedField,
    IncludeMetaAttrMixin,
    TrackingMixinSerializer,
)
from regulatory_reporting.models import SRPReport, SRPReportMilestone


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

    # Declared so drf-spectacular includes them in openapi.yml
    due_at = serializers.DateTimeField(read_only=True, allow_null=True)
    hours_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    days_remaining = serializers.IntegerField(read_only=True, allow_null=True)
    is_overdue = serializers.BooleanField(read_only=True)
    # ACLs are inherited from the parent report; not mutable via this API.
    # Must be declared read_only: Meta.read_only_fields does not apply to
    # fields declared on ACLMixinSerializer. update() also skips
    # ACLMixinSerializer.update() so omitted embargoed cannot rewrite ACLs.
    embargoed = EmbargoedField(
        source="*",
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
                "request_received_at",
                "request_source",
                "request_text",
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
            "created_dt",
            "updated_dt",
            "due_at",
            "hours_remaining",
            "days_remaining",
            "is_overdue",
            "acl_read",
            "acl_write",
            "alerts",
        ]

    def update(self, instance, validated_data, *args, **kwargs):
        """
        Preserve ACLs on update.

        ACLMixinSerializer.update() reads request.data.get("embargoed") and
        rewrites ACLs; omitting embargoed resolves as public. Milestone ACLs
        are inherited from the parent report and are not mutable via this API.
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


class SRPReportMilestoneCreateSerializer(SRPReportMilestoneSerializer):
    """
    Serializer for creating SRP Report Milestones.

    Only additional_information_response milestones can be created via the API;
    all other milestone types are auto-created by signals.
    ACLs are inherited from the parent report in the view's perform_create.
    """

    updated_dt = serializers.DateTimeField(read_only=True)


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

    Status is always PRE_REQUIRED. ACLs are inherited from the flaw in the
    view's perform_create. evidence, srp_reference_id, and srp_reference_url
    are required for manual create.
    """

    flaw_id = serializers.PrimaryKeyRelatedField(
        queryset=Flaw.objects.all(),
        source="flaw",
        help_text="UUID of the flaw to create an SRP report for",
    )
    title = serializers.CharField(required=False, max_length=255)
    responsibility_scope = serializers.ChoiceField(
        choices=SRPReport.ResponsibilityScope.choices,
        required=False,
    )
    evidence = serializers.CharField(allow_blank=False, trim_whitespace=True)
    srp_reference_id = serializers.CharField(
        allow_blank=False,
        trim_whitespace=True,
        max_length=255,
    )
    srp_reference_url = serializers.URLField(allow_blank=False, max_length=200)
    status = serializers.ChoiceField(
        choices=SRPReport.SRPReportStatus.choices,
        read_only=True,
    )
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
        ]

    def validate_evidence(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("This field may not be blank.")
        return value.strip()

    def validate_srp_reference_id(self, value):
        if not value or not value.strip():
            raise serializers.ValidationError("This field may not be blank.")
        return value.strip()

    def validate(self, attrs):
        attrs = super().validate(attrs)
        flaw = attrs.get("flaw")
        reportable_event_type = attrs.get("reportable_event_type")
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
