"""
Serializers for SRP (Single Reporting Platform) models.

Provides REST API serialization for CRA compliance reporting.
"""

from django.utils import timezone
from drf_spectacular.utils import extend_schema_serializer
from rest_framework import serializers

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
    # fields declared on ACLMixinSerializer.
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
            "alerts",
        ]

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


@extend_schema_serializer(exclude_fields=["updated_dt"])
class SRPReportMilestoneCreateSerializer(SRPReportMilestoneSerializer):
    """
    Serializer for creating SRP Report Milestones.

    Only additional_information_response milestones can be created via the API;
    all other milestone types are auto-created by signals.
    ACLs are inherited from the parent report in the view's perform_create.
    """


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
