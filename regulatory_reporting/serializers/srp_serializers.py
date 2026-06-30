"""
Serializers for SRP (Single Reporting Platform) models.

Provides REST API serialization for CRA compliance reporting.
"""

from django.utils import timezone
from rest_framework import serializers

from osidb.serializer import (
    ACLMixinSerializer,
    AlertMixinSerializer,
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

    # Computed fields
    due_at = serializers.SerializerMethodField()

    class Meta:
        model = SRPReportMilestone
        fields = [
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
            # ACL fields
            "acl_read",
            "acl_write",
            # Computed fields
            "due_at",
        ] + AlertMixinSerializer.Meta.fields
        read_only_fields = [
            "uuid",
            "created_dt",
            "updated_dt",
            "due_at",
            "alerts",
        ]

    def get_due_at(self, obj):
        """Get the milestone due date from the model property."""
        return obj.due_at

    def to_representation(self, instance):
        rep = super().to_representation(instance)
        due_at = instance.due_at
        rep["due_at"] = due_at
        if due_at is None:
            rep["hours_remaining"] = None
            rep["days_remaining"] = None
            rep["is_overdue"] = False
        else:
            now = timezone.now()
            delta = due_at - now
            total_seconds = delta.total_seconds()
            rep["hours_remaining"] = int(total_seconds / 3600)
            rep["days_remaining"] = int(total_seconds / 86400)
            rep["is_overdue"] = total_seconds < 0
        return rep


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
