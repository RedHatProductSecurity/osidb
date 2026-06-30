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
    days_remaining = serializers.SerializerMethodField()
    is_overdue = serializers.SerializerMethodField()

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
            "days_remaining",
            "is_overdue",
        ]
        read_only_fields = [
            "uuid",
            "created_dt",
            "updated_dt",
            "due_at",
            "days_remaining",
            "is_overdue",
        ]

    def get_due_at(self, obj):
        """Get the milestone due date from the model property."""
        return obj.due_at

    def get_days_remaining(self, obj):
        """
        Calculate days remaining until deadline.

        Returns:
            int: Days remaining (negative if overdue), or None if no due date
        """
        if not obj.due_at:
            return None
        delta = obj.due_at - timezone.now()
        return delta.days

    def get_is_overdue(self, obj):
        """
        Check if milestone is past its deadline.

        Returns:
            bool: True if overdue, False otherwise
        """
        if not obj.due_at:
            return False
        return timezone.now() > obj.due_at


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

    # Minimal flaw representation
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
        ]
        read_only_fields = [
            "uuid",
            "created_dt",
            "updated_dt",
            "milestones",
            "flaw_id",
            "meta_attr",
        ]

    def get_meta_attr(self, obj):
        return super().get_meta_attr(obj)
