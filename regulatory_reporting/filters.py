"""
Filters for regulatory reporting API endpoints.
"""

from django_filters import ChoiceFilter
from django_filters.rest_framework import (
    CharFilter,
    DateTimeFilter,
    FilterSet,
    UUIDFilter,
)
from djangoql.schema import DjangoQLSchema

from regulatory_reporting.models import SRPReport, SRPReportMilestone

from .models.upstream import UpstreamNotification


class UpstreamNotificationFilter(FilterSet):
    """
    Filters queries to UpstreamNotificationView based on UpstreamNotification fields.
    """

    status = ChoiceFilter(
        field_name="status",
        choices=UpstreamNotification.NotificationStatus.choices,
    )
    method = ChoiceFilter(
        field_name="method",
        choices=UpstreamNotification.NotificationMethod.choices,
    )
    upstream_project = UUIDFilter(field_name="upstream_project__uuid")
    flaw = UUIDFilter(field_name="flaw__uuid")


class SRPReportQLSchema(DjangoQLSchema):
    """DjangoQL schema for SRP Report filtering."""

    include = (SRPReport,)


class SRPReportFilter(FilterSet):
    """
    Filter for SRP Reports with DjangoQL support.

    Supports filtering by status, reportable_event_type, flaw_id, and date ranges.
    """

    uuid = UUIDFilter(field_name="uuid", lookup_expr="exact")
    flaw_id = UUIDFilter(field_name="flaw_id", lookup_expr="exact")
    status = CharFilter(field_name="status", lookup_expr="exact")
    reportable_event_type = CharFilter(
        field_name="reportable_event_type", lookup_expr="exact"
    )
    responsibility_scope = CharFilter(
        field_name="responsibility_scope", lookup_expr="exact"
    )
    created_dt__gte = DateTimeFilter(field_name="created_dt", lookup_expr="gte")
    created_dt__lte = DateTimeFilter(field_name="created_dt", lookup_expr="lte")
    updated_dt__gte = DateTimeFilter(field_name="updated_dt", lookup_expr="gte")
    updated_dt__lte = DateTimeFilter(field_name="updated_dt", lookup_expr="lte")
    timer_started_at__gte = DateTimeFilter(
        field_name="timer_started_at", lookup_expr="gte"
    )
    timer_started_at__lte = DateTimeFilter(
        field_name="timer_started_at", lookup_expr="lte"
    )
    srp_reference_id = CharFilter(
        field_name="srp_reference_id", lookup_expr="icontains"
    )
    title = CharFilter(field_name="title", lookup_expr="icontains")

    class Meta:
        model = SRPReport
        fields = [
            "uuid",
            "flaw_id",
            "status",
            "reportable_event_type",
            "responsibility_scope",
            "created_dt__gte",
            "created_dt__lte",
            "updated_dt__gte",
            "updated_dt__lte",
            "timer_started_at__gte",
            "timer_started_at__lte",
            "srp_reference_id",
            "title",
        ]


class SRPReportMilestoneFilter(FilterSet):
    """
    Filter for SRP Report Milestones.

    Supports filtering by status, milestone_type, and parent report.
    """

    uuid = UUIDFilter(field_name="uuid", lookup_expr="exact")
    srp_report = UUIDFilter(field_name="srp_report__uuid", lookup_expr="exact")
    milestone_type = CharFilter(field_name="milestone_type", lookup_expr="exact")
    status = CharFilter(field_name="status", lookup_expr="exact")
    created_dt__gte = DateTimeFilter(field_name="created_dt", lookup_expr="gte")
    created_dt__lte = DateTimeFilter(field_name="created_dt", lookup_expr="lte")
    request_source = CharFilter(field_name="request_source", lookup_expr="icontains")
    request_text = CharFilter(field_name="request_text", lookup_expr="icontains")

    class Meta:
        model = SRPReportMilestone
        fields = [
            "uuid",
            "srp_report",
            "milestone_type",
            "status",
            "created_dt__gte",
            "created_dt__lte",
            "request_source",
            "request_text",
        ]
