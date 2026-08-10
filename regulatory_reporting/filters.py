"""
Filters for regulatory reporting API endpoints.
"""

from typing import ClassVar

from django.db.models import Exists, F, OuterRef, Subquery
from django_filters import ChoiceFilter
from django_filters.rest_framework import (
    CharFilter,
    DateTimeFilter,
    FilterSet,
    UUIDFilter,
)
from djangoql.schema import DjangoQLSchema

from osidb.filters import PURLFilter
from regulatory_reporting.models import SRPReport, SRPReportMilestone

from .models.upstream import UpstreamNotification, UpstreamProject


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
    owner = CharFilter(field_name="actor__username", lookup_expr="exact")

    class Meta:
        model = UpstreamNotification
        fields: ClassVar[list[str]] = [
            "status",
            "method",
            "upstream_project",
            "flaw",
            "owner",
        ]


class SRPReportQLSchema(DjangoQLSchema):
    """DjangoQL schema for SRP Report filtering."""

    include = (SRPReport,)


class SRPReportFilter(FilterSet):
    """
    Filter for SRP Reports with DjangoQL support.

    Supports filtering by status, reportable_event_type, flaw_id, and date ranges.

    ``status`` matches the derived report status
    ``{milestone_type}:{status}`` (e.g. ``24h:required``), based on the first
    active milestone (PRE_REQUIRED/REQUIRED/PREPARED) in order 24h → 72h →
    final → additional_information_response (by request_received_at). When
    none are active, falls back to the furthest milestone (latest additional
    → final → 72h → 24h).

    ``last_active_status`` matches the status half of that same derived
    milestone (e.g. ``required``, ``submitted``), regardless of type.

    ``milestone_status`` matches reports that have any milestone with the given
    status (e.g. ``submitted``), regardless of derived report status.
    """

    uuid = UUIDFilter(field_name="uuid", lookup_expr="exact")
    flaw_id = UUIDFilter(field_name="flaw_id", lookup_expr="exact")
    status = CharFilter(
        method="filter_status",
        help_text=(
            "Derived report status as {milestone_type}:{status} "
            "(e.g. 24h:required, 72h:prepared)."
        ),
    )
    last_active_status = CharFilter(
        method="filter_last_active_status",
        help_text=(
            "Status component of the derived report status only "
            "(e.g. required, prepared, submitted)."
        ),
    )
    milestone_status = CharFilter(
        method="filter_milestone_status",
        help_text=(
            "Match reports that have any milestone with this status "
            "(e.g. submitted), regardless of derived report status."
        ),
    )
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
            "last_active_status",
            "milestone_status",
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

    def filter_milestone_status(self, queryset, name, value):
        valid_statuses = {choice[0] for choice in SRPReport.SRPReportStatus.choices}
        if not value or value not in valid_statuses:
            return queryset.none()
        return queryset.filter(
            Exists(
                SRPReportMilestone.objects.filter(
                    srp_report=OuterRef("pk"),
                    status=value,
                )
            )
        )

    def filter_last_active_status(self, queryset, name, value):
        valid_statuses = {choice[0] for choice in SRPReport.SRPReportStatus.choices}
        if not value or value not in valid_statuses:
            return queryset.none()

        # Match any derived composite status ending in :{value} via DB-side OR.
        types = list(SRPReport.STANDARD_MILESTONE_TYPES) + [
            SRPReport.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        ]
        matched = queryset.none()
        for milestone_type in types:
            matched = matched | self.filter_status(
                queryset, "status", f"{milestone_type}:{value}"
            )
        return queryset.filter(pk__in=matched.values("pk"))

    def filter_status(self, queryset, name, value):
        if not value or ":" not in value:
            return queryset.none()

        milestone_type, milestone_status = value.split(":", 1)
        valid_types = {choice[0] for choice in SRPReport.MilestoneType.choices}
        valid_statuses = {choice[0] for choice in SRPReport.SRPReportStatus.choices}
        if milestone_type not in valid_types or milestone_status not in valid_statuses:
            return queryset.none()

        if milestone_status in SRPReport.ACTIVE_MILESTONE_STATUSES:
            return self._filter_status_active(
                queryset, milestone_type, milestone_status
            )
        return self._filter_status_fallback(queryset, milestone_type, milestone_status)

    def _filter_status_active(self, queryset, milestone_type, milestone_status):
        """Derived status from first active milestone (PRE_REQUIRED/REQUIRED/PREPARED)."""
        active_statuses = SRPReport.ACTIVE_MILESTONE_STATUSES
        standard_types = SRPReport.STANDARD_MILESTONE_TYPES

        if milestone_type in standard_types:
            earlier_types = standard_types[: standard_types.index(milestone_type)]
            has_matching = Exists(
                SRPReportMilestone.objects.filter(
                    srp_report=OuterRef("pk"),
                    milestone_type=milestone_type,
                    status=milestone_status,
                )
            )
            queryset = queryset.filter(has_matching)
            if earlier_types:
                has_earlier_active = Exists(
                    SRPReportMilestone.objects.filter(
                        srp_report=OuterRef("pk"),
                        milestone_type__in=earlier_types,
                        status__in=active_statuses,
                    )
                )
                queryset = queryset.filter(~has_earlier_active)
            return queryset

        # additional_information_response: earliest active by request_received_at
        first_additional_status = (
            SRPReportMilestone.objects.filter(
                srp_report=OuterRef("pk"),
                milestone_type=SRPReport.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
                status__in=active_statuses,
            )
            .order_by(F("request_received_at").asc(nulls_last=True), "created_dt")
            .values("status")[:1]
        )
        has_standard_active = Exists(
            SRPReportMilestone.objects.filter(
                srp_report=OuterRef("pk"),
                milestone_type__in=standard_types,
                status__in=active_statuses,
            )
        )
        return (
            queryset.annotate(
                _active_additional_status=Subquery(first_additional_status)
            )
            .filter(_active_additional_status=milestone_status)
            .filter(~has_standard_active)
        )

    def _filter_status_fallback(self, queryset, milestone_type, milestone_status):
        """
        Derived status when no active milestones remain: furthest in pipeline
        (latest additional → final → 72h → 24h).
        """
        active_statuses = SRPReport.ACTIVE_MILESTONE_STATUSES
        standard_types = SRPReport.STANDARD_MILESTONE_TYPES
        additional_type = SRPReport.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE

        has_any_active = Exists(
            SRPReportMilestone.objects.filter(
                srp_report=OuterRef("pk"),
                status__in=active_statuses,
            )
        )
        queryset = queryset.filter(~has_any_active)

        has_additional = Exists(
            SRPReportMilestone.objects.filter(
                srp_report=OuterRef("pk"),
                milestone_type=additional_type,
            )
        )

        if milestone_type == additional_type:
            latest_additional_status = (
                SRPReportMilestone.objects.filter(
                    srp_report=OuterRef("pk"),
                    milestone_type=additional_type,
                )
                .order_by(F("request_received_at").desc(nulls_last=True), "-created_dt")
                .values("status")[:1]
            )
            return queryset.annotate(
                _fallback_additional_status=Subquery(latest_additional_status)
            ).filter(_fallback_additional_status=milestone_status)

        # Standard type is furthest only when no additional milestones exist,
        # and no later standard types exist.
        later_types = standard_types[standard_types.index(milestone_type) + 1 :]
        has_matching = Exists(
            SRPReportMilestone.objects.filter(
                srp_report=OuterRef("pk"),
                milestone_type=milestone_type,
                status=milestone_status,
            )
        )
        queryset = queryset.filter(has_matching).filter(~has_additional)
        if later_types:
            has_later = Exists(
                SRPReportMilestone.objects.filter(
                    srp_report=OuterRef("pk"),
                    milestone_type__in=later_types,
                )
            )
            queryset = queryset.filter(~has_later)
        return queryset


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


class UpstreamProjectFilter(FilterSet):
    """
    Filters queries to UpstreamProjectView based on UpstreamProject fields.
    """

    component = CharFilter(field_name="component_name", lookup_expr="icontains")
    purl = PURLFilter(field_name="purl", lookup_expr="exact")
    repository_url = CharFilter(field_name="repository_url", lookup_expr="icontains")

    class Meta:
        model = UpstreamProject
        fields = ["component", "purl", "repository_url"]
