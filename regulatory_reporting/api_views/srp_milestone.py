"""
ViewSet for SRP Report Milestone endpoints (nested under reports).

Provides list, retrieve, update, and create operations for milestones.
"""

from django.shortcuts import get_object_or_404
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.viewsets import ModelViewSet

from regulatory_reporting.constants import UUID_PATH_REGEX
from regulatory_reporting.filters import SRPReportMilestoneFilter
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.serializers import (
    SRPReportMilestoneCreateSerializer,
    SRPReportMilestoneSerializer,
)


class SRPReportMilestoneViewSet(ModelViewSet):
    """
    ViewSet for SRP Report Milestones (nested under reports).

    Supports:
    - GET /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones - List milestones for a report
    - GET /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones/{uuid} - Retrieve single milestone
    - POST /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones - Create additional_information_response milestone
    - PUT /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones/{uuid} - Full update
    - PATCH /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones/{uuid} - Partial update

    Standard milestones (24h, 72h, final) are auto-created by signals.
    Only additional_information_response milestones can be created via POST.
    """

    serializer_class = SRPReportMilestoneSerializer
    filterset_class = SRPReportMilestoneFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = [IsAuthenticatedOrReadOnly]
    http_method_names = ["get", "post", "put", "patch", "head", "options"]
    lookup_field = "uuid"
    lookup_value_regex = UUID_PATH_REGEX

    def get_serializer_class(self):
        if self.action == "create":
            return SRPReportMilestoneCreateSerializer
        return SRPReportMilestoneSerializer

    def get_queryset(self):
        """Filter milestones to the specified report."""
        # Required for autogeneration of filter parameters in openapi.yml because
        # get_queryset depends on "report_uuid" not available at schema generation
        # time. Documented in
        # https://drf-spectacular.readthedocs.io/en/latest/faq.html#my-get-queryset-depends-on-some-attributes-not-available-at-schema-generation-time
        if getattr(self, "swagger_fake_view", False):
            return SRPReportMilestone.objects.none()

        report_uuid = self.kwargs.get("report_uuid")
        # Validate report exists
        get_object_or_404(SRPReport, uuid=report_uuid)
        return SRPReportMilestone.objects.filter(
            srp_report__uuid=report_uuid
        ).select_related("srp_report")

    def perform_create(self, serializer):
        report_uuid = self.kwargs.get("report_uuid")
        srp_report = get_object_or_404(SRPReport, uuid=report_uuid)
        serializer.save(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
            srp_report=srp_report,
            acl_read=srp_report.acl_read,
            acl_write=srp_report.acl_write,
        )
