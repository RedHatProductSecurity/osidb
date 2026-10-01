"""
ViewSet for top-level SRP Report endpoints.

Provides list, retrieve, create, and update operations for SRP reports.
"""

from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.viewsets import ModelViewSet

from apps.regulatory_reporting.api_views.base import RegulatoryReportingEnabledMixin
from apps.regulatory_reporting.constants import UUID_PATH_REGEX
from apps.regulatory_reporting.filters import SRPReportFilter
from apps.regulatory_reporting.models import SRPReport
from apps.regulatory_reporting.serializers import (
    SRPReportCreateResponseSerializer,
    SRPReportCreateSerializer,
    SRPReportSerializer,
)
from apps.regulatory_reporting.services import (
    create_srp_report_milestones,
    recalculate_srp_report_milestone_due_dates,
)
from osidb.api_views import get_valid_http_methods


class SRPReportViewSet(RegulatoryReportingEnabledMixin, ModelViewSet):
    """
    ViewSet for SRP Reports (top-level).

    Supports:
    - GET /regulatory-reporting/api/v1/srp-reports - List all reports with filtering
    - GET /regulatory-reporting/api/v1/srp-reports/{uuid} - Retrieve single report
    - POST /regulatory-reporting/api/v1/srp-reports - Manually create a report
    - PUT /regulatory-reporting/api/v1/srp-reports/{uuid} - Update

    Reports are also auto-created by signals when Critter criteria are met.
    Manual POST creates the report in EMPTY status with milestones.
    DELETE is not allowed. PATCH is globally blacklisted (BLACKLISTED_HTTP_METHODS).
    """

    queryset = SRPReport.objects.all().prefetch_related("milestones")
    serializer_class = SRPReportSerializer
    filterset_class = SRPReportFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = [IsAuthenticatedOrReadOnly]
    http_method_names = get_valid_http_methods(ModelViewSet, excluded=["delete"])
    lookup_field = "uuid"
    lookup_value_regex = UUID_PATH_REGEX

    def get_serializer_class(self):
        if self.action == "create":
            return SRPReportCreateSerializer
        return SRPReportSerializer

    @extend_schema(
        request=SRPReportCreateSerializer,
        responses={201: SRPReportCreateResponseSerializer},
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        flaw = serializer.validated_data["flaw"]
        with transaction.atomic():
            srp_report = serializer.save(
                status=SRPReport.SRPReportStatus.EMPTY,
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
            )
            create_srp_report_milestones(srp_report)

    def perform_update(self, serializer):
        previous_timer_started_at = serializer.instance.timer_started_at
        with transaction.atomic():
            srp_report = serializer.save()
            if srp_report.timer_started_at != previous_timer_started_at:
                recalculate_srp_report_milestone_due_dates(
                    srp_report,
                    previous_timer_started_at,
                )
