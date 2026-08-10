"""
ViewSet for top-level SRP Report endpoints.

Provides list, retrieve, create, and update operations for SRP reports.
"""

from django.db import transaction
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.viewsets import ModelViewSet

from osidb.api_views import get_valid_http_methods
from regulatory_reporting.constants import UUID_PATH_REGEX
from regulatory_reporting.filters import SRPReportFilter
from regulatory_reporting.models import SRPReport
from regulatory_reporting.serializers import (
    SRPReportCreateSerializer,
    SRPReportSerializer,
)
from regulatory_reporting.services import create_srp_report_milestones


class SRPReportViewSet(ModelViewSet):
    """
    ViewSet for SRP Reports (top-level).

    Supports:
    - GET /regulatory-reporting/api/v1/srp-reports - List all reports with filtering
    - GET /regulatory-reporting/api/v1/srp-reports/{uuid} - Retrieve single report
    - POST /regulatory-reporting/api/v1/srp-reports - Manually create a report
    - PUT /regulatory-reporting/api/v1/srp-reports/{uuid} - Update

    Reports are also auto-created by signals when Critter criteria are met.
    Manual POST creates milestones in PRE_REQUIRED; report status is derived.
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

    def perform_create(self, serializer):
        flaw = serializer.validated_data["flaw"]
        with transaction.atomic():
            srp_report = serializer.save(
                acl_read=flaw.acl_read,
                acl_write=flaw.acl_write,
            )
            create_srp_report_milestones(
                srp_report,
                status=SRPReport.SRPReportStatus.PRE_REQUIRED,
            )
