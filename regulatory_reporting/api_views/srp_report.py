"""
ViewSet for top-level SRP Report endpoints.

Provides list, retrieve, and update operations for SRP reports.
"""

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.viewsets import ModelViewSet

from regulatory_reporting.constants import UUID_PATH_REGEX
from regulatory_reporting.filters import SRPReportFilter
from regulatory_reporting.models import SRPReport
from regulatory_reporting.serializers import SRPReportSerializer


class SRPReportViewSet(ModelViewSet):
    """
    ViewSet for SRP Reports (top-level).

    Supports:
    - GET /regulatory-reporting/api/v1/srp-reports - List all reports with filtering
    - GET /regulatory-reporting/api/v1/srp-reports/{uuid} - Retrieve single report
    - PUT /regulatory-reporting/api/v1/srp-reports/{uuid} - Full update
    - PATCH /regulatory-reporting/api/v1/srp-reports/{uuid} - Partial update

    No POST/DELETE - reports are auto-created by signals.
    """

    queryset = SRPReport.objects.all().prefetch_related("milestones")
    serializer_class = SRPReportSerializer
    filterset_class = SRPReportFilter
    filter_backends = [DjangoFilterBackend]
    permission_classes = [IsAuthenticatedOrReadOnly]
    http_method_names = ["get", "put", "patch", "head", "options"]
    lookup_field = "uuid"
    lookup_value_regex = UUID_PATH_REGEX
