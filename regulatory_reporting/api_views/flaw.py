"""
ViewSets for flaw subresource SRP endpoints (read-only convenience wrappers).

Provides read-only access to SRP reports and milestones via flaw context.
"""

import uuid

from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework.viewsets import ReadOnlyModelViewSet

from osidb.models import Flaw
from regulatory_reporting.constants import UUID_PATH_REGEX
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.serializers import (
    SRPReportMilestoneSerializer,
    SRPReportSerializer,
)


def _require_uuid(value):
    """Reject malformed path UUIDs with 404 before ORM lookup."""
    try:
        uuid.UUID(str(value))
    except (AttributeError, TypeError, ValueError):
        raise Http404


class FlawSRPReportViewSet(ReadOnlyModelViewSet):
    """
    ViewSet for flaw SRP reports (read-only subresource).

    Supports:
    - GET /regulatory-reporting/api/v1/flaws/{flaw_id}/srp-reports - List reports for a flaw
    - GET /regulatory-reporting/api/v1/flaws/{flaw_id}/srp-reports/{uuid} - Retrieve single report

    Read-only convenience wrapper. Updates must use top-level endpoints.
    """

    serializer_class = SRPReportSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    lookup_field = "uuid"
    lookup_value_regex = UUID_PATH_REGEX

    def get_queryset(self):
        """Filter reports to the specified flaw."""
        # Required for openapi.yml generation; path kwargs unavailable at schema time.
        # https://drf-spectacular.readthedocs.io/en/latest/faq.html#my-get-queryset-depends-on-some-attributes-not-available-at-schema-generation-time
        if getattr(self, "swagger_fake_view", False):
            return SRPReport.objects.none()

        flaw_id = self.kwargs.get("flaw_id")
        _require_uuid(flaw_id)
        get_object_or_404(Flaw, uuid=flaw_id)
        return SRPReport.objects.filter(flaw_id=flaw_id).prefetch_related("milestones")


class FlawSRPReportMilestoneViewSet(ReadOnlyModelViewSet):
    """
    ViewSet for flaw SRP report milestones (read-only subresource).

    Supports:
    - GET /regulatory-reporting/api/v1/flaws/{flaw_id}/srp-reports/{report_uuid}/milestones - List milestones
    - GET /regulatory-reporting/api/v1/flaws/{flaw_id}/srp-reports/{report_uuid}/milestones/{uuid} - Retrieve milestone

    Read-only convenience wrapper. Updates must use top-level endpoints.
    """

    serializer_class = SRPReportMilestoneSerializer
    permission_classes = [IsAuthenticatedOrReadOnly]
    lookup_field = "uuid"
    lookup_value_regex = UUID_PATH_REGEX

    def get_queryset(self):
        """Filter milestones to the specified flaw and report."""
        # Required for openapi.yml generation; path kwargs unavailable at schema time.
        # https://drf-spectacular.readthedocs.io/en/latest/faq.html#my-get-queryset-depends-on-some-attributes-not-available-at-schema-generation-time
        if getattr(self, "swagger_fake_view", False):
            return SRPReportMilestone.objects.none()

        flaw_id = self.kwargs.get("flaw_id")
        report_uuid = self.kwargs.get("report_uuid")

        _require_uuid(flaw_id)
        _require_uuid(report_uuid)
        get_object_or_404(Flaw, uuid=flaw_id)
        get_object_or_404(SRPReport, uuid=report_uuid, flaw_id=flaw_id)

        return SRPReportMilestone.objects.filter(
            srp_report__uuid=report_uuid, srp_report__flaw_id=flaw_id
        )
