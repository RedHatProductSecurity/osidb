"""
URL routing for SRP (Security Response Pipeline) endpoints.

Registers both top-level and flaw subresource endpoints.
"""

from rest_framework.routers import DefaultRouter

from regulatory_reporting.api_views import (
    FlawSRPReportMilestoneViewSet,
    FlawSRPReportViewSet,
    SRPReportMilestoneViewSet,
    SRPReportViewSet,
)
from regulatory_reporting.constants import UUID_PATH_REGEX

router = DefaultRouter(trailing_slash=False)

# Top-level SRP Reports
router.register(r"srp-reports", SRPReportViewSet, basename="srpreports")

# Top-level SRP Milestones (nested under reports)
router.register(
    rf"srp-reports/(?P<report_uuid>{UUID_PATH_REGEX})/milestones",
    SRPReportMilestoneViewSet,
    basename="srpreportmilestones",
)

# Flaw subresource SRP Reports (read-only)
router.register(
    rf"flaws/(?P<flaw_id>{UUID_PATH_REGEX})/srp-reports",
    FlawSRPReportViewSet,
    basename="flawsrpreports",
)

# Flaw subresource SRP Milestones (read-only)
router.register(
    rf"flaws/(?P<flaw_id>{UUID_PATH_REGEX})/srp-reports/(?P<report_uuid>{UUID_PATH_REGEX})/milestones",
    FlawSRPReportMilestoneViewSet,
    basename="flawsrpreportmilestones",
)

urlpatterns = router.urls
