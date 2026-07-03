"""
Middleware gating access to the CRA reporting API.
"""

from django.conf import settings
from django.http import Http404

CRA_API_PATH_PREFIX = "/regulatory-reporting/api/v1/"
CRA_NOTIFICATIONS_PATH_PREFIX = "/osidb/api/v2/notifications/"


class CRAReportingEnabledMiddleware:
    """
    Return 404 for CRA API endpoints when the relevant feature flag is off.

    - /osidb/api/v2/notifications/... is gated by CRA_NOTIFICATIONS_ENABLED
    - /regulatory-reporting/api/v1/... CRA routes (SRP reports/milestones) are
      gated by CRA_REPORTING_ENABLED

    Flags are checked here, per request, rather than used to conditionally
    register routes in urlpatterns at import time. Django caches the compiled
    URLconf, so a setting read once at import time cannot be toggled at
    runtime (e.g. by tests overriding settings) without manually clearing that
    cache. Checking in middleware keeps urlpatterns static while still fully
    disabling the API when the feature flag is off.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path_info
        if path.startswith(CRA_NOTIFICATIONS_PATH_PREFIX):
            if not settings.CRA_NOTIFICATIONS_ENABLED:
                raise Http404
        elif path.startswith(CRA_API_PATH_PREFIX) and not (
            settings.CRA_REPORTING_ENABLED
        ):
            raise Http404

        return self.get_response(request)
