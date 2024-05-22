"""
define urls
"""
from django.urls import include, path, re_path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework import routers

from apps.workflows.api import promote, reject
from config import get_env

from .api_views import (
    AffectCVSSView,
    AffectView,
    AlertView,
    FlawAcknowledgmentView,
    FlawCommentView,
    FlawCVSSView,
    FlawPackageVersionView,
    FlawReferenceView,
    FlawView,
    JiraStageForwarderView,
    ManifestView,
    StatusView,
    TrackerView,
    healthy,
    whoami,
)
from .constants import OSIDB_API_VERSION

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"flaws", FlawView)
router.register(
    r"flaws/(?P<flaw_id>[^/.]+)/acknowledgments",
    FlawAcknowledgmentView,
    basename="flawacknowledgments",
)
router.register(
    r"flaws/(?P<flaw_id>[^/.]+)/comments", FlawCommentView, basename="flawcomments"
)
router.register(
    r"flaws/(?P<flaw_id>[^/.]+)/cvss_scores", FlawCVSSView, basename="flawcvss"
)
router.register(
    r"flaws/(?P<flaw_id>[^/.]+)/package_versions",
    FlawPackageVersionView,
    basename="flawpackageversions",
)
router.register(
    r"flaws/(?P<flaw_id>[^/.]+)/references",
    FlawReferenceView,
    basename="flawreferences",
)
router.register(r"affects", AffectView)
router.register(
    r"affects/(?P<affect_id>[^/.]+)/cvss_scores", AffectCVSSView, basename="affectcvss"
)
router.register(r"trackers", TrackerView)
router.register(r"alerts", AlertView)

urlpatterns = [
    path("healthy", healthy),
    path("whoami", whoami),
    re_path(
        rf"^api/{OSIDB_API_VERSION}/flaws/(?P<flaw_id>[^/.]+)/promote$",
        promote.as_view(),
    ),
    re_path(
        rf"^api/{OSIDB_API_VERSION}/flaws/(?P<flaw_id>[^/.]+)/reject$",
        reject.as_view(),
    ),
    path(f"api/{OSIDB_API_VERSION}/status", StatusView.as_view()),
    path(f"api/{OSIDB_API_VERSION}/manifest", ManifestView.as_view()),
    path(f"api/{OSIDB_API_VERSION}/", include(router.urls)),
    path(
        f"api/{OSIDB_API_VERSION}/schema/", SpectacularAPIView.as_view(), name="schema"
    ),
    path(
        f"api/{OSIDB_API_VERSION}/schema/swagger-ui/",
        SpectacularSwaggerView.as_view(url_name="schema"),
    ),
]

# TODO: undocumented endpoint only is enabled on non production environments and will be removed in the future.
if get_env() != "prod":
    urlpatterns.append(
        path(
            f"api/{OSIDB_API_VERSION}/jira_stage_forwarder",
            JiraStageForwarderView.as_view(),
        )
    )
