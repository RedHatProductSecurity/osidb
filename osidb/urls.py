"""
define urls
"""
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework import routers

from .api_views import (
    AffectView,
    FlawView,
    ManifestView,
    StatusView,
    TrackerView,
    healthy,
    whoami,
)
from .constants import OSIDB_API_VERSION

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"flaws", FlawView)
router.register(r"affects", AffectView)
router.register(r"trackers", TrackerView)

urlpatterns = [
    path("healthy", healthy),
    path("whoami", whoami),
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
