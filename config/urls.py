"""
URL Configuration
"""

from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path
from kaminarimon.views import krb5_obtain_token_pair_view, refresh_token
from rest_framework_simplejwt.views import TokenVerifyView

from osidb.api_views import OsidbTokenObtainPairView
from osidb.views import index

token_obtain_path = path(
    "auth/token", OsidbTokenObtainPairView.as_view(), name="token_obtain"
)
if "kaminarimon" in settings.INSTALLED_APPS:
    token_obtain_path = path(
        "auth/token", krb5_obtain_token_pair_view, name="token_obtain"
    )


urlpatterns = [
    path("", index.as_view(), name="index"),
    # Exploits
    path("exploits/", include("apps.exploits.urls")),
    # Workflows
    path("workflows/", include("apps.workflows.urls")),
    # collectors
    path("collectors/", include("collectors.framework.urls")),
    # data
    path("osidb/", include("osidb.urls")),
    # Trackers
    path("trackers/", include("apps.trackers.urls")),
    # auth
    token_obtain_path,
    path("auth/token/refresh", refresh_token, name="token_refresh"),
    path("auth/token/verify", TokenVerifyView.as_view(), name="token_verify"),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
