"""
URL Configuration
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from krb5_auth.views import OsidbTokenObtainPairView
from osidb.views import index

token_obtain_path = path(
    "auth/token", OsidbTokenObtainPairView.as_view(), name="token_obtain"
)
if "krb5_auth" in settings.INSTALLED_APPS:
    from krb5_auth.views import krb5_obtain_token_pair_view

    token_obtain_path = path(
        "auth/token", krb5_obtain_token_pair_view, name="token_obtain"
    )


urlpatterns = [
    path("", index.as_view(), name="index"),
    # Exploits
    path("exploits/", include("apps.exploits.urls")),
    # OSIM
    path("osim/", include("apps.osim.urls")),
    # Task Manager
    path("taskman/", include("apps.taskman.urls")),
    # collectors
    path("collectors/", include("collectors.framework.urls")),
    # data
    path("osidb/", include("osidb.urls")),
    # Trackers
    path("trackers/", include("apps.trackers.urls")),
    # auth
    token_obtain_path,
    path("auth/token/refresh", TokenRefreshView.as_view(), name="token_refresh"),
    path("auth/token/verify", TokenVerifyView.as_view(), name="token_verify"),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
