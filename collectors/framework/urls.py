"""
collector URLs
"""

from django.urls import include, path

from .api import healthy, index, status
from .constants import COLLECTOR_API_VERSION

urlpatterns = [
    path("", index.as_view()),
    path("healthy", healthy.as_view()),
    path(f"api/{COLLECTOR_API_VERSION}/status", status.as_view()),
    path("auth/", include("rest_framework.urls")),
]
