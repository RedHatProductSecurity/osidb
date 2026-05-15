"""
Workflows URLs
"""

import logging

from django.urls import path

from .api import (
    adjust,
    classification,
    healthy,
    index,
    workflows,
)
from .constants import WORKFLOWS_API_VERSION_V1, WORKFLOWS_API_VERSION_V2
from .views import classification as graph_classification
from .views import workflows as graph_workflows

logger = logging.getLogger(__name__)

urlpatterns = [
    # TODO
    # why authenticated
    path("", index.as_view()),
    path("healthy", healthy.as_view()),
    # V1 API (deprecated mutation endpoints)
    path(f"api/{WORKFLOWS_API_VERSION_V1}/workflows", workflows.as_view()),
    path(f"api/{WORKFLOWS_API_VERSION_V1}/workflows/<str:pk>", classification.as_view()),
    path(f"api/{WORKFLOWS_API_VERSION_V1}/workflows/<str:pk>/adjust", adjust.as_view()),
    path(f"api/{WORKFLOWS_API_VERSION_V1}/graph/workflows", graph_workflows.as_view()),
    path(
        f"api/{WORKFLOWS_API_VERSION_V1}/graph/workflows/<str:pk>",
        graph_classification.as_view(),
    ),
    # V2 API
    path(f"api/{WORKFLOWS_API_VERSION_V2}/workflows", workflows.as_view()),
    path(f"api/{WORKFLOWS_API_VERSION_V2}/workflows/<str:pk>", classification.as_view()),
]
