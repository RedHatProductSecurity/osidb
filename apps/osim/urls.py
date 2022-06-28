"""
OSIM URLs
"""

import logging

from django.urls import path

from .api import adjust, classification, healthy, index, workflows
from .constants import OSIM_API_VERSION
from .views import classification as graph_classification
from .views import workflows as graph_workflows

logger = logging.getLogger(__name__)

urlpatterns = [
    path("", index.as_view()),
    path("healthy", healthy.as_view()),
    path(f"api/{OSIM_API_VERSION}/workflows", workflows.as_view()),
    path(f"api/{OSIM_API_VERSION}/workflows/<str:pk>", classification.as_view()),
    path(f"api/{OSIM_API_VERSION}/workflows/<str:pk>/adjust", adjust.as_view()),
    path(f"api/{OSIM_API_VERSION}/graph/workflows", graph_workflows.as_view()),
    path(
        f"api/{OSIM_API_VERSION}/graph/workflows/<str:pk>",
        graph_classification.as_view(),
    ),
]
