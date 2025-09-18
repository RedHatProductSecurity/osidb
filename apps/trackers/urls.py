from django.urls import path

from apps.trackers.api import TrackerFileSuggestionV1View, TrackerFileSuggestionView
from apps.trackers.constants import TRACKERS_API_V1, TRACKERS_API_VERSION

urlpatterns = [
    path(f"api/{TRACKERS_API_V1}/file", TrackerFileSuggestionV1View.as_view()),
    path(f"api/{TRACKERS_API_VERSION}/file", TrackerFileSuggestionView.as_view()),
]
