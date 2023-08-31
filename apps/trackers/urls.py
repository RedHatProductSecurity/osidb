from django.urls import path

from apps.trackers.api import TrackerFileSuggestionView
from apps.trackers.constants import TRACKERS_API_VERSION

urlpatterns = [
    path(f"api/{TRACKERS_API_VERSION}/file", TrackerFileSuggestionView.as_view()),
]
