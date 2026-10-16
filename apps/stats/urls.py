from django.urls import path

from .api import StatsFlawsView, StatsTrackerView
from .constants import STATS_API_VERSION

urlpatterns = [
    path(f"api/{STATS_API_VERSION}/flaws", StatsFlawsView.as_view()),
    path(f"api/{STATS_API_VERSION}/trackers", StatsTrackerView.as_view()),
]
