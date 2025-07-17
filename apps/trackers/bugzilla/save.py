"""
Bugzilla tracker funtionality module
"""

from apps.bbsync.save import BugzillaSaver
from osidb.models import Tracker

from .query import TrackerBugzillaQueryBuilder


class TrackerBugzillaSaver(BugzillaSaver):
    """
    Bugzilla tracker bug save handler
    """

    @property
    def tracker(self):
        """
        concrete name shortcut
        """
        return self.instance

    @property
    def model(self):
        """
        Tracker model class getter
        """
        return Tracker

    @property
    def query_builder(self):
        """
        query builder class getter
        """
        return TrackerBugzillaQueryBuilder
