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

    def create(self):
        """
        create tracker in Bugzilla
        """
        self.assert_context()
        return super().create()

    def update(self):
        """
        update tracker in Bugzilla
        """
        self.assert_context()
        return super().update()

    def assert_context(self):
        """
        the vital tracker related pieces of information need to exist
        or otherwise we would not be able to construct the tracker query
        """
        # TODO these assertions are applicable to the Jira
        # trackers too but let me keep it here until we merge
        from osidb.models import PsModule, PsUpdateStream

        assert self.tracker.affects.first()
        assert PsModule.objects.filter(name=self.tracker.affects.first().ps_module)
        assert PsUpdateStream.objects.filter(name=self.tracker.ps_update_stream)
