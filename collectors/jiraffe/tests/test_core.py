import pytest
from django.utils import timezone
from freezegun import freeze_time

from osidb.models import Affect, Tracker

from ..core import find_jira_trackers, upsert_trackers

pytestmark = pytest.mark.unit


class TestJiraTrackerCollection(object):
    @staticmethod
    def _gen_affect(flaw, module, component):
        affect = Affect.objects.create_affect(
            flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
            impact=Affect.AffectImpact.NOVALUE,
            ps_module=module,
            ps_component=component,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        affect.save()
        return affect

    @pytest.mark.vcr
    def test_collect_from_affect(self, good_flaw, good_jira_trackers):
        """
        Test the collection of JIRA trackers from a given affect.
        """
        affect = self._gen_affect(good_flaw, "fis-2", "xmlrpc-common")
        trackers = find_jira_trackers(affect)
        assert trackers
        assert len(trackers) == 1
        assert trackers[0].key == good_jira_trackers[0]

    @pytest.mark.vcr
    def test_collect_non_jira_tracker_from_affect(self, good_flaw, good_jira_trackers):
        """
        Test the collection of non-JIRA trackers from a given affect.
        """
        # fedora-all is tracked in Bugzilla, therefore it should not return any results
        affect = self._gen_affect(good_flaw, "fedora-all", "springframework")
        trackers = find_jira_trackers(affect)
        assert not trackers

    @pytest.mark.vcr
    @freeze_time(timezone.datetime(2020, 10, 10))
    def test_tracker_creation_from_affect(self, good_flaw, good_jira_trackers):
        """
        Test the creation of Tracker objects from Affect objects by querying the JIRA API.
        """
        affect = self._gen_affect(good_flaw, "fis-2", "xmlrpc-common")
        assert not affect.trackers.all()

        upsert_trackers(affect)
        tracker = affect.trackers.all().first()

        assert tracker is not None
        assert tracker.external_system_id in good_jira_trackers
        assert tracker.status == "Closed"
        assert tracker.resolution == "Done"
        assert tracker.ps_update_stream == "fis-2.0"
        assert tracker.meta_attr.get("status", False)
        assert tracker.meta_attr.get("resolution", False)
        assert tracker.meta_attr.get("owner", False) is None
        assert tracker.meta_attr.get("qe_owner", False) is None
        assert tracker.meta_attr.get("ps_module", False)
        assert tracker.meta_attr.get("ps_component", False)
        assert tracker.created_dt == timezone.datetime(
            2018, 4, 24, 1, 2, 47, tzinfo=timezone.utc
        )
        assert tracker.updated_dt == timezone.datetime(
            2018, 6, 5, 16, 2, 24, tzinfo=timezone.utc
        )

    @pytest.mark.vcr
    @freeze_time(timezone.datetime(2020, 10, 10))
    def test_tracker_update_from_affect(self, good_flaw, good_jira_trackers):
        """
        Test updating an existing Tracker object from an Affect object by querying the JIRA API.
        """
        affect = self._gen_affect(good_flaw, "fis-2", "xmlrpc-common")
        tracker = Tracker.objects.create_tracker(
            affect=affect,
            _type=Tracker.TrackerType.JIRA,
            external_system_id=good_jira_trackers[0],
            status="random_status",
            resolution="random_resolution",
            acl_read=affect.acl_read,
            acl_write=affect.acl_write,
        )
        tracker.save()
        tracker.affects.add(affect)

        tracker = affect.trackers.all().first()
        assert affect.trackers.count() == 1
        assert not tracker.meta_attr
        assert tracker.status == "random_status"
        assert tracker.resolution == "random_resolution"
        assert tracker.ps_update_stream == ""
        assert tracker.created_dt == timezone.datetime(
            2020, 10, 10, tzinfo=timezone.utc
        )
        assert tracker.updated_dt == timezone.datetime(
            2020, 10, 10, tzinfo=timezone.utc
        )

        # Should update the previously created tracker, not create a new one
        upsert_trackers(affect)

        tracker = affect.trackers.all().first()
        assert affect.trackers.count() == 1
        assert tracker.meta_attr
        assert tracker.status == "Closed"
        assert tracker.resolution == "Done"
        assert tracker.ps_update_stream == "fis-2.0"
        assert tracker.created_dt == timezone.datetime(
            2018, 4, 24, 1, 2, 47, tzinfo=timezone.utc
        )
        assert tracker.updated_dt == timezone.datetime(
            2018, 6, 5, 16, 2, 24, tzinfo=timezone.utc
        )
