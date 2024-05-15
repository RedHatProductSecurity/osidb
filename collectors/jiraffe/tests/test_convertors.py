import pytest

from collectors.jiraffe.convertors import JiraTrackerConvertor
from collectors.jiraffe.core import JiraQuerier
from osidb.models import Affect, Tracker
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestJiraTrackerConvertor:
    """
    test that Jira issue to OSIDB tracker convertor works
    """

    tracker_id = "ENTMQ-755"

    @pytest.mark.vcr
    def test_convert(self):
        """
        test that the convertor works
        """
        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker = tracker_convertor._gen_tracker_object()

        assert tracker.type == Tracker.TrackerType.JIRA
        assert tracker.external_system_id == self.tracker_id
        assert tracker.status == "Closed"
        assert tracker.resolution == "Done"
        assert tracker.ps_update_stream == "amq-7.1"
        assert tracker.created_dt == "2014-08-04T15:07:19.000+0000"
        assert tracker.updated_dt == "2014-09-10T01:43:37.000+0000"
        # make sure the tracker is set public if non-embargoed
        # which is the case here with Red Hat Employee security level
        assert not tracker.is_embargoed

    @pytest.mark.vcr
    @pytest.mark.parametrize(
        "security_level", ["Embargoed Security Issue", "Security Issue"]
    )
    def test_convert_embargoed(self, security_level):
        """
        test that the convertor ACLs setting works properly for the embargoed trackers
        """
        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_data.fields.security.name = security_level  # set to embargoed
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker = tracker_convertor._gen_tracker_object()

        assert tracker.is_embargoed

    @pytest.mark.vcr
    def test_convert_linked(self):
        """
        test that the convertor linking works
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED, flaw=flaw
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker = tracker_convertor.tracker

        # TODO
        # assert tracker.affects.count() == 1
        # assert tracker.affects.first() == affect
