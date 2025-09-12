import datetime

import pytest

from collectors.bzimport.convertors import BugzillaTrackerConvertor
from osidb.models import Tracker

pytestmark = pytest.mark.unit


class TestBugzillaTrackerConvertor:
    @classmethod
    def get_bz_tracker(cls):
        """
        minimal Bugzilla flaw data getter
        """
        return {
            "id": "583164",
            "creation_time": "2010-01-01T12:12:12Z",
            "depends_on": [],
            "description": "text",
            "fixed_in": None,
            "groups": [],
            "blocks": [583162],
            "assigned_to": "foo@bar.com",
            "qa_contact": "foo@fedoraproject.com",
            "last_change_time": "2015-03-02T10:37:22Z",
            "status": "CLOSED",
            "resolution": "NEXTRELEASE",
            "summary": "EMBARGOED TRIAGE CVE-2000-1234 foo: ACL bypass with Authorization: 0000 HTTP header",
            "cf_last_closed": "2014-03-02T10:37:22Z",
            "whiteboard": "",
        }

    def test_resolved_dt(self):
        """
        test that resolved date is correctly set
        """
        bz_tracker = self.get_bz_tracker()

        BugzillaTrackerConvertor(bz_tracker).tracker.save()
        tracker = Tracker.objects.get(external_system_id=bz_tracker["id"])
        assert tracker.resolved_dt == datetime.datetime(
            2014, 3, 2, 10, 37, 22, tzinfo=datetime.timezone.utc
        )
