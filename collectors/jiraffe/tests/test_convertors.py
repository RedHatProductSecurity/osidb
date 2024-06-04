import json

import pytest

from collectors.jiraffe.convertors import JiraTrackerConvertor
from collectors.jiraffe.core import JiraQuerier
from osidb.models import Affect, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
)

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
    def test_convert_not_linked(self):
        """
        test that the convertor linking works
        when the link is actually not there
        """
        flaw = FlawFactory(embargoed=False)
        ps_module = PsModuleFactory(name="amq-7")
        PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="elasticsearch",
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()

        tracker = Tracker.objects.get(external_system_id=self.tracker_id)
        assert not flaw.meta_attr.get("jira_trackers")
        assert not any(
            "CVE" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert not any(
            "flaw:bz#" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert tracker.affects.count() == 0

    @pytest.mark.vcr
    def test_convert_linked_from_flaw_side(self):
        """
        test that the convertor linking works
        when the link is in flaw SRT notes
        """
        flaw = FlawFactory(
            embargoed=False,
            meta_attr={"jira_trackers": json.dumps([{"key": self.tracker_id}])},
        )
        ps_module = PsModuleFactory(name="amq-7")
        PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="elasticsearch",
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()

        tracker = Tracker.objects.get(external_system_id=self.tracker_id)
        assert tracker.external_system_id in [
            t["key"] for t in json.loads(flaw.meta_attr["jira_trackers"])
        ]
        assert not any(
            "CVE" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert not any(
            "flaw:bz#" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect

    @pytest.mark.vcr
    def test_convert_linked_from_flaw_side_no_affect(self):
        """
        test the convertor alerts while linking
        when the link is in flaw SRT notes
        """
        flaw = FlawFactory(
            embargoed=False,
            meta_attr={"jira_trackers": json.dumps([{"key": self.tracker_id}])},
        )
        PsUpdateStreamFactory(name="amq-7.1")

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()

        tracker = Tracker.objects.get(external_system_id=self.tracker_id)
        assert tracker.external_system_id in [
            t["key"] for t in json.loads(flaw.meta_attr["jira_trackers"])
        ]
        assert not any(
            "CVE" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert not any(
            "flaw:bz#" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert tracker.affects.count() == 0
        assert tracker.alerts
        assert "tracker_no_affect" in tracker.alerts.values_list("name", flat=True)

    @pytest.mark.vcr
    def test_convert_linked_from_tracker_side_cve(self):
        """
        test that the convertor linking works
        when the link is in tracker CVE label
        """
        flaw = FlawFactory(
            cve_id="CVE-2014-3120",
            embargoed=False,
        )
        ps_module = PsModuleFactory(name="amq-7")
        PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="elasticsearch",
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()

        tracker = Tracker.objects.get(external_system_id=self.tracker_id)
        assert not flaw.meta_attr.get("jira_trackers")
        assert flaw.cve_id in json.loads(tracker.meta_attr["labels"])
        assert not any(
            "flaw:bz#" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect

    @pytest.mark.vcr
    def test_convert_linked_from_tracker_side_no_flaw(self):
        """
        test the convertor alerts while linking
        when the link is in tracker CVE label
        """
        PsUpdateStreamFactory(name="amq-7.1")

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()

        tracker = Tracker.objects.get(external_system_id=self.tracker_id)
        assert tracker.alerts
        assert "tracker_no_flaw" in tracker.alerts.values_list("name", flat=True)

    @pytest.mark.vcr
    def test_convert_linked_from_tracker_side_bz_id(self):
        """
        test that the convertor linking works
        when the link is in tracker BZ ID label
        """
        flaw = FlawFactory(
            bz_id="12345",
            embargoed=False,
        )
        ps_module = PsModuleFactory(name="amq-7")
        PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="elasticsearch",
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()

        tracker = Tracker.objects.get(external_system_id=self.tracker_id)
        assert not flaw.meta_attr.get("jira_trackers")
        assert not any(
            "CVE" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert f"flaw:bz#{flaw.bz_id}" in json.loads(tracker.meta_attr["labels"])
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect

    @pytest.mark.vcr
    def test_convert_linked_from_tracker_side_flawuuid(self, pin_envs):
        """
        test that the convertor linking works
        when the link is in tracker flawuuid label
        """
        flaw = FlawFactory(
            uuid="56f06643-6eb9-4fd0-aef7-38ddcbfab65d",  # remove randomness
            bz_id=None,
            cve_id=None,
            embargoed=False,
        )
        ps_module = PsModuleFactory(name="amq-7")
        PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="elasticsearch",
        )
        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        tracker = Tracker.objects.get(external_system_id=self.tracker_id)

        assert not flaw.meta_attr.get("jira_trackers")
        assert not any(
            "CVE" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert not any(
            "flaw:bz#" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect
