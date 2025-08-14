import datetime
import json

import pytest

from collectors.jiraffe.convertors import (
    JiraTaskConvertor,
    JiraTrackerConvertor,
)
from collectors.jiraffe.core import JiraQuerier
from osidb.models import Affect, Flaw, Tracker
from osidb.sync_manager import JiraTrackerLinkManager
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
        assert tracker.created_dt == datetime.datetime(
            2014, 8, 4, 15, 7, 19, tzinfo=datetime.timezone.utc
        )
        assert tracker.updated_dt == datetime.datetime(
            2014, 9, 10, 1, 43, 37, tzinfo=datetime.timezone.utc
        )
        # make sure the tracker is set public if non-embargoed
        # which is the case here with Red Hat Employee security level
        assert not tracker.is_embargoed
        assert tracker.resolved_dt == datetime.datetime(
            2014, 9, 10, 1, 43, 37, tzinfo=datetime.timezone.utc
        )
        assert tracker.special_handling == []

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
        ps_update_stream = PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="elasticsearch",
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        JiraTrackerLinkManager.link_tracker_with_affects(self.tracker_id)

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
        ps_update_stream = PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="elasticsearch",
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        JiraTrackerLinkManager.link_tracker_with_affects(self.tracker_id)

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
        ps_module = PsModuleFactory(name="amq-7")
        PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        _, _, failed_affects = JiraTrackerLinkManager.link_tracker_with_affects(
            self.tracker_id
        )

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
        assert failed_affects
        assert (None, ps_module.name, "elasticsearch") in failed_affects

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
        ps_update_stream = PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="elasticsearch",
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        JiraTrackerLinkManager.link_tracker_with_affects(self.tracker_id)

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
        _, failed_flaws, _ = JiraTrackerLinkManager.link_tracker_with_affects(
            self.tracker_id
        )

        assert failed_flaws
        assert "12345" in failed_flaws
        assert "CVE-2014-3130" in failed_flaws

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
        ps_update_stream = PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="elasticsearch",
        )

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        JiraTrackerLinkManager.link_tracker_with_affects(self.tracker_id)

        tracker = Tracker.objects.get(external_system_id=self.tracker_id)
        assert not flaw.meta_attr.get("jira_trackers")
        assert not any(
            "CVE" in label for label in json.loads(tracker.meta_attr["labels"])
        )
        assert f"flaw:bz#{flaw.bz_id}" in json.loads(tracker.meta_attr["labels"])
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect

    @pytest.mark.vcr
    def test_convert_linked_from_tracker_side_flawuuid(self):
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
        ps_update_stream = PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="elasticsearch",
        )
        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        JiraTrackerLinkManager.link_tracker_with_affects(self.tracker_id)
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

    @pytest.mark.vcr
    def test_convert_not_affected_justification(self):
        """
        Test that a tracker closed as Not a Bug as a VEX justification field which
        translates to a valid 'not affected justification'.
        """
        tracker_data = JiraQuerier().get_issue("RHEL-59004")
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker = tracker_convertor._gen_tracker_object()

        assert tracker.type == Tracker.TrackerType.JIRA
        assert tracker.external_system_id == "RHEL-59004"
        assert tracker.status == "Closed"
        assert tracker.resolution == "Not a Bug"
        assert tracker.not_affected_justification == "Inline Mitigations already Exist"

    @pytest.mark.vcr
    def test_convert_special_handling(self):
        """
        Test that a tracker with special handling fields gets them correctly
        as an array of values.
        """
        tracker_data = JiraQuerier().get_issue("RHEL-60033")
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker = tracker_convertor._gen_tracker_object()

        assert tracker.type == Tracker.TrackerType.JIRA
        assert tracker.external_system_id == "RHEL-60033"
        assert tracker.special_handling == [
            "Major Incident",
            "KEV (active exploit case)",
            "compliance-priority",
        ]


class TestJiraTaskConvertor:
    """
    test that Jira issue to OSIDB task convertor works
    """

    task_id = "OSIM-36885"

    @pytest.mark.vcr
    def test_convert(self):
        """
        test that the convertor works
        """
        task_data = JiraQuerier().get_issue(self.task_id, expand="changelog")
        task_convertor = JiraTaskConvertor(task_data)

        # Create an empty flaw with same uuid and CVE to hold the data comming from Jira
        flaw_uuid = next(
            label
            for label in task_convertor.task_data["labels"]
            if label.startswith("flawuuid:")
        ).split(":")[1]
        cve_id = next(
            label
            for label in task_convertor.task_data["labels"]
            if label.startswith("CVE")
        )
        FlawFactory(uuid=flaw_uuid, cve_id=cve_id, embargoed=False)

        # Trigger the conversion
        task_convertor.flaw.save()
        flaw = Flaw.objects.get(uuid=flaw_uuid)

        assert flaw is not None
        assert flaw.task_key == self.task_id
        assert flaw.team_id == ""
        assert flaw.task_updated_dt == datetime.datetime(
            2025, 9, 8, 9, 25, 14, 405000, tzinfo=datetime.timezone.utc
        )
        assert flaw.workflow_name == "DEFAULT"
        assert flaw.workflow_state == "TRIAGE"
        assert flaw.owner == "rh-ee-atinocom"
