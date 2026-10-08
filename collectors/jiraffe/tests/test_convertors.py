import datetime
import json
from unittest.mock import Mock

import pytest

from collectors.jiraffe.convertors import (
    JiraTaskConvertor,
    JiraTrackerConvertor,
    TrackerSaver,
)
from collectors.jiraffe.core import JiraQuerier
from osidb.models import Affect, Flaw, Impact, Tracker, WorkflowLabel
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
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
        from collectors.jiraffe.collectors import JiraTrackerDownloadManager

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
        JiraTrackerDownloadManager.link_tracker_with_affects(self.tracker_id)

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
    def test_convert_linked_from_tracker_side_no_affect(self):
        """
        test the convertor alerts while linking
        when the tracker CVE label resolves to a flaw with no matching affect
        """
        flaw = FlawFactory(
            cve_id="CVE-2014-3120",
            embargoed=False,
            # no bz_id so the failed affect is reported with a None flaw id
            meta_attr={},
        )
        ps_module = PsModuleFactory(name="amq-7")
        ps_update_stream = PsUpdateStreamFactory(name="amq-7.1", ps_module=ps_module)

        from collectors.jiraffe.collectors import JiraTrackerDownloadManager

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        _, _, failed_affects = JiraTrackerDownloadManager.link_tracker_with_affects(
            self.tracker_id
        )

        tracker = Tracker.objects.get(external_system_id=self.tracker_id)
        assert flaw.cve_id in json.loads(tracker.meta_attr["labels"])
        assert tracker.affects.count() == 0
        assert failed_affects
        assert (None, ps_update_stream.name, "elasticsearch") in failed_affects

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

        from collectors.jiraffe.collectors import JiraTrackerDownloadManager

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        JiraTrackerDownloadManager.link_tracker_with_affects(self.tracker_id)

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

        from collectors.jiraffe.collectors import JiraTrackerDownloadManager

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        _, failed_flaws, _ = JiraTrackerDownloadManager.link_tracker_with_affects(
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

        from collectors.jiraffe.collectors import JiraTrackerDownloadManager

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        JiraTrackerDownloadManager.link_tracker_with_affects(self.tracker_id)

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
        from collectors.jiraffe.collectors import JiraTrackerDownloadManager

        tracker_data = JiraQuerier().get_issue(self.tracker_id)
        tracker_convertor = JiraTrackerConvertor(tracker_data)
        tracker_convertor.tracker.save()
        JiraTrackerDownloadManager.link_tracker_with_affects(self.tracker_id)
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
        type(tracker_data.fields)
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

    @pytest.mark.parametrize(
        "update_stream,labels,summary",
        [
            (
                "test-stream",
                ["pscomponent:test-component"],
                "CVE-2026-99999 component: description [stream]",
            ),
            (
                None,
                ["pscomponent:test-component"],
                "CVE-2026-99999 component: description [test-stream]",
            ),
            (
                "test-stream",
                [],
                "CVE-2026-99999 test-component: description [stream]",
            ),
            (
                None,
                [],
                "CVE-2026-99999 test-component: description [test-stream]",
            ),
        ],
    )
    def test_ps_update_stream_and_component_syncing(
        self, update_stream, labels, summary
    ):
        """
        Test that ps_update_stream is parsed from the Update Stream field and
        and ps_component is parsed from the pscomponent label. If either is
        missing test the fallback to the summary.
        """
        ps_module = PsModuleFactory(name="test-module")
        PsUpdateStreamFactory(name="test-stream", ps_module=ps_module)

        mock_issue = Mock()
        mock_issue.key = "TEST-0"
        mock_issue.fields.customfield_10832 = update_stream
        mock_issue.fields.labels = labels
        mock_issue.fields.summary = summary
        mock_issue.fields.created = "2026-01-01T00:00:00.000+0000"
        mock_issue.fields.updated = "2026-01-01T00:00:00.000+0000"
        mock_issue.fields.resolutiondate = None
        convertor = JiraTrackerConvertor(mock_issue)

        assert convertor.ps_update_stream == "test-stream"
        assert convertor.ps_component == "test-component"
        assert convertor.ps_module == "test-module"


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
        assert flaw.task_updated_dt == datetime.datetime(
            2025, 9, 8, 9, 25, 14, 404000, tzinfo=datetime.timezone.utc
        )


class TestTrackerSaver:
    """
    tests for the download-side TrackerSaver (collectors.jiraffe.convertors)
    shared by the Jira and Bugzilla tracker download paths
    """

    def test_save_preserves_existing_affect_links(self):
        """
        re-saving a tracker during a download must NOT unlink its affects

        regression: TrackerSaver.save() used to call affects.set([]), which
        cleared every link until the follow-up link_tracker_with_affects()
        relinked them. That transient unlinking flipped the flaw's has_trackers
        check to False and demoted its workflow state, polluting the audit
        history with meaningless DONE <-> PRE_SECONDARY_ASSESSMENT transitions
        on every sync.
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=FlawFactory(embargoed=False),
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )
        assert tracker.affects.count() == 1

        # simulate a periodic re-download: the convertor builds a TrackerSaver
        # with no explicit affects (they are reconciled separately afterwards
        # via link_tracker_with_affects -> relink_affects)
        TrackerSaver(tracker, [], []).save()

        affect.refresh_from_db()
        tracker.refresh_from_db()
        assert affect.tracker == tracker
        assert tracker.affects.count() == 1

    @pytest.mark.enable_signals
    def test_download_does_not_ping_pong_workflow_state(self):
        """
        reproduce the production workflow ping-pong and prove the fix stops it

        A flaw sitting in DONE (approved, all affects resolved and tracked)
        used to bounce DONE <-> PRE_SECONDARY_ASSESSMENT on every tracker
        download. Each per-tracker download task ran TrackerSaver.save(), which
        cleared the tracker's affect link via affects.set([]) before a later
        step relinked it. While one tracker's affect was transiently unlinked,
        saving another tracker of the same flaw fired the
        update_local_updated_dt_tracker signal, which re-saved and
        re-classified the flaw; has_trackers was momentarily False so the flaw
        dropped out of DONE and popped back once relinked - spamming the audit
        trail with meaningless transitions.

        This simulates two concurrent per-tracker downloads interleaving and
        asserts the flaw never leaves DONE and no PRE_SECONDARY_ASSESSMENT
        event is recorded. Against the old affects.set([]) behaviour it fails:
        a PRE_SECONDARY_ASSESSMENT event appears in the flaw's history.
        """
        event_model = Flaw.pgh_event_model

        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker_type = Tracker.BTS2TYPE[ps_module.bts_name]

        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-PINGPONG",
            impact=Impact.MODERATE,
            cwe_id="CWE-1",
            cve_description="random cve_description",
        )

        def _affect_with_tracker(component):
            affect = AffectFactory(
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                ps_component=component,
            )
            tracker = TrackerFactory(
                affects=[affect],
                embargoed=False,
                ps_update_stream=ps_update_stream.name,
                type=tracker_type,
            )
            return affect, tracker

        affect1, tracker1 = _affect_with_tracker("component-1")
        affect2, tracker2 = _affect_with_tracker("component-2")

        # approve and settle into DONE
        WorkflowLabel.objects.create(flaw=flaw, name="approved")
        flaw.adjust_classification()
        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"

        # ignore everything recorded while climbing to DONE
        baseline_ids = set(
            event_model.objects.filter(pgh_obj_id=flaw.uuid).values_list(
                "pgh_id", flat=True
            )
        )

        # simulate two per-tracker download tasks interleaving: both run their
        # TrackerSaver.save() (the point where the old code unlinked the
        # affects) before the follow-up step relinks them
        TrackerSaver(tracker1, [], []).save()
        TrackerSaver(tracker2, [], []).save()
        # the sync managers reconcile the links afterwards via relink_affects()
        tracker1.relink_affects([affect1])
        tracker1.save(auto_timestamps=False, raise_validation_error=False)
        tracker2.relink_affects([affect2])
        tracker2.save(auto_timestamps=False, raise_validation_error=False)

        flaw.refresh_from_db()
        assert flaw.workflow_state == "DONE"

        recorded_states = set(
            event_model.objects.filter(pgh_obj_id=flaw.uuid)
            .exclude(pgh_id__in=baseline_ids)
            .values_list("workflow_state", flat=True)
        )
        assert recorded_states <= {"DONE"}, (
            "tracker download produced spurious workflow transitions: "
            f"{sorted(recorded_states)}"
        )
