import json
import uuid
from datetime import datetime

import pytest
from django.utils import timezone
from freezegun import freeze_time

import collectors.jiraffe.collectors as collectors
import collectors.jiraffe.convertors as convertors
import osidb.models as models
from apps.taskman.constants import JIRA_AUTH_TOKEN
from apps.taskman.service import JiraTaskmanQuerier
from apps.trackers.models import JiraProjectFields
from apps.workflows.workflow import WorkflowModel
from collectors.bzimport.collectors import FlawCollector
from collectors.framework.models import CollectorMetadata
from collectors.jiraffe.collectors import (
    JiraTaskCollector,
    JiraTrackerCollector,
    MetadataCollector,
)
from collectors.jiraffe.core import JiraQuerier
from osidb.models import Affect, Flaw, Impact, Tracker
from osidb.sync_manager import JiraTrackerLinkManager
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestJiraTaskCollector:
    @pytest.mark.vcr
    def test_collect(self, monkeypatch):
        """
        test the Jira collector run
        """
        jira_token = JIRA_AUTH_TOKEN if JIRA_AUTH_TOKEN else "USER_JIRA_TOKEN"
        monkeypatch.setattr(models, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(convertors, "JIRA_AUTH_TOKEN", jira_token)
        monkeypatch.setattr(collectors, "JIRA_TOKEN", jira_token)

        collector = JiraTaskCollector()
        jtq = JiraTaskmanQuerier(token=jira_token)

        # remove randomness for VCR usage
        uuid = "fb145b06-82a7-4851-a429-541288633d16"
        flaw = FlawFactory(uuid=uuid, embargoed=False, impact=Impact.IMPORTANT)
        AffectFactory(flaw=flaw)
        flaw.tasksync(force_creation=True, jira_token=jira_token)
        assert flaw.impact == Impact.IMPORTANT

        assert flaw.task_key

        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "New"
        assert not issue["fields"]["resolution"]
        assert f"flawuuid:{str(uuid)}" in issue["fields"]["labels"]
        assert f"impact:{Impact.IMPORTANT}" in issue["fields"]["labels"]

        # Manually modify Jira task status
        data = {
            "fields": {
                "labels": [f"flawuuid:{str(uuid)}", f"impact:{Impact.IMPORTANT}"],
            }
        }
        url = f"{jtq.jira_conn._get_url('issue')}/{flaw.task_key}"
        jtq.jira_conn._session.put(url, json.dumps(data))
        jtq.jira_conn.transition_issue(
            issue=flaw.task_key,
            transition="Refinement",
        )
        issue = jtq.jira_conn.issue(flaw.task_key).raw
        assert issue["fields"]["status"]["name"] == "Refinement"
        assert f"flawuuid:{str(uuid)}" in issue["fields"]["labels"]
        assert f"impact:{Impact.IMPORTANT}" in issue["fields"]["labels"]
        assert not issue["fields"]["resolution"]

        collector.collect(flaw.task_key)

        # refresh instance
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert flaw.workflow_state == "TRIAGE"

    @pytest.mark.vcr
    def test_link_on_cve(self, monkeypatch):
        monkeypatch.setattr(collectors, "JIRA_TOKEN", "SECRET")

        # some random UUID
        flaw = FlawFactory(cve_id="CVE-2024-34703")
        # this is super-unprobable to happen but based
        # on the review feedback I am adding the assert
        assert flaw.uuid != uuid.UUID("9d9132a4-0484-48a5-b484-185abf39b771")
        assert not flaw.task_key

        collector = JiraTaskCollector()
        collector.collect("OSIM-156")
        assert Flaw.objects.get(uuid=flaw.uuid).task_key

    @pytest.mark.vcr
    def test_outdated_query(self, monkeypatch):
        """
        test that Jira task collector ignores tasks with outdated timestamp
        """
        jira_token = JIRA_AUTH_TOKEN if JIRA_AUTH_TOKEN else "USER_JIRA_TOKEN"
        monkeypatch.setattr(models, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(convertors, "JIRA_AUTH_TOKEN", jira_token)
        monkeypatch.setattr(collectors, "JIRA_TOKEN", jira_token)

        jtq = JiraTaskmanQuerier(token=jira_token)

        # 1 - create a flaw with task
        # remove randomness for VCR usage
        uuid = "e49a732a-06fe-4942-94d8-3a8b0407e827"
        flaw = FlawFactory(uuid=uuid, embargoed=False, impact=Impact.IMPORTANT)
        AffectFactory(flaw=flaw)
        flaw.tasksync(force_creation=True, jira_token=jira_token)
        assert flaw.task_key

        # 2 - get the current Jira task and make sure db is in-sync
        issue = jtq.jira_conn.issue(flaw.task_key)
        last_update = datetime.strptime(issue.fields.updated, "%Y-%m-%dT%H:%M:%S.%f%z")
        assert last_update == flaw.task_updated_dt
        assert issue.fields.status.name == "New"

        # 3 - freeze the issue in time to simulate long queries being outdated
        def mock_get_issue(self, jira_id: str):
            return issue

        monkeypatch.setattr(JiraQuerier, "get_issue", mock_get_issue)

        # 4 - simulate user promoting a flaw
        flaw.workflow_state = WorkflowModel.WorkflowState.TRIAGE
        flaw.tasksync(jira_token=jira_token)
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert last_update < flaw.task_updated_dt
        assert flaw.workflow_state == "TRIAGE"

        # 5 - make sure collector does not change flaw if it is holding outdated issue
        collector = JiraTaskCollector()
        collector.collect(flaw.task_key)
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert flaw.workflow_state == "TRIAGE"
        assert last_update < flaw.task_updated_dt


class TestJiraTrackerCollector:
    """
    test that Jira collector works
    """

    @pytest.mark.vcr
    def test_get_batch(self):
        """
        test that getting the next batch of Jira issues works
        """
        collector = JiraTrackerCollector()
        collector.BATCH_PERIOD_DAYS = 365
        assert collector.BEGINNING == timezone.datetime(2014, 1, 1, tzinfo=timezone.utc)
        assert collector.metadata.updated_until_dt is None

        CollectorMetadata(
            name="collectors.bzimport.tasks.flaw_collector",
            updated_until_dt=timezone.now(),
        ).save()

        trackers, period_end = collector.get_batch()
        assert len(trackers) == 15  # all the trackers from 2014
        assert period_end == timezone.datetime(2015, 1, 1, tzinfo=timezone.utc)

        # artificially change the updated until timestamp
        collector.metadata.updated_until_dt = period_end

        trackers, period_end = collector.get_batch()
        assert len(trackers) == 30  # all the trackers from 2015
        assert period_end == timezone.datetime(2016, 1, 1, tzinfo=timezone.utc)

    @pytest.mark.vcr
    def test_get_batch_till_flaws(self):
        """
        test that getting the next batch of Jira issues works
        correctly taking into account the FlawCollector freshness
        """
        collector = JiraTrackerCollector()
        collector.BATCH_PERIOD_DAYS = 365
        assert collector.BEGINNING == timezone.datetime(2014, 1, 1, tzinfo=timezone.utc)
        assert collector.metadata.updated_until_dt is None

        CollectorMetadata(
            name="collectors.bzimport.tasks.flaw_collector",
            updated_until_dt=timezone.datetime(2014, 9, 1, tzinfo=timezone.utc),
        ).save()

        trackers, period_end = collector.get_batch()
        assert len(trackers) == 1
        assert period_end == timezone.datetime(2014, 9, 1, tzinfo=timezone.utc)

        # artificially change the updated until timestamp
        collector.metadata.updated_until_dt = period_end

        # consecutive sync should not sync anything new
        trackers, period_end = collector.get_batch()
        assert len(trackers) == 0
        assert period_end == timezone.datetime(2014, 9, 1, tzinfo=timezone.utc)

        CollectorMetadata(
            name="collectors.bzimport.tasks.flaw_collector",
            updated_until_dt=timezone.datetime(2015, 2, 15, tzinfo=timezone.utc),
        ).save()

        trackers, period_end = collector.get_batch()
        assert len(trackers) == 16
        assert period_end == timezone.datetime(2015, 2, 15, tzinfo=timezone.utc)

    @pytest.mark.vcr
    def test_collect(self):
        """
        test the Jira collector run
        """
        collector = JiraTrackerCollector()
        collector.BATCH_PERIOD_DAYS = 365
        assert collector.BEGINNING == timezone.datetime(2014, 1, 1, tzinfo=timezone.utc)
        assert collector.metadata.updated_until_dt is None

        CollectorMetadata(
            name="collectors.bzimport.tasks.flaw_collector",
            updated_until_dt=timezone.now(),
        ).save()

        msg = collector.collect()
        assert Tracker.objects.count() == 15  # all the trackers from 2014
        assert collector.metadata.updated_until_dt == timezone.datetime(
            2015, 1, 1, tzinfo=timezone.utc
        )
        assert msg == (
            "collectors.jiraffe.collectors.jira_tracker_collector is "
            "updated until 2015-01-01 00:00:00+00:00. Jira trackers updated: "
            "ENTMQ-755, ENTMQ-754, ENTMQ-701, ENTMQ-643, ENTESB-1767, "
            "ENTESB-1766, ENTESB-1660, ENTESB-1639, ENTESB-1525, ENTESB-1524, "
            "ENTESB-1523, ENTESB-1521, ENTESB-1431, ENTESB-1383, ENTESB-1382"
        )

        msg = collector.collect()
        assert Tracker.objects.count() == 45  # all the trackers from 2014 and 2015
        assert collector.metadata.updated_until_dt == timezone.datetime(
            2016, 1, 1, tzinfo=timezone.utc
        )
        assert msg == (
            "collectors.jiraffe.collectors.jira_tracker_collector is "
            "updated until 2016-01-01 00:00:00+00:00. Jira trackers updated: "
            "WFCORE-120, PLINK-708, ENTMQ-1346, ENTMQ-931, ENTMQ-863, "
            "ENTMQ-663, ENTMQ-662, ENTMQ-661, ENTMQ-660, ENTESB-3080, "
            "ENTESB-3079, ENTESB-2837, ENTESB-2732, ENTESB-2731, ENTESB-2730, "
            "ENTESB-2662, ENTESB-2661, ENTESB-2660, ENTESB-2659, ENTESB-2658, "
            "ENTESB-2656, ENTESB-2535, ENTESB-2523, ENTESB-2214, ENTESB-2145, "
            "ENTESB-2144, ENTESB-2066, ENTESB-2065, ENTESB-1835, ENTESB-1661"
        )

    @pytest.mark.vcr
    @freeze_time(timezone.datetime(2015, 12, 12))
    def test_collect_complete(self):
        """
        test that Jira collector data status is changed to complete when the data are current
        """
        collector = JiraTrackerCollector()
        collector.BATCH_PERIOD_DAYS = 365
        collector.metadata.updated_until_dt = timezone.now()
        CollectorMetadata(
            name="collectors.bzimport.tasks.flaw_collector",
            updated_until_dt=timezone.datetime(2020, 12, 12, tzinfo=timezone.utc),
        ).save()
        assert not collector.is_complete

        collector.collect()
        assert collector.is_complete

    @pytest.mark.vcr
    def test_collect_embargoed(self):
        """
        test that an embargoed tracker loaded from Jira is preserved as embargoed
        """
        tracker_id = "RHEL-12102"
        assert Tracker.objects.count() == 0
        collector = JiraTrackerCollector()
        collector.collect(tracker_id)
        assert Tracker.objects.filter(external_system_id=tracker_id).exists()
        assert Tracker.objects.get(external_system_id=tracker_id).is_embargoed

    @pytest.mark.vcr
    def test_collect_id(self):
        """
        test collecting a Jira issue specified by the given ID
        """
        tracker_id = "ENTMQ-755"
        collector = JiraTrackerCollector()

        msg = collector.collect(tracker_id)
        assert msg == f"Jira tracker sync of {tracker_id} completed"
        assert Tracker.objects.count() == 1
        assert Tracker.objects.first().external_system_id == tracker_id

    @pytest.mark.vcr
    def test_collect_id_known(self):
        """
        test collecting a known Jira issue specified by the given ID
        which should result in updating the known one and no duplicates
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )
        tracker_id = "ENTMQ-755"
        TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            embargoed=affect.flaw.embargoed,
            external_system_id=tracker_id,
            status="New",
            resolution=None,
        )
        collector = JiraTrackerCollector()

        msg = collector.collect(tracker_id)
        assert msg == f"Jira tracker sync of {tracker_id} completed"
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()
        assert tracker.external_system_id == tracker_id
        assert tracker.status == "Closed"
        assert tracker.resolution == "Done"

    @pytest.mark.vcr
    def test_collect_id_known_linked(self):
        """
        test collecting a known Jira issue specified by the given ID
        linked to an affect which should preserve the linking
        """
        tracker_id = "ENTMQ-755"
        flaw1 = FlawFactory(
            embargoed=False,
            meta_attr={"jira_trackers": json.dumps([{"key": tracker_id}])},
        )
        flaw2 = FlawFactory(
            embargoed=False,
            meta_attr={"jira_trackers": json.dumps([{"key": tracker_id}])},
        )
        ps_module = PsModuleFactory(bts_name="jboss", name="module")
        affect1 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw1,
            ps_module=ps_module.name,
            ps_component="component",
        )
        affect2 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw2,
            ps_module=ps_module.name,
            ps_component="component",
        )
        ps_update_stream = PsUpdateStreamFactory(name="stream", ps_module=ps_module)
        TrackerFactory(
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
            external_system_id=tracker_id,
            affects=[affect1, affect2],
        )
        collector = JiraTrackerCollector()

        msg = collector.collect(tracker_id)
        JiraTrackerLinkManager.link_tracker_with_affects(tracker_id)

        assert msg == f"Jira tracker sync of {tracker_id} completed"
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()
        assert tracker.external_system_id == tracker_id
        assert tracker.affects.count() == 2
        assert all(tracker in affect.trackers.all() for affect in Affect.objects.all())

    @pytest.mark.vcr
    def test_collect_tracker_with_multi_cve_flaw(self):
        """
        test collecting a Jira issue linked to a multi-CVE flaw
        https://issues.redhat.com/browse/OSIDB-2708
        """
        flaw_id = "2090226"
        tracker_id = "OSD-12347"

        fc = FlawCollector()
        fc.sync_flaw(flaw_id)
        assert Flaw.objects.count() == 2
        assert Flaw.objects.filter(meta_attr__bz_id=flaw_id).count() == 2

        ps_module = PsModuleFactory(name="openshift-hosted-osd4")
        PsUpdateStreamFactory(name="openshift-hosted-osd4-default", ps_module=ps_module)

        jtc = JiraTrackerCollector()
        # before fixing OSIDB-2708
        # we get traceback here
        msg = jtc.collect(tracker_id)
        JiraTrackerLinkManager.link_tracker_with_affects(tracker_id)

        assert msg == f"Jira tracker sync of {tracker_id} completed"
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()
        assert tracker.external_system_id == tracker_id
        assert tracker.affects.count() == 2
        assert tracker.affects.first().flaw != tracker.affects.last().flaw


class TestMetadataCollector:
    @freeze_time(timezone.datetime(2015, 12, 12))
    @pytest.mark.vcr
    @pytest.mark.parametrize("project_key,fields_count", [("RHEL", 120), ("OSIM", 20)])
    def test_collect(self, pin_envs, project_key, fields_count):
        """
        Test that collector is able to get metadata from Jira projects
        """
        ps_module = PsModuleFactory(
            bts_name="jira",
            bts_key=project_key,
            supported_until_dt=timezone.make_aware(timezone.datetime(2020, 12, 12)),
        )
        PsUpdateStreamFactory(ps_module=ps_module)

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == 0

        mc = MetadataCollector()
        mc.collect()

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == fields_count
