import json

import pytest
from django.utils import timezone
from freezegun import freeze_time

from apps.trackers.models import JiraProjectFields
from collectors.framework.models import CollectorMetadata
from collectors.jiraffe.collectors import JiraTrackerCollector, MetadataCollector
from osidb.models import Affect, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


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
        assert msg == f"Jira tracker sync of {tracker_id} completed"
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()
        assert tracker.external_system_id == tracker_id
        assert tracker.affects.count() == 2
        assert all(tracker in affect.trackers.all() for affect in Affect.objects.all())


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
