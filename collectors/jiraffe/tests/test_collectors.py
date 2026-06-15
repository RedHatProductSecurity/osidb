import json
from datetime import datetime, timedelta, timezone

import pytest
from freezegun import freeze_time
from jira.exceptions import JIRAError

from apps.trackers.models import JiraProjectFields
from collectors.bzimport.constants import BZ_DT_FMT
from collectors.jiraffe.collectors import (
    JiraTrackerCollector,
    JiraTrackerDownloadManager,
    MetadataCollector,
)
from collectors.jiraffe.constants import jira_collector_settings
from collectors.jiraffe.exceptions import (
    MetadataCollectorInsufficientDataJiraffeException,
)
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
        assert collector.BEGINNING == datetime(2014, 1, 1, tzinfo=timezone.utc)
        assert collector.metadata.updated_until_dt is None

        trackers, _, period_end = collector.get_batch()
        assert len(trackers) == 15  # all the trackers from 2014
        assert period_end == datetime(2015, 1, 1, tzinfo=timezone.utc)

        # artificially change the updated until timestamp
        collector.metadata.updated_until_dt = period_end

        trackers, _, period_end = collector.get_batch()
        assert len(trackers) == 31  # all the trackers from 2015
        assert period_end == datetime(2016, 1, 1, tzinfo=timezone.utc)

    def test_get_batch_with_overlap(self, monkeypatch):
        """
        test that overlap_seconds works correctly when getting batches

        - First batch: [period_start - overlap, period_end]
        - Second batch: [period_end - overlap, new_period_end]
        - The two batches should overlap by exactly overlap_seconds
        """

        # Set overlap to 5 minutes (300 seconds)
        overlap_seconds = 300
        monkeypatch.setattr(jira_collector_settings, "overlap_seconds", overlap_seconds)

        collector = JiraTrackerCollector()
        collector.BATCH_PERIOD_DAYS = 1

        # Set initial period_start
        initial_start = datetime(2026, 2, 10, 10, 0, 0, tzinfo=timezone.utc)
        collector.metadata.updated_until_dt = initial_start

        # Mock get_tracker_period to avoid actual Jira calls
        def mock_get_tracker_period(period_start, period_end):
            return []

        monkeypatch.setattr(
            collector.jira_querier, "get_tracker_period", mock_get_tracker_period
        )

        _, first_period_start, first_period_end = collector.get_batch()

        expected_first_start = initial_start - timedelta(seconds=overlap_seconds)
        expected_first_end = initial_start + timedelta(days=collector.BATCH_PERIOD_DAYS)

        assert first_period_start == expected_first_start
        assert first_period_end == expected_first_end

        collector.metadata.updated_until_dt = first_period_end
        _, second_period_start, second_period_end = collector.get_batch()

        expected_second_start = first_period_end - timedelta(seconds=overlap_seconds)
        expected_second_end = first_period_end + timedelta(
            days=collector.BATCH_PERIOD_DAYS
        )

        overlap_duration = first_period_end - second_period_start

        # Verify the overlap
        assert second_period_start == expected_second_start
        assert second_period_end == expected_second_end
        assert overlap_duration == timedelta(seconds=overlap_seconds)

        assert first_period_start == datetime(
            2026, 2, 10, 9, 55, 0, tzinfo=timezone.utc
        )
        assert first_period_end == datetime(2026, 2, 11, 10, 0, 0, tzinfo=timezone.utc)
        assert second_period_start == datetime(
            2026, 2, 11, 9, 55, 0, tzinfo=timezone.utc
        )
        assert second_period_end == datetime(2026, 2, 12, 10, 0, 0, tzinfo=timezone.utc)

    @pytest.mark.vcr
    def test_collect(self):
        """
        test the Jira collector run
        """
        collector = JiraTrackerCollector()
        collector.BATCH_PERIOD_DAYS = 365
        assert collector.BEGINNING == datetime(2014, 1, 1, tzinfo=timezone.utc)
        assert collector.metadata.updated_until_dt is None

        msg = collector.collect()
        # the tracker collection is now only scheduled and not really performed
        # assert Tracker.objects.count() == 15  # all the trackers from 2014
        assert collector.metadata.updated_until_dt == datetime(
            2015, 1, 1, tzinfo=timezone.utc
        )
        assert msg == (
            "collectors.jiraffe.collectors.jira_tracker_collector is "
            "updated until 2015-01-01 00:00:00+00:00. Jira tracker sync scheduled: "
            "ENTMQ-755, ENTMQ-754, ENTMQ-701, ENTMQ-643, ENTESB-1767, "
            "ENTESB-1766, ENTESB-1660, ENTESB-1639, ENTESB-1525, ENTESB-1524, "
            "ENTESB-1523, ENTESB-1521, ENTESB-1431, ENTESB-1383, ENTESB-1382"
        )

        msg = collector.collect()
        # the tracker collection is now only scheduled and not really performed
        # assert Tracker.objects.count() == 45  # all the trackers from 2014 and 2015
        assert collector.metadata.updated_until_dt == datetime(
            2016, 1, 1, tzinfo=timezone.utc
        )
        assert msg == (
            "collectors.jiraffe.collectors.jira_tracker_collector is "
            "updated until 2016-01-01 00:00:00+00:00. Jira tracker sync scheduled: "
            "WFCORE-120, PLINK-708, ENTMQ-1346, ENTMQ-931, ENTMQ-863, "
            "ENTMQ-663, ENTMQ-662, ENTMQ-661, ENTMQ-660, ENTESB-3080, "
            "ENTESB-3079, ENTESB-2837, ENTESB-2732, ENTESB-2731, ENTESB-2730, "
            "ENTESB-2662, ENTESB-2661, ENTESB-2660, ENTESB-2659, ENTESB-2658, "
            "ENTESB-2656, ENTESB-2535, ENTESB-2523, ENTESB-2214, ENTESB-2145, "
            "ENTESB-2144, ENTESB-2066, ENTESB-2065, ENTESB-1835, ENTESB-1696, ENTESB-1661"
        )

    @pytest.mark.vcr
    @freeze_time(datetime(2024, 10, 1, 12, 0, 0))
    def test_collect_complete(self):
        """
        test that Jira collector data status is changed to complete when the data are current
        """
        collector = JiraTrackerCollector()
        collector.BATCH_PERIOD_DAYS = 365
        collector.metadata.updated_until_dt = datetime.now().replace(
            tzinfo=timezone.utc
        )
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
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        tracker_id = "ENTMQ-755"
        TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            embargoed=affect.flaw.embargoed,
            external_system_id=tracker_id,
            ps_update_stream=ps_update_stream.name,
            status="New",
            resolution=None,
            # collector only modify trackers
            # when it is outdated in OSIDB
            updated_dt=datetime.strptime("1970-01-01T00:00:00Z", BZ_DT_FMT),
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
        ps_update_stream = PsUpdateStreamFactory(name="stream", ps_module=ps_module)
        affect1 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw1,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )
        affect2 = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw2,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )
        TrackerFactory(
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
            external_system_id=tracker_id,
            affects=[affect1, affect2],
            updated_dt=datetime.strptime("1970-01-01T00:00:00Z", BZ_DT_FMT),
        )
        collector = JiraTrackerCollector()

        msg = collector.collect(tracker_id)
        JiraTrackerDownloadManager.link_tracker_with_affects(tracker_id)

        assert msg == f"Jira tracker sync of {tracker_id} completed"
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()
        assert tracker.external_system_id == tracker_id
        assert tracker.affects.count() == 2
        assert all(tracker == affect.tracker for affect in Affect.objects.all())


class TestMetadataCollector:
    BASE_METADATA_COLLECTOR_VCRS = (
        "TestMetadataCollector.test_collect_basic[OSIM-20].yaml",
        "TestMetadataCollector.test_collect_basic[RHEL-120].yaml",
    )

    @freeze_time(datetime(2015, 12, 12))
    @pytest.mark.vcr(*BASE_METADATA_COLLECTOR_VCRS)
    @pytest.mark.parametrize("project_key,fields_count", [("RHEL", 120), ("OSIM", 20)])
    def test_collect_basic(self, project_key, fields_count):
        """
        Test that collector is able to get metadata from Jira projects
        """
        ps_module = PsModuleFactory(
            bts_name="jira",
            bts_key=project_key,
            supported_until_dt=datetime(2020, 12, 12, tzinfo=timezone.utc),
        )
        PsUpdateStreamFactory(ps_module=ps_module)

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == 0

        mc = MetadataCollector()
        mc.collect()

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == fields_count

    @freeze_time(datetime(2015, 12, 12))
    @pytest.mark.vcr(*BASE_METADATA_COLLECTOR_VCRS)
    @pytest.mark.parametrize("project_key,fields_count", [("RHEL", 120), ("OSIM", 20)])
    def test_metadata_not_deleted_after_failure(
        self, monkeypatch, project_key, fields_count
    ):
        ps_module = PsModuleFactory(
            bts_name="jira",
            bts_key=project_key,
            supported_until_dt=datetime(2020, 12, 12, tzinfo=timezone.utc),
        )
        PsUpdateStreamFactory(ps_module=ps_module)

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == 0

        mc = MetadataCollector()
        mc.collect()

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == fields_count

        def raiseJiraError(*args, **kwargs):
            raise JIRAError

        monkeypatch.setattr(mc.jira_querier.jira_conn, "_get_json", raiseJiraError)
        with pytest.raises(MetadataCollectorInsufficientDataJiraffeException):
            mc.collect()

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == fields_count

    @freeze_time(datetime(2015, 12, 12))
    @pytest.mark.vcr(*BASE_METADATA_COLLECTOR_VCRS)
    @pytest.mark.parametrize("project_key,fields_count", [("RHEL", 120), ("OSIM", 20)])
    def test_metadata_deleted_based_on_product_definitions(
        self, project_key, fields_count
    ):
        ps_module = PsModuleFactory(
            bts_name="jira",
            bts_key=project_key,
            supported_until_dt=datetime(2020, 12, 12, tzinfo=timezone.utc),
        )
        PsUpdateStreamFactory(ps_module=ps_module)

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == 0

        mc = MetadataCollector()
        mc.collect()

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == fields_count

        # Remove active PS Update Streams to rule out PS Module and force project
        # removal in Jira metadata
        ps_module.active_ps_update_streams.set([])

        mc.collect()

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == 0

    @freeze_time(datetime(2024, 8, 8))
    @pytest.mark.vcr
    @pytest.mark.parametrize(
        "project_key,fields_count,vulntype_exists",
        [
            ("RHEL", 125, False),
            ("OSIM", 18, False),
            ("RHEL", 98, True),
            ("OSIM", 15, True),
        ],
    )
    def test_collect_vulnerability_issuetype(
        self, project_key, fields_count, vulntype_exists
    ):
        """
        Test that collector is able to get metadata from Jira projects
        """
        ps_module = PsModuleFactory(
            bts_name="jira",
            bts_key=project_key,
            supported_until_dt=datetime(2025, 12, 12, tzinfo=timezone.utc),
        )
        PsUpdateStreamFactory(ps_module=ps_module)

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == 0

        mc = MetadataCollector()
        mc.collect()

        project_fields = JiraProjectFields.objects.filter(project_key=project_key)
        assert len(project_fields) == fields_count

    @pytest.mark.vcr
    def test_sync_task_links_affects_when_tracker_up_to_date(self, monkeypatch):
        """
        Regression: when Jira tracker data is up-to-date (convertor returns None),
        sync_task should still link affects for an existing tracker.
        """
        tracker_id = "RHEL-159920"
        ps_module = PsModuleFactory(name="module", bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(name="stream", ps_module=ps_module)

        flaw = FlawFactory(
            embargoed=False,
            meta_attr={"jira_trackers": json.dumps([{"key": tracker_id}])},
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )

        meta_atr = {
            "issuetype": {"id": "17"},
            "project": {"id": "12337520"},
            "summary": "test validations",
            "description": "this is a simple test",
            "ps_component": "component",
            "labels": json.dumps(
                [flaw.cve_id, "Security", "SecurityTracking", "component:elasticsearch"]
            ),
        }

        tracker = TrackerFactory.build(
            ps_update_stream=ps_update_stream.name,
            external_system_id=tracker_id,
            type=Tracker.TrackerType.JIRA,
            embargoed=False,
            meta_attr=meta_atr,
        )
        tracker.save()

        # started()/finished() expect the SyncManager row to exist (normally created by schedule())
        JiraTrackerDownloadManager.objects.update_or_create(
            name=JiraTrackerDownloadManager.__name__,
            sync_id=tracker_id,
            defaults={"last_scheduled_dt": datetime.now(tz=timezone.utc)},
        )

        assert tracker.affects.count() == 0
        JiraTrackerDownloadManager.sync_task(tracker_id)
        tracker.refresh_from_db()
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect
