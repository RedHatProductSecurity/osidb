"""
tracker app integration tests
"""

import json

import pytest
from django.utils import timezone
from rest_framework import status

from apps.trackers.save import TrackerSaver
from collectors.bzimport.collectors import BugzillaTrackerCollector
from collectors.bzimport.constants import BZ_DT_FMT
from collectors.jiraffe.collectors import JiraTrackerCollector
from osidb.models import Affect, Flaw, Impact, PsUpdateStream, Tracker
from osidb.sync_manager import BZTrackerLinkManager, JiraTrackerLinkManager
from osidb.tests.factories import AffectFactory, FlawFactory, TrackerFactory

pytestmark = pytest.mark.integration


class TestTrackerSaver:
    @pytest.mark.vcr
    def test_tracker_create_bugzilla(
        self, bugzilla_token, setup_sample_external_resources
    ):
        """
        test basic Bugzilla tracker creation
        """
        # 1) get valid external data
        ps_update_stream = (
            PsUpdateStream.objects.filter(active_to_ps_module__bts_name="bugzilla")
            .order_by("name")
            .first()
        )
        ps_module = ps_update_stream.active_to_ps_module

        # 2) define all the context
        flaw = FlawFactory(
            bz_id="2217733",
            embargoed=False,
            impact=Impact.IMPORTANT,
            title="sample title",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_module.default_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=None,  # creating new tracker
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
            status="NEW",
            resolution="",
            meta_attr={
                "blocks": f'["{flaw.bz_id}"]',
                "whiteboard": {"flaws": [flaw.uuid]},
                "ps_module": affect.ps_module,
                "ps_component": affect.ps_component,
            },
        )
        assert tracker.bz_id is None

        # 3) create tracker in OSIDB and Bugzilla
        ts = TrackerSaver(tracker, bz_api_key=bugzilla_token)
        created_tracker = ts.save()
        assert created_tracker.bz_id
        assert created_tracker.uuid == tracker.uuid
        created_tracker.save()

        # 4) load tracker from Bugzilla
        btc = BugzillaTrackerCollector()
        btc.sync_tracker(created_tracker.bz_id)
        BZTrackerLinkManager.link_tracker_with_affects(created_tracker.bz_id)

        # 5) get the newly loaded tracker from the DB
        loaded_tracker = Tracker.objects.get(external_system_id=created_tracker.bz_id)
        loaded_tracker.save()  # get rid of Tracker alerts related to missing affect

        # 6) check the correct result of the creation and loading
        assert loaded_tracker.bz_id == created_tracker.bz_id
        assert not loaded_tracker.embargoed
        assert loaded_tracker.type == Tracker.TrackerType.BUGZILLA
        assert loaded_tracker.ps_update_stream == ps_update_stream.name
        assert loaded_tracker.status == "NEW"
        assert not loaded_tracker.resolution
        assert loaded_tracker.affects.count() == 1
        assert loaded_tracker.affects.first() == affect
        assert not loaded_tracker.alerts.exists()

    @pytest.mark.vcr
    def test_tracker_update_bugzilla(
        self, bugzilla_token, setup_sample_external_resources
    ):
        """
        test basic Bugzilla tracker update
        """
        # 1) get valid external data
        ps_update_stream = (
            PsUpdateStream.objects.filter(active_to_ps_module__bts_name="bugzilla")
            .order_by("name")
            .first()
        )
        ps_module = ps_update_stream.active_to_ps_module

        # 2) define all the context
        flaw = FlawFactory(
            bz_id="2217733",
            embargoed=False,
            impact=Impact.IMPORTANT,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_module.default_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # 3) define a tracker model instance
        #    according an exising Bugzilla tracker
        tracker_id = "2291491"
        updated_dt = "2024-11-13T12:56:45Z"
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=tracker_id,
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
            status="NEW",
            resolution="",
            meta_attr={
                "whiteboard": {"flaws": [flaw.uuid]},
                "updated_dt": updated_dt,
                "ps_module": affect.ps_module,
                "ps_component": affect.ps_component,
            },
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )
        assert tracker.bz_id == tracker_id
        # 4) update tracker in OSIDB and Bugzilla
        ts = TrackerSaver(tracker, bz_api_key=bugzilla_token)
        updated_tracker = ts.save()
        assert updated_tracker.bz_id == tracker_id
        assert updated_tracker.uuid == tracker.uuid
        updated_tracker.save(auto_timestamps=False)

        # 5) load tracker from Bugzilla
        btc = BugzillaTrackerCollector()
        btc.bz_querier._bz_api_key = bugzilla_token

        btc.sync_tracker(updated_tracker.bz_id)
        BZTrackerLinkManager.link_tracker_with_affects(updated_tracker.bz_id)

        # 6) get the newly loaded tracker from the DB
        loaded_tracker = Tracker.objects.get(external_system_id=tracker_id)

        # 7) check the correct result of the update and loading
        assert loaded_tracker.bz_id == tracker_id
        assert not loaded_tracker.embargoed
        assert loaded_tracker.type == Tracker.TrackerType.BUGZILLA
        assert loaded_tracker.ps_update_stream == ps_update_stream.name
        assert loaded_tracker.status == "NEW"
        assert not loaded_tracker.resolution
        assert loaded_tracker.affects.count() == 1
        assert loaded_tracker.affects.first() == affect
        assert not loaded_tracker.alerts.exists()

        # 8) check that the update actually happened
        assert "updated_dt" in loaded_tracker.meta_attr
        assert updated_dt != loaded_tracker.meta_attr["updated_dt"]


class TestTrackerAPI:
    @pytest.mark.vcr
    def test_tracker_create_bugzilla(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_sync,
        jira_token,
        setup_sample_external_resources,
        test_api_v2_uri,
    ):
        """
        test the whole stack Bugzilla tracker creation
        starting on the API and ending in Bugzilla
        """
        # 1) get valid external data
        ps_update_stream = (
            PsUpdateStream.objects.filter(active_to_ps_module__bts_name="bugzilla")
            .order_by("name")
            .first()
        )
        ps_module = ps_update_stream.active_to_ps_module

        # 2) define all the context
        flaw = FlawFactory(
            bz_id="2217733",
            cve_id=None,
            embargoed=False,
            impact=Impact.IMPORTANT,
            title="sample title",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_module.default_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # 3) create tracker in OSIDB and Bugzilla
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_stream.name,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == status.HTTP_201_CREATED

        # 4) the tracker is not stored to DB as it happens async
        #    so check that there is no tracker relic stored
        assert not Tracker.objects.count()

        # 5) so check at least the response
        #    even though it is not complete
        tracker_json = response.json()
        assert tracker_json["external_system_id"]
        assert not tracker_json["embargoed"]
        assert tracker_json["type"] == Tracker.TrackerType.BUGZILLA
        assert tracker_json["ps_update_stream"] == ps_update_stream.name

    # Stuck since the time syncing is throwing an ERROR
    @pytest.mark.vcr
    def test_tracker_update_bugzilla(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_sync,
        jira_token,
        setup_sample_external_resources,
        test_api_v2_uri,
    ):
        """
        test the whole stack Bugzilla tracker update
        starting on the API and ending in Bugzilla
        """
        # 1) get valid external data
        ps_update_streams = PsUpdateStream.objects.filter(
            active_to_ps_module__bts_name="bugzilla"
        ).order_by("name")
        ps_module = ps_update_streams.first().active_to_ps_module

        # 2) define all the context
        flaw = FlawFactory(
            bz_id="2217733",
            embargoed=False,
            impact=Impact.IMPORTANT,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_streams[0].name,
            ps_component=ps_module.default_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # 3) define a tracker model instance
        #    according an exising Bugzilla tracker
        tracker_id = "2291491"
        updated_dt = "2024-06-13T14:29:58Z"
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=tracker_id,
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_streams[0].name,
            type=Tracker.TrackerType.BUGZILLA,
            meta_attr={"blocks": '["2217733"]', "updated_dt": updated_dt},
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )
        print(ps_update_streams[0].name)
        # 4) update tracker in OSIDB and Bugzilla
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_streams[1].name,  # new value
            "updated_dt": updated_dt,
        }

        # update the affect's PS update stream since the tracker's ps_update_stream would be changed
        # validation requires the update streams to be the same.
        affect.ps_update_stream = ps_update_streams[1].name
        affect.save(auto_timestamps=False)

        response = auth_client().put(
            f"{test_api_v2_uri}/trackers/{tracker.uuid}",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == 200

        # 5) the actual update in the database happens async
        #    so check at least the correct data in the response
        tracker_json = response.json()
        assert tracker_json["external_system_id"] == tracker_id
        assert not tracker_json["embargoed"]
        assert tracker_json["type"] == Tracker.TrackerType.BUGZILLA
        assert tracker_json["ps_update_stream"] == ps_update_streams[1].name
        assert len(tracker_json["affects"]) == 1
        assert tracker_json["affects"][0] == str(affect.uuid)
        assert not tracker_json["alerts"]

        # 6) check that the actual update did not happen
        assert updated_dt == tracker_json["updated_dt"]

    @pytest.mark.vcr
    def test_tracker_create_jira(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_sync,
        enable_jira_tracker_sync,
        jira_token,
        setup_sample_external_resources,
        test_api_v2_uri,
    ):
        """
        test the whole stack Jira tracker creation
        starting on the API and ending in Jira
        """
        # 1) get valid external data
        ps_update_stream = (
            PsUpdateStream.objects.filter(active_to_ps_module__bts_name="jboss")
            .order_by("name")
            .first()
        )
        ps_module = ps_update_stream.active_to_ps_module

        # 2) define all the context
        flaw = FlawFactory(
            uuid="675df471-7375-4ba1-9d0f-c178a8a58ae7",
            bz_id="2217733",
            cve_id=None,
            embargoed=False,
            impact=Impact.LOW,
            title="sample title",
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            updated_dt=timezone.datetime.strptime("2024-06-13T14:42:15Z", BZ_DT_FMT),
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_module.default_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=flaw.impact,
        )

        # 3) create tracker in OSIDB and Jira
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_stream.name,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == status.HTTP_201_CREATED

        # 4) the tracker is not stored to DB as it happens async
        #    so check that there is no tracker relic stored
        assert not Tracker.objects.count()

        # 5) so check at least the response
        #    even though it is not complete
        tracker_json = response.json()
        assert tracker_json["external_system_id"]
        assert "OSIDB" in tracker_json["external_system_id"]
        assert not tracker_json["embargoed"]
        assert tracker_json["type"] == Tracker.TrackerType.JIRA
        assert tracker_json["ps_update_stream"] == ps_update_stream.name

    # Same time syncing ERROR as the one previously
    @pytest.mark.vcr
    def test_tracker_update_jira(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_sync,
        enable_jira_tracker_sync,
        jira_token,
        setup_sample_external_resources,
        test_api_v2_uri,
    ):
        """
        test the whole stack Jira tracker update
        starting on the API and ending in Jira
        """
        # 1) get valid external data
        ps_update_streams = PsUpdateStream.objects.filter(
            active_to_ps_module__bts_name="jboss"
        ).order_by("name")
        ps_module = ps_update_streams.first().active_to_ps_module

        # 2) define all the context
        # flaw to keep linked
        flaw1 = FlawFactory(
            bz_id="1663908",
            cve_id=None,
            embargoed=False,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="sample title",
            updated_dt=timezone.datetime.strptime("2023-07-07T08:33:20Z", BZ_DT_FMT),
        )
        affect1 = AffectFactory(
            flaw=flaw1,
            ps_update_stream=ps_update_streams[0].name,
            ps_component=ps_module.default_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=flaw1.impact,
        )
        # flaw to unlink
        flaw2 = FlawFactory(
            bz_id="1656210",
            cve_id=None,
            embargoed=False,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="sample title",
            updated_dt=timezone.datetime.strptime("2023-07-07T08:30:56Z", BZ_DT_FMT),
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            ps_update_stream=ps_update_streams[0].name,
            ps_component=ps_module.default_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=flaw2.impact,
        )
        # flaw to link
        flaw3 = FlawFactory(
            bz_id="1663907",
            cve_id=None,
            embargoed=False,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="sample title",
            updated_dt=timezone.datetime.strptime("2023-07-07T08:35:40Z", BZ_DT_FMT),
        )
        affect3 = AffectFactory(
            flaw=flaw3,
            ps_update_stream=ps_update_streams[0].name,
            ps_component=ps_module.default_component,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=flaw3.impact,
        )

        # 3) define a tracker model instance
        #    according an exising Jira tracker
        tracker_id = "OSIDB-920"
        updated_dt = "2024-06-17T12:41:00Z"
        tracker = TrackerFactory(
            affects=[affect1, affect2],
            bz_id=tracker_id,
            embargoed=flaw1.embargoed,
            ps_update_stream=ps_update_streams[0].name,
            type=Tracker.TrackerType.JIRA,
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )

        # 4) update tracker in OSIDB and Jira
        tracker_data = {
            "affects": [
                affect1.uuid,
                affect3.uuid,
            ],  # affect2 removed and affect3 added
            "embargoed": flaw1.embargoed,
            "ps_update_stream": ps_update_streams[2].name,  # new value
            "updated_dt": updated_dt,
        }

        # update the affect1 and affect3's PS update stream since the tracker's ps_update_stream would be changed
        # validation requires the update streams to be the same.
        affect1.ps_update_stream = ps_update_streams[2].name
        affect1.save(auto_timestamps=False)
        affect3.ps_update_stream = ps_update_streams[2].name
        affect3.save(auto_timestamps=False)

        response = auth_client().put(
            f"{test_api_v2_uri}/trackers/{tracker.uuid}",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == 200

        # 5) the actual update in the database happens async
        #    so check at least the correct data in the response
        tracker_json = response.json()
        assert tracker_json["external_system_id"] == tracker_id
        assert "OSIDB" in tracker_json["external_system_id"]
        assert not tracker_json["embargoed"]
        assert tracker_json["type"] == Tracker.TrackerType.JIRA
        assert tracker_json["ps_update_stream"] == ps_update_streams[2].name
        assert len(tracker_json["affects"]) == 2
        assert str(affect1.uuid) in tracker_json["affects"]
        assert str(affect3.uuid) in tracker_json["affects"]
        assert not tracker_json["alerts"]

        # 6) check that the actual update did not happen
        assert updated_dt == tracker_json["updated_dt"]

    @pytest.mark.vcr
    def test_tracker_create_update_jira_vulnerability_issuetype(
        self,
        auth_client,
        bugzilla_token,
        enable_bz_sync,
        enable_jira_tracker_sync,
        jira_token,
        setup_sample_external_resources,
        test_api_v2_uri,
        monkeypatch,
    ):
        """
        Test the whole stack Jira tracker creation starting on the API and ending in Jira,
        then also test tracker update.
        Tested in just one test so that complex set up is not necessary for the follow-up
        test of tracker update.
        """
        # 1) get valid external data
        ps_update_streams = PsUpdateStream.objects.filter(
            active_to_ps_module__bts_name="jboss"
        ).order_by("name")
        ps_module = ps_update_streams.first().active_to_ps_module
        ps_component1 = setup_sample_external_resources["jboss_components"][0]
        ps_component2 = setup_sample_external_resources["jboss_components"][1]

        # 2) define all the context

        # Create the flaw for the purpose of the test
        # (this is not part of the test per se, but necessary setup).

        sync_count = 0

        from rest_framework.response import Response

        def mock_create_or_update_task(self, flaw):
            nonlocal sync_count
            sync_count += 1
            return Response(
                data={
                    "key": "TASK-123",
                    "fields": {
                        "status": {"name": "New"},
                        "resolution": None,
                        "updated": "2024-06-25T21:20:43.988+0000",
                    },
                },
                status=200,
            )

        from apps.taskman.service import JiraTaskmanQuerier

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )

        flaw_data = {
            "cwe_id": "CWE-1",
            "title": "Foo",
            "impact": "CRITICAL",
            "components": ["curl"],
            "source": "REDHAT",
            "comment_zero": "test",
            "reported_dt": "2023-11-22T15:55:22.830Z",
            "unembargo_dt": "2023-11-23T15:55:22.830Z",
            "embargoed": False,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/flaws",
            flaw_data,
            format="json",
            # TODO sanitize keys both here and in VCRs
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 201

        # This part is properly tested elsewhere, here just as a sanity check
        # that the prerequisite is being set up in an expected way.
        assert sync_count == 1

        assert Flaw.objects.count() == 1

        # NOTE: When recording cassette, delete this line. After recording,
        #       grep for "flawuuid" and update the UUID accordingly.
        Flaw.objects.all().update(uuid="9143582e-8711-4e69-ba6a-b3ead61fbb42")

        flaw = Flaw.objects.first()

        affect = AffectFactory(
            uuid="7cb199fd-86eb-45eb-aa3a-8fd7ecd32c1d",
            flaw=flaw,
            ps_update_stream=ps_update_streams[0].name,
            ps_component=ps_component1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=flaw.impact,
        )

        # Basic sanity check
        assert Flaw.objects.count() == 1
        assert Affect.objects.count() == 1
        assert Flaw.objects.first().affects.count() == 1
        assert flaw.affects.count() == 1
        assert Tracker.objects.count() == 0
        assert Affect.objects.first() == affect
        assert affect.flaw == flaw

        # 3) create tracker in OSIDB and Jira
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_streams[0].name,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == status.HTTP_201_CREATED

        # 4) the tracker is not stored to DB as it happens async
        #    so check that there is no tracker relic stored
        assert not Tracker.objects.count()

        # 5) so check at least the response
        #    even though it is not complete
        tracker_json = response.json()
        assert tracker_json["external_system_id"]
        assert ps_module.bts_key in tracker_json["external_system_id"]
        assert not tracker_json["embargoed"]
        assert tracker_json["type"] == Tracker.TrackerType.JIRA
        assert tracker_json["ps_update_stream"] == ps_update_streams[0].name

        # NOTE: Reloading flaw is tested in test_tracker_create_jira.
        #       That test requires the flaw to be set up correctly in the BTS
        #       and collection enabled. We're not using flaw collector
        #       as of 2024-09 anymore.
        #       The flaw sync works the same for both Bug and Vulnerability
        #       issuetype trackers. No need to test it here.

        # 6) check that the data are the same also when collecting the Tracker

        tracker_id = tracker_json["external_system_id"]

        assert Flaw.objects.count() == 1
        assert Affect.objects.count() == 1
        assert Flaw.objects.first().affects.count() == 1
        assert flaw.affects.count() == 1
        assert Tracker.objects.count() == 0
        assert Affect.objects.first() == affect
        assert affect.flaw == flaw

        jc = JiraTrackerCollector()
        jc.collect(tracker_id)
        assert Tracker.objects.count() == 1
        tracker_new = Tracker.objects.first()

        assert tracker_new.external_system_id == tracker_id
        assert not tracker_new.embargoed
        assert tracker_new.type == Tracker.TrackerType.JIRA
        assert tracker_new.ps_update_stream == ps_update_streams[0].name
        assert tracker_new.status == "New"
        assert not tracker_new.resolution
        labels_new = json.loads(tracker_new.meta_attr["labels"])
        assert [
            "Security",
            "SecurityTracking",
            f"flawuuid:{flaw.uuid}",
            "pscomponent:" + ps_component1,
        ] == sorted(labels_new)
        assert tracker_new.meta_attr["jira_issuetype"] == "Bug"

        # Not linked yet
        assert tracker_new.affects.count() == 0

        JiraTrackerLinkManager.link_tracker_with_affects(tracker_id)

        # Linked
        assert tracker_new.affects.count() == 1
        assert tracker_new.affects.first() == affect
        assert not tracker_new.alerts.exists()

        # 7) test tracker update
        affect2 = AffectFactory(
            uuid="8db199fd-86eb-45eb-aa3a-8fd7ecd32c2e",
            flaw=flaw,
            ps_update_stream=ps_update_streams[1].name,
            ps_component=ps_component2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=flaw.impact,
        )

        tracker_data = {
            "affects": [  # changed
                affect2.uuid,
            ],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_streams[1].name,  # new value
            "updated_dt": tracker_new.updated_dt,
        }
        response = auth_client().put(
            f"{test_api_v2_uri}/trackers/{tracker_new.uuid}",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200

        # Basic sanity check again
        assert Flaw.objects.count() == 1
        assert Affect.objects.count() == 2
        assert Flaw.objects.first().affects.count() == 2
        assert flaw.affects.count() == 2
        assert Tracker.objects.count() == 1
        assert affect.flaw == flaw
        assert affect2.flaw == flaw

        # 8) the actual update in the database happens async
        #    so check at least the correct data in the response
        tracker_json = response.json()
        assert tracker_json["external_system_id"] == tracker_id
        assert tracker_json["external_system_id"] == tracker_new.external_system_id
        assert not tracker_json["embargoed"]
        assert tracker_json["type"] == Tracker.TrackerType.JIRA
        assert tracker_json["ps_update_stream"] == ps_update_streams[1].name
        assert len(tracker_json["affects"]) == 1
        assert str(affect.uuid) not in tracker_json["affects"]
        assert str(affect2.uuid) in tracker_json["affects"]
        assert not tracker_json["alerts"]

        # 9) check that the actual update did not happen
        assert tracker_new.updated_dt == timezone.datetime.strptime(
            tracker_json["updated_dt"], "%Y-%m-%dT%H:%M:%S.%f%z"
        )
