"""
tracker app integration tests
"""

import json

import pytest
from django.utils import timezone
from rest_framework import status

from apps.trackers.jira.query import JiraPriority
from apps.trackers.save import TrackerSaver
from apps.trackers.tests.factories import JiraProjectFieldsFactory
from collectors.bzimport.collectors import BugzillaTrackerCollector, FlawCollector
from collectors.bzimport.constants import BZ_DT_FMT
from osidb.models import Affect, Flaw, Impact, Tracker
from osidb.sync_manager import BZTrackerLinkManager
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.integration


class TestTrackerSaver:
    @pytest.mark.vcr
    def test_tracker_create_bugzilla(self):
        """
        test basic Bugzilla tracker creation
        """
        # 1) define all the context
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Certification Program",
            bts_groups={"public": ["devel"]},
            default_component="redhat-certification",
            name="rhcertification-6",
        )
        ps_update_stream = PsUpdateStreamFactory(
            name="rhcertification-6",
            ps_module=ps_module,
            version="1.0",
        )
        flaw = FlawFactory(
            bz_id="2217733",
            embargoed=False,
            impact=Impact.IMPORTANT,
            title="sample title",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="openssl",
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
                "blocks": f"[{flaw.bz_id}]",
                "whiteboard": {"flaws": [flaw.uuid]},
                "ps_module": affect.ps_module,
                "ps_component": affect.ps_component,
            },
        )
        assert tracker.bz_id is None

        # 2) create tracker in OSIDB and Bugzilla
        ts = TrackerSaver(tracker, bz_api_key="SECRET")
        created_tracker = ts.save()
        assert created_tracker.bz_id
        assert created_tracker.uuid == tracker.uuid
        created_tracker.save()

        # 3) load tracker from Bugzilla
        btc = BugzillaTrackerCollector()
        btc.sync_tracker(created_tracker.bz_id)
        BZTrackerLinkManager.link_tracker_with_affects(created_tracker.bz_id)

        # 4) get the newly loaded tracker from the DB
        loaded_tracker = Tracker.objects.get(external_system_id=created_tracker.bz_id)
        loaded_tracker.save()  # get rid of Tracker alerts related to missing affect

        # 5) check the correct result of the creation and loading
        assert loaded_tracker.bz_id == created_tracker.bz_id
        assert not loaded_tracker.embargoed
        assert loaded_tracker.type == Tracker.TrackerType.BUGZILLA
        assert loaded_tracker.ps_update_stream == "rhcertification-6"
        assert loaded_tracker.status == "NEW"
        assert not loaded_tracker.resolution
        assert loaded_tracker.affects.count() == 1
        assert loaded_tracker.affects.first() == affect
        assert not loaded_tracker.alerts.exists()

    @pytest.mark.vcr
    def test_tracker_update_bugzilla(self):
        """
        test basic Bugzilla tracker update
        """
        # 1) define all the context
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Certification Program",
            bts_groups={"public": ["devel"]},
            default_component="redhat-certification",
            name="rhcertification-6",
        )
        ps_update_stream = PsUpdateStreamFactory(
            name="rhcertification-6",
            ps_module=ps_module,
            version="1.0",
        )
        flaw = FlawFactory(
            bz_id="2217733",
            embargoed=False,
            impact=Impact.IMPORTANT,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="openssl",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # 2) define a tracker model instance
        #    according an exising Bugzilla tracker
        tracker_id = "2291491"
        updated_dt = "2024-08-12T20:26:54Z"
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=tracker_id,
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
            status="NEW",
            resolution="",
            meta_attr={
                "blocks": f"[{flaw.bz_id}]",
                "whiteboard": {"flaws": [flaw.uuid]},
                "updated_dt": updated_dt,
                "ps_module": affect.ps_module,
                "ps_component": affect.ps_component,
            },
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )
        assert tracker.bz_id == tracker_id
        # 3) update tracker in OSIDB and Bugzilla
        ts = TrackerSaver(tracker, bz_api_key="SECRET")
        updated_tracker = ts.save()
        assert updated_tracker.bz_id == tracker_id
        assert updated_tracker.uuid == tracker.uuid
        updated_tracker.save(auto_timestamps=False)

        # 4) load tracker from Bugzilla
        btc = BugzillaTrackerCollector()
        btc.sync_tracker(updated_tracker.bz_id)
        BZTrackerLinkManager.link_tracker_with_affects(updated_tracker.bz_id)

        # 5) get the newly loaded tracker from the DB
        loaded_tracker = Tracker.objects.get(external_system_id=tracker_id)

        # 6) check the correct result of the update and loading
        assert loaded_tracker.bz_id == tracker_id
        assert not loaded_tracker.embargoed
        assert loaded_tracker.type == Tracker.TrackerType.BUGZILLA
        assert loaded_tracker.ps_update_stream == "rhcertification-6"
        assert loaded_tracker.status == "NEW"
        assert not loaded_tracker.resolution
        assert loaded_tracker.affects.count() == 1
        assert loaded_tracker.affects.first() == affect
        assert not loaded_tracker.alerts.exists()

        # 7) check that the update actually happened
        assert "updated_dt" in loaded_tracker.meta_attr
        assert updated_dt != loaded_tracker.meta_attr["updated_dt"]


class TestTrackerAPI:
    @pytest.mark.vcr
    def test_tracker_create_bugzilla(
        self, auth_client, enable_bugzilla_sync, test_api_uri
    ):
        """
        test the whole stack Bugzilla tracker creation
        starting on the API and ending in Bugzilla
        """
        # 1) define all the context
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Certification Program",
            bts_groups={"public": ["devel"]},
            default_component="redhat-certification",
            name="rhcertification-6",
        )
        ps_update_stream = PsUpdateStreamFactory(
            name="rhcertification-6",
            ps_module=ps_module,
            version="1.0",
        )
        flaw = FlawFactory(
            bz_id="2217733",
            cve_id=None,
            embargoed=False,
            impact=Impact.IMPORTANT,
            title="sample title",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="openssl",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # 2) create tracker in OSIDB and Bugzilla
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_stream.name,
        }
        response = auth_client().post(
            f"{test_api_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # 3) get the newly loaded tracker from the DB
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()

        # 4) check the correct result of the creation and loading
        assert tracker.bz_id
        assert not tracker.embargoed
        assert tracker.type == Tracker.TrackerType.BUGZILLA
        assert tracker.ps_update_stream == "rhcertification-6"
        assert tracker.status == "NEW"
        assert not tracker.resolution
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect
        assert not tracker.alerts.exists()

    @pytest.mark.vcr
    def test_tracker_update_bugzilla(
        self, auth_client, enable_bugzilla_sync, test_api_uri
    ):
        """
        test the whole stack Bugzilla tracker update
        starting on the API and ending in Bugzilla
        """
        # 1) define all the context
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Certification Program",
            bts_groups={"public": ["devel"]},
            default_component="redhat-certification",
            name="rhcertification-6",
        )
        ps_update_stream1 = PsUpdateStreamFactory(
            name="rhcertification-6",
            ps_module=ps_module,
            version="1.0",
        )
        ps_update_stream2 = PsUpdateStreamFactory(
            name="rhcertification-6-default",
            ps_module=ps_module,
            version="1.0",
        )
        flaw = FlawFactory(
            bz_id="2217733",
            embargoed=False,
            impact=Impact.IMPORTANT,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="openssl",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # 2) define a tracker model instance
        #    according an exising Bugzilla tracker
        tracker_id = "2291491"
        updated_dt = "2024-06-13T14:29:58Z"
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=tracker_id,
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream1.name,
            type=Tracker.TrackerType.BUGZILLA,
            meta_attr={"blocks": ["2217733"], "updated_dt": updated_dt},
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )

        # 3) update tracker in OSIDB and Bugzilla
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_stream2.name,  # new value
            "status": "NEW",  # this one is mandatory even though ignored in the backend query for now
            "updated_dt": updated_dt,
        }
        response = auth_client().put(
            f"{test_api_uri}/trackers/{tracker.uuid}",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        # 4) get the newly loaded tracker from the DB
        tracker = Tracker.objects.get(external_system_id=tracker_id)

        # 5) check the correct result of the update and loading
        assert tracker.bz_id == tracker_id
        assert not tracker.embargoed
        assert tracker.type == Tracker.TrackerType.BUGZILLA
        assert tracker.ps_update_stream == ps_update_stream2.name
        assert tracker.status == "NEW"
        assert not tracker.resolution
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect
        assert not tracker.alerts.exists()

        # 6) check that the update actually happened
        assert "updated_dt" in tracker.meta_attr
        assert updated_dt != tracker.meta_attr["updated_dt"]

    @pytest.mark.vcr
    def test_tracker_create_jira(
        self, auth_client, enable_bugzilla_sync, enable_jira_sync, test_api_uri
    ):
        """
        test the whole stack Jira tracker creation
        starting on the API and ending in Jira
        """
        # 1) define all the context
        ps_module = PsModuleFactory(
            bts_name="jboss",
            bts_key="OSIDB",
            bts_groups={"public": []},
            default_component="Security",
            name="openshift-4",
        )
        ps_update_stream = PsUpdateStreamFactory(
            name="openshift-4.8.z",
            ps_module=ps_module,
            version="4.8",
        )
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
            ps_module=ps_module.name,
            ps_component="openshift",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=flaw.impact,
        )
        JiraProjectFieldsFactory(
            project_key="OSIDB",
            field_id="priority",
            allowed_values=[JiraPriority.MINOR],
        )
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="security",
            field_name="Security Level",
            allowed_values=[
                "Embargoed Security Issue",
                "Red Hat Employee",
                "Red Hat Engineering Authorized",
                "Red Hat Partner",
                "Restricted",
                "Team",
            ],
        )

        # 2) create tracker in OSIDB and Jira
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_stream.name,
        }
        response = auth_client().post(
            f"{test_api_uri}/trackers",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # 3) get the newly loaded tracker from the DB
        assert Tracker.objects.count() == 1
        tracker = Tracker.objects.first()

        # 4) check the correct result of the creation and loading
        assert tracker.external_system_id
        assert "OSIDB" in tracker.external_system_id
        assert not tracker.embargoed
        assert tracker.type == Tracker.TrackerType.JIRA
        assert tracker.ps_update_stream == "openshift-4.8.z"
        assert tracker.status == "New"
        assert not tracker.resolution
        labels = json.loads(tracker.meta_attr["labels"])
        assert "flaw:bz#2217733" in labels
        assert "flawuuid:675df471-7375-4ba1-9d0f-c178a8a58ae7" in labels
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect
        assert not tracker.alerts.exists()

        # 5) reload the flaw and check that the tracker still links
        fc = FlawCollector()
        fc.sync_flaw(flaw.bz_id)
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect
        assert tracker.affects.first().flaw == flaw

    @pytest.mark.vcr
    def test_tracker_update_jira(
        self, auth_client, enable_bugzilla_sync, enable_jira_sync, test_api_uri
    ):
        """
        test the whole stack Jira tracker update
        starting on the API and ending in Jira
        """
        # 1) define all the context
        ps_module = PsModuleFactory(
            bts_name="jboss",
            bts_key="OSIDB",
            bts_groups={"public": []},
            default_component="Security",
            name="openshift-4",
        )
        ps_update_stream1 = PsUpdateStreamFactory(
            name="openshift-4.8.z",
            ps_module=ps_module,
            version="4.8",
        )
        ps_update_stream2 = PsUpdateStreamFactory(
            name="openshift-4.9.z",
            ps_module=ps_module,
            version="4.9",
        )
        JiraProjectFieldsFactory(
            project_key="OSIDB",
            field_id="priority",
            allowed_values=[JiraPriority.MINOR],
        )
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="security",
            field_name="Security Level",
            allowed_values=[
                "Embargoed Security Issue",
                "Red Hat Employee",
                "Red Hat Engineering Authorized",
                "Red Hat Partner",
                "Restricted",
                "Team",
            ],
        )
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
            ps_module=ps_module.name,
            ps_component="openshift",
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
            ps_module=ps_module.name,
            ps_component="openshift",
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
            ps_module=ps_module.name,
            ps_component="openshift",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=flaw3.impact,
        )

        # 2) define a tracker model instance
        #    according an exising Bugzilla tracker
        tracker_id = "OSIDB-920"
        updated_dt = "2024-06-17T12:41:00Z"
        tracker = TrackerFactory(
            affects=[affect1, affect2],
            bz_id=tracker_id,
            embargoed=flaw1.embargoed,
            ps_update_stream=ps_update_stream1.name,
            type=Tracker.TrackerType.JIRA,
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )

        # 3) update tracker in OSIDB and Bugzilla
        tracker_data = {
            "affects": [
                affect1.uuid,
                affect3.uuid,
            ],  # affect2 removed and affect3 added
            "embargoed": flaw1.embargoed,
            "ps_update_stream": ps_update_stream2.name,  # new value
            "updated_dt": updated_dt,
        }
        response = auth_client().put(
            f"{test_api_uri}/trackers/{tracker.uuid}",
            tracker_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        # 4) get the newly loaded tracker from the DB
        tracker = Tracker.objects.get(external_system_id=tracker_id)

        # 5) check the correct result of the update and loading
        assert tracker.external_system_id == tracker_id
        assert "OSIDB" in tracker.external_system_id
        assert not tracker.embargoed
        assert tracker.type == Tracker.TrackerType.JIRA
        assert tracker.ps_update_stream == ps_update_stream2.name
        assert "flaw:bz#1663908" in json.loads(tracker.meta_attr["labels"])
        assert "flaw:bz#1663907" in json.loads(tracker.meta_attr["labels"])
        assert tracker.affects.count() == 2
        assert affect1 in tracker.affects.all()
        assert affect3 in tracker.affects.all()
        assert not tracker.alerts.exists()

        # 6) check that the update actually happened
        assert updated_dt != tracker.updated_dt

        # 7) reload the flaws and check that the tracker links remain
        fc = FlawCollector()
        fc.sync_flaw(flaw1.bz_id)
        fc.sync_flaw(flaw2.bz_id)
        fc.sync_flaw(flaw3.bz_id)
        flaw1 = Flaw.objects.get(uuid=flaw1.uuid)
        flaw2 = Flaw.objects.get(uuid=flaw2.uuid)
        flaw3 = Flaw.objects.get(uuid=flaw3.uuid)
        tracker = Tracker.objects.get(uuid=tracker.uuid)
        assert tracker.affects.count() == 2
        assert flaw1.affects.count() == 1
        assert flaw1.affects.first().trackers.count() == 1
        assert flaw1.affects.first().trackers.first().uuid == tracker.uuid
        assert flaw2.affects.count() == 1
        assert not flaw2.affects.first().trackers.exists()
        assert flaw3.affects.count() == 1
        assert flaw3.affects.first().trackers.count() == 1
        assert flaw3.affects.first().trackers.first().uuid == tracker.uuid
