"""
tracker app integration tests
"""

import pytest
from django.utils import timezone
from rest_framework import status

from apps.trackers.jira.query import JiraPriority
from apps.trackers.save import TrackerSaver
from apps.trackers.tests.factories import JiraProjectFieldsFactory
from collectors.bzimport.collectors import FlawCollector
from collectors.bzimport.constants import BZ_DT_FMT
from osidb.models import Affect, Impact, Tracker
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
            bz_id="2013494",
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
            resolution=Affect.AffectResolution.FIX,
        )
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=None,  # creating new tracker
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert tracker.bz_id is None

        # 2) create tracker in OSIDB and Bugzilla
        ts = TrackerSaver(tracker, bz_api_key="SECRET")
        created_tracker = ts.save()
        assert created_tracker.bz_id

        # 3) load tracker from Bugzilla
        #    this must be done through flaw collector
        #    because that one is responsible for linking
        fc = FlawCollector()
        fc.sync_flaw(flaw.bz_id)

        # 4) get the newly loaded tracker from the DB
        loaded_tracker = Tracker.objects.get(external_system_id=created_tracker.bz_id)

        # 5) check the correct result of the creation and loading
        assert loaded_tracker.bz_id == created_tracker.bz_id
        assert not loaded_tracker.embargoed
        assert loaded_tracker.type == Tracker.TrackerType.BUGZILLA
        assert loaded_tracker.ps_update_stream == "rhcertification-6"
        assert loaded_tracker.status == "NEW"
        assert not loaded_tracker.resolution
        assert loaded_tracker.affects.count() == 1
        assert loaded_tracker.affects.first() == affect
        assert not loaded_tracker._alerts

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
            bz_id="2013494",
            embargoed=False,
            impact=Impact.IMPORTANT,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="openssl",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
        )

        # 2) define a tracker model instance
        #    according an exising Bugzilla tracker
        tracker_id = "2017149"
        updated_dt = "2023-09-04T15:05:15Z"
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=tracker_id,
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
            meta_attr={"blocks": ["2013494"], "updated_dt": updated_dt},
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )
        assert tracker.bz_id == tracker_id

        # 3) update tracker in OSIDB and Bugzilla
        ts = TrackerSaver(tracker, bz_api_key="SECRET")
        updated_tracker = ts.save()
        assert updated_tracker.bz_id == tracker_id

        # 4) load tracker from Bugzilla
        #    this must be done through flaw collector
        #    because that one is responsible for linking
        fc = FlawCollector()
        fc.sync_flaw(flaw.bz_id)

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
        assert not loaded_tracker._alerts

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
            bz_id="2013494",
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
            resolution=Affect.AffectResolution.FIX,
        )

        # 2) create tracker in OSIDB and Bugzilla
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_stream.name,
            "status": "NEW",  # this one is mandatory even though ignored in the backend query for now
        }
        response = auth_client.post(
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
        assert not tracker._alerts

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
            bz_id="2013494",
            embargoed=False,
            impact=Impact.IMPORTANT,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="openssl",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
        )

        # 2) define a tracker model instance
        #    according an exising Bugzilla tracker
        tracker_id = "2017676"
        updated_dt = "2023-09-13T08:34:21Z"
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=tracker_id,
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream1.name,
            type=Tracker.TrackerType.BUGZILLA,
            meta_attr={"blocks": ["2013494"], "updated_dt": updated_dt},
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
        response = auth_client.put(
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
        assert not tracker._alerts

        # 6) check that the update actually happened
        assert "updated_dt" in tracker.meta_attr
        assert updated_dt != tracker.meta_attr["updated_dt"]

    @pytest.mark.vcr
    def test_tracker_create_jira(self, auth_client, enable_jira_sync, test_api_uri):
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
            bz_id="1997880",
            cve_id=None,
            embargoed=False,
            impact=Impact.LOW,
            title="sample title",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="openshift",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            impact=flaw.impact,
        )
        JiraProjectFieldsFactory(
            project_key="OSIDB",
            field_id="priority",
            allowed_values=[
                {"name": JiraPriority.MINOR},
            ],
        )

        # 2) create tracker in OSIDB and Bugzilla
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_stream.name,
            "status": "New",  # this one is mandatory even though ignored in the backend query for now
        }
        response = auth_client.post(
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
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect
        assert not tracker._alerts

    @pytest.mark.vcr
    def test_tracker_update_jira(self, auth_client, enable_jira_sync, test_api_uri):
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
        flaw = FlawFactory(
            bz_id="1997880",
            cve_id=None,
            embargoed=False,
            impact=Impact.LOW,
            title="sample title",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="openshift",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            impact=flaw.impact,
        )
        JiraProjectFieldsFactory(
            project_key="OSIDB",
            field_id="priority",
            allowed_values=[
                {"name": JiraPriority.MINOR},
            ],
        )

        # 2) define a tracker model instance
        #    according an exising Bugzilla tracker
        tracker_id = "OSIDB-920"
        updated_dt = "2020-01-01T00:00:00Z"  # TODO no mid-air collision detection
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=tracker_id,
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream1.name,
            type=Tracker.TrackerType.JIRA,
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )

        # 3) update tracker in OSIDB and Bugzilla
        tracker_data = {
            "affects": [affect.uuid],
            "embargoed": flaw.embargoed,
            "ps_update_stream": ps_update_stream2.name,  # new value
            "status": "New",  # this one is mandatory even though ignored in the backend query for now
            "updated_dt": updated_dt,
        }
        response = auth_client.put(
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
        assert tracker.status == "New"
        assert not tracker.resolution
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect
        assert not tracker._alerts

        # 6) check that the update actually happened
        assert updated_dt != tracker.updated_dt
