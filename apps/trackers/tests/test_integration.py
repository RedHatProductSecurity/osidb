"""
tracker app integration tests
"""

import pytest
from django.utils import timezone

from apps.trackers.save import TrackerSaver
from collectors.bzimport.collectors import BugzillaTrackerCollector
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
        btc = BugzillaTrackerCollector()
        btc.sync_tracker(created_tracker.bz_id)

        # 4) get the newly loaded tracker from the DB
        loaded_tracker = Tracker.objects.get(external_system_id=created_tracker.bz_id)

        # 5) check the correct result of the creation and loading
        assert loaded_tracker.bz_id == created_tracker.bz_id
        assert not loaded_tracker.embargoed
        assert loaded_tracker.type == Tracker.TrackerType.BUGZILLA
        assert loaded_tracker.ps_update_stream == "rhcertification-6"
        assert loaded_tracker.status == "NEW"
        assert not loaded_tracker.resolution
        # TODO to be implemented
        # assert loaded_tracker.affects.count() == 1
        # assert loaded_tracker.affects.first() == affect
        # TODO will fail on no associated affect
        # assert not loaded_tracker._alerts

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
        tracker_id = "2016018"
        updated_dt = "2023-08-04T10:43:55Z"
        tracker = TrackerFactory(
            affects=[affect],
            bz_id=tracker_id,
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
            meta_attr={"updated_dt": updated_dt},
            updated_dt=timezone.datetime.strptime(updated_dt, BZ_DT_FMT),
        )
        assert tracker.bz_id == tracker_id

        # 3) update tracker in OSIDB and Bugzilla
        ts = TrackerSaver(tracker, bz_api_key="SECRET")
        updated_tracker = ts.save()
        assert updated_tracker.bz_id == tracker_id

        # 4) load tracker from Bugzilla
        btc = BugzillaTrackerCollector()
        btc.sync_tracker(tracker_id)

        # 5) get the newly loaded tracker from the DB
        loaded_tracker = Tracker.objects.get(external_system_id=tracker_id)

        # 6) check the correct result of the update and loading
        assert loaded_tracker.bz_id == tracker_id
        assert not loaded_tracker.embargoed
        assert loaded_tracker.type == Tracker.TrackerType.BUGZILLA
        assert loaded_tracker.ps_update_stream == "rhcertification-6"
        assert loaded_tracker.status == "NEW"
        assert not loaded_tracker.resolution
        # TODO to be implemented
        # assert loaded_tracker.affects.count() == 1
        # assert loaded_tracker.affects.first() == affect
        # TODO will fail on no associated affect
        # assert not loaded_tracker._alerts

        # 7) check that the update actually happened
        assert "updated_dt" in loaded_tracker.meta_attr
        assert updated_dt != loaded_tracker.meta_attr["updated_dt"]
