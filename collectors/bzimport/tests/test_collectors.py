from datetime import datetime

import pytest
from django.db.utils import IntegrityError
from django.utils import timezone

from apps.bbsync.models import BugzillaComponent, BugzillaProduct
from collectors.bzimport.collectors import BugzillaQuerier, MetadataCollector
from collectors.bzimport.constants import BZ_DT_FMT
from osidb.dmodels.affect import Affect
from osidb.dmodels.flaw.comment import FlawComment
from osidb.dmodels.flaw.flaw import Flaw
from osidb.dmodels.package_versions import Package
from osidb.dmodels.tracker import Tracker
from osidb.sync_manager import BZTrackerLinkManager
from osidb.tests.factories import (
    AffectFactory,
    FlawCommentFactory,
    FlawFactory,
    PackageFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestBugzillaQuerier:
    def test_remove_testing(self):
        flaw1 = FlawFactory(
            title="regular flaw", embargoed=False, meta_attr={"bz_id": "321"}
        )
        flaw2 = FlawFactory(
            title="testing: flaw", embargoed=False, meta_attr={"bz_id": "123"}
        )
        AffectFactory(flaw=flaw2)
        PackageFactory(flaw=flaw2)
        FlawCommentFactory(flaw=flaw2)

        flaw1 = Flaw.objects.filter(meta_attr__bz_id="321").first()
        flaw2 = Flaw.objects.filter(meta_attr__bz_id="123").first()
        affect = Affect.objects.first()
        package_version = Package.objects.first()
        comment = FlawComment.objects.first()

        assert flaw1 is not None
        assert flaw2 is not None
        assert affect is not None
        assert affect.flaw == flaw2
        assert package_version is not None
        assert package_version.flaw == flaw2
        assert comment is not None
        assert comment.flaw == flaw2

        bugs = [
            ("321", None, flaw1.title),
            ("123", None, flaw2.title),
        ]
        assert BugzillaQuerier.exclude_testing(bugs) == [
            ("321", None),
        ]

        flaw1 = Flaw.objects.filter(meta_attr__bz_id="321").first()
        flaw2 = Flaw.objects.filter(meta_attr__bz_id="123").first()
        affect = Affect.objects.first()
        package_version = Package.objects.first()
        comment = FlawComment.objects.first()

        assert flaw1 is not None
        assert flaw2 is None
        assert affect is None
        assert package_version is None
        assert comment is None


class TestBZImportCollector:
    def test_end_period_heuristic(self, flaw_collector):
        """
        test that the heuristic of getting the end of the currect
        sync period correctly proceeds till the present time
        """
        period_start = flaw_collector.BEGINNING

        while True:
            period_end = flaw_collector.end_period_heuristic(period_start)
            assert period_start < period_end

            period_start = period_end
            if period_start > timezone.now():
                break

    def test_end_period_heuristic_migrations(self, flaw_collector):
        """
        test that the heuristic of getting the end of the currect
        sync period correctly accounts for the data migration periods
        """
        for migration in flaw_collector.MIGRATIONS:
            assert migration["start"] + migration[
                "step"
            ] == flaw_collector.end_period_heuristic(migration["start"])

    @pytest.mark.vcr
    def test_get_batch(self, flaw_collector):
        first_batch = flaw_collector.get_batch()
        assert first_batch
        assert first_batch[0][0] == "240155"
        # update metadata so that next batch returns the next batch of flaws
        flaw_collector.metadata.updated_until_dt = first_batch[-1][1]

        second_batch = flaw_collector.get_batch()
        assert second_batch
        # the batches should be different
        assert first_batch != second_batch
        # avoid fetching the boundary flaw multiple times
        assert not set(first_batch) & set(second_batch)

    @pytest.mark.vcr
    def test_sync_flaw(self, flaw_collector, bz_bug_id):
        """
        Simply test that sync_flaw works and related objects are correctly created.
        """
        # define all necessary product info
        # so the test does not produce warnings
        ps_module = PsModuleFactory(name="rhel-6")
        PsUpdateStreamFactory(name="rhel-6.0", ps_module=ps_module)
        ps_module = PsModuleFactory(name="rhel-5")
        PsUpdateStreamFactory(name="rhel-5.5.z", ps_module=ps_module)
        PsUpdateStreamFactory(name="rhel-5.6", ps_module=ps_module)
        ps_module = PsModuleFactory(name="fedora-all")
        PsUpdateStreamFactory(name="fedora-all", ps_module=ps_module)

        assert Flaw.objects.count() == 0
        assert Affect.objects.count() == 0
        assert Tracker.objects.count() == 0

        flaw_collector.sync_flaw(str(bz_bug_id))

        assert Flaw.objects.count() != 0
        assert Affect.objects.count() != 0
        assert Tracker.objects.count() == 0

    @pytest.mark.vcr
    def test_sync_embargoed_flaw(self, flaw_collector):
        """
        test that an embargoed flaw loaded from Bugzilla is preserved as embargoed
        """
        flaw_id = "1629662"
        assert Flaw.objects.count() == 0
        flaw_collector.sync_flaw(flaw_id)
        assert Flaw.objects.filter(meta_attr__bz_id=flaw_id).exists()
        assert Flaw.objects.get(meta_attr__bz_id=flaw_id).is_embargoed

    @pytest.mark.vcr
    def test_empty_affiliation(self, flaw_collector):
        """
        test that syncing a flaw with an acknowledgment with an empty (null) affilitation works
        this is a reproducer of the bug tracked by https://issues.redhat.com/browse/OSIDB-1195
        """
        try:
            # known public flaw with empty
            # acknowledgment affiliation
            flaw_collector.sync_flaw("1824033")
        except IntegrityError:
            pytest.fail("Flaw synchronization failed")


class TestBugzillaTrackerCollector:
    @pytest.mark.vcr
    def test_sync_tracker(self, bz_tracker_collector):
        PsUpdateStreamFactory(name="update-stream")

        assert Tracker.objects.count() == 0
        bz_tracker_collector.sync_tracker("1629664")

        trackers = Tracker.objects.all()
        assert len(trackers) == 1

        tracker = trackers.first()
        assert tracker.external_system_id == "1629664"
        assert tracker.type == Tracker.TrackerType.BUGZILLA
        assert tracker.status == "NEW"
        assert tracker.resolution == ""
        # no affect, thus this should be empty
        assert list(tracker.affects.all()) == []
        assert tracker.ps_update_stream == "epel-all"

    @pytest.mark.vcr
    def test_sync_embargoed_tracker(self, bz_tracker_collector):
        """
        test that an embargoed tracker loaded from Bugzilla is preserved as embargoed
        reproducer for https://issues.redhat.com/browse/OSIDB-2118
        """
        tracker_id = "1642774"
        assert Tracker.objects.count() == 0
        bz_tracker_collector.sync_tracker(tracker_id)
        assert Tracker.objects.filter(external_system_id=tracker_id).exists()
        assert Tracker.objects.get(external_system_id=tracker_id).is_embargoed

    @pytest.mark.vcr
    def test_sync_with_affect(self, bz_tracker_collector):
        ps_module = PsModuleFactory(bts_name="bugzilla", name="epel-all")
        PsUpdateStreamFactory(name="epel-all", ps_module=ps_module)

        flaw = FlawFactory(
            bz_id="1629662",
            embargoed=False,
        )
        affect = AffectFactory.create(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module="epel-all",
            ps_component="jhead",
        )
        creation_dt = datetime(2011, 1, 1, tzinfo=timezone.utc)
        TrackerFactory.create(
            affects=(affect,),
            external_system_id="1629664",
            type=Tracker.TrackerType.BUGZILLA,
            embargoed=affect.flaw.is_embargoed,
            created_dt=creation_dt,
            updated_dt=creation_dt,
        )

        tracker = Tracker.objects.first()
        assert tracker.created_dt == creation_dt
        assert tracker.updated_dt == creation_dt
        assert affect in list(tracker.affects.all())

        bz_tracker_collector.sync_tracker("1629664")
        BZTrackerLinkManager.link_tracker_with_affects("1629664")

        tracker = Tracker.objects.first()
        # should be updated from the bz values
        assert tracker.created_dt == datetime(
            2018, 9, 17, 9, 21, 54, tzinfo=timezone.utc
        )
        assert tracker.updated_dt == datetime(
            2018, 9, 17, 9, 22, 0, tzinfo=timezone.utc
        )
        assert tracker.status == "NEW"
        assert tracker.resolution == ""
        assert affect in list(tracker.affects.all())

    @pytest.mark.vcr
    def test_sync_with_multiple_affects(self, bz_tracker_collector):
        ps_module = PsModuleFactory(bts_name="bugzilla", name="epel-7")
        PsUpdateStreamFactory(name="epel-7", ps_module=ps_module)

        flaw1 = FlawFactory(
            bz_id="1343538",
            embargoed=False,
        )
        affect1 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module="epel-7",
            ps_component="struts",
        )

        flaw2 = FlawFactory(
            bz_id="1343540",
            embargoed=False,
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module="epel-7",
            ps_component="struts",
        )

        bz_tracker_collector.sync_tracker("1343542")
        BZTrackerLinkManager.link_tracker_with_affects("1343542")

        tracker = Tracker.objects.first()
        assert tracker.affects.count() == 2
        assert affect1 in list(tracker.affects.all())
        assert affect2 in list(tracker.affects.all())

    @pytest.mark.vcr
    def test_sync_with_removed_affect(self, bz_tracker_collector):
        ps_module = PsModuleFactory(bts_name="bugzilla", name="openstack-rdo")
        PsUpdateStreamFactory(name="openstack-rdo", ps_module=ps_module)

        flaw1 = FlawFactory(
            bz_id="1765660",
            embargoed=False,
        )
        affect1 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module="openstack-rdo",
            ps_component="novnc",
        )

        flaw2 = FlawFactory(
            bz_id="1417567",
            embargoed=False,
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module="openstack-rdo",
            ps_component="novnc",
        )

        TrackerFactory(
            affects=[affect1, affect2],
            external_system_id="1765663",
            type=Tracker.TrackerType.BUGZILLA,
            embargoed=False,
            updated_dt=timezone.datetime.strptime("1970-01-01T00:00:00Z", BZ_DT_FMT),
        )
        # make sure the links are there
        tracker = Tracker.objects.first()
        assert tracker.affects.count() == 2
        assert affect1 in list(tracker.affects.all())
        assert affect2 in list(tracker.affects.all())

        bz_tracker_collector.sync_tracker("1765663")
        BZTrackerLinkManager.link_tracker_with_affects("1765663")

        # make sure the second link was removed
        tracker = Tracker.objects.first()
        assert tracker.affects.count() == 1
        assert affect1 in list(tracker.affects.all())
        assert affect2 not in list(tracker.affects.all())

    @pytest.mark.vcr
    def test_sync_with_non_bz_flaws(self, bz_tracker_collector):
        ps_module = PsModuleFactory(bts_name="bugzilla", name="rhcertification-9")
        PsUpdateStreamFactory(name="rhcertification-9", ps_module=ps_module)

        flaw1 = FlawFactory(
            uuid="12472365-87e0-4376-be09-c1d4b4cbc6b0",
            bz_id=None,
            embargoed=False,
        )
        affect1 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module="rhcertification-9",
            ps_component="ssh",
        )

        flaw2 = FlawFactory(
            uuid="8ea223a7-7805-4d55-9a12-46d8b49b70a3",
            bz_id=None,
            embargoed=False,
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module="rhcertification-9",
            ps_component="ssh",
        )
        # no Bugzilla flaws
        assert all(flaw for flaw in Flaw.objects.all() if not flaw.bz_id)

        bz_tracker_collector.sync_tracker("2280681")
        BZTrackerLinkManager.link_tracker_with_affects("2280681")

        # make sure the links are there
        tracker = Tracker.objects.first()
        assert tracker
        assert tracker.affects.count() == 2
        assert affect1 in list(tracker.affects.all())
        assert affect2 in list(tracker.affects.all())


class TestMetadataCollector:
    @pytest.mark.vcr
    def test_collect(self):
        ps_product = PsProductFactory(business_unit="Cloud Platform")
        PsModuleFactory(
            ps_product=ps_product,
            bts_name="bugzilla",
            bts_key="Container Native Virtualization (CNV)",
        )

        mc = MetadataCollector()
        mc.collect()

        assert BugzillaProduct.objects.count() == 1
        bz_product = BugzillaProduct.objects.first()
        assert bz_product.name == "Container Native Virtualization (CNV)"
        assert (
            BugzillaProduct.objects.first().name
            == "Container Native Virtualization (CNV)"
        )
        assert BugzillaComponent.objects.count() == 18
        assert all(
            c for c in BugzillaComponent.objects.all() if c.product == bz_product
        )
        assert {c.name for c in BugzillaComponent.objects.all()} == {
            "Build",
            "Design",
            "Documentation",
            "Entitlements",
            "Guest Support",
            "Infrastructure",
            "Installation",
            "Logging",
            "Metrics",
            "Networking",
            "Providers",
            "Release",
            "RFE",
            "SSP",
            "Storage",
            "User Experience",
            "V2V",
            "Virtualization",
        }
        # pick one component and check details
        assert (
            BugzillaComponent.objects.get(name="Installation").default_owner
            == "stirabos@redhat.com"
        )
        assert BugzillaComponent.objects.get(name="Installation").default_cc == [
            "stirabos@redhat.com"
        ]
