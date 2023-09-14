import uuid
from datetime import datetime

import pytest
from django.conf import settings
from django.db.utils import IntegrityError
from django.utils import timezone
from freezegun import freeze_time

from apps.bbsync.models import BugzillaComponent, BugzillaProduct
from collectors.bzimport.collectors import BugzillaQuerier, MetadataCollector
from osidb.core import generate_acls
from osidb.models import Affect, Flaw, FlawComment, FlawMeta, Package, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawCommentFactory,
    FlawFactory,
    FlawMetaFactory,
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
        FlawMetaFactory(flaw=flaw2)

        flaw1 = Flaw.objects.filter(meta_attr__bz_id="321").first()
        flaw2 = Flaw.objects.filter(meta_attr__bz_id="123").first()
        affect = Affect.objects.first()
        package_version = Package.objects.first()
        comment = FlawComment.objects.first()
        meta = FlawMeta.objects.first()

        assert flaw1 is not None
        assert flaw2 is not None
        assert affect is not None
        assert affect.flaw == flaw2
        assert package_version is not None
        assert package_version.flaw == flaw2
        assert comment is not None
        assert comment.flaw == flaw2
        assert meta is not None
        assert meta.flaw == flaw2

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
        meta = FlawMeta.objects.first()

        assert flaw1 is not None
        assert flaw2 is None
        assert affect is None
        assert package_version is None
        assert comment is None
        assert meta is None


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
        assert Tracker.objects.count() != 0

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

    @pytest.mark.vcr
    def test_flawmeta_acl_change(
        self, flaw_collector, bz_bug_requires_summary, monkeypatch
    ):
        """
        Test that FlawMetas are correctly updated.
        """
        assert Flaw.objects.count() == 0
        assert FlawMeta.objects.count() == 0

        with monkeypatch.context() as m:
            # avoid triggering the validator, the alternative would be to define
            # in this test **all** the PsModules found in this particular flaw's
            # affects, which is a lot of work
            m.setattr(Affect, "_validate_ps_module_new_flaw", lambda s: None)
            flaw_collector.sync_flaw(bz_bug_requires_summary)

        assert Flaw.objects.count() != 0
        assert FlawMeta.objects.count() != 0

        doctext_meta = FlawMeta.objects.filter(
            type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY
        ).first()
        old_acls = doctext_meta.acl_read + doctext_meta.acl_write
        # make metadata embargoed so we change to a valid ACL combination
        doctext_meta.acl_read = [
            uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_READ_GROUP])
        ]
        doctext_meta.acl_write = [
            uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_WRITE_GROUP])
        ]
        new_acls = doctext_meta.acl_read + doctext_meta.acl_write

        # in Bugzilla world it is not possible to have different Flaw and FlawMeta visibility
        # but here we want to be in OSIDB world only so let us turn off this Bugzilla validation
        with monkeypatch.context() as m:
            m.setattr(
                FlawMeta, "_validate_acl_identical_to_parent_flaw", lambda s: None
            )
            doctext_meta.save()

        assert old_acls != new_acls

        # ACL data should be updated
        with monkeypatch.context() as m:
            # see explanation above
            m.setattr(Affect, "_validate_ps_module_new_flaw", lambda s: None)
            flaw_collector.sync_flaw(bz_bug_requires_summary)
        doctext_meta = FlawMeta.objects.filter(
            type=FlawMeta.FlawMetaType.REQUIRES_SUMMARY
        ).first()
        new_acls = doctext_meta.acl_read + doctext_meta.acl_write

        assert old_acls == new_acls


class TestBugzillaTrackerCollector:
    def test_jira_connection(self, flaw_collector):
        """Test that collector is able to instantiate a Jira connection object"""
        assert flaw_collector.jira_conn

    @pytest.mark.vcr
    def test_sync_tracker(self, bz_tracker_collector):
        PsUpdateStreamFactory(name="update-stream")

        assert Tracker.objects.count() == 0
        bz_tracker_collector.sync_tracker("577404")

        trackers = Tracker.objects.all()
        assert len(trackers) == 1

        tracker = trackers.first()
        assert tracker.external_system_id == "577404"
        assert tracker.type == Tracker.TrackerType.BUGZILLA
        assert tracker.status == "CLOSED"
        assert tracker.resolution == "NOTABUG"
        # no affect, thus this should be empty
        assert list(tracker.affects.all()) == []
        assert tracker.ps_update_stream == "update-stream"

    @pytest.mark.vcr
    def test_sync_with_affect(self, bz_tracker_collector):
        PsModuleFactory(bts_name="bugzilla", name="module")
        PsUpdateStreamFactory(name="update-stream")

        creation_dt = datetime(2011, 1, 1, tzinfo=timezone.utc)
        with freeze_time(creation_dt):
            affect = AffectFactory.create(
                flaw__embargoed=False,
                affectedness=Affect.AffectAffectedness.NEW,
                ps_module="module",
            )
            TrackerFactory.create(
                affects=(affect,),
                external_system_id="577404",
                type=Tracker.TrackerType.BUGZILLA,
                embargoed=affect.flaw.is_embargoed,
            )

        tracker = Tracker.objects.first()
        assert tracker.created_dt == creation_dt
        assert tracker.updated_dt == creation_dt
        assert affect in list(tracker.affects.all())

        update_dt = datetime(2012, 1, 1, tzinfo=timezone.utc)
        with freeze_time(update_dt):
            bz_tracker_collector.sync_tracker("577404")

        tracker = Tracker.objects.first()
        # should be updated from the bz values
        assert tracker.created_dt == datetime(
            2010, 3, 26, 21, 10, 29, tzinfo=timezone.utc
        )
        assert tracker.updated_dt == datetime(
            2010, 4, 13, 22, 20, 14, tzinfo=timezone.utc
        )
        assert tracker.resolution == "NOTABUG"
        assert tracker.status == "CLOSED"
        assert affect in list(tracker.affects.all())


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
