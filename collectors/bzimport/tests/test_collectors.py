import uuid
from datetime import datetime

import pytest
from django.utils import timezone
from freezegun import freeze_time

from collectors.bzimport.collectors import BugzillaQuerier
from osidb.models import (
    Affect,
    CVEv5PackageVersions,
    Flaw,
    FlawComment,
    FlawMeta,
    Tracker,
)
from osidb.tests.factories import (
    AffectFactory,
    CVEv5PackageVersionsFactory,
    FlawCommentFactory,
    FlawFactory,
    FlawMetaFactory,
    PsModuleFactory,
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
        CVEv5PackageVersionsFactory(flaw=flaw2)
        FlawCommentFactory(flaw=flaw2)
        FlawMetaFactory(flaw=flaw2)

        flaw1 = Flaw.objects.filter(meta_attr__bz_id="321").first()
        flaw2 = Flaw.objects.filter(meta_attr__bz_id="123").first()
        affect = Affect.objects.first()
        package_version = CVEv5PackageVersions.objects.first()
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
        package_version = CVEv5PackageVersions.objects.first()
        comment = FlawComment.objects.first()
        meta = FlawMeta.objects.first()

        assert flaw1 is not None
        assert flaw2 is None
        assert affect is None
        assert package_version is None
        assert comment is None
        assert meta is None


class TestBZImportCollector:
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
    def test_flawmeta_acl_change(
        self, flaw_collector, bz_bug_requires_doc_text, monkeypatch
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
            flaw_collector.sync_flaw(bz_bug_requires_doc_text)

        assert Flaw.objects.count() != 0
        assert FlawMeta.objects.count() != 0

        doctext_meta = FlawMeta.objects.filter(
            type=FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT
        ).first()
        old_acls = doctext_meta.acl_read + doctext_meta.acl_write
        doctext_meta.acl_read = [uuid.uuid4(), uuid.uuid4()]
        doctext_meta.acl_write = [uuid.uuid4(), uuid.uuid4()]
        new_acls = doctext_meta.acl_read + doctext_meta.acl_write
        doctext_meta.save()

        assert old_acls != new_acls

        # ACL data should be updated
        with monkeypatch.context() as m:
            # see explanation above
            m.setattr(Affect, "_validate_ps_module_new_flaw", lambda s: None)
            flaw_collector.sync_flaw(bz_bug_requires_doc_text)
        doctext_meta = FlawMeta.objects.filter(
            type=FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT
        ).first()
        new_acls = doctext_meta.acl_read + doctext_meta.acl_write

        assert old_acls == new_acls


class TestBzTrackerCollector:
    @pytest.mark.vcr
    def test_sync_tracker(self, bz_tracker_collector):
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
        assert tracker.ps_update_stream == ""

    @pytest.mark.vcr
    def test_sync_with_affect(self, bz_tracker_collector):
        creation_dt = datetime(2011, 1, 1, tzinfo=timezone.utc)
        with freeze_time(creation_dt):
            affect = AffectFactory.create()
            TrackerFactory.create(
                affects=(affect,),
                external_system_id="577404",
                type=Tracker.TrackerType.BUGZILLA,
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
