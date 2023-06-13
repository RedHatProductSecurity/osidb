import uuid

import pytest
from django.utils import timezone

from collectors.bzimport.convertors import FlawConvertor, FlawSaver
from osidb.models import (
    Affect,
    CVEv5PackageVersions,
    CVEv5Version,
    Flaw,
    FlawComment,
    FlawHistory,
    FlawImpact,
    FlawMeta,
    FlawReference,
    Tracker,
    VersionStatus,
)
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestFlawSaver:
    def get_acls(self):
        """
        minimal acls getter
        """
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]

    def get_flaw(self):
        """
        minimal flaw getter
        """
        return Flaw(
            cve_id="CVE-2000-1234",
            title="title",
            description="description",
            impact=FlawImpact.CRITICAL,
            created_dt=timezone.now(),
            updated_dt=timezone.now(),
            acl_read=self.get_acls(),
            acl_write=self.get_acls(),
        )

    def get_affects(self, flaw):
        """
        minimal affects getter
        """
        return [
            Affect(
                flaw=flaw,
                ps_module="module",
                ps_component="component",
                created_dt=timezone.now(),
                updated_dt=timezone.now(),
                acl_read=self.get_acls(),
                acl_write=self.get_acls(),
            )
        ]

    def get_comments(self, flaw):
        """
        minimal comments getter
        """
        return [
            FlawComment(
                flaw=flaw,
                external_system_id="123",
                text="test comment",
                order=1,
                created_dt=timezone.now(),
                updated_dt=timezone.now(),
                acl_read=self.get_acls(),
                acl_write=self.get_acls(),
            )
        ]

    def get_history(self):
        """
        minimal history getter
        """
        return [
            FlawHistory(
                cve_id="CVE-2000-1234",
                impact=FlawImpact.IMPORTANT,
                title="historical title",
                description="historical description",
                pgh_created_at=timezone.now(),
                pgh_label="user",
                acl_read=self.get_acls(),
                acl_write=self.get_acls(),
            )
        ]

    def get_meta(self, flaw):
        """
        minimal meta getter
        """
        return [
            FlawMeta.objects.create_flawmeta(
                flaw=flaw,
                _type=FlawMeta.FlawMetaType.ACKNOWLEDGMENT,
                meta={"name": "Lon Wnderer"},
                created_dt=timezone.now(),
                updated_dt=timezone.now(),
                acl_read=self.get_acls(),
                acl_write=self.get_acls(),
            ),
            FlawMeta.objects.create_flawmeta(
                flaw=flaw,
                _type=FlawMeta.FlawMetaType.ACKNOWLEDGMENT,
                meta={"name": "Lone Wanderer"},
                created_dt=timezone.now(),
                updated_dt=timezone.now(),
                acl_read=self.get_acls(),
                acl_write=self.get_acls(),
            ),
        ]

    def get_references(self, flaw):
        """
        minimal references getter
        """
        return [
            FlawReference(
                flaw=flaw,
                url="https://httpd.apache.org/link123",
                type=FlawReference.FlawReferenceType.EXTERNAL,
                created_dt=timezone.now(),
                updated_dt=timezone.now(),
                acl_read=self.get_acls(),
                acl_write=self.get_acls(),
            )
        ]

    def get_trackers(self, affect):
        """
        minimal trackers getter
        """
        return [
            Tracker(
                type=Tracker.TrackerType.JIRA,
                external_system_id="OSIDB-1",
                status="New",
                meta_attr={
                    "ps_module": affect.ps_module,
                    "ps_component": affect.ps_component,
                },
                created_dt=timezone.now(),
                updated_dt=timezone.now(),
                acl_read=self.get_acls(),
                acl_write=self.get_acls(),
            )
        ]

    def get_package_versions(self):
        """
        minimal package versions getter
        """
        return {
            "package": ["version"],
        }

    def test_basic(self):
        """
        test basic flaw and realated entities save
        """
        acls = self.get_acls()
        flaw = self.get_flaw()
        affects = self.get_affects(flaw)

        FlawSaver(
            flaw,
            affects,
            self.get_comments(flaw),
            self.get_history(),
            self.get_meta(flaw),
            self.get_references(flaw),
            self.get_trackers(affects[0]),
            self.get_package_versions(),
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()
        comment = FlawComment.objects.first()
        history = FlawHistory.objects.first()
        meta = FlawMeta.objects.first()
        reference = FlawReference.objects.first()
        tracker = Tracker.objects.first()
        package_versions = CVEv5PackageVersions.objects.first()
        version = CVEv5Version.objects.first()

        assert flaw is not None
        assert flaw.cve_id == "CVE-2000-1234"
        assert flaw.title == "title"
        assert flaw.description == "description"
        assert flaw.impact == FlawImpact.CRITICAL
        assert flaw.acl_read == acls
        assert flaw.acl_write == acls
        assert flaw.affects.first() == affect
        assert flaw.comments.first() == comment
        assert flaw.meta.first() == meta
        assert flaw.references.first() == reference
        assert flaw.package_versions.first() == package_versions

        assert affect is not None
        assert affect.ps_module == "module"
        assert affect.ps_component == "component"
        assert affect.acl_read == acls
        assert affect.acl_write == acls
        assert affect.flaw == flaw
        assert affect.trackers.count() == 1
        assert affect.trackers.first() == tracker

        assert comment is not None
        assert comment.external_system_id == "123"
        assert comment.text == "test comment"
        assert comment.acl_read == acls
        assert comment.acl_write == acls
        assert comment.flaw == flaw

        assert history is not None
        assert history.cve_id == "CVE-2000-1234"
        assert history.impact == FlawImpact.IMPORTANT
        assert history.title == "historical title"
        assert history.description == "historical description"
        assert history.acl_read == acls
        assert history.acl_write == acls

        assert meta is not None
        assert meta.type == FlawMeta.FlawMetaType.ACKNOWLEDGMENT
        assert meta.acl_read == acls
        assert meta.acl_write == acls
        assert meta.flaw == flaw

        assert reference is not None
        assert reference.url == "https://httpd.apache.org/link123"
        assert reference.type == "EXTERNAL"
        assert reference.description == ""
        assert reference.acl_read == acls
        assert reference.acl_write == acls
        assert reference.flaw == flaw

        assert tracker is not None
        assert tracker.type == Tracker.TrackerType.JIRA
        assert tracker.external_system_id == "OSIDB-1"
        assert tracker.status == "New"
        assert tracker.acl_read == acls
        assert tracker.acl_write == acls
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect

        assert package_versions is not None
        assert package_versions.package == "package"
        assert package_versions.default_status == VersionStatus.UNAFFECTED
        assert package_versions.flaw == flaw
        assert package_versions.versions.count() == 1
        assert package_versions.versions.first() == version

        assert version is not None
        assert version.version == "version"
        assert version.status == VersionStatus.UNAFFECTED
        assert version.packageversions_set.count() == 1
        assert version.packageversions_set.first() == package_versions

    def test_affect_removed(self):
        """
        test affect removal save
        """
        flaw = self.get_flaw()

        FlawSaver(
            flaw,
            self.get_affects(flaw),
            [],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()

        assert flaw is not None
        assert affect is not None
        assert flaw.affects.count() == 1
        assert flaw.affects.first() == affect
        assert affect.flaw == flaw

        FlawSaver(
            flaw,
            [],
            [],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()

        assert flaw is not None
        assert affect is None
        assert flaw.affects.count() == 0

    def test_meta_removed(self):
        """
        test meta removal save
        """
        flaw = self.get_flaw()

        FlawSaver(
            flaw,
            [],
            [],
            [],
            self.get_meta(flaw),
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        meta = FlawMeta.objects.first()

        assert flaw is not None
        assert meta is not None
        assert flaw.meta.count() == 2
        assert flaw.meta.first() == meta
        assert meta.flaw == flaw

        FlawSaver(
            flaw,
            [],
            [],
            [],
            [
                self.get_meta(flaw)[1],
            ],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        meta = FlawMeta.objects.first()

        assert flaw is not None
        assert flaw.meta.count() == 1
        assert flaw.meta.first() == self.get_meta(flaw)[1]
        assert flaw.meta.first().meta_attr["name"] == "Lone Wanderer"

    def test_reference_removed(self):
        """
        test reference removal save
        """
        flaw = self.get_flaw()

        FlawSaver(
            flaw,
            [],
            [],
            [],
            [],
            self.get_references(flaw),
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        reference = FlawReference.objects.first()

        assert flaw is not None
        assert reference is not None
        assert flaw.references.count() == 1
        assert flaw.references.first() == reference
        assert reference.flaw == flaw

        FlawSaver(
            flaw,
            [],
            [],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        reference = FlawReference.objects.first()

        assert flaw is not None
        assert reference is None
        assert flaw.references.count() == 0

    def test_trackers_removed(self):
        """
        test tracker removal save
        """
        flaw = self.get_flaw()
        affects = self.get_affects(flaw)

        FlawSaver(
            flaw,
            affects,
            [],
            [],
            [],
            [],
            self.get_trackers(affects[0]),
            {},
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()
        tracker = Tracker.objects.first()

        assert flaw is not None
        assert affect is not None
        assert tracker is not None
        assert flaw.affects.count() == 1
        assert flaw.affects.first() == affect
        assert affect.flaw == flaw
        assert affect.trackers.count() == 1
        assert affect.trackers.first() == tracker
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect

        FlawSaver(
            flaw,
            affects,
            [],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()
        tracker = Tracker.objects.first()

        assert flaw is not None
        assert affect is not None
        # tracker should not be removed
        # only the affect-tracker link
        assert tracker is not None
        assert flaw.affects.count() == 1
        assert flaw.affects.first() == affect
        assert affect.flaw == flaw
        assert affect.trackers.count() == 0
        assert tracker.affects.count() == 0

    def test_packageversions_removed(self):
        """
        test packageversions removal save
        """
        flaw = self.get_flaw()

        FlawSaver(
            flaw,
            [],
            [],
            [],
            [],
            [],
            [],
            self.get_package_versions(),
        ).save()

        flaw = Flaw.objects.first()
        package_versions = CVEv5PackageVersions.objects.first()
        version = CVEv5Version.objects.first()

        assert flaw is not None
        assert package_versions is not None
        assert version is not None
        assert flaw.package_versions.count() == 1
        assert flaw.package_versions.first() == package_versions
        assert package_versions.flaw == flaw
        assert package_versions.versions.count() == 1
        assert package_versions.versions.first() == version
        assert version.packageversions_set.count() == 1
        assert version.packageversions_set.first() == package_versions

        FlawSaver(
            flaw,
            [],
            [],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        package_versions = CVEv5PackageVersions.objects.first()
        version = CVEv5Version.objects.first()

        assert flaw is not None
        assert package_versions is None
        assert version is None
        assert flaw.package_versions.count() == 0


class TestFlawConvertor:
    @classmethod
    def get_flaw_bug(cls):
        """
        minimal Bugzilla flaw data getter
        """
        return {
            "alias": [
                "CVE-2000-1234",
            ],
            "cf_release_notes": None,
            "creation_time": "2000-01-01T12:12:12Z",
            "depends_on": [],
            "description": "text",
            "fixed_in": None,
            "id": "123",
            "last_change_time": "2001-01-01T12:12:12Z",
            "status": "CLOSED",
            "resolution": "",
            "summary": "kernel: text",
            "cf_srtnotes": cls.get_flaw_srtnotes(),
        }

    @classmethod
    def get_flaw_history(cls):
        """
        minimal Bugzilla flaw data getter
        """
        return {"bugs": [{"history": []}]}

    @classmethod
    def get_flaw_srtnotes(cls):
        """
        minimal Bugzilla flaw SRT notes getter
        """
        return """
        {
            "affects": [],
            "impact": "moderate",
            "public": "2000-04-04T00:00:00Z",
            "reported": "2000-01-01T00:00:00Z",
            "source": "customer"
        }
        """

    def test_affect_ps_module_fixup(self):
        """
        test that flaw with an affect fixed by a fixup
        can be synced multiple times without causing an error

        this tests that https://issues.redhat.com/browse/OSIDB-152 is fixed
        """
        flaw_bug = self.get_flaw_bug()
        srtnotes = """
        {
            "affects": [
                {
                    "ps_module": "rhel-6.0",
                    "ps_component": "firefox",
                    "affectedness": "affected",
                    "resolution": "fix"
                }
            ],
            "impact": "moderate",
            "public": "2000-04-04T00:00:00Z",
            "reported": "2000-01-01T00:00:00Z",
            "source": "customer"
        }
        """
        flaw_bug["cf_srtnotes"] = srtnotes

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        flaw = Flaw.objects.first()
        assert flaw is not None
        affect = flaw.affects.first()
        assert affect is not None
        # test that PS module was fixed
        assert affect.ps_module == "rhel-6"

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert len(flaws) == 1
        flaw = flaws[0]
        # we test that the second save
        # does not throw an exception
        flaw.save()

    def test_multiple_same_affects_after_ps_module_fixup(self):
        """
        test that flaw with an affects fixed by a fixup
        resulting to a multiple occurences can be synced without causing an error
        it should merge the affects into just a single one

        this tests that /merge_requests/310#note_101271 is fixed
        """
        flaw_bug = self.get_flaw_bug()
        srtnotes = """
        {
            "affects": [
                {
                    "ps_module": "rhel-6.0",
                    "ps_component": "firefox",
                    "affectedness": "affected",
                    "resolution": "fix"
                },{
                    "ps_module": "rhel-6.1",
                    "ps_component": "firefox",
                    "affectedness": "affected",
                    "resolution": "fix"
                }
            ],
            "impact": "moderate",
            "public": "2000-04-04T00:00:00Z",
            "reported": "2000-01-01T00:00:00Z",
            "source": "customer"
        }
        """
        flaw_bug["cf_srtnotes"] = srtnotes

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        flaw = Flaw.objects.first()
        assert flaw is not None
        assert flaw.affects.count() == 1
        affect = flaw.affects.first()
        assert affect.ps_module == "rhel-6"
        assert affect.ps_component == "firefox"

    def test_cve_changed(self):
        """
        test that flaw CVE change is correctly reflected
        """
        flaw_bug = self.get_flaw_bug()

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id == "CVE-2000-1234"

        # changing CVE - bug ID is unchanged
        flaw_bug["alias"] = ["CVE-2000-9999"]
        flaw_uuid = flaw.uuid

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id == "CVE-2000-9999"
        assert flaw.uuid == flaw_uuid

    def test_cve_preserved_and_changed(self):
        """
        test that flaw CVE change is correctly reflected
        while there is additionally another CVE preserved
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["alias"] = ["CVE-2000-0001", "CVE-2000-0002"]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 2
        for flaw in flaws:
            flaw.save()

        assert Flaw.objects.count() == 2
        cve_ids = [flaw.cve_id for flaw in Flaw.objects.all()]
        assert sorted(cve_ids) == ["CVE-2000-0001", "CVE-2000-0002"]
        # store UUID for later comparison
        flaw_uuid = Flaw.objects.get(cve_id="CVE-2000-0001").uuid

        # changing CVE - bug ID is unchanged
        flaw_bug["alias"] = ["CVE-2000-0001", "CVE-2000-9999"]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 2
        for flaw in flaws:
            flaw.save()

        assert Flaw.objects.count() == 2
        cve_ids = [flaw.cve_id for flaw in Flaw.objects.all()]
        assert sorted(cve_ids) == ["CVE-2000-0001", "CVE-2000-9999"]
        assert flaw_uuid == Flaw.objects.get(cve_id="CVE-2000-0001").uuid

    def test_cve_removed(self):
        """
        test that flaw CVE removal is correctly reflected
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["alias"] = ["CVE-2000-0001", "CVE-2000-0002"]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 2
        for flaw in flaws:
            flaw.save()

        assert Flaw.objects.count() == 2
        cve_ids = [flaw.cve_id for flaw in Flaw.objects.all()]
        assert sorted(cve_ids) == ["CVE-2000-0001", "CVE-2000-0002"]
        # store UUID for later comparison
        flaw_uuid = Flaw.objects.get(cve_id="CVE-2000-0001").uuid

        # removing one of the CVEs
        flaw_bug["alias"] = ["CVE-2000-0001"]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id == "CVE-2000-0001"
        assert flaw.uuid == flaw_uuid

        # removing all CVEs
        flaw_bug["alias"] = []

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id is None
        assert flaw.uuid == flaw_uuid

    def test_cves_removed(self):
        """
        test that removal of multiple CVEs at once is correctly reflected
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["alias"] = ["CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 3
        for flaw in flaws:
            flaw.save()

        assert Flaw.objects.count() == 3
        cve_ids = [flaw.cve_id for flaw in Flaw.objects.all()]
        assert sorted(cve_ids) == ["CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"]
        # store UUID for later comparison
        flaw_uuid = Flaw.objects.get(cve_id="CVE-2000-0001").uuid

        # removing two CVEs at once
        flaw_bug["alias"] = ["CVE-2000-0001"]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id == "CVE-2000-0001"
        assert flaw.uuid == flaw_uuid

    def test_no_cve(self):
        """
        test that CVE-less flaw is correctly processed
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["alias"] = ["non-CVE-alias"]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id is None

        # test that repeated sync preserves UUID
        flaw_uuid = flaw.uuid

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id is None
        assert flaw.uuid == flaw_uuid

    def test_cve_assign(self):
        """
        test that CVE assignment to a CVE-less flaw is correctly processed
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["alias"] = []

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id is None
        flaw_uuid = flaw.uuid

        # assign CVE to the flaw
        flaw_bug["alias"] = ["CVE-2000-0001"]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id == "CVE-2000-0001"
        assert flaw.uuid == flaw_uuid

    def test_major_incident_flag_order(self):
        """
        test reproducer for OSIDB-416 where the erroneous condition logic led to unsetting
        is_major_incident boolean when following flag was not setting it to True
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["flags"] = [
            {
                "name": "requires_summary",
                "status": "+",
            },
            {
                "name": "hightouch",
                "status": "?",
            },
            {
                "name": "nist_cvss_validation",
                "status": "-",
            },
        ]

        fbc = FlawConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.is_major_incident is True

    def test_attributes_removed_in_bugzilla(self):
        """
        test that the attribute removals in Bugzilla
        will correctly result in empty values

        OSIDB-910 reproducer (old non-empty values were not emptied)
        """
        flaw = FlawFactory(
            bz_id="123",
            cvss2="10.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            cvss2_score=10.0,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            cvss3_score=3.7,
            embargoed=False,
            reported_dt="2000-01-01T01:01:01Z",
            summary="test",
            unembargo_dt="2000-01-01T01:01:01Z",
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="ssh",
            cvss2="10.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            cvss2_score=10.0,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            cvss3_score=3.7,
        )

        flaw_bug = self.get_flaw_bug()
        # attributes removed or not available in Bugzilla
        # - some situations are maybe hypothetical
        #   but better safe than sorry
        flaw_bug.pop("cf_release_notes")
        # removing public and reported timestamps
        # plus also all the CVSS stuff
        flaw_bug[
            "cf_srtnotes"
        ] = """
        {
            "affects": [
                {
                    "ps_module": "rhel-8",
                    "ps_component": "ssh",
                    "affectedness": "affected",
                    "resolution": "fix"
                }
            ],
            "impact": "moderate",
            "source": "customer"
        }
        """

        fbc = FlawConvertor(
            flaw_bug,
            [],
            None,
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert "has no reported_dt (reported)" in fbc.errors
        assert "no cf_release_notes" in fbc.errors
        assert "has no unembargo_dt (public date)" in fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cvss2 == ""
        assert flaw.cvss2_score is None
        assert flaw.cvss3 == ""
        assert flaw.cvss3_score is None
        assert flaw.reported_dt is None
        assert flaw.summary == ""
        assert flaw.unembargo_dt is None

        assert Affect.objects.count() == 1
        affect = Affect.objects.first()
        assert affect.cvss2 == ""
        assert affect.cvss2_score is None
        assert affect.cvss3 == ""
        assert affect.cvss3_score is None


class TestFlawConvertorFixedIn:
    def init_models(self, fixed_in):
        """
        init Django models with provided version
        by performing the conversion from Bugzilla data
        """
        flaw_bug = TestFlawConvertor.get_flaw_bug()
        flaw_bug["fixed_in"] = fixed_in

        fbc = FlawConvertor(
            flaw_bug,
            [],
            TestFlawConvertor.get_flaw_history(),
            None,
            [],
            [],
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

    def test_find_package_multi(self):
        self.init_models("django 3.2.5, django 3.1.13")

        package_versions = CVEv5PackageVersions.objects.all()
        assert package_versions.count() == 1

        package_version = package_versions.first()
        assert package_version.package == "django"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 2

        versions = [c5v.version for c5v in cvev5versions]
        assert "3.1.13" in versions
        assert "3.2.5" in versions

    def test_find_package_single(self):
        self.init_models("django 3.2.5")

        package_versions = CVEv5PackageVersions.objects.all()
        assert package_versions.count() == 1

        package_version = package_versions.first()
        assert package_version.package == "django"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 1

        versions = [c5v.version for c5v in cvev5versions]
        assert "3.2.5" in versions

    def test_find_package_single_dash(self):
        self.init_models("django-3.2.5")

        package_versions = CVEv5PackageVersions.objects.all()
        assert package_versions.count() == 1

        package_version = package_versions.first()
        assert package_version.package == "django"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 1

        versions = [c5v.version for c5v in cvev5versions]
        assert "3.2.5" in versions

    def test_find_package_multi_dash(self):
        self.init_models("python-pillow-2.8.0")

        package_versions = CVEv5PackageVersions.objects.all()
        assert package_versions.count() == 1

        package_version = package_versions.first()
        assert package_version.package == "python-pillow"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 1

        versions = [c5v.version for c5v in cvev5versions]
        assert "2.8.0" in versions

    def test_find_package_no_value(self):
        self.init_models("")

        assert not CVEv5PackageVersions.objects.count()

    def test_find_package_null_value(self):
        self.init_models(None)

        assert not CVEv5PackageVersions.objects.count()

    def test_find_package_with_golang(self):
        self.init_models("github.com/gogo/protobuf 1.3.2")

        package_versions = CVEv5PackageVersions.objects.all()
        assert package_versions.count() == 1

        package_version = package_versions.first()
        assert package_version.package == "github.com/gogo/protobuf"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 1

        versions = [c5v.version for c5v in cvev5versions]
        assert "1.3.2" in versions

    def test_parse_fixed_in_multi_package(self):
        self.init_models("a 1, b 1")

        package_versions = CVEv5PackageVersions.objects.all()
        assert package_versions.count() == 2

        package_version1 = package_versions.filter(package="a").first()
        package_version2 = package_versions.filter(package="b").first()
        assert package_version1
        assert package_version2

        cvev5versions1 = package_version1.versions.all()
        cvev5versions2 = package_version2.versions.all()
        assert cvev5versions1.count() == 1
        assert cvev5versions2.count() == 1

        versions1 = [c5v.version for c5v in cvev5versions1]
        versions2 = [c5v.version for c5v in cvev5versions2]
        assert "1" in versions1
        assert "1" in versions2

    def test_parse_fixed_in_multi_package_dash(self):
        self.init_models("a-1, b 1")

        package_versions = CVEv5PackageVersions.objects.all()
        assert package_versions.count() == 2

        package_version1 = package_versions.filter(package="a").first()
        package_version2 = package_versions.filter(package="b").first()
        assert package_version1
        assert package_version2

        cvev5versions1 = package_version1.versions.all()
        cvev5versions2 = package_version2.versions.all()
        assert cvev5versions1.count() == 1
        assert cvev5versions2.count() == 1

        versions1 = [c5v.version for c5v in cvev5versions1]
        versions2 = [c5v.version for c5v in cvev5versions2]
        assert "1" in versions1
        assert "1" in versions2
