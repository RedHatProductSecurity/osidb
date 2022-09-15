import uuid

import pytest
from django.utils import timezone

from collectors.bzimport.convertors import FlawBugConvertor, FlawSaver
from osidb.models import (
    Affect,
    CVEv5PackageVersions,
    CVEv5Version,
    Flaw,
    FlawComment,
    FlawHistory,
    FlawImpact,
    FlawMeta,
    Tracker,
    VersionStatus,
)

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
            self.get_trackers(affects[0]),
            self.get_package_versions(),
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()
        comment = FlawComment.objects.first()
        history = FlawHistory.objects.first()
        meta = FlawMeta.objects.first()
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
            {},
        ).save()

        flaw = Flaw.objects.first()
        meta = FlawMeta.objects.first()

        assert flaw is not None
        assert flaw.meta.count() == 1
        assert flaw.meta.first() == self.get_meta(flaw)[1]
        assert flaw.meta.first().meta_attr["name"] == "Lone Wanderer"

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
            {},
        ).save()

        flaw = Flaw.objects.first()
        package_versions = CVEv5PackageVersions.objects.first()
        version = CVEv5Version.objects.first()

        assert flaw is not None
        assert package_versions is None
        assert version is None
        assert flaw.package_versions.count() == 0


class TestFlawBugConvertor:
    def get_flaw_bug(self):
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
            "summary": "text",
            "cf_srtnotes": self.get_flaw_srtnotes(),
        }

    def get_flaw_history(self):
        """
        minimal Bugzilla flaw data getter
        """
        return {"bugs": [{"history": []}]}

    def get_flaw_srtnotes(self):
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

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
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

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
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

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
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

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
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

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id == "CVE-2000-9999"

    def test_cve_removed(self):
        """
        test that flaw CVE removal is correctly reflected
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["alias"] = ["CVE-2000-0001", "CVE-2000-0002"]

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 2
        for flaw in flaws:
            flaw.save()

        assert Flaw.objects.count() == 2
        cve_ids = [flaw.cve_id for flaw in Flaw.objects.all()]
        assert sorted(cve_ids) == ["CVE-2000-0001", "CVE-2000-0002"]

        # removing one of the CVEs
        flaw_bug["alias"] = ["CVE-2000-0001"]

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id == "CVE-2000-0001"

        # removing all CVEs
        flaw_bug["alias"] = []

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id is None

    def test_no_cve(self):
        """
        test that CVE-less flaw is correctly processed
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["alias"] = ["non-CVE-alias"]

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id is None

    def test_major_incident_flag_order(self):
        """
        test reproducer for OSIDB-416 where the erroneous condition logic led to unsetting
        is_major_incident boolean when following flag was not setting it to True
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["flags"] = [
            {
                "name": "requires_doc_text",
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

        fbc = FlawBugConvertor(
            flaw_bug,
            [],
            self.get_flaw_history(),
            None,
            [],
            [],
            {},
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.is_major_incident is True
