import uuid

import pytest
from django.utils import timezone

from collectors.bzimport.constants import BZ_DT_FMT
from collectors.bzimport.convertors import FlawConvertor, FlawSaver
from osidb.dmodels import Impact
from osidb.dmodels.affect import Affect, AffectCVSS
from osidb.dmodels.flaw.cvss import FlawCVSS
from osidb.dmodels.package_versions import Package, PackageVer
from osidb.dmodels.tracker import Tracker
from osidb.models import Flaw, FlawAcknowledgment, FlawComment, FlawReference
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawFactory,
    TrackerFactory,
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

    def get_acls_write(self):
        """
        minimal acls getter
        """
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]

    def get_flaw(self):
        """
        minimal flaw getter
        """
        return Flaw(
            cve_id="CVE-2000-1234",
            title="title",
            comment_zero="comment_zero",
            impact=Impact.CRITICAL,
            major_incident_state=Flaw.FlawMajorIncident.REQUESTED,
            requires_cve_description=Flaw.FlawRequiresCVEDescription.NOVALUE,
            nist_cvss_validation=Flaw.FlawNistCvssValidation.REJECTED,
            created_dt=timezone.now(),
            updated_dt=timezone.now(),
            acl_read=self.get_acls(),
            acl_write=self.get_acls_write(),
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

    def get_affects_cvss_scores(self, affect):
        """
        minimal affect cvss scores getter
        """
        return [
            AffectCVSS(
                affect=affect,
                vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                score=3.7,
                version=AffectCVSS.CVSSVersion.VERSION3,
                issuer=AffectCVSS.CVSSIssuer.REDHAT,
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

    def get_acknowledgments(self, flaw, from_upstream=False, name="Jane Doe"):
        """
        minimal acknowledgments getter
        """
        return [
            FlawAcknowledgment.objects.create_flawacknowledgment(
                flaw=flaw,
                name=name,
                affiliation="XYZ Widget Company",
                from_upstream=from_upstream,
                created_dt=timezone.now(),
                updated_dt=timezone.now(),
                acl_read=self.get_acls(),
                acl_write=self.get_acls(),
            )
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

    def get_cvss_scores(self, flaw):
        """
        minimal flaw cvss score getter
        """
        return [
            FlawCVSS(
                flaw=flaw,
                vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
                score=3.7,
                version=FlawCVSS.CVSSVersion.VERSION3,
                issuer=FlawCVSS.CVSSIssuer.REDHAT,
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
        acls_write = self.get_acls_write()
        flaw = self.get_flaw()
        affects = self.get_affects(flaw)

        FlawSaver(
            flaw,
            [affects, self.get_affects_cvss_scores(affects[0])],
            self.get_comments(flaw),
            self.get_acknowledgments(flaw),
            self.get_references(flaw),
            self.get_cvss_scores(flaw),
            self.get_package_versions(),
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()
        affect_cvss_score = AffectCVSS.objects.first()
        comment = FlawComment.objects.first()
        acknowledgment = FlawAcknowledgment.objects.first()
        reference = FlawReference.objects.first()
        cvss_score = FlawCVSS.objects.first()
        package = Package.objects.first()
        package_version = PackageVer.objects.first()

        assert flaw is not None
        assert flaw.cve_id == "CVE-2000-1234"
        assert flaw.title == "title"
        assert flaw.comment_zero == "comment_zero"
        assert flaw.impact == Impact.CRITICAL
        assert flaw.acl_read == acls
        assert flaw.acl_write == acls_write
        assert flaw.affects.first() == affect
        assert flaw.comments.first() == comment
        assert flaw.references.first() == reference
        assert flaw.cvss_scores.first() == cvss_score
        assert flaw.package_versions.first() == package
        assert flaw.major_incident_state == Flaw.FlawMajorIncident.REQUESTED
        assert flaw.requires_cve_description == Flaw.FlawRequiresCVEDescription.NOVALUE
        assert flaw.nist_cvss_validation == Flaw.FlawNistCvssValidation.REJECTED

        assert affect is not None
        assert affect.ps_module == "module"
        assert affect.ps_component == "component"
        assert affect.acl_read == acls
        assert affect.acl_write == acls
        assert affect.flaw == flaw
        assert affect.trackers.count() == 0
        assert affect.cvss_scores.first() == affect_cvss_score

        assert affect_cvss_score is not None
        assert (
            affect_cvss_score.vector == "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
        )
        assert affect_cvss_score.score == 3.7
        assert affect_cvss_score.version == AffectCVSS.CVSSVersion.VERSION3
        assert affect_cvss_score.issuer == AffectCVSS.CVSSIssuer.REDHAT
        assert affect_cvss_score.acl_read == acls
        assert affect_cvss_score.acl_write == acls
        assert affect_cvss_score.affect == affect

        assert comment is not None
        assert comment.external_system_id == "123"
        assert comment.text == "test comment"
        assert comment.acl_read == acls
        assert comment.acl_write == acls
        assert comment.flaw == flaw

        assert acknowledgment is not None
        assert acknowledgment.name == "Jane Doe"
        assert acknowledgment.affiliation == "XYZ Widget Company"
        assert acknowledgment.from_upstream is False
        assert acknowledgment.acl_read == acls
        assert acknowledgment.acl_write == acls
        assert acknowledgment.flaw == flaw

        assert reference is not None
        assert reference.url == "https://httpd.apache.org/link123"
        assert reference.type == "EXTERNAL"
        assert reference.description == ""
        assert reference.acl_read == acls
        assert reference.acl_write == acls
        assert reference.flaw == flaw

        assert cvss_score is not None
        assert cvss_score.vector == "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
        assert cvss_score.score == 3.7
        assert cvss_score.version == FlawCVSS.CVSSVersion.VERSION3
        assert cvss_score.issuer == FlawCVSS.CVSSIssuer.REDHAT
        assert cvss_score.acl_read == acls
        assert cvss_score.acl_write == acls
        assert cvss_score.flaw == flaw

        assert package is not None
        assert package.package == "package"
        assert package.flaw == flaw
        assert package.versions.count() == 1
        assert package.versions.first() == package_version

        assert package_version is not None
        assert package_version.version == "version"
        assert package_version.package == package

    def test_affect_removed(self):
        """
        test affect removal save
        """
        flaw = self.get_flaw()

        FlawSaver(
            flaw,
            [self.get_affects(flaw), []],
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
            [[], []],
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

    def test_affect_cvss_score_removed(self):
        """
        test affect cvss score removal save
        """
        flaw = self.get_flaw()
        affects = self.get_affects(flaw)

        FlawSaver(
            flaw,
            [affects, self.get_affects_cvss_scores(affects[0])],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()
        affect_cvss_score = AffectCVSS.objects.first()

        assert flaw is not None
        assert affect is not None
        assert affect_cvss_score is not None
        assert flaw.affects.count() == 1
        assert flaw.affects.first() == affect
        assert affect.cvss_scores.count() == 1
        assert affect.cvss_scores.first() == affect_cvss_score
        assert affect_cvss_score.affect == affect

        FlawSaver(
            flaw,
            [affects, []],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        affect = Affect.objects.first()
        affect_cvss_score = AffectCVSS.objects.first()

        assert flaw is not None
        assert affect is not None
        assert affect_cvss_score is None
        assert affect.cvss_scores.count() == 0

    def test_acknowledgment_removed(self):
        """
        test acknowledgment removal on save
        """
        flaw = flaw_orig = self.get_flaw()
        assert flaw_orig is not None

        FlawSaver(
            flaw,
            [[], []],
            [],
            self.get_acknowledgments(flaw, from_upstream=False),
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        assert flaw == flaw_orig
        assert Flaw.objects.count() == 1

        acknowledgment = acknowledgment_orig = FlawAcknowledgment.objects.first()
        assert FlawAcknowledgment.objects.count() == 1
        assert flaw.acknowledgments.count() == 1
        assert flaw.acknowledgments.first() == acknowledgment
        assert acknowledgment.flaw == flaw

        # Test that when only from_upstream is changed, the FlawAcknowledgment object is updated
        # in place.
        FlawSaver(
            flaw,
            [[], []],
            [],
            self.get_acknowledgments(flaw, from_upstream=True),
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        assert flaw == flaw_orig
        assert Flaw.objects.count() == 1

        acknowledgment = FlawAcknowledgment.objects.first()
        assert acknowledgment == acknowledgment_orig
        assert FlawAcknowledgment.objects.count() == 1
        assert flaw.acknowledgments.count() == 1
        assert flaw.acknowledgments.first() == acknowledgment
        assert acknowledgment.flaw == flaw

        # Test that when the acknowledgment is changed, the old one is deleted.
        FlawSaver(
            flaw,
            [[], []],
            [],
            self.get_acknowledgments(flaw, name="jaroslava kudrnova"),
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        assert flaw == flaw_orig
        assert Flaw.objects.count() == 1

        acknowledgment = FlawAcknowledgment.objects.first()
        assert acknowledgment.name == "jaroslava kudrnova"
        # This created a new instance
        assert acknowledgment != acknowledgment_orig
        # The old instance has been deleted
        assert FlawAcknowledgment.objects.count() == 1
        assert flaw.acknowledgments.count() == 1
        assert flaw.acknowledgments.first() == acknowledgment
        assert acknowledgment.flaw == flaw

        # Test that when the acknowledgment is removed, it is deleted.
        FlawSaver(
            flaw,
            [[], []],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        assert flaw == flaw_orig
        assert Flaw.objects.count() == 1

        assert not FlawAcknowledgment.objects.exists()
        assert flaw.acknowledgments.count() == 0

    def test_reference_removed(self):
        """
        test reference removal save
        """
        flaw = self.get_flaw()

        FlawSaver(
            flaw,
            [[], []],
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
            [[], []],
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

    def test_cvss_score_removed(self):
        """
        test cvss score removal save
        """
        flaw = self.get_flaw()

        FlawSaver(
            flaw,
            [[], []],
            [],
            [],
            [],
            self.get_cvss_scores(flaw),
            {},
        ).save()

        flaw = Flaw.objects.first()
        cvss = FlawCVSS.objects.first()

        assert flaw is not None
        assert cvss is not None
        assert flaw.cvss_scores.count() == 1
        assert flaw.cvss_scores.first() == cvss
        assert cvss.flaw == flaw

        FlawSaver(
            flaw,
            [[], []],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        cvss = FlawCVSS.objects.first()

        assert flaw is not None
        assert cvss is None
        assert flaw.cvss_scores.count() == 0

    def test_trackers_not_removed(self):
        """
        test that neither tracker is removed
        on flaw and affect save nor the link
        """
        flaw = self.get_flaw()
        affects = self.get_affects(flaw)

        FlawSaver(
            flaw,
            [affects, []],
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
        assert affect.trackers.count() == 0
        assert Tracker.objects.count() == 0

        # add the tracker to affect
        tracker = TrackerFactory.build()
        tracker.save(raise_validation_error=False)  # ignore validations
        tracker.affects.add(affect)

        affect = Affect.objects.first()
        tracker = Tracker.objects.first()
        assert affect.trackers.count() == 1
        assert affect.trackers.first() == tracker
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect

        FlawSaver(
            flaw,
            [affects, []],
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
        # neither the tracker should be removed
        # nor the affect-tracker link
        assert tracker is not None
        assert flaw.affects.count() == 1
        assert flaw.affects.first() == affect
        assert affect.flaw == flaw
        assert affect.trackers.count() == 1
        assert affect.trackers.first() == tracker
        assert tracker.affects.count() == 1
        assert tracker.affects.first() == affect

    def test_packageversions_removed(self):
        """
        test packageversions removal save
        """
        flaw = self.get_flaw()

        FlawSaver(
            flaw,
            [[], []],
            [],
            [],
            [],
            [],
            self.get_package_versions(),
        ).save()

        flaw = Flaw.objects.first()
        package = Package.objects.first()
        package_version = PackageVer.objects.first()

        assert flaw is not None
        assert package is not None
        assert package_version is not None
        assert flaw.package_versions.count() == 1
        assert flaw.package_versions.first() == package
        assert package.flaw == flaw
        assert package.versions.count() == 1
        assert package.versions.first() == package_version
        assert package_version.package == package

        FlawSaver(
            flaw,
            [[], []],
            [],
            [],
            [],
            [],
            {},
        ).save()

        flaw = Flaw.objects.first()
        package = Package.objects.first()
        package_version = PackageVer.objects.first()

        assert flaw is not None
        assert package is None
        assert package_version is None
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
            "component": "vulnerability",
            "creation_time": "2000-01-01T12:12:12Z",
            "depends_on": [],
            "description": "text",
            "fixed_in": None,
            "groups": [],
            "id": "123",
            "last_change_time": "2001-01-01T12:12:12Z",
            "status": "CLOSED",
            "resolution": "",
            "summary": "EMBARGOED TRIAGE CVE-2000-1234 foo: ACL bypass with Authorization: 0000 HTTP header",
            "cf_srtnotes": cls.get_flaw_srtnotes(),
        }

    @classmethod
    def get_flaw_srtnotes(cls):
        """
        minimal Bugzilla flaw SRT notes getter
        """
        return """
        {
            "affects": [],
            "external_ids": ["CVE-2000-1234"],
            "impact": "moderate",
            "public": "2000-04-04T00:00:00Z",
            "reported": "2000-01-01T00:00:00Z",
            "source": "customer"
        }
        """

    @pytest.mark.parametrize(
        "hightouch,hightouch_lite,result",
        [
            # valid pairs
            ("", "", Flaw.FlawMajorIncident.NOVALUE),
            ("?", "?", Flaw.FlawMajorIncident.REQUESTED),
            ("?", "", Flaw.FlawMajorIncident.REQUESTED),
            ("", "?", Flaw.FlawMajorIncident.REQUESTED),
            ("-", "-", Flaw.FlawMajorIncident.REJECTED),
            ("-", "", Flaw.FlawMajorIncident.REJECTED),
            ("", "-", Flaw.FlawMajorIncident.REJECTED),
            ("+", "", Flaw.FlawMajorIncident.APPROVED),
            ("+", "-", Flaw.FlawMajorIncident.APPROVED),
            ("", "+", Flaw.FlawMajorIncident.CISA_APPROVED),
            ("-", "+", Flaw.FlawMajorIncident.CISA_APPROVED),
            # invalid pairs
            ("+", "+", Flaw.FlawMajorIncident.INVALID),
            ("+", "?", Flaw.FlawMajorIncident.INVALID),
            ("?", "+", Flaw.FlawMajorIncident.INVALID),
            ("-", "?", Flaw.FlawMajorIncident.INVALID),
            ("?", "-", Flaw.FlawMajorIncident.INVALID),
            # flags may not be present
            ("+", None, Flaw.FlawMajorIncident.APPROVED),
            (None, "+", Flaw.FlawMajorIncident.CISA_APPROVED),
            (None, None, Flaw.FlawMajorIncident.NOVALUE),
        ],
    )
    def test_flags_major_incident(self, hightouch, hightouch_lite, result):
        """
        Tests that hightouch and hightouch-lite flags from Bugzilla are correctly
        converted into major_incident_state in OSIDB.
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["flags"] = []

        if hightouch is not None:
            flag = {
                "name": "hightouch",
                "status": hightouch,
                "creation_date": timezone.now(),
            }
            flaw_bug["flags"].append(flag)

        if hightouch_lite is not None:
            flag = {
                "name": "hightouch-lite",
                "status": hightouch_lite,
                "creation_date": timezone.now(),
            }
            flaw_bug["flags"].append(flag)

        fc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        flaws = fc.bug2flaws()
        assert not fc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        flaw = Flaw.objects.first()
        assert flaw is not None
        assert flaw.major_incident_state == result

    @pytest.mark.parametrize(
        "requires_doc_text,setter,requires_cve_description",
        [
            ("", "", Flaw.FlawRequiresCVEDescription.NOVALUE),
            ("-", "", Flaw.FlawRequiresCVEDescription.REJECTED),
            ("?", "", Flaw.FlawRequiresCVEDescription.REQUESTED),
            ("+", "joe@redhat.com", Flaw.FlawRequiresCVEDescription.APPROVED),
            ("+", "bugzilla@redhat.com", Flaw.FlawRequiresCVEDescription.REQUESTED),
            # a flag may not be present
            (None, "", Flaw.FlawRequiresCVEDescription.NOVALUE),
        ],
    )
    def test_flag_requires_cve_description(
        self, requires_doc_text, setter, requires_cve_description
    ):
        """
        Tests that requires_doc_text flag from Bugzilla is correctly
        converted into requires_cve_description in OSIDB.
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["flags"] = []

        if requires_doc_text is not None:
            flag = {
                "name": "requires_doc_text",
                "status": requires_doc_text,
                "setter": setter,
            }
            flaw_bug["flags"].append(flag)

        fc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        flaws = fc.bug2flaws()
        assert not fc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        flaw = Flaw.objects.first()
        assert flaw is not None
        assert flaw.requires_cve_description == requires_cve_description

    @pytest.mark.parametrize(
        "flag_value,mapped_result",
        [
            (None, Flaw.FlawNistCvssValidation.NOVALUE),
            ("", Flaw.FlawNistCvssValidation.NOVALUE),
            ("?", Flaw.FlawNistCvssValidation.REQUESTED),
            ("+", Flaw.FlawNistCvssValidation.APPROVED),
            ("-", Flaw.FlawNistCvssValidation.REJECTED),
        ],
    )
    def test_flag_nist_cvss_validation(self, flag_value, mapped_result):
        """
        Tests that the nist_cvss_validation flag from Bugzilla is correctly
        converted into nist_cvss_validation field in OSIDB.
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["flags"] = []
        if flag_value is not None:
            flag = {"name": "nist_cvss_validation", "status": flag_value}
            flaw_bug["flags"].append(flag)

        fc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        flaws = fc.bug2flaws()
        assert not fc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        flaw = Flaw.objects.first()
        assert flaw is not None
        assert flaw.nist_cvss_validation == mapped_result

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
                    "resolution": "delegated"
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
            None,
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
            None,
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
                    "resolution": "delegated"
                },{
                    "ps_module": "rhel-6.1",
                    "ps_component": "firefox",
                    "affectedness": "affected",
                    "resolution": "delegated"
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
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
                "name": "requires_doc_text",
                "status": "+",
                "setter": "bob@redhat.com",
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
            None,
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.major_incident_state == Flaw.FlawMajorIncident.REQUESTED
        assert flaw.requires_cve_description == Flaw.FlawRequiresCVEDescription.APPROVED
        assert flaw.nist_cvss_validation == Flaw.FlawNistCvssValidation.REJECTED

    @pytest.mark.enable_signals
    def test_attributes_removed_in_bugzilla(self):
        """
        test that the attribute removals in Bugzilla
        will correctly result in empty values

        OSIDB-910 reproducer (old non-empty values were not emptied)
        """
        flaw = FlawFactory(
            bz_id="123",
            embargoed=False,
            reported_dt="2000-01-01T01:01:01Z",
            cve_description="test",
            unembargo_dt="2000-01-01T01:01:01Z",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component=["ssh"],
        )
        AffectCVSSFactory(
            affect=affect,
            version=AffectCVSS.CVSSVersion.VERSION3,
            vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
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
                    "resolution": "delegated"
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
        assert flaw.reported_dt is None
        assert flaw.cve_description == ""
        assert flaw.unembargo_dt is None

        assert Affect.objects.count() == 1
        affect = Affect.objects.first()
        assert not affect.cvss_scores.all()

    def test_component_meta_attr(self):
        """
        Test that the "component" BZ field is saved as "bz_component" in Flaw.meta_attr
        """
        flaw_bug = self.get_flaw_bug()
        fbc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        [flaw] = fbc.bug2flaws()
        flaw.save()
        flaw = Flaw.objects.first()

        assert "bz_component" in flaw.meta_attr
        assert flaw.meta_attr["bz_component"] == flaw_bug["component"]

    def test_external_ids_meta_attr(self):
        """
        Test saving "external_ids" in Flaw.meta_attr
        """
        flaw_bug = self.get_flaw_bug()

        fbc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        [flaw] = fbc.bug2flaws()
        flaw.save()
        flaw = Flaw.objects.first()

        assert "external_ids" in flaw.meta_attr
        assert flaw.cve_id in flaw.meta_attr["external_ids"]

    def test_summary_meta_attr(self):
        """
        Test that the title (summary in BZ) is saved as-is in Flaw.meta_attr

        Since the actual Flaw title goes through some parsing / transformations,
        we need to at least provide the summary as-is from BZ in case the
        parsing was subpar, this way clients can have the full context.
        """
        # TODO: make self.get_flaw_bug() into a fixture
        flaw_bug = self.get_flaw_bug()
        fbc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        [flaw] = fbc.bug2flaws()
        flaw.save()
        flaw = Flaw.objects.first()

        assert "bz_summary" in flaw.meta_attr
        assert flaw.meta_attr["bz_summary"] == flaw_bug["summary"]

    def test_fixed_in_meta_attr(self):
        """
        Test that fixed_in bz field is saved as-is in Flaw.meta_attr

        The model structure of Package and PackageVer doesn't store the
        separator between package and version used in bugzilla fixed_in.
        Therefore, we need to store fixed_in as-is for bbsync's reference
        to keep the original separators.
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["fixed_in"] = "foobar 1.2, foobaz-1.2"
        fbc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        [flaw] = fbc.bug2flaws()
        flaw.save()
        flaw = Flaw.objects.first()

        assert "fixed_in" in flaw.meta_attr
        assert flaw.meta_attr["fixed_in"] == flaw_bug["fixed_in"]

    @pytest.mark.parametrize(
        "bz_groups,ldap_read_group,ldap_write_group",
        [
            ([], "public_read_groups", "public_write_groups"),
            (["security"], "embargoed_read_groups", "embargoed_write_groups"),
            (["redhat"], "internal_read_groups", "internal_write_groups"),
        ],
    )
    def test_groups(self, request, bz_groups, ldap_read_group, ldap_write_group):
        """
        Test that "groups" field is correctly matched to LDAP groups.
        """
        ldap_read_group = request.getfixturevalue(ldap_read_group)
        ldap_write_group = request.getfixturevalue(ldap_write_group)

        flaw_bug = self.get_flaw_bug()
        flaw_bug["groups"] = bz_groups
        fbc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        [flaw] = fbc.bug2flaws()
        flaw.save()
        flaw = Flaw.objects.first()

        assert flaw.acl_read == ldap_read_group
        assert flaw.acl_write == ldap_write_group

    @pytest.mark.parametrize(
        "hightouch,hightouch_lite,creation_date",
        [
            (None, None, None),  # no flags
            ("-", "-", None),  # rejected
            ("+", "", "2021-09-15T08:19:46Z"),  # approved
        ],
    )
    def test_major_incident_start_dt(self, hightouch, hightouch_lite, creation_date):
        """
        Test that if the appropriate flags are set to be a MI, then the MI start
        date is properly set from the flag creation date.
        """
        flaw_bug = self.get_flaw_bug()
        flaw_bug["flags"] = []

        if hightouch is not None and hightouch_lite is not None:
            # hightouch flag
            flag = {
                "name": "hightouch",
                "status": hightouch,
                "creation_date": creation_date,
            }
            flaw_bug["flags"].append(flag)
            flag = {
                "name": "hightouch-lite",
                "status": hightouch_lite,
                "creation_date": creation_date,
            }
            flaw_bug["flags"].append(flag)

        fc = FlawConvertor(
            flaw_bug,
            [],
            None,
        )
        [flaw] = fc.bug2flaws()
        flaw.save()

        flaw = Flaw.objects.first()
        assert flaw is not None
        if creation_date is not None:
            expected_start_dt = timezone.datetime.strptime(creation_date, BZ_DT_FMT)
        else:
            expected_start_dt = None
        assert flaw.major_incident_start_dt == expected_start_dt

    def test_comments(self):
        """
        test comment conversion and test that once bzimport is deleted,
        bifurcated comment history doesn't get synced from bz to osidb
        """
        flaw_bug = self.get_flaw_bug()
        assert FlawComment.objects.count() == 0

        # Simulate initial bzimport
        bz_comment_1 = {
            "text": "test comment",
            "count": 1,
            "id": 123,
            "is_private": False,
            "creator": "test@redhat.com",
            "creation_time": "2010-07-12T11:27:47Z",
        }

        fbc = FlawConvertor(
            flaw_bug,
            [
                bz_comment_1,
            ],
            None,
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        assert Flaw.objects.count() == 0
        assert FlawComment.objects.count() == 0
        flaw.save()
        assert FlawComment.objects.count() == 1

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id == "CVE-2000-1234"

        comment = FlawComment.objects.get(external_system_id=123)

        assert comment.external_system_id == "123"
        assert comment.text == "test comment"
        assert comment.synced_to_bz is True
        assert comment.flaw == flaw

        # Creating a new comment in OSIDB
        FlawComment(
            order=2,
            external_system_id="",
            text="test comment 2",
            synced_to_bz=False,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
            flaw=flaw,
        ).save()
        assert FlawComment.objects.count() == 2

        # bzimport will not do anything with the comment, it exists only in OSIDB
        fbc = FlawConvertor(
            flaw_bug,
            [
                bz_comment_1,
            ],
            None,
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        assert Flaw.objects.count() == 1
        assert FlawComment.objects.count() == 2
        flaw.save()
        assert Flaw.objects.count() == 1
        assert FlawComment.objects.count() == 2
        flaw = Flaw.objects.first()

        comment = FlawComment.objects.get(external_system_id=123)

        assert comment.external_system_id == "123"
        assert comment.text == "test comment"
        assert comment.synced_to_bz is True
        assert comment.flaw == flaw

        comment = FlawComment.objects.get(order=2)

        assert comment.external_system_id == ""
        assert comment.text == "test comment 2"
        assert comment.synced_to_bz is False  # not synced TO nor FROM bz
        assert comment.flaw == flaw

        comment_2_uuid = comment.uuid

        # Simulating bbsync and bzimport obtaining an external_system_id for the
        # second comment created in OSIDB and synced to BZ
        bz_comment_2 = {
            "text": "test comment 2",
            "count": 2,
            "id": 124,
            "is_private": False,
            "creator": "test@redhat.com",
            "creation_time": "2010-07-12T11:27:48Z",
        }

        # bzimport will not do anything with the first comment and will update
        # the second comment in place
        fbc = FlawConvertor(
            flaw_bug,
            [
                bz_comment_1,
                bz_comment_2,
            ],
            None,
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        assert Flaw.objects.count() == 1
        assert FlawComment.objects.count() == 2
        flaw.save()
        assert Flaw.objects.count() == 1
        assert FlawComment.objects.count() == 2
        flaw = Flaw.objects.first()

        comment = FlawComment.objects.get(external_system_id=123)

        assert comment.external_system_id == "123"
        assert comment.text == "test comment"
        assert comment.synced_to_bz is True
        assert comment.flaw == flaw

        comment = FlawComment.objects.get(order=2)

        assert comment.external_system_id == "124"  # updated
        assert comment.text == "test comment 2"
        assert comment.synced_to_bz is True  # switched by bzimport
        assert comment.flaw == flaw
        assert comment.uuid == comment_2_uuid

        # Creating another new comment in OSIDB
        FlawComment(
            order=3,
            external_system_id="",
            text="test comment 3",
            synced_to_bz=False,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
            flaw=flaw,
        ).save()
        assert FlawComment.objects.count() == 3

        # Simulating new BZ comments when bzimport was already turned off,
        # bifurcating comment history
        bz_comment_3 = {
            "text": "test comment bz 3",
            "count": 3,
            "id": 125,
            "is_private": False,
            "creator": "test@redhat.com",
            "creation_time": "2010-07-12T11:27:49Z",
        }

        bz_comment_4 = {
            "text": "test comment bz 4",
            "count": 4,
            "id": 126,
            "is_private": False,
            "creator": "test@redhat.com",
            "creation_time": "2010-07-12T11:27:50Z",
        }

        # bzimport will not do anything with the existing OSIDB comments and will skip
        # BZ comments since the bifurcation point
        fbc = FlawConvertor(
            flaw_bug,
            [
                bz_comment_1,
                bz_comment_2,
                bz_comment_3,
                bz_comment_4,
            ],
            None,
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        assert Flaw.objects.count() == 1
        assert FlawComment.objects.count() == 3
        flaw.save()
        assert Flaw.objects.count() == 1
        assert FlawComment.objects.count() == 3
        flaw = Flaw.objects.first()

        comment = FlawComment.objects.get(external_system_id=123)

        assert comment.external_system_id == "123"
        assert comment.text == "test comment"
        assert comment.synced_to_bz is True
        assert comment.flaw == flaw

        comment = FlawComment.objects.get(order=2)

        assert comment.external_system_id == "124"
        assert comment.text == "test comment 2"
        assert comment.synced_to_bz is True
        assert comment.flaw == flaw
        assert comment.uuid == comment_2_uuid

        comment = FlawComment.objects.get(order=3)

        assert comment.external_system_id == ""
        assert comment.text == "test comment 3"
        assert comment.synced_to_bz is False
        assert comment.flaw == flaw


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
            None,
        )
        flaws = fbc.bug2flaws()
        assert not fbc.errors
        assert len(flaws) == 1
        flaw = flaws[0]
        flaw.save()

    def test_find_package_multi(self):
        self.init_models("django 3.2.5, django 3.1.13")

        package = Package.objects.all()
        assert package.count() == 1

        package_version = package.first()
        assert package_version.package == "django"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 2

        versions = [c5v.version for c5v in cvev5versions]
        assert "3.1.13" in versions
        assert "3.2.5" in versions

    def test_find_package_single(self):
        self.init_models("django 3.2.5")

        package = Package.objects.all()
        assert package.count() == 1

        package_version = package.first()
        assert package_version.package == "django"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 1

        versions = [c5v.version for c5v in cvev5versions]
        assert "3.2.5" in versions

    def test_find_package_single_dash(self):
        self.init_models("django-3.2.5")

        package = Package.objects.all()
        assert package.count() == 1

        package_version = package.first()
        assert package_version.package == "django"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 1

        versions = [c5v.version for c5v in cvev5versions]
        assert "3.2.5" in versions

    def test_find_package_multi_dash(self):
        self.init_models("python-pillow-2.8.0")

        package = Package.objects.all()
        assert package.count() == 1

        package_version = package.first()
        assert package_version.package == "python-pillow"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 1

        versions = [c5v.version for c5v in cvev5versions]
        assert "2.8.0" in versions

    def test_find_package_no_value(self):
        self.init_models("")

        assert not Package.objects.count()

    def test_find_package_null_value(self):
        self.init_models(None)

        assert not Package.objects.count()

    def test_find_package_with_golang(self):
        self.init_models("github.com/gogo/protobuf 1.3.2")

        package = Package.objects.all()
        assert package.count() == 1

        package_version = package.first()
        assert package_version.package == "github.com/gogo/protobuf"

        cvev5versions = package_version.versions.all()
        assert cvev5versions.count() == 1

        versions = [c5v.version for c5v in cvev5versions]
        assert "1.3.2" in versions

    def test_parse_fixed_in_multi_package(self):
        self.init_models("a 1, b 1")

        package = Package.objects.all()
        assert package.count() == 2

        package_version1 = package.filter(package="a").first()
        package_version2 = package.filter(package="b").first()
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

        package = Package.objects.all()
        assert package.count() == 2

        package_version1 = package.filter(package="a").first()
        package_version2 = package.filter(package="b").first()
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
