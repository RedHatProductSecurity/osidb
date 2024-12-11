import uuid

import pytest
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from apps.bbsync.constants import RHSCL_BTS_KEY
from apps.bbsync.models import BugzillaComponent, BugzillaProduct
from apps.workflows.workflow import WorkflowModel
from collectors.bzimport.constants import FLAW_PLACEHOLDER_KEYWORD
from osidb.constants import BZ_ID_SENTINEL
from osidb.core import generate_acls
from osidb.models import (
    Affect,
    Flaw,
    FlawAcknowledgment,
    FlawComment,
    FlawCVSS,
    FlawReference,
    FlawSource,
    Impact,
    Tracker,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCommentFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    SpecialConsiderationPackageFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


def tzdatetime(*args):
    return timezone.datetime(*args, tzinfo=timezone.get_current_timezone())


class TestFlaw:
    @property
    def acl_read(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]

    @property
    def acl_write(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]

    @pytest.mark.enable_signals
    def test_create(self, datetime_with_tz, good_cve_id):
        """test raw flaw creation"""
        meta_attr = {}
        meta_attr["test"] = 1
        vuln_1 = FlawFactory.build(
            cve_id=good_cve_id,
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            title="title",
            comment_zero="comment_zero",
            impact=Impact.CRITICAL,
            source=FlawSource.APPLE,
            statement="statement",
            major_incident_state=Flaw.FlawMajorIncident.APPROVED,
            nist_cvss_validation=Flaw.FlawNistCvssValidation.REQUESTED,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            requires_cve_description=Flaw.FlawRequiresCVEDescription.APPROVED,
            # META
            meta_attr=meta_attr,
        )
        vuln_1.save(raise_validation_error=False)

        nist_cvss = FlawCVSSFactory(
            flaw=vuln_1,
            version=FlawCVSS.CVSSVersion.VERSION3,
            issuer=FlawCVSS.CVSSIssuer.NIST,
        )
        rh_cvss = FlawCVSSFactory(
            flaw=vuln_1,
            version=FlawCVSS.CVSSVersion.VERSION3,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
        )
        all_cvss_scores = vuln_1.cvss_scores.all()
        assert len(all_cvss_scores) == 2
        assert nist_cvss in all_cvss_scores
        assert rh_cvss in all_cvss_scores

        FlawReferenceFactory(
            flaw=vuln_1,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )
        assert vuln_1.major_incident_state == Flaw.FlawMajorIncident.APPROVED
        assert vuln_1.nist_cvss_validation == Flaw.FlawNistCvssValidation.REQUESTED

        affect1 = AffectFactory(flaw=vuln_1)
        all_trackers = affect1.trackers.all()
        assert vuln_1.save() is None
        assert len(all_trackers) == 0

        affect2 = Affect.objects.create_affect(
            vuln_1,
            "fakemodule",
            "fake_component",
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
            impact=Impact.NOVALUE,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        affect2.save()
        ps_module = PsModuleFactory(bts_name="bugzilla", name="fakemodule")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker1 = TrackerFactory(
            affects=(affect2,),
            embargoed=affect2.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            status="random_status",
            resolution="random_resolution",
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker1.save()
        all_affects = vuln_1.affects.all()
        assert len(all_affects) == 2
        assert affect1 in all_affects
        assert affect2 in all_affects

        comment1 = FlawCommentFactory(flaw=vuln_1, order=0)
        comment2 = FlawComment(
            flaw=vuln_1,
            external_system_id="9999991",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            text="some comment text",
            order=1,
        )
        comment2.save()
        all_comments = vuln_1.comments.all()
        assert len(all_comments) == 2
        assert comment1 in all_comments
        assert comment2 in all_comments

        reference1 = FlawReferenceFactory(flaw=vuln_1)
        reference2 = FlawReference.objects.create_flawreference(
            vuln_1,
            "https://www.openwall.com/link123",
            type=FlawReference.FlawReferenceType.EXTERNAL,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        reference2.save()
        all_references = vuln_1.references.all()
        assert len(all_references) == 3
        assert reference1 in all_references
        assert reference2 in all_references

        acknowledgment1 = FlawAcknowledgmentFactory(flaw=vuln_1)
        acknowledgment2 = FlawAcknowledgment.objects.create_flawacknowledgment(
            vuln_1,
            "name",
            "company",
            from_upstream=True,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        acknowledgment2.save()
        all_acknowledgments = vuln_1.acknowledgments.all()
        assert len(all_acknowledgments) == 2
        assert acknowledgment1 in all_acknowledgments
        assert acknowledgment2 in all_acknowledgments

        vuln_2 = Flaw(
            cve_id="CVE-2000-12345",
            cwe_id="CWE-1",
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            title="title",
            comment_zero="comment_zero",
            impact=Impact.CRITICAL,
            components=["curl"],
            source=FlawSource.INTERNET,
            statement="statement",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        assert vuln_2.validate() is None

        # assert vuln_1.delete()
        # assert vuln_2.delete()

    def test_create_flaw_method(self):
        Flaw.objects.all().delete()
        flaw1 = Flaw.objects.create_flaw(
            bz_id="12345",
            cwe_id="CWE-1",
            title="first",
            unembargo_dt=tzdatetime(2000, 1, 1),
            comment_zero="comment_zero",
            impact=Impact.LOW,
            components=["curl"],
            source=FlawSource.INTERNET,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            reported_dt=timezone.now(),
        )
        flaw1.save()
        AffectFactory(flaw=flaw1)

        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().meta_attr["bz_id"] == "12345"
        Flaw.objects.create_flaw(
            bz_id="12345",
            title="second",
            comment_zero="comment_zero",
            impact=Impact.LOW,
            source=FlawSource.INTERNET,
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            reported_dt=timezone.now(),
        ).save()
        # no new flaw should be created
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().title == "second"

    def test_multi_affect_tracker(self):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect1 = AffectFactory(
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module=ps_module.name,
            ps_component="component",
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory.create(
            affects=(affect1,),
            embargoed=affect1.flaw.is_embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert len(tracker.affects.all()) == 1
        affect2 = AffectFactory(
            flaw__embargoed=False,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_module=ps_module.name,
            ps_component="component",
        )
        Tracker.objects.create_tracker(
            affect2,
            tracker.external_system_id,
            tracker.type,
            ps_update_stream=ps_update_stream.name,
        )
        assert len(tracker.affects.all()) == 2

    def test_trackers_filed(self):
        flaw = FlawFactory()
        ps_module = PsModuleFactory(bts_name="bugzilla")
        fix_affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            flaw=flaw,
        )
        assert not flaw.trackers_filed
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=(fix_affect,),
            embargoed=flaw.is_embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert flaw.trackers_filed
        AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw=flaw,
        )
        assert not flaw.trackers_filed

    def test_delegated_affects(self):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        delegated_affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            flaw__embargoed=False,
            # prevent LOW special handling
            impact=Impact.MODERATE,
        )
        # no trackers = affected
        assert delegated_affect.delegated_resolution == Affect.AffectFix.AFFECTED

        # Migrated/duplicate trackers should be ignored
        # regardless whether there are other trackers or not
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=(delegated_affect,),
            ps_update_stream=ps_update_stream1.name,
            status="closed",
            resolution="migrated",
            embargoed=delegated_affect.flaw.is_embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=(delegated_affect,),
            ps_update_stream=ps_update_stream2.name,
            status="closed",
            resolution="duplicate",
            embargoed=delegated_affect.flaw.is_embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert delegated_affect.delegated_resolution == Affect.AffectFix.AFFECTED

        ps_update_stream3 = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=(delegated_affect,),
            ps_update_stream=ps_update_stream3.name,
            status="done",
            resolution="notabug",
            embargoed=delegated_affect.flaw.is_embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        # if the only tracker is notaffected, delegated_resolution is notaffected
        assert delegated_affect.delegated_resolution == Affect.AffectFix.NOTAFFECTED

        ps_update_stream4 = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=(delegated_affect,),
            ps_update_stream=ps_update_stream4.name,
            status="closed",
            resolution="deferred",
            embargoed=delegated_affect.flaw.is_embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        # DEFER is ranked higher than NOTAFFECTED
        assert delegated_affect.delegated_resolution == Affect.AffectFix.DEFER

        ps_update_stream5 = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=(delegated_affect,),
            ps_update_stream=ps_update_stream5.name,
            status="done",
            resolution="eol",
            embargoed=delegated_affect.flaw.is_embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        # OOSS is ranked higher than DEFER
        assert delegated_affect.delegated_resolution == Affect.AffectFix.OOSS

        ps_update_stream6 = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=(delegated_affect,),
            ps_update_stream=ps_update_stream6.name,
            status="won't fix",
            embargoed=delegated_affect.flaw.is_embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        # WONTFIX is ranked higher than OOSS
        assert delegated_affect.delegated_resolution == Affect.AffectFix.WONTFIX

        # AFFECTED should have higher precedence than any other resolution
        ps_update_stream7 = PsUpdateStreamFactory(ps_module=ps_module)
        t = TrackerFactory(
            affects=(delegated_affect,),
            ps_update_stream=ps_update_stream7.name,
            status="foo",
            resolution="bar",
            embargoed=delegated_affect.flaw.is_embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert t.fix_state == Affect.AffectFix.AFFECTED
        assert delegated_affect.delegated_resolution == Affect.AffectFix.AFFECTED

        new_affect = AffectFactory(affectedness=Affect.AffectAffectedness.NEW)
        assert new_affect.delegated_resolution is None
        undelegated_affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DEFER,
        )
        assert undelegated_affect.delegated_resolution is None

        undelegated_affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.WONTFIX,
        )
        assert undelegated_affect.delegated_resolution is None

    def test_delegated_resolution_low(self):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            flaw__embargoed=False,
            impact=Impact.LOW,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        TrackerFactory(
            affects=[affect],
            ps_update_stream=ps_update_stream.name,
            status="won't fix",
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert affect.delegated_resolution == Affect.AffectFix.DEFER

    def test_tracker_fix_state(self):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            flaw__embargoed=False,
        )
        ps_update_stream1 = PsUpdateStreamFactory(ps_module=ps_module)
        wontfix_tracker = TrackerFactory(
            affects=[affect],
            ps_update_stream=ps_update_stream1.name,
            status="won't fix",
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert wontfix_tracker.fix_state == Affect.AffectFix.WONTFIX
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module)
        random_tracker = TrackerFactory(
            ps_update_stream=ps_update_stream2.name,
            status="foo",
            resolution="bar",
            affects=[affect],
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert random_tracker.fix_state == Affect.AffectFix.AFFECTED
        ps_update_stream3 = PsUpdateStreamFactory(ps_module=ps_module)
        empty_tracker = TrackerFactory(
            ps_update_stream=ps_update_stream3.name,
            status="foo",
            resolution="",
            affects=[affect],
            type=Tracker.TrackerType.BUGZILLA,
        )
        assert empty_tracker.fix_state == Affect.AffectFix.AFFECTED

    def test_objects_create_flaw(self, datetime_with_tz, good_cve_id):
        """test creating with manager .create_flow()"""
        meta_attr = {}
        meta_attr["test"] = 1
        vuln_1 = Flaw(
            cve_id=good_cve_id,
            cwe_id="CWE-1",
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            title="title",
            comment_zero="comment_zero",
            impact=Impact.CRITICAL,
            components=["curl"],
            source=FlawSource.INTERNET,
            statement="statement",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            # META
            meta_attr=meta_attr,
        )

        assert vuln_1.save() is None

    def test_flaw_queryset(self, datetime_with_tz):
        """retrieve flaw manager queryset"""
        flaw = Flaw(
            cve_id="CVE-2000-12345",
            cwe_id="CWE-1",
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            title="title",
            comment_zero="comment_zero",
            impact=Impact.CRITICAL,
            components=["curl"],
            source=FlawSource.INTERNET,
            statement="statement",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        assert Flaw.objects.get_queryset().count() == 0
        flaw.save()
        assert Flaw.objects.get_queryset().count() == 1

    def test_fts_search(self, datetime_with_tz, good_cve_id):
        """check fts search is working"""
        flaw = Flaw(
            cve_id=good_cve_id,
            cwe_id="CWE-1",
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            title="title",
            comment_zero="comment_zero",
            impact=Impact.CRITICAL,
            components=["curl"],
            source=FlawSource.INTERNET,
            statement="statement",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )

        assert not Flaw.objects.fts_search("title")

        flaw.save()

        assert Flaw.objects.fts_search("title")

    @pytest.mark.enable_signals
    def test_local_updated_dt(self):
        ps_module = PsModuleFactory(bts_name="bugzilla")
        f = FlawFactory(embargoed=False)
        assert f.local_updated_dt > f.updated_dt

        with freeze_time(tzdatetime(2077, 1, 1, 13, 39, 0)):
            a = AffectFactory(
                flaw=f,
                created_dt=timezone.now(),
                ps_module=ps_module.name,
                ps_component="component",
                affectedness=Affect.AffectAffectedness.AFFECTED,
            )
            assert f.local_updated_dt == timezone.now()

        with freeze_time(tzdatetime(3333, 3, 3, 3, 3, 3)):
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            _ = TrackerFactory(
                affects=(a,),
                created_dt=timezone.now(),
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.BUGZILLA,
                embargoed=f.embargoed,
            )
            f.refresh_from_db()
            assert f.local_updated_dt == timezone.now()

    @pytest.mark.enable_signals
    def test_local_updated_dt_inverse_relationship(self):
        f = FlawFactory(embargoed=False)
        ps_module = PsModuleFactory(bts_name="bugzilla")
        a = AffectFactory(
            flaw=f,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        t = TrackerFactory(
            affects=(a,),
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
            embargoed=f.embargoed,
        )
        og_local_updated_dt = f.local_updated_dt
        # try updating trackers from the affect (inverse relationship)
        # it should not fail and update the timestamp correctly
        a.trackers.remove(t)
        assert Flaw.objects.first().local_updated_dt > og_local_updated_dt

    @pytest.mark.parametrize(
        "ps_module_name,ps_product_name",
        [
            ("rhel-8", "Red Hat Enterprise Linux"),
            ("jbcs-1", "Red Hat JBoss Core Services"),
            ("", None),
        ],
    )
    def test_ps_product_affect(self, ps_module_name, ps_product_name):
        """
        Test that the ps_product property in Affect correctly maps to the
        one given by the ps_module of the Affect.
        """
        if ps_module_name:
            PsModuleFactory(
                name=ps_module_name, ps_product=PsProductFactory(name=ps_product_name)
            )
            affect = AffectFactory(ps_module=ps_module_name)
        else:
            affect = AffectFactory()
        assert affect.ps_product == ps_product_name

    def test_cve_id_nullified(self):
        """Test an empty string CVE is converted into a null value."""
        f = FlawFactory()
        f.cve_id = ""
        f.save()
        assert f.cve_id is None

    @pytest.mark.enable_signals
    def test_major_incident_start_dt(self):
        """
        Test that the signal to set the MI start date is correctly called.
        """
        f = FlawFactory(
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        # Initially it is not a MI so it should have no date
        assert f.major_incident_start_dt is None
        with freeze_time(tzdatetime(2077, 1, 1, 13, 39, 0)):
            f.major_incident_state = Flaw.FlawMajorIncident.APPROVED
            f.save()
            assert f.major_incident_start_dt == timezone.now()


class TestImpact:
    @pytest.mark.parametrize(
        "first,second",
        [
            ("", "LOW"),
            ("", "MODERATE"),
            ("", "IMPORTANT"),
            ("", "CRITICAL"),
            ("LOW", "MODERATE"),
            ("LOW", "IMPORTANT"),
            ("LOW", "CRITICAL"),
            ("MODERATE", "IMPORTANT"),
            ("MODERATE", "CRITICAL"),
            ("IMPORTANT", "CRITICAL"),
        ],
    )
    def test_less(self, first, second):
        """
        test that the first is less than the second
        """
        assert Impact(first) < Impact(second)

    @pytest.mark.parametrize(
        "maximum,impacts",
        [
            ("LOW", ["", "", "LOW", "LOW"]),
            ("MODERATE", ["MODERATE"]),
            ("IMPORTANT", ["LOW", "MODERATE", "IMPORTANT"]),
            ("CRITICAL", ["IMPORTANT", "CRITICAL", ""]),
        ],
    )
    def test_max(self, maximum, impacts):
        """
        test that the maximum is correctly identified
        """
        assert Impact(maximum) == max(Impact(impact) for impact in impacts)


class TestFlawValidators:
    def test_validate_good(self):
        """test that no validator complains about valid flaw"""
        # do not raise here
        # validation is run on save
        FlawFactory()

    @pytest.mark.parametrize("cve_id", ["test", "CVE-2020-1234-b", "no CVE-2020-1234"])
    def test_validate_cve_id(self, cve_id):
        """test cve_id validator"""
        with pytest.raises(ValidationError) as e:
            FlawFactory(cve_id=cve_id)
        assert "Malformed CVE or alias." in str(e)

    # TODO CWE validation is temporarily off
    # @pytest.mark.parametrize("cwe_id", ["test", "CWE-", "no CWE-2020"])
    # def test_validate_cwe_id(self, cwe_id):
    #     """test cwe_id validator"""
    #     with pytest.raises(ValidationError) as e:
    #         FlawFactory(cwe_id=cwe_id)
    #     assert "Invalid CWE." in str(e)

    @freeze_time(tzdatetime(2021, 11, 23))
    def test_validate_reported_dt(self):
        """test reported_dt validation - no future date"""
        future_dt = tzdatetime(2021, 11, 27)

        with pytest.raises(ValidationError) as e:
            FlawFactory(reported_dt=future_dt)
        assert (
            f"'{future_dt}' is an Invalid datetime, cannot be set in the future."
            in str(e)
        )

        with freeze_time(future_dt):
            FlawFactory(reported_dt=future_dt)
            # no exception should be raised now

    @pytest.mark.parametrize("attr_name", ["impact"])
    def test_validate_choice(self, attr_name):
        """test choice validation"""
        with pytest.raises(ValidationError) as e:
            FlawFactory(**{attr_name: "half of FISH"})
        assert "Value 'half of FISH' is not a valid choice." in str(e)

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "rh_cvss,nist_cvss,should_alert",
        [
            # difference is higher or equal to 1
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # score 8.1
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",  # score 7.1
                True,
            ),
            # difference is lower than 1
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",  # score 7.1
                "CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",  # score 7.2
                False,
            ),
        ],
    )
    def test_validate_rh_nist_cvss_score_diff(self, nist_cvss, rh_cvss, should_alert):
        """
        Tests that the difference between the RH and NIST CVSSv3 score is not >= 1.0.
        """
        flaw = FlawFactory(
            # fields below are set to avoid any alerts
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )

        for issuer, vector, comment in [
            (FlawCVSS.CVSSIssuer.REDHAT, rh_cvss, "comment"),
            (FlawCVSS.CVSSIssuer.NIST, nist_cvss, ""),
        ]:
            FlawCVSSFactory(
                flaw=flaw,
                version=FlawCVSS.CVSSVersion.VERSION3,
                issuer=issuer,
                vector=vector,
                comment="",
            )

        AffectFactory(flaw=flaw)
        flaw.save()

        if should_alert:
            assert flaw.valid_alerts.count() == 1
            assert flaw.valid_alerts.first().name == "rh_nist_cvss_score_diff"
        else:
            assert not flaw.valid_alerts.exists()

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "rh_cvss,nist_cvss,should_alert",
        [
            # Note: not possible to test None vs Low since the lowest possible
            # CVSS score of low severity is 1.6 which violates the RH vs NIST
            # score diff constraint
            # Low vs Medium
            (
                "CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",  # score 3.8
                "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L",  # score 4.0
                True,
            ),
            # Medium vs Low
            (
                "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L",  # score 4.0
                "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",  # score 3.9
                True,
            ),
            # Medium vs High
            (
                "CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H",  # score 6.9
                "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:H",  # score 7.6
                True,
            ),
            # High vs Critical
            (
                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",  # score 8.8
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H",  # score 9.4
                True,
            ),
            # everything below is without alerts
            # None vs None
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",  # score 0.0
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",  # score 0.0
                False,
            ),
            # Low vs Low (right boundary)
            (
                "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",  # score 3.9
                "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H",  # score 3.8
                False,
            ),
            # Medium vs Medium (left boundary)
            (
                "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L",  # score 4.0
                "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:H",  # score 4.9
                False,
            ),
            # High vs High
            (
                "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:H",  # score 7.6
                "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:H",  # score 7.5
                False,
            ),
            # High vs Critical
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H",  # score 9.4
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",  # score 10.0
                False,
            ),
        ],
    )
    def test_validate_rh_nist_cvss_severity_diff(
        self, nist_cvss, rh_cvss, should_alert
    ):
        """
        Tests that the NIST and RH CVSSv3 score are not of a different severity.
        """
        flaw = FlawFactory(
            # fields below are set to avoid any alerts
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )

        for issuer, vector, comment in [
            (FlawCVSS.CVSSIssuer.REDHAT, rh_cvss, "comment"),
            (FlawCVSS.CVSSIssuer.NIST, nist_cvss, ""),
        ]:
            FlawCVSSFactory(
                flaw=flaw,
                version=FlawCVSS.CVSSVersion.VERSION3,
                issuer=issuer,
                vector=vector,
                comment="",
            )

        AffectFactory(flaw=flaw)
        flaw.save()

        if should_alert:
            assert flaw.valid_alerts.count() == 1
            assert flaw.valid_alerts.first().name == "rh_nist_cvss_severity_diff"
        else:
            assert not flaw.valid_alerts.exists()

    @pytest.mark.parametrize(
        "name,business_unit,is_rh_product",
        [
            ("rhel-7", "Core RHEL", True),
            ("epel-6", "Community", False),
            ("rhel-br-9", "Core RHEL", False),
        ],
    )
    def test_validate_rh_products_in_affects(self, name, business_unit, is_rh_product):
        """
        Tests that a flaw with RH products in its affects list returns True,
        False otherwise.
        """
        flaw = FlawFactory()
        PsModuleFactory(
            name=name, ps_product=PsProductFactory(business_unit=business_unit)
        )
        AffectFactory(flaw=flaw, ps_module=name)
        flaw.save()

        if is_rh_product:
            assert flaw._validate_rh_products_in_affects()
        else:
            assert not flaw._validate_rh_products_in_affects()

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "nist_cvss,rh_cvss,ps_module,rh_cvss_comment,rescore,should_alert",
        [
            # should alert, there is no RH CVSSv3 comment or NIST rescore request
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",  # score 7.1
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # score 8.1
                "rhel-7",
                "",
                Flaw.FlawNistCvssValidation.NOVALUE,
                True,
            ),
            # everything below is without alerts
            # no NIST CVSSv3 score
            (
                "",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # score 8.1
                "rhel-7",
                "",
                Flaw.FlawNistCvssValidation.NOVALUE,
                False,
            ),
            # NIST CVSSv3 is lower than 7.0
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H",  # score 6.8
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # score 8.1
                "rhel-7",
                "",
                Flaw.FlawNistCvssValidation.NOVALUE,
                False,
            ),
            # NIST CVSSv3 and RH CVSSv3 are not significantly different
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",  # score 7.1
                "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",  # score 7.0
                "rhel-7",
                "",
                Flaw.FlawNistCvssValidation.NOVALUE,
                False,
            ),
            # no RH product
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",  # score 7.1
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # score 8.1
                "rhel-br-9",
                "",
                Flaw.FlawNistCvssValidation.NOVALUE,
                False,
            ),
            # solved via RH CVSSv3 comment
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",  # score 7.1
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # score 8.1
                "rhel-7",
                "explanation comment",
                Flaw.FlawNistCvssValidation.NOVALUE,
                False,
            ),
            # solved via NIST rescore request
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",  # score 7.1
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # score 8.1
                "rhel-7",
                "",
                Flaw.FlawNistCvssValidation.REQUESTED,
                False,
            ),
        ],
    )
    def test_validate_nist_rh_cvss_feedback_loop(
        self,
        nist_cvss,
        rh_cvss,
        ps_module,
        rh_cvss_comment,
        rescore,
        should_alert,
    ):
        """
        Tests whether RH should send a request to NIST on flaw CVSS rescore.
        """
        flaw = FlawFactory.build(
            nist_cvss_validation=rescore,
            # fields below are set to avoid any alerts
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            cve_description="cve_description",
            statement="statement",
        )
        flaw.save(raise_validation_error=False)

        if nist_cvss:
            FlawCVSSFactory(
                flaw=flaw,
                version=FlawCVSS.CVSSVersion.VERSION3,
                issuer=FlawCVSS.CVSSIssuer.NIST,
                vector=nist_cvss,
                comment="",
            )
        FlawCVSSFactory(
            flaw=flaw,
            version=FlawCVSS.CVSSVersion.VERSION3,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            vector=rh_cvss,
            comment=rh_cvss_comment,
        )
        PsModuleFactory(
            name=ps_module, ps_product=PsProductFactory(business_unit="Core RHEL")
        )
        AffectFactory(flaw=flaw, ps_module=ps_module)
        flaw.save()

        # there may be an extra alert if the difference between the RH and NIST
        # CVSSv3 score is >= 1.0, regardless of whether a test should fail or not
        if should_alert:
            assert flaw.valid_alerts.filter(
                name="request_nist_cvss_validation"
            ).exists()
            assert (
                flaw.valid_alerts.count() == 1
                if not flaw.valid_alerts.filter(name="rh_nist_cvss_score_diff").exists()
                else 2
            )
        else:
            assert not flaw.valid_alerts.filter(
                name="request_nist_cvss_validation"
            ).exists()
            assert (
                flaw.valid_alerts.count() == 0
                if not flaw.valid_alerts.filter(name="rh_nist_cvss_score_diff").exists()
                else 1
            )

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "rescore,nist_cvss,rh_cvss,should_raise",
        [
            (Flaw.FlawNistCvssValidation.REQUESTED, False, True, True),
            (Flaw.FlawNistCvssValidation.REJECTED, False, False, True),
            (Flaw.FlawNistCvssValidation.APPROVED, True, True, False),
            (Flaw.FlawNistCvssValidation.APPROVED, False, True, False),
            (Flaw.FlawNistCvssValidation.NOVALUE, False, True, False),
        ],
    )
    def test_validate_cvss_scores_and_nist_cvss_validation(
        self, rescore, nist_cvss, rh_cvss, should_raise
    ):
        """
        Tests that if nist_cvss_validation is set, then both NIST CVSSv3 and RH CVSSv3
        scores need to be present.
        """
        flaw = FlawFactory.build(
            nist_cvss_validation=rescore,
            # fields below are set to avoid any alerts
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        flaw.save(raise_validation_error=False)

        if nist_cvss:
            FlawCVSSFactory(
                flaw=flaw,
                version=FlawCVSS.CVSSVersion.VERSION3,
                issuer=FlawCVSS.CVSSIssuer.NIST,
            )
        if rh_cvss:
            FlawCVSSFactory(
                flaw=flaw,
                version=FlawCVSS.CVSSVersion.VERSION3,
                issuer=FlawCVSS.CVSSIssuer.REDHAT,
            )
        AffectFactory(flaw=flaw)

        if should_raise:
            error_msg = (
                "nist_cvss_validation can only be set if a flaw has both "
                "NIST CVSSv3 and RH CVSSv3 scores assigned."
            )
            with pytest.raises(ValidationError, match=error_msg):
                flaw.save()
        else:
            assert flaw.save() is None

    @pytest.mark.parametrize(
        "impact,cve_description,should_alert,alert",
        [
            (Impact.MODERATE, "", True, "impact_without_cve_description"),
            (Impact.IMPORTANT, "", True, "impact_without_cve_description"),
            (Impact.CRITICAL, "", True, "impact_without_cve_description"),
            # everything below is correct
            (Impact.LOW, "", False, None),
            (Impact.LOW, "cve_description", False, None),
            (Impact.MODERATE, "cve_description", False, None),
            (Impact.IMPORTANT, "cve_description", False, None),
            (Impact.CRITICAL, "cve_description", False, None),
        ],
    )
    def test_validate_impact_and_cve_description(
        self, impact, cve_description, should_alert, alert
    ):
        """
        Tests that if impact has MODERATE, IMPORTANT or CRITICAL value set,
        then cve_description must not be missing.
        """
        flaw = FlawFactory(
            impact=impact,
            cve_description=cve_description,
            # fields below are set to avoid any alerts
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        FlawCVSSFactory(
            flaw=flaw,
            version=FlawCVSS.CVSSVersion.VERSION3,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
        )
        AffectFactory(flaw=flaw)
        flaw.save()

        if should_alert:
            assert flaw.valid_alerts.count() == 1
            assert flaw.valid_alerts.filter(name=alert).exists()
        else:
            assert not flaw.valid_alerts.exists()

    @pytest.mark.parametrize(
        "requires_cve_description,cve_description,should_raise",
        [
            (Flaw.FlawRequiresCVEDescription.REQUESTED, "", True),
            (Flaw.FlawRequiresCVEDescription.APPROVED, "", True),
            # everything below is correct
            (Flaw.FlawRequiresCVEDescription.NOVALUE, "cve_description", False),
            (Flaw.FlawRequiresCVEDescription.NOVALUE, "", False),
            (Flaw.FlawRequiresCVEDescription.REJECTED, "cve_description", False),
            (Flaw.FlawRequiresCVEDescription.REJECTED, "", False),
            (Flaw.FlawRequiresCVEDescription.REQUESTED, "cve_description", False),
            (Flaw.FlawRequiresCVEDescription.APPROVED, "cve_description", False),
        ],
    )
    def test_validate_cve_description_and_requires_cve_description(
        self, requires_cve_description, cve_description, should_raise
    ):
        """
        Tests that if cve_description is missing, then requires_cve_description must not have
        REQUESTED or APPROVED value set.
        """
        flaw = FlawFactory.build(
            cve_description=cve_description,
            requires_cve_description=requires_cve_description,
            # fields below are set to avoid any alerts
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            impact=Impact.LOW,
        )
        flaw.save(raise_validation_error=False)
        AffectFactory(flaw=flaw)

        if should_raise:
            error_msg = f"requires_cve_description cannot be {requires_cve_description} if cve_description is missing."
            with pytest.raises(ValidationError, match=error_msg):
                flaw.save()
        else:
            assert flaw.save() is None

    @pytest.mark.parametrize(
        "old_requires_cve_description,requires_cve_description,should_raise",
        [
            (
                Flaw.FlawRequiresCVEDescription.REQUESTED,
                Flaw.FlawRequiresCVEDescription.APPROVED,
                False,
            ),
            (
                Flaw.FlawRequiresCVEDescription.APPROVED,
                Flaw.FlawRequiresCVEDescription.REQUESTED,
                False,
            ),
            (
                Flaw.FlawRequiresCVEDescription.NOVALUE,
                Flaw.FlawRequiresCVEDescription.REQUESTED,
                False,
            ),
            (
                Flaw.FlawRequiresCVEDescription.REQUESTED,
                Flaw.FlawRequiresCVEDescription.NOVALUE,
                True,
            ),
            (
                Flaw.FlawRequiresCVEDescription.APPROVED,
                Flaw.FlawRequiresCVEDescription.NOVALUE,
                True,
            ),
        ],
    )
    def test_validate_requires_cve_description(
        self, old_requires_cve_description, requires_cve_description, should_raise
    ):
        """
        Tests that if requires_cve_description was already set to something other than NOVALUE
        it cannot be set to NOVALUE.
        """
        flaw = FlawFactory.build(
            requires_cve_description=old_requires_cve_description,
            # fields below are set to avoid any alerts
            cve_description="cve_description",
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            impact=Impact.LOW,
        )
        flaw.save(raise_validation_error=False)

        flaw.requires_cve_description = requires_cve_description

        if should_raise:
            error_msg = "requires_cve_description cannot be unset if it was previously set to something other than NOVALUE"
            with pytest.raises(ValidationError, match=error_msg):
                flaw.save()
        else:
            assert flaw.save() is None

    def test_no_source(self):
        """
        test that flaw cannot have an empty source
        """
        with pytest.raises(ValidationError, match="Source value is required"):
            FlawFactory(source=None)

    @pytest.mark.parametrize(
        "source",
        [FlawSource.INTERNET, FlawSource.TWITTER],
    )
    def test_embargoed_public_source_invalid(self, source):
        with pytest.raises(ValidationError) as e:
            FlawFactory(embargoed=True, source=source)
        assert "Flaw is embargoed but contains public source" in str(e)

    def test_embargoed_public_source_invalid_exception_suppressed(self):
        """
        execute the previous validation in same context as in the previous test case however
        this time suppress the exception raising and check that an alert is stored instead
        """
        flaw = FlawFactory(embargoed=True)
        flaw.source = FlawSource.INTERNET
        flaw.save(raise_validation_error=False)
        assert flaw.valid_alerts.filter(name="_validate_embargoed_source").exists()

    @pytest.mark.parametrize(
        "source",
        [FlawSource.APPLE, FlawSource.GOOGLE, FlawSource.MOZILLA, FlawSource.GENTOO],
    )
    def test_embargoed_public_source_valid(self, source):
        assert Flaw.objects.count() == 0
        FlawFactory(embargoed=True, source=source)
        assert Flaw.objects.count() == 1

    @pytest.mark.parametrize(
        "source",
        [FlawSource.GENTOO, FlawSource.UBUNTU],
    )
    def test_embargoed_both_source_valid(self, source):
        assert Flaw.objects.count() == 0
        flaw = FlawFactory(embargoed=True, source=source)
        assert Flaw.objects.count() == 1
        assert flaw.valid_alerts.filter(name="embargoed_source_public").exists()

    @pytest.mark.parametrize(
        "bz_id,ps_module,should_alert",
        [
            (BZ_ID_SENTINEL, "rhel-6.8.z", True),
            (BZ_ID_SENTINEL - 1, "rhel-6.8.z", True),
            (BZ_ID_SENTINEL, "rhel-6", False),
            (BZ_ID_SENTINEL - 1, "rhel-6", False),
            (BZ_ID_SENTINEL + 1, "rhel-6", False),
        ],
    )
    def test_validate_affect_ps_module_alerts(self, bz_id, ps_module, should_alert):
        PsModuleFactory(name="rhel-6")
        flaw = FlawFactory(meta_attr={"bz_id": bz_id})
        affect = AffectFactory(flaw=flaw, ps_module=ps_module)
        if should_alert:
            assert affect.valid_alerts.filter(name="old_flaw_affect_ps_module").exists()
        else:
            assert not affect.valid_alerts.exists()

    @pytest.mark.parametrize(
        "bz_id,ps_module,should_raise",
        [
            (BZ_ID_SENTINEL, "rhel-6.8.z", False),
            (BZ_ID_SENTINEL - 1, "rhel-6.8.z", False),
            (BZ_ID_SENTINEL + 1, "rhel-6.8.z", True),
            (BZ_ID_SENTINEL + 1, "rhel-6", False),
            (BZ_ID_SENTINEL - 1, "rhel-6", False),
            (BZ_ID_SENTINEL, "rhel-6", False),
        ],
    )
    def test_validate_affect_ps_module_errors(self, bz_id, ps_module, should_raise):
        PsModuleFactory(name="rhel-6")
        flaw = FlawFactory(meta_attr={"bz_id": bz_id})
        if should_raise:
            with pytest.raises(ValidationError) as e:
                AffectFactory(flaw=flaw, ps_module=ps_module)
            assert f"{ps_module} is not a valid ps_module" in str(e)
        else:
            affect = AffectFactory(flaw=flaw, ps_module=ps_module)
            assert affect

    def test_validate_reported_date_empty(self):
        """
        test that the ValidationError is raised when the flaw has an empty reported_dt
        """
        with pytest.raises(ValidationError) as e:
            FlawFactory(reported_dt=None)
        assert "Flaw has an empty reported_dt" in str(e)

    def test_validate_reported_date_non_empty(self):
        """
        test that the ValidationError is not raised when the flaw the reported_dt provided
        """
        # whenever we save the flaw which the factory does automatically the validations are run
        # and if there is an exception the test will fail so creating the flaw is enough to test it
        FlawFactory()

    @pytest.mark.parametrize(
        "embargoed,unembargo_date,error_str",
        [
            (False, None, "Public flaw has an empty unembargo_dt"),
            (False, tzdatetime(2022, 11, 22), "Public flaw has a future unembargo_dt"),
            (False, tzdatetime(2021, 11, 22), None),
            (True, None, None),
            (
                True,
                tzdatetime(2021, 11, 22),
                "Flaw still embargoed but unembargo date is in the past.",
            ),
        ],
    )
    @freeze_time(tzdatetime(2021, 11, 23))
    def test_validate_public_unembargo_date(self, embargoed, unembargo_date, error_str):
        if error_str:
            with pytest.raises(ValidationError) as e:
                FlawFactory(unembargo_dt=unembargo_date, embargoed=embargoed)
            assert error_str in str(e)
        else:
            assert FlawFactory(unembargo_dt=unembargo_date, embargoed=embargoed)

    @freeze_time(tzdatetime(2021, 11, 23))
    def test_validate_future_unembargo_date(self):
        """test that unembargo_dt is in future for embargoed flaws"""
        past_dt = tzdatetime(2021, 11, 18)
        future_dt = tzdatetime(2021, 11, 27)

        with pytest.raises(ValidationError) as e:
            FlawFactory(unembargo_dt=past_dt, embargoed=True)
        assert "Flaw still embargoed but unembargo date is in the past." in str(e)

        with freeze_time(future_dt):
            FlawFactory(unembargo_dt=future_dt, embargoed=True)
            # no exception should be raised now

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "rh_cvss,should_alert",
        [
            ("", True),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H", False),
        ],
    )
    def test_validate_cvss3(self, rh_cvss, should_alert):
        """
        Tests that an alert is raised when the CVSSv3 string is not present.
        """
        flaw = FlawFactory(
            # fields below are set to avoid any alerts
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        if rh_cvss:
            FlawCVSSFactory(
                flaw=flaw,
                version=FlawCVSS.CVSSVersion.VERSION3,
                issuer=FlawCVSS.CVSSIssuer.REDHAT,
                vector=rh_cvss,
                comment="",
            )
        AffectFactory(flaw=flaw)
        flaw.save()

        if should_alert:
            assert flaw.valid_alerts.count() == 1
            assert flaw.valid_alerts.filter(name="cvss3_missing").exists()
        else:
            assert not flaw.valid_alerts.exists()

    @pytest.mark.parametrize(
        "state,should_raise",
        [
            (Flaw.FlawMajorIncident.NOVALUE, False),
            (Flaw.FlawMajorIncident.REQUESTED, False),
            (Flaw.FlawMajorIncident.REJECTED, False),
            (Flaw.FlawMajorIncident.APPROVED, False),
            (Flaw.FlawMajorIncident.CISA_APPROVED, False),
            (Flaw.FlawMajorIncident.MINOR, False),
            (Flaw.FlawMajorIncident.ZERO_DAY, False),
            (Flaw.FlawMajorIncident.INVALID, True),
        ],
    )
    def test_validate_major_incident_state(self, state, should_raise):
        """
        Tests that a flaw has a valid Major Incident state.
        """
        flaw = FlawFactory.build(
            major_incident_state=state,
            mitigation="mitigation",
            statement="statement",
            cve_description="cve_description",
            embargoed=False,
            requires_cve_description=Flaw.FlawRequiresCVEDescription.APPROVED,
        )
        flaw.save(raise_validation_error=False)

        AffectFactory(flaw=flaw)
        FlawReferenceFactory(
            flaw=flaw,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )

        if should_raise:
            error_msg = "A flaw does not have a valid Major Incident state."
            with pytest.raises(ValidationError, match=error_msg):
                flaw.save()
        else:
            assert flaw.save() is None

    @pytest.mark.parametrize(
        "mitigation,statement,cve_description,requires_cve_description,article,should_alert,alerts",
        [
            # all good
            (
                "mitigation text",
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.APPROVED,
                [
                    FlawReference.FlawReferenceType.ARTICLE,
                    "https://access.redhat.com/link123",
                ],
                False,
                None,
            ),
            # empty mitigation
            (
                "",
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.APPROVED,
                [
                    FlawReference.FlawReferenceType.ARTICLE,
                    "https://access.redhat.com/link123",
                ],
                True,
                ["mi_mitigation_missing"],
            ),
            # empty statement
            (
                "mitigation text",
                "",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.APPROVED,
                [
                    FlawReference.FlawReferenceType.ARTICLE,
                    "https://access.redhat.com/link123",
                ],
                True,
                ["mi_statement_missing"],
            ),
            # empty cve_description
            (
                "mitigation text",
                "statement text",
                "",
                Flaw.FlawRequiresCVEDescription.NOVALUE,
                [
                    FlawReference.FlawReferenceType.ARTICLE,
                    "https://access.redhat.com/link123",
                ],
                True,
                ["mi_cve_description_missing", "mi_cve_description_not_reviewed"],
            ),
            # cve_description review missing
            (
                "mitigation text",
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.NOVALUE,
                [
                    FlawReference.FlawReferenceType.ARTICLE,
                    "https://access.redhat.com/link123",
                ],
                True,
                ["mi_cve_description_not_reviewed"],
            ),
            # cve_description review requested
            (
                "mitigation text",
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.REQUESTED,
                [
                    FlawReference.FlawReferenceType.ARTICLE,
                    "https://access.redhat.com/link123",
                ],
                True,
                ["mi_cve_description_not_reviewed"],
            ),
            # cve_description review not required
            (
                "mitigation text",
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.REJECTED,
                [
                    FlawReference.FlawReferenceType.ARTICLE,
                    "https://access.redhat.com/link123",
                ],
                True,
                ["mi_cve_description_not_reviewed"],
            ),
            # article missing
            (
                "mitigation text",
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.APPROVED,
                [
                    FlawReference.FlawReferenceType.EXTERNAL,
                    "https://httpd.apache.org/link123",
                ],
                True,
                ["mi_article_missing"],
            ),
        ],
    )
    def test_validate_major_incident_fields(
        self,
        mitigation,
        statement,
        cve_description,
        requires_cve_description,
        article,
        should_alert,
        alerts,
    ):
        """
        Tests that a Flaw that is Major Incident complies with the following:
        * has a mitigation
        * has a statement
        * has a cve_description
        * requires_cve_description is APPROVED
        * has exactly one article
        """
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.APPROVED,
            mitigation=mitigation,
            statement=statement,
            cve_description=cve_description,
            requires_cve_description=requires_cve_description,
            embargoed=False,  # to simplify fields that a flaw requires
            impact=Impact.LOW,
        )
        FlawCVSSFactory(
            flaw=flaw,
            version=FlawCVSS.CVSSVersion.VERSION3,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
        )
        FlawReferenceFactory(flaw=flaw, type=article[0], url=article[1])
        AffectFactory(flaw=flaw)
        flaw.save()

        if should_alert:
            assert flaw.valid_alerts.count() == len(alerts)
            for alert in alerts:
                assert flaw.valid_alerts.filter(name=alert).exists()
        else:
            assert not flaw.valid_alerts.exists()

    @pytest.mark.parametrize(
        "statement,cve_description,requires_cve_description,should_alert,alerts",
        [
            # all good
            (
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.APPROVED,
                False,
                None,
            ),
            # empty statement
            (
                "",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.APPROVED,
                True,
                ["cisa_mi_statement_missing"],
            ),
            # empty cve_description
            (
                "statement text",
                "",
                Flaw.FlawRequiresCVEDescription.NOVALUE,
                True,
                [
                    "cisa_mi_cve_description_missing",
                    "cisa_mi_cve_description_not_reviewed",
                ],
            ),
            # cve_description review missing
            (
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.NOVALUE,
                True,
                ["cisa_mi_cve_description_not_reviewed"],
            ),
            # cve_description review requested
            (
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.REQUESTED,
                True,
                ["cisa_mi_cve_description_not_reviewed"],
            ),
            # cve_description review not required
            (
                "statement text",
                "cve_description text",
                Flaw.FlawRequiresCVEDescription.REJECTED,
                True,
                ["cisa_mi_cve_description_not_reviewed"],
            ),
        ],
    )
    def test_validate_cisa_major_incident_fields(
        self,
        statement,
        cve_description,
        requires_cve_description,
        should_alert,
        alerts,
    ):
        """
        Tests that a Flaw that is CISA Major Incident complies with the following:
        * has a statement
        * has a cve_description
        * requires_cve_description is APPROVED
        """
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.CISA_APPROVED,
            statement=statement,
            cve_description=cve_description,
            requires_cve_description=requires_cve_description,
            embargoed=False,  # to simplify fields that a flaw requires
            impact=Impact.LOW,
        )
        FlawCVSSFactory(
            flaw=flaw,
            version=FlawCVSS.CVSSVersion.VERSION3,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
        )
        AffectFactory(flaw=flaw)
        flaw.save()

        AffectFactory(flaw=flaw)
        flaw.save()

        if should_alert:
            assert flaw.valid_alerts.count() == len(alerts)
            for alert in alerts:
                assert flaw.valid_alerts.filter(name=alert).exists()
        else:
            assert not flaw.valid_alerts.exists()

    @freeze_time(tzdatetime(2021, 11, 23))
    def test_validate_embargoing_public_flaw(self):
        flaw = FlawFactory(embargoed=False)
        with pytest.raises(ValidationError, match="Embargoing a public flaw is futile"):
            flaw.title = "EMBARGOED foo bar baz"
            flaw.source = FlawSource.CUSTOMER
            flaw.acl_read = [
                uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_READ_GROUP])
            ]
            flaw.acl_write = [
                uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_WRITE_GROUP])
            ]
            flaw.unembargo_dt = tzdatetime(2022, 1, 1)
            flaw.save()

    @pytest.mark.parametrize(
        "cwe,should_raise",
        [
            ("", False),
            ("CWE-123", False),
            ("(CWE-123)", False),
            ("CWE-123->CWE-12324", False),
            ("CWE-123->(CWE-12324)", False),
            ("CWE-1+CWE-2", True),
            ("CWE-1->", True),
            ("cwe-1->CWE-2", True),
        ],
    )
    def test_validate_cwe_format(self, cwe, should_raise):
        """test that flaws only accepts a valid CWE ID"""
        if should_raise:
            with pytest.raises(ValidationError) as e:
                FlawFactory(cwe_id=cwe)
            assert "CWE IDs is not well formated." in str(e)
        else:
            assert FlawFactory(cwe_id=cwe)

    @pytest.mark.parametrize(
        "flaws_embargoed_status,embargoed_tracker,should_raise",
        [
            ([True], True, False),
            ([True], False, True),
            ([False], False, False),
            ([False], True, False),
            ([True, True], True, False),
            ([True, True], False, True),
            ([False, False], True, False),
            ([False, False], False, False),
            ([True, False], True, False),
            ([True, False], False, True),
        ],
    )
    def test_validate_tracker_flaw_accesses(
        self, flaws_embargoed_status, embargoed_tracker, should_raise
    ):
        """test Tracker model validator making sure flaws can't have a public tracker"""

        affects = []
        ps_module = PsModuleFactory(bts_name="bugzilla", name="module")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        for embargoed_flaw in flaws_embargoed_status:
            affects.append(
                AffectFactory(
                    flaw__embargoed=embargoed_flaw,
                    ps_module="module",
                    ps_component="component",
                )
            )

        if should_raise:
            with pytest.raises(
                ValidationError,
                match="Tracker is public but is associated with an embargoed flaw",
            ):
                TrackerFactory(
                    affects=affects,
                    embargoed=embargoed_tracker,
                    ps_update_stream=ps_update_stream.name,
                    type=Tracker.TrackerType.BUGZILLA,
                    status="CLOSED",
                )
        else:
            assert TrackerFactory(
                affects=affects,
                embargoed=embargoed_tracker,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.BUGZILLA,
                status="CLOSED",
            )

    def test_validate_no_placeholder(self):
        """
        test that placeholder flaw cannot be saved
        unless it is performed by the collector
        """
        flaw = FlawFactory.build(
            meta_attr={"keywords": '["' + FLAW_PLACEHOLDER_KEYWORD + '"]'}
        )

        with pytest.raises(ValidationError):
            flaw.save()

        # exclude collectors from restriction
        flaw.save(raise_validation_error=False)

    def test_validate_flaw_without_affect(self):
        """
        test that flaws without affect raises an error on editing,
        unless it is in a new workflow state
        """
        flaw1 = FlawFactory()
        AffectFactory(flaw=flaw1)
        assert flaw1.save() is None

        flaw2 = FlawFactory(workflow_state=WorkflowModel.WorkflowState.TRIAGE)
        with pytest.raises(ValidationError) as e:
            flaw2.save()
        assert "Flaw does not contain any affects." in str(e)

        # Flaws in the 'new' state can be edited without any affects, but
        # an alert is raised
        flaw3 = FlawFactory(workflow_state=WorkflowModel.WorkflowState.NEW)
        assert flaw3.save() is None
        assert flaw3.valid_alerts.filter(name="_validate_flaw_without_affect").exists()

    def test_no_component(self):
        """
        test that flaw cannot have an empty component
        """
        with pytest.raises(ValidationError, match="Components value is required"):
            FlawFactory(components=None)

    @pytest.mark.parametrize(
        "start_impact,new_impact,tracker_statuses,should_raise",
        [
            (Impact.LOW, Impact.MODERATE, ["Closed", "Open"], False),
            (Impact.CRITICAL, Impact.IMPORTANT, ["Closed", "Open"], False),
            (Impact.LOW, Impact.CRITICAL, ["Closed", "Open"], True),
            (Impact.CRITICAL, Impact.LOW, ["Closed", "Open"], True),
            (Impact.LOW, Impact.CRITICAL, ["Closed", "Closed"], False),
            (Impact.CRITICAL, Impact.LOW, ["Closed", "Closed"], False),
        ],
    )
    def test_validate_unsupported_impact_change(
        self, start_impact, new_impact, tracker_statuses, should_raise
    ):
        """
        test that flaws with CRITICAL / IMPORTANT impact cannot be changed
        to LOW / MODERATE while having open trackers and vice-versa
        """

        flaw = FlawFactory(
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            impact=start_impact,
            cve_description="cve_description",
        )
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.NEW,
        )
        for status in tracker_statuses:
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            TrackerFactory(
                embargoed=False,
                ps_update_stream=ps_update_stream.name,
                status=status,
                type=Tracker.TrackerType.BUGZILLA,
                affects=(affect,),
            )
        flaw.impact = new_impact
        flaw.save()

        assert should_raise == bool(
            flaw.valid_alerts.filter(name="unsupported_impact_change").exists()
        )

    @pytest.mark.parametrize(
        "was_major,is_major,tracker_statuses,should_raise",
        [
            (
                Flaw.FlawMajorIncident.NOVALUE,
                Flaw.FlawMajorIncident.NOVALUE,
                ["Closed", "Open"],
                False,
            ),
            (
                Flaw.FlawMajorIncident.APPROVED,
                Flaw.FlawMajorIncident.APPROVED,
                ["Closed", "Open"],
                False,
            ),
            (
                Flaw.FlawMajorIncident.NOVALUE,
                Flaw.FlawMajorIncident.APPROVED,
                ["Closed", "Open"],
                True,
            ),
            (
                Flaw.FlawMajorIncident.APPROVED,
                Flaw.FlawMajorIncident.NOVALUE,
                ["Closed", "Open"],
                True,
            ),
            (
                Flaw.FlawMajorIncident.NOVALUE,
                Flaw.FlawMajorIncident.APPROVED,
                ["Closed", "Closed"],
                False,
            ),
            (
                Flaw.FlawMajorIncident.APPROVED,
                Flaw.FlawMajorIncident.NOVALUE,
                ["Closed", "Closed"],
                False,
            ),
            (
                Flaw.FlawMajorIncident.ZERO_DAY,
                Flaw.FlawMajorIncident.NOVALUE,
                ["Closed", "Open"],
                True,
            ),
        ],
    )
    def test_validate_unsupported_major_incident_change(
        self, was_major, is_major, tracker_statuses, should_raise
    ):
        """test that major incident flaws cannot be changed to non-major while having open trackers"""

        flaw = FlawFactory.build(
            embargoed=False,
            major_incident_state=was_major,
            impact=Impact.LOW,
        )
        flaw.save(raise_validation_error=False)
        FlawReferenceFactory(
            flaw=flaw,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.NEW,
        )
        for status in tracker_statuses:
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            TrackerFactory(
                affects=(affect,),
                embargoed=False,
                ps_update_stream=ps_update_stream.name,
                status=status,
                type=Tracker.TrackerType.BUGZILLA,
            )
        flaw.major_incident_state = is_major
        flaw.save()

        assert should_raise == bool(
            flaw.valid_alerts.filter(name="unsupported_impact_change").exists()
        )

    @pytest.mark.parametrize(
        "is_rhscl,ps_component,alerts",
        [
            (True, "valid-component", []),
            (True, "source-to-image", []),
            (False, "valid-component", []),
            (False, "valid", []),
            (False, "invalid-component", []),
            (False, "source-to-image", []),
            (
                True,
                "valid",
                [
                    "flaw_affects_rhscl_collection_only",
                    "flaw_affects_rhscl_invalid_collection",
                ],
            ),
            (
                True,
                "invalid-component",
                ["flaw_affects_rhscl_invalid_collection"],
            ),
        ],
    )
    def test_flaw_affects_rhscl_invalid_collection(
        self, is_rhscl, ps_component, alerts
    ):
        VALID_COLLECTIONS = ["valid"]
        bts_key = "Not a RHSCL" if not is_rhscl else RHSCL_BTS_KEY
        module_obj = PsModuleFactory(name="test-module", bts_key=bts_key)
        PsUpdateStreamFactory(collections=VALID_COLLECTIONS, ps_module=module_obj)
        affect = AffectFactory(ps_module="test-module", ps_component=ps_component)
        if alerts:
            assert set(alerts).issubset(
                affect.valid_alerts.values_list("name", flat=True).distinct()
            )

    @pytest.mark.parametrize(
        "affectedness_old,affectedness_new,resolution_old,resolution_new,should_raise,should_alert",
        [
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                Affect.AffectResolution.WONTFIX,
                False,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                Affect.AffectResolution.DEFER,
                False,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                Affect.AffectResolution.FIX,
                True,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.FIX,
                Affect.AffectResolution.FIX,
                False,
                True,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.FIX,
                Affect.AffectResolution.DELEGATED,
                False,
                False,
            ),
        ],
    )
    def test_validate_historical_affectedness_resolution(
        self,
        affectedness_old,
        affectedness_new,
        resolution_old,
        resolution_new,
        should_raise,
        should_alert,
    ):
        """
        Test modifying an affect into a historical affectedness/resolution combination raises a
        validation error only when modifying one of those fields, and otherwise it throws an
        alert.
        """
        flaw = FlawFactory()
        affect = AffectFactory.build(
            affectedness=affectedness_old,
            resolution=resolution_old,
            impact=Impact.LOW,
            flaw=flaw,
        )
        affect.save(raise_validation_error=False)
        # Initially there shouldn't be any alerts
        assert not affect.valid_alerts.filter(
            name="flaw_historical_affect_status"
        ).exists()

        affect.affectedness = affectedness_new
        affect.resolution = resolution_new

        if should_raise:
            with pytest.raises(
                ValidationError,
                match=f"{affect.resolution} is not a valid resolution for {affect.affectedness}.",
            ):
                affect.save()
        else:
            assert affect.save() is None

        if should_alert:
            assert affect.valid_alerts.filter(
                name="flaw_historical_affect_status"
            ).exists()
        else:
            assert not affect.valid_alerts.filter(
                name="flaw_historical_affect_status"
            ).exists()

    @pytest.mark.parametrize(
        "affectedness,resolution,should_raise",
        [
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.NOVALUE, False),
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.DEFER, False),
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.WONTFIX, False),
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.OOSS, False),
            (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.FIX, True),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.WONTREPORT,
                True,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DEFER,
                False,
            ),
            (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.OOSS, False),
            (
                Affect.AffectAffectedness.NOTAFFECTED,
                Affect.AffectResolution.NOVALUE,
                False,
            ),
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.FIX, True),
            (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.NOVALUE, True),
            (
                Affect.AffectAffectedness.NOTAFFECTED,
                Affect.AffectResolution.DEFER,
                True,
            ),
        ],
    )
    def test_validate_flaw_affects_status_resolution(
        self, affectedness, resolution, should_raise
    ):
        """
        Test that error is raised if any affect have a
        invalid combination of affectedness and resolution
        """
        flaw = FlawFactory()
        affect = AffectFactory.build(
            flaw=flaw, affectedness=affectedness, resolution=resolution
        )

        # Service product and low/medium impact is needed to test pass WONTREPORT affects validations
        if resolution == Affect.AffectResolution.WONTREPORT:
            PsModuleFactory(
                name="other-services-test-module",
                ps_product=PsProductFactory(short_name="other-services"),
            )
            affect.ps_module = "other-services-test-module"
            affect.impact = Impact.LOW

        if should_raise:
            with pytest.raises(
                ValidationError,
                match=f"{affect.resolution} is not a valid resolution for {affect.affectedness}.",
            ):
                affect.save()
        else:
            assert affect.save() is None

    @pytest.mark.parametrize("entity", ["affect", "tracker"])
    @pytest.mark.parametrize(
        "affectedness,is_tracker_open,should_raise",
        [
            (
                Affect.AffectAffectedness.NOTAFFECTED,
                True,
                True,
            ),
            (
                Affect.AffectAffectedness.NEW,
                True,
                False,
            ),
            (
                Affect.AffectAffectedness.NOTAFFECTED,
                False,
                False,
            ),
        ],
    )
    def test_validate_notaffected_open_tracker(
        self, entity, affectedness, is_tracker_open, should_raise
    ):
        """
        Test that notaffected products with open trackers raises error.
        """
        status = "OPEN" if is_tracker_open else "CLOSED"
        flaw = FlawFactory(embargoed=False)
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=affectedness,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory.build(
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            status=status,
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker.save(raise_validation_error=False)
        tracker.affects.add(affect)
        error_message = (
            f"The tracker is associated with a {Affect.AffectAffectedness.NOTAFFECTED} affect: "
            f"{affect.ps_module}/{affect.ps_component} \\({affect.uuid}\\)"
        )
        match = (
            error_message
            if entity == "tracker"
            else f"{affect.uuid}.*is marked as.*but has open tracker"
        )
        entity = tracker if entity == "tracker" else affect
        if should_raise:
            with pytest.raises(
                ValidationError,
                match=match,
            ):
                entity.save()
        else:
            assert entity.save() is None

    @pytest.mark.parametrize("entity", ["affect", "tracker"])
    @pytest.mark.parametrize(
        "resolution,is_tracker_open,should_raise",
        [
            (
                Affect.AffectResolution.OOSS,
                True,
                True,
            ),
            (
                Affect.AffectResolution.DEFER,
                False,
                False,
            ),
            (
                Affect.AffectResolution.WONTFIX,
                False,
                False,
            ),
        ],
    )
    def test_validate_ooss_open_tracker(
        self, entity, resolution, is_tracker_open, should_raise
    ):
        """
        Test that ooss affects with open trackers raise errors.
        """
        status = "OPEN" if is_tracker_open else "CLOSED"
        flaw = FlawFactory(embargoed=False)
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=resolution,
        )

        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory.build(
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            status=status,
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker.save(raise_validation_error=False)
        tracker.affects.add(affect)
        error_message = (
            "The tracker is associated with an OOSS affect: "
            f"{affect.ps_module}/{affect.ps_component} \\({affect.uuid}\\)"
        )
        match = (
            error_message
            if entity == "tracker"
            else f"{affect.uuid}.*is marked as.*but has open tracker"
        )
        entity = tracker if entity == "tracker" else affect
        if should_raise:
            with pytest.raises(
                ValidationError,
                match=match,
            ):
                entity.save()
        else:
            assert entity.save() is None

    @pytest.mark.parametrize("entity", ["affect", "tracker"])
    @pytest.mark.parametrize(
        "resolution,is_tracker_open,should_raise",
        [
            (
                Affect.AffectResolution.DEFER,
                True,
                True,
            ),
            (
                Affect.AffectResolution.DEFER,
                False,
                False,
            ),
        ],
    )
    def test_validate_defer_open_tracker(
        self, entity, resolution, is_tracker_open, should_raise
    ):
        """
        Test that defer affects with open trackers raises error.
        """
        status = "OPEN" if is_tracker_open else "CLOSED"
        flaw = FlawFactory(embargoed=False)
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=resolution,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory.build(
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            status=status,
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker.save(raise_validation_error=False)
        tracker.affects.add(affect)
        error_message = (
            f"The tracker is associated with a {Affect.AffectResolution.DEFER} affect: "
            f"{affect.ps_module}/{affect.ps_component} \\({affect.uuid}\\)"
        )
        match = (
            error_message
            if entity == "tracker"
            else f"{affect.uuid}.*cannot have resolution {Affect.AffectResolution.DEFER} with open tracker"
        )
        entity = tracker if entity == "tracker" else affect
        if should_raise:
            with pytest.raises(
                ValidationError,
                match=match,
            ):
                entity.save()
        else:
            assert entity.save() is None

    @pytest.mark.parametrize("entity", ["affect", "tracker"])
    @pytest.mark.parametrize(
        "resolution,is_tracker_open,should_raise",
        [
            (
                Affect.AffectResolution.WONTFIX,
                True,
                True,
            ),
            (
                Affect.AffectResolution.WONTFIX,
                False,
                False,
            ),
        ],
    )
    def test_validate_wontfix_open_tracker(
        self, entity, resolution, is_tracker_open, should_raise
    ):
        """
        Test that wontfix affects with open trackers raises error.
        """
        status = "OPEN" if is_tracker_open else "CLOSED"
        flaw = FlawFactory(embargoed=False)
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=resolution,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory.build(
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            status=status,
            type=Tracker.TrackerType.BUGZILLA,
        )
        tracker.save(raise_validation_error=False)
        tracker.affects.add(affect)
        error_message = (
            f"The tracker is associated with a {Affect.AffectResolution.WONTFIX} affect: "
            f"{affect.ps_module}/{affect.ps_component} \\({affect.uuid}\\)"
        )
        match = (
            error_message
            if entity == "tracker"
            else f"{affect.uuid}.*is marked as WONTFIX but has open tracker"
        )
        entity = tracker if entity == "tracker" else affect
        if should_raise:
            with pytest.raises(
                ValidationError,
                match=match,
            ):
                entity.save()
        else:
            assert entity.save() is None

    def test_special_consideration_flaw(self):
        """
        Test that a flaw affecting special consideration packages(s) alerts when
        missing cve_description or statement
        """
        special_consideration_package = SpecialConsiderationPackageFactory()

        # Test that none of the models will raise alerts
        flaw1 = FlawFactory(
            statement="statement",
            cve_description="cve_description",
            requires_cve_description=Flaw.FlawRequiresCVEDescription.NOVALUE,
            impact=Impact.LOW,
        )
        AffectFactory(flaw=flaw1, ps_component=special_consideration_package.name)
        flaw1.save()

        assert not flaw1.valid_alerts.filter(
            name="special_consideration_flaw_missing_cve_description"
        ).exists()
        assert not flaw1.valid_alerts.filter(
            name="special_consideration_flaw_missing_statement"
        ).exists()

        # Test from Flaw validation perspective
        flaw1.cve_description = ""
        flaw1.statement = ""
        flaw1.save()

        assert flaw1.valid_alerts.filter(
            name="special_consideration_flaw_missing_cve_description"
        ).exists()
        assert flaw1.valid_alerts.filter(
            name="special_consideration_flaw_missing_statement"
        ).exists()

        # Test from Affect validation perspective
        flaw2 = FlawFactory(statement="", cve_description="", impact=Impact.LOW)
        AffectFactory(flaw=flaw2, ps_component=special_consideration_package.name)

        assert flaw2.valid_alerts.filter(
            name="special_consideration_flaw_missing_cve_description"
        ).exists()
        assert flaw2.valid_alerts.filter(
            name="special_consideration_flaw_missing_statement"
        ).exists()

    def test_validate_private_source_no_ack(
        self, private_source, public_source, both_source
    ):
        """
        Test that flaw with private source without acknowledgments raises alert
        """
        flaw1 = FlawFactory(source=private_source, embargoed=True)
        assert flaw1.valid_alerts.filter(name="private_source_no_ack").exists()
        flaw2 = FlawFactory(source=both_source, embargoed=True)
        assert flaw2.valid_alerts.filter(name="private_source_no_ack").exists()
        flaw3 = FlawFactory(source=public_source, embargoed=False)
        assert not flaw3.valid_alerts.filter(name="private_source_no_ack").exists()

    def test_validate_allowed_source(self):
        """
        Test that a disallowed (historical) flaw source raises an exception.
        """
        error_msg = r"The flaw has a disallowed \(historical\) source."
        with pytest.raises(ValidationError, match=error_msg):
            FlawFactory(source=FlawSource.ASF)

    def test_validate_article_link(self):
        """
        Tests that an article link not starting with https://access.redhat.com/
        raises an exception.
        """
        error_msg = (
            r"A flaw reference of the ARTICLE type does not begin with "
            r"https://access.redhat.com/."
        )
        with pytest.raises(ValidationError, match=error_msg):
            FlawReferenceFactory(
                type=FlawReference.FlawReferenceType.ARTICLE,
                url="https://httpd.apache.org/link123",
            )

    def test_validate_article_links_count_via_flawreferences(self):
        """
        Tests that creating a flaw reference of the article type for
        a flaw which already has a flaw reference of this type raises an alert.
        """
        flaw = FlawFactory()
        assert flaw.references.count() == 0

        FlawReferenceFactory(
            flaw=flaw,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )
        assert flaw.references.count() == 1

        error_msg = "A flaw has 2 article links, but only 1 is allowed."
        with pytest.raises(ValidationError, match=error_msg):
            FlawReferenceFactory(
                flaw=flaw,
                type=FlawReference.FlawReferenceType.ARTICLE,
                url="https://access.redhat.com/link456",
            )
        assert flaw.references.count() == 1

        reference = FlawReferenceFactory(
            flaw=flaw,
            type=FlawReference.FlawReferenceType.EXTERNAL,
            url="https://example.com/link456",
        )
        assert flaw.references.count() == 2

        with pytest.raises(ValidationError, match=error_msg):
            reference.url = "https://access.redhat.com/link456"
            reference.type = FlawReference.FlawReferenceType.ARTICLE
            reference.save()

    def test_validate_article_links_count_via_flaw(self):
        """
        Tests that creating a flaw with two flaw references of the article
        type raises an alert.
        """
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)

        FlawReferenceFactory(
            flaw=flaw,
            type=FlawReference.FlawReferenceType.ARTICLE,
            url="https://access.redhat.com/link123",
        )

        error_msg = "A flaw has 2 article links, but only 1 is allowed."
        with pytest.raises(ValidationError, match=error_msg):
            FlawReferenceFactory(
                flaw=flaw,
                type=FlawReference.FlawReferenceType.ARTICLE,
                url="https://access.redhat.com/link456",
            )

    def test_validate_public_source_no_ack(self, both_source):
        """
        Flaws with a public source can't have acknowledgments.
        """
        flaw = FlawFactory(source=both_source, embargoed=True)
        assert FlawAcknowledgment.objects.count() == 0
        flaw_ack = FlawAcknowledgmentFactory(flaw=flaw)
        assert FlawAcknowledgment.objects.count() == 1
        assert flaw_ack.valid_alerts.filter(name="public_source_no_ack").exists()

    @pytest.mark.parametrize(
        "is_same_product_name, should_raise",
        [
            (False, True),
            (True, False),
        ],
    )
    @pytest.mark.parametrize(
        "ps_component,is_rhscl",
        [
            ("test-module", False),
            ("rhscl-custom-collection-test-module", True),
        ],
    )
    def test_validate_unknown_component(
        self, is_same_product_name, should_raise, ps_component, is_rhscl
    ):
        """
        Test that a flaw affecting a component not tracked in Bugzilla raises
        alert if its not an override set in Product Definitions.
        """
        bts_key = "Not a RHSCL" if not is_rhscl else RHSCL_BTS_KEY
        ps_module = PsModuleFactory(
            name="test-ps-module",
            bts_name="bugzilla",
            bts_key=bts_key,
            default_component="",
        )
        PsUpdateStreamFactory(
            ps_module=ps_module, collections=["rhscl-custom-collection"]
        )
        product_name = (
            ps_module.bts_key if is_same_product_name else "other-test-module"
        )
        bz_product = BugzillaProduct(name=product_name)
        bz_product.save()
        BugzillaComponent(name="test-module", product=bz_product).save()
        affect = AffectFactory(ps_module="test-ps-module", ps_component=ps_component)

        assert should_raise == bool(
            affect.valid_alerts.filter(name="flaw_affects_unknown_component").exists()
        )

    def test_dry_run_validations(self, private_source, public_source):
        """
        Test that a model using AlertMixin can run validations without writing alerts
        """
        # regular save should create alerts
        flaw1 = FlawFactory.build(source=private_source, embargoed=False)
        flaw1.save()
        assert flaw1.valid_alerts.filter(name="private_source_no_ack").exists()

        # updates with no_alerts should not modify alert table
        flaw1.source = public_source
        flaw1.save(no_alerts=True)
        assert flaw1.valid_alerts.filter(name="private_source_no_ack").exists()

        # alert fixed
        flaw1.save()
        assert not flaw1.valid_alerts.filter(name="private_source_no_ack").exists()

        # flaw creation without alerts
        flaw2 = FlawFactory.build(source=private_source, embargoed=False)
        flaw2.save(no_alerts=True)
        assert not flaw2.valid_alerts.filter(name="private_source_no_ack").exists()
