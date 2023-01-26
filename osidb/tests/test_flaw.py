import uuid

import pytest
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from collectors.bzimport.constants import FLAW_PLACEHOLDER_KEYWORD
from osidb.constants import BZ_ID_SENTINEL
from osidb.core import generate_acls
from osidb.models import (
    Affect,
    Flaw,
    FlawComment,
    FlawImpact,
    FlawMeta,
    FlawResolution,
    FlawSource,
    FlawType,
    Tracker,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawCommentFactory,
    FlawFactory,
    FlawMetaFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


def tzdatetime(*args):
    return timezone.datetime(*args, tzinfo=timezone.get_current_timezone())


class TestFlaw:
    def test_create(self, datetime_with_tz, good_cve_id):
        """test raw flaw creation"""

        acls = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]
        meta_attr = {}
        meta_attr["test"] = 1
        vuln_1 = FlawFactory.build(
            cve_id=good_cve_id,
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            type=FlawType.VULNERABILITY,
            title="title",
            description="description",
            impact=FlawImpact.CRITICAL,
            statement="statement",
            resolution=FlawResolution.NOVALUE,
            is_major_incident=True,
            acl_read=acls,
            acl_write=acls,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            # META
            meta_attr=meta_attr,
        )
        vuln_1.save(raise_validation_error=False)
        FlawMetaFactory(
            flaw=vuln_1,
            type=FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT,
            meta_attr={"status": "+"},
        )
        assert vuln_1.is_major_incident

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
            impact=Affect.AffectImpact.NOVALUE,
            acl_read=acls,
            acl_write=acls,
        )
        affect2.save()
        tracker1 = TrackerFactory(
            affects=(affect2,),
            status="random_status",
            resolution="random_resolution",
        )
        tracker1.save()
        all_affects = vuln_1.affects.all()
        assert len(all_affects) == 2
        assert affect1 in all_affects
        assert affect2 in all_affects

        comment1 = FlawCommentFactory(flaw=vuln_1)
        comment2 = FlawComment.objects.create_flawcomment(
            vuln_1,
            "9999991",
            {
                "id": "1285930",
                "tags": "[]",
                "text": "some comment text",
                "time": "2006-03-30T11:56:45Z",
                "count": "0",
                "bug_id": "187353",
                "creator": "nonexistantuser@redhat.com",
                "creator_id": "9999991",
                "is_private": "False",
                "creation_time": "2006-03-30T11:56:45Z",
            },
            type=FlawComment.FlawCommentType.BUGZILLA,
            acl_read=acls,
            acl_write=acls,
        )
        comment2.save()
        all_comments = vuln_1.comments.all()
        assert len(all_comments) == 2
        assert comment1 in all_comments
        assert comment2 in all_comments

        meta1 = FlawMetaFactory(flaw=vuln_1)
        meta2 = FlawMeta.objects.create_flawmeta(
            vuln_1,
            FlawMeta.FlawMetaType.REFERENCE,
            {
                "url": "http://nonexistenturl.example.com/99999",
                "type": "external",
            },
            acl_read=acls,
            acl_write=acls,
        )
        meta2.save()
        all_meta = vuln_1.meta.all()
        assert len(all_meta) == 3
        assert meta1 in all_meta
        assert meta2 in all_meta

        vuln_2 = Flaw(
            cve_id="CVE-1970-12345",
            cwe_id="CWE-1",
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            type=FlawType.VULNERABILITY,
            title="title",
            description="description",
            impact=FlawImpact.CRITICAL,
            statement="statement",
            resolution=FlawResolution.NOVALUE,
            acl_read=acls,
            acl_write=acls,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        )
        assert vuln_2.validate() is None

        # assert vuln_1.delete()
        # assert vuln_2.delete()

    def test_create_flaw_method(self):
        acls = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]
        Flaw.objects.all().delete()
        flaw1 = Flaw.objects.create_flaw(
            bz_id="12345",
            cwe_id="CWE-1",
            title="first",
            unembargo_dt=tzdatetime(2000, 1, 1),
            description="description",
            acl_read=acls,
            acl_write=acls,
            reported_dt=timezone.now(),
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        )
        flaw1.save()
        AffectFactory(flaw=flaw1)

        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().meta_attr["bz_id"] == "12345"
        Flaw.objects.create_flaw(
            bz_id="12345",
            title="second",
            description="description",
            acl_read=acls,
            acl_write=acls,
            reported_dt=timezone.now(),
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        ).save()
        # no new flaw should be created
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().title == "second"

    def test_multi_affect_tracker(self):
        affect1 = AffectFactory()
        tracker = TrackerFactory.create(
            affects=(affect1,), embargoed=affect1.flaw.is_embargoed
        )
        assert len(tracker.affects.all()) == 1
        affect2 = AffectFactory(flaw__embargoed=False)
        Tracker.objects.create_tracker(
            affect2, tracker.external_system_id, tracker.type
        )
        assert len(tracker.affects.all()) == 2

    def test_trackers_filed(self):
        flaw = FlawFactory()
        fix_affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            flaw=flaw,
        )
        assert not flaw.trackers_filed
        TrackerFactory(affects=(fix_affect,), embargoed=flaw.is_embargoed)
        assert flaw.trackers_filed
        AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            flaw=flaw,
        )
        assert not flaw.trackers_filed

    def test_delegated_affects(self):
        delegated_affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            flaw__embargoed=False,
        )
        TrackerFactory(
            affects=(delegated_affect,),
            status="won't fix",
            embargoed=delegated_affect.flaw.is_embargoed,
        )
        assert delegated_affect.delegated_resolution == Affect.AffectFix.WONTFIX
        # NOTAFFECTED is ranked higher than WONTFIX
        TrackerFactory(
            affects=(delegated_affect,),
            status="done",
            resolution="notabug",
            embargoed=delegated_affect.flaw.is_embargoed,
        )
        assert delegated_affect.delegated_resolution == Affect.AffectFix.NOTAFFECTED
        # DEFER is ranged lower than NOTAFFECTED
        TrackerFactory(
            affects=(delegated_affect,),
            status="closed",
            resolution="deferred",
            embargoed=delegated_affect.flaw.is_embargoed,
        )
        assert delegated_affect.delegated_resolution == Affect.AffectFix.NOTAFFECTED

        new_affect = AffectFactory(affectedness=Affect.AffectAffectedness.NEW)
        assert new_affect.delegated_resolution is None
        undelegated_affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
        )
        assert undelegated_affect.delegated_resolution is None

    def test_tracker_fix_state(self):
        wontfix_tracker = TrackerFactory(status="won't fix")
        assert wontfix_tracker.fix_state == Affect.AffectFix.WONTFIX
        random_tracker = TrackerFactory(status="foo", resolution="bar")
        assert random_tracker.fix_state == Affect.AffectFix.AFFECTED
        empty_tracker = TrackerFactory(status="foo", resolution="")
        assert empty_tracker.fix_state == Affect.AffectFix.AFFECTED

    def test_flawmeta_create_or_update(self):
        flaw = FlawFactory()
        meta = FlawMeta.objects.create_flawmeta(
            flaw=flaw,
            _type=FlawMeta.FlawMetaType.MAJOR_INCIDENT,
            meta={},
            acl_read=[uuid.uuid4()],
            acl_write=[uuid.uuid4()],
        )
        meta.save()
        old_updated_dt = meta.updated_dt

        assert FlawMeta.objects.first().updated_dt == old_updated_dt

        meta = FlawMeta.objects.create_flawmeta(
            flaw=flaw,
            _type=FlawMeta.FlawMetaType.MAJOR_INCIDENT,
            meta={},
            updated_dt=timezone.now(),
        )
        meta.save(auto_timestamps=False)

        assert FlawMeta.objects.first().updated_dt > old_updated_dt

    def test_objects_create_flaw(self, datetime_with_tz, good_cve_id):
        """test creating with manager .create_flow()"""

        acls = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]
        meta_attr = {}
        meta_attr["test"] = 1
        vuln_1 = Flaw(
            cve_id=good_cve_id,
            cwe_id="CWE-1",
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            type=FlawType.VULNERABILITY,
            title="title",
            description="description",
            impact=FlawImpact.CRITICAL,
            statement="statement",
            resolution=FlawResolution.NOVALUE,
            acl_read=acls,
            acl_write=acls,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            # META
            meta_attr=meta_attr,
        )

        assert vuln_1.save() is None

    def test_flaw_queryset(self, datetime_with_tz):
        """retrieve flaw manager queryset"""
        acls = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]

        flaw = Flaw(
            cve_id="CVE-1970-12345",
            cwe_id="CWE-1",
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            type=FlawType.VULNERABILITY,
            title="title",
            description="description",
            impact=FlawImpact.CRITICAL,
            statement="statement",
            resolution=FlawResolution.NOVALUE,
            acl_read=acls,
            acl_write=acls,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        )
        assert Flaw.objects.get_queryset().count() == 0
        flaw.save()
        assert Flaw.objects.get_queryset().count() == 1

    def test_fts_search(self, datetime_with_tz, good_cve_id):
        """check fts search is working"""
        acls = [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]

        flaw = Flaw(
            cve_id=good_cve_id,
            cwe_id="CWE-1",
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            reported_dt=datetime_with_tz,
            unembargo_dt=datetime_with_tz,
            type=FlawType.VULNERABILITY,
            title="title",
            description="description",
            impact=FlawImpact.CRITICAL,
            statement="statement",
            resolution=FlawResolution.NOVALUE,
            acl_read=acls,
            acl_write=acls,
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        )

        assert not Flaw.objects.fts_search("title")

        flaw.save()

        assert Flaw.objects.fts_search("title")


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

    @pytest.mark.parametrize(
        "cvss2",
        [
            "test",
            "7.8/AV:N/AC:L/Au:N/C:N/I:N/A:C ",
            "2.8/AV:N/AC:L/Au:N/C:N/I:N/A:C",  # score does not correspond to vector
            "AV:N/AC:L/Au:N/C:N/I:N/A:C",
        ],
    )
    def test_validate_cvss2(self, cvss2):
        """test cvss2 validator"""
        with pytest.raises(ValidationError) as e:
            FlawFactory(cvss2=cvss2)
        assert "Invalid CVSS2:" in str(e)

    @pytest.mark.parametrize(
        "cvss3",
        [
            "test",
            "5.3/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N "
            "3.3/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # score does not correspond to vector
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            "5.3/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ],
    )
    def test_validate_cvss3_field(self, cvss3):
        """test cvss3 validator"""
        with pytest.raises(ValidationError) as e:
            FlawFactory(cvss3=cvss3)
        assert "Invalid CVSS3:" in str(e)

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

    @pytest.mark.parametrize(
        "attr_name", ["impact", "resolution", "state", "state", "type"]
    )
    def test_validate_choice(self, attr_name):
        """test choice validation"""
        with pytest.raises(ValidationError) as e:
            FlawFactory(**{attr_name: "half of FISH"})
        assert "Value 'half of FISH' is not a valid choice." in str(e)

    @pytest.mark.parametrize(
        "flag_pair", [("+", "+"), ("+", "?"), ("?", "+"), ("-", "?"), ("?", "-")]
    )
    def test_major_incident_flag_invalid(self, flag_pair):
        """
        Test invalid combinations of hightouch / hightouch-lite flag values.
        """
        flaw = FlawFactory()
        FlawMetaFactory(
            type="MAJOR_INCIDENT",
            meta_attr={"status": flag_pair[0]},
            flaw=flaw,
        )

        with pytest.raises(ValidationError) as e:
            FlawMetaFactory(
                type="MAJOR_INCIDENT_LITE",
                meta_attr={"status": flag_pair[1]},
                flaw=flaw,
            )
        assert (
            f"Flaw MAJOR_INCIDENT and MAJOR_INCIDENT_LITE combination cannot be {flag_pair}."
            in str(e)
        )
        # test that it works with RelatedManager methods such as add()
        meta2 = FlawMetaFactory(
            type="MAJOR_INCIDENT_LITE",
            meta_attr={"status": flag_pair[1]},
        )
        with pytest.raises(ValidationError) as e:
            # Note: only works with bulk=False which is not the default value
            # if bulk=False is omitted, it will do an SQL update which means
            # save() won't be called thus no validation will be performed
            # this is a Django limitation and there's not much that we can do
            # about it.
            flaw.meta.add(meta2, bulk=False)

    @pytest.mark.parametrize(
        "flag_pair",
        [
            ("", ""),
            ("?", "?"),
            ("-", "-"),
            ("+", ""),
            ("+", "-"),
            ("", "+"),
            ("-", "+"),
        ],
    )
    def test_major_incident_flag_valid(self, flag_pair):
        """
        Test valid combinations of hightouch / hightouch-lite flag values.
        """
        flaw = FlawFactory()
        meta1 = FlawMetaFactory(
            type="MAJOR_INCIDENT",
            meta_attr={"status": flag_pair[0]},
            flaw=flaw,
        )
        meta2 = FlawMetaFactory(
            type="MAJOR_INCIDENT_LITE",
            meta_attr={"status": flag_pair[1]},
            flaw=flaw,
        )
        assert FlawMeta.objects.count() == 2
        # test that it works with RelatedManager methods such as add()
        flaw = FlawFactory()
        # see previous test for explanation on bulk=False
        flaw.meta.set([meta1, meta2], bulk=False)
        assert flaw.meta.count() == 2

    @pytest.mark.parametrize(
        "vector_pair",
        [
            (
                "8.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                # delta of exactly 1.0
                "7.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",
            ),
            (
                "8.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                # delta of > 1.0
                "6.8/CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H",
            ),
            (
                "7.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",
                # delta of exactly 1.0 in the opposite direction
                "8.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ),
            (
                "6.8/CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H",
                # delta of > 1.0 in the opposite direction
                "8.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            ),
        ],
    )
    def test_cvss_rh_nvd_score_diff_invalid(self, vector_pair):
        nvd_v, rh_v = vector_pair
        rh_score = rh_v.split("/", 1)[0]
        flaw = FlawFactory(cvss3=rh_v, cvss3_score=rh_score, nvd_cvss3=nvd_v)
        assert Flaw.objects.count() == 1
        assert "rh_nvd_cvss_score_diff" in flaw._alerts

    @pytest.mark.parametrize(
        "vector_pair",
        [
            (
                "7.2/CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
                # delta within acceptable range
                "7.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",
            ),
            (
                "7.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:H",
                # delta within acceptable range in the opposite direction
                "7.2/CVSS:3.1/AV:P/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
            ),
        ],
    )
    def test_cvss_rh_nvd_score_diff_valid(self, vector_pair):
        nvd_v, rh_v = vector_pair
        rh_score = rh_v.split("/", 1)[0]
        flaw = FlawFactory(cvss3=rh_v, cvss3_score=rh_score, nvd_cvss3=nvd_v)
        assert Flaw.objects.count() == 1
        assert "rh_nvd_cvss_score_diff" not in flaw._alerts

    @pytest.mark.parametrize(
        "vector_pair",
        [
            # Note: not possible to test None vs Low since the lowest possible
            # CVSS score of low severity is 1.6 which violates the RH vs NVD
            # score diff constraint
            (
                # Low vs Medium
                "3.8/CVSS:3.1/AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
                "4.0/CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L",
            ),
            (
                # Medium vs Low
                "4.0/CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L",
                "3.9/CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
            ),
            (
                # Medium vs High
                "6.9/CVSS:3.1/AV:P/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H",
                "7.6/CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:H",
            ),
            (
                # High vs Critical
                "8.8/CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                "9.4/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H",
            ),
        ],
    )
    def test_cvss_rh_nvd_severity_diff_invalid(self, vector_pair):
        nvd_v, rh_v = vector_pair
        rh_score = rh_v.split("/", 1)[0]
        flaw = FlawFactory(cvss3=rh_v, cvss3_score=rh_score, nvd_cvss3=nvd_v)
        assert Flaw.objects.count() == 1
        assert "rh_nvd_cvss_severity_diff" in flaw._alerts

    @pytest.mark.parametrize(
        "vector_pair",
        [
            (
                # None vs None
                "0.0/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "0.0/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
            ),
            (
                # Low vs Low (right boundary)
                "3.9/CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
                "3.8/CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:H",
            ),
            (
                # Medium vs Medium (left boundary)
                "4.0/CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:L",
                "4.9/CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:H",
            ),
            (
                # High vs High
                "7.6/CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:H",
                "7.5/CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:H/A:H",
            ),
            (
                # High vs Critical
                "9.4/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H",
                "10.0/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H",
            ),
        ],
    )
    def test_cvss_rh_nvd_severity_diff_valid(self, vector_pair):
        nvd_v, rh_v = vector_pair
        rh_score = rh_v.split("/", 1)[0]
        flaw = FlawFactory(cvss3=rh_v, cvss3_score=rh_score, nvd_cvss3=nvd_v)
        assert Flaw.objects.count() == 1
        assert "rh_nvd_cvss_severity_diff" not in flaw._alerts

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
        assert flaw._alerts
        assert any(
            alert for alert in flaw._alerts if alert == "_validate_embargoed_source"
        )

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
        assert "embargoed_source_public" in flaw._alerts

    def test_public_source_ack(self, public_source):
        flaw = FlawFactory(source=public_source, embargoed=False)
        assert FlawMeta.objects.count() == 0
        with pytest.raises(ValidationError) as e:
            FlawMetaFactory(type=FlawMeta.FlawMetaType.ACKNOWLEDGMENT, flaw=flaw)
        assert (
            f"Flaw contains acknowledgments for public source {public_source}" in str(e)
        )
        assert FlawMeta.objects.count() == 0

    def test_private_source_ack(self, private_source):
        flaw = FlawFactory(source=private_source, embargoed=True)
        FlawMetaFactory(type=FlawMeta.FlawMetaType.ACKNOWLEDGMENT, flaw=flaw)
        assert FlawMeta.objects.count() == 1

    def test_private_and_public_source_ack(self, both_source):
        flaw = FlawFactory(source=both_source, embargoed=True)
        flaw_meta = FlawMetaFactory(
            type=FlawMeta.FlawMetaType.ACKNOWLEDGMENT, flaw=flaw
        )
        assert FlawMeta.objects.count() == 1
        assert "public_source_no_ack" in flaw_meta._alerts

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
        flaw = FlawFactory(meta_attr={"bz_id": bz_id})
        affect = AffectFactory(flaw=flaw, ps_module=ps_module)
        if should_alert:
            assert "old_flaw_affect_ps_module" in affect._alerts
        else:
            assert len(affect._alerts.keys()) == 0

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

    @pytest.mark.parametrize(
        "cvss3,should_raise",
        [
            ("3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", False),
            (None, True),
        ],
    )
    def test_validate_cvss3_model(self, cvss3, should_raise):
        """
        Test that the ValidationError is not raised when the flaw has a CVSS3 string
        """
        if should_raise:
            with pytest.raises(ValidationError) as e:
                FlawFactory(cvss3=cvss3)
            assert "CVSSv3 score is missing" in str(e)
        else:
            assert FlawFactory(cvss3=cvss3)

    @pytest.mark.parametrize(
        "summary,is_major_incident,req,should_raise",
        [
            ("", True, None, True),
            ("", True, "+", True),
            ("", True, "?", True),
            ("", True, "-", False),
            ("", False, None, False),
            ("", False, "+", False),
            ("", False, "?", False),
            ("", False, "-", False),
            ("foo", False, None, False),
            ("foo", False, "+", False),
            ("foo", False, "?", False),
            ("foo", False, "-", False),
            ("foo", True, None, True),
            ("foo", True, "+", False),
            ("foo", True, "?", True),
            ("foo", True, "-", False),
        ],
    )
    def test_validate_major_incident_summary(
        self, summary, is_major_incident, req, should_raise
    ):
        """
        Test that a Flaw that is Major Incident has a summary
        """
        flaw1 = FlawFactory.build(
            summary=summary,
            is_major_incident=is_major_incident,
        )
        flaw1.save(raise_validation_error=False)
        AffectFactory(flaw=flaw1)

        if req:
            FlawMetaFactory(
                flaw=flaw1,
                type=FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT,
                meta_attr={"status": req},
            )
        if should_raise:
            with pytest.raises(ValidationError, match="does not have Summary"):
                flaw1.save()
        else:
            assert flaw1.save() is None

    @pytest.mark.parametrize(
        "title,should_raise",
        [
            ("CVE-2022-1234 kernel: some description", False),
            ("EMBARGOED CVE-2022-1234 kernel: some description", True),
        ],
    )
    def test_validate_public_flaw_title(self, title, should_raise):
        """test that public flaws only accepts a valid title without the "EMBARGOED" word"""
        if should_raise:
            with pytest.raises(ValidationError) as e:
                FlawFactory(embargoed=False, title=title)
            assert 'Flaw title contains "EMBARGOED" despite being public.' in str(e)
        else:
            assert FlawFactory(embargoed=False, title=title)

    @pytest.mark.parametrize(
        "title,should_raise",
        [
            ("EMBARGOED CVE-2022-1234 kernel: some description", False),
            ("CVE-2022-1234 kernel: some description", True),
        ],
    )
    def test_validate_embargoed_flaw_title(self, title, should_raise):
        """test that embargoed flaws only accepts a valid title containing the "EMBARGOED" word"""
        if should_raise:
            with pytest.raises(ValidationError) as e:
                FlawFactory(embargoed=True, title=title)
            assert (
                'Flaw title does not contains "EMBARGOED" despite being embargoed.'
                in str(e)
            )
        else:
            assert FlawFactory(embargoed=True, title=title)

    @freeze_time(tzdatetime(2021, 11, 23))
    def test_validate_embargoing_public_flaw(self):
        flaw = FlawFactory(embargoed=False)
        with pytest.raises(ValidationError, match="Embargoing a public flaw is futile"):
            flaw.title = "EMBARGOED foo bar baz"
            flaw.acl_read = [
                uuid.UUID(acl) for acl in generate_acls([settings.EMBARGO_READ_GROUP])
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
        for embargoed_flaw in flaws_embargoed_status:
            affects.append(AffectFactory(flaw__embargoed=embargoed_flaw))

        if should_raise:
            with pytest.raises(
                ValidationError,
                match="Tracker is public but is associated with an embargoed flaw",
            ):
                TrackerFactory(affects=affects, embargoed=embargoed_tracker)
        else:
            assert TrackerFactory(affects=affects, embargoed=embargoed_tracker)

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
        """test that flaws without affect raises an error on editing"""
        flaw1 = FlawFactory()
        AffectFactory(flaw=flaw1)
        assert flaw1.save() is None

        flaw2 = FlawFactory()
        with pytest.raises(ValidationError) as e:
            flaw2.save()
        assert "Flaw does not contain any affects." in str(e)

    @pytest.mark.parametrize(
        "start_impact,new_impact,tracker_statuses,should_raise",
        [
            (FlawImpact.LOW, FlawImpact.MODERATE, ["Closed", "Open"], False),
            (FlawImpact.CRITICAL, FlawImpact.IMPORTANT, ["Closed", "Open"], False),
            (FlawImpact.LOW, FlawImpact.CRITICAL, ["Closed", "Open"], True),
            (FlawImpact.CRITICAL, FlawImpact.LOW, ["Closed", "Open"], True),
            (FlawImpact.LOW, FlawImpact.CRITICAL, ["Closed", "Closed"], False),
            (FlawImpact.CRITICAL, FlawImpact.LOW, ["Closed", "Closed"], False),
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
            embargoed=False, is_major_incident=False, impact=start_impact
        )
        affect = AffectFactory(flaw=flaw)
        for status in tracker_statuses:
            TrackerFactory(embargoed=False, status=status, affects=(affect,))
        flaw.impact = new_impact
        flaw.save()

        assert should_raise == bool("unsupported_impact_change" in flaw._alerts)

    @pytest.mark.parametrize(
        "was_major,is_major,tracker_statuses,should_raise",
        [
            (False, False, ["Closed", "Open"], False),
            (True, True, ["Closed", "Open"], False),
            (False, True, ["Closed", "Open"], True),
            (True, False, ["Closed", "Open"], True),
            (False, True, ["Closed", "Closed"], False),
            (True, False, ["Closed", "Closed"], False),
        ],
    )
    def test_validate_unsupported_major_incident_change(
        self, was_major, is_major, tracker_statuses, should_raise
    ):
        """test that major incident flaws cannot be changed to non-major while having open trackers"""

        flaw = FlawFactory.build(
            embargoed=False, is_major_incident=was_major, impact=FlawImpact.LOW
        )
        flaw.save(raise_validation_error=False)
        FlawMetaFactory(
            flaw=flaw,
            type=FlawMeta.FlawMetaType.REQUIRES_DOC_TEXT,
            meta_attr={"status": "-"},
        )
        affect = AffectFactory(flaw=flaw)
        for status in tracker_statuses:
            TrackerFactory(embargoed=False, status=status, affects=(affect,))
        flaw.is_major_incident = is_major
        flaw.save()

        assert should_raise == bool("unsupported_impact_change" in flaw._alerts)

    @pytest.mark.parametrize(
        "state,resolution,affectedness,should_raise",
        [
            (
                Flaw.FlawState.CLOSED,
                FlawResolution.NOTABUG,
                Affect.AffectAffectedness.AFFECTED,
                True,
            ),
            (
                Flaw.FlawState.NEW,
                FlawResolution.NOTABUG,
                Affect.AffectAffectedness.AFFECTED,
                False,
            ),
            (
                Flaw.FlawState.CLOSED,
                FlawResolution.NEXTRELEASE,
                Affect.AffectAffectedness.AFFECTED,
                False,
            ),
            (
                Flaw.FlawState.CLOSED,
                FlawResolution.NOTABUG,
                Affect.AffectAffectedness.NOTAFFECTED,
                False,
            ),
        ],
    )
    def test_validate_affect_in_notabug_flaw(
        self, state, resolution, affectedness, should_raise
    ):
        flaw = FlawFactory(resolution=resolution, state=state)
        AffectFactory(flaw=flaw, affectedness=affectedness)

        assert should_raise == bool("notabug_affect_ps_component" in flaw._alerts)

    @pytest.mark.parametrize(
        "state,resolution,affectedness,should_raise",
        [
            (
                Flaw.FlawState.CLOSED,
                FlawResolution.NOTABUG,
                Affect.AffectAffectedness.AFFECTED,
                True,
            ),
            (
                Flaw.FlawState.NEW,
                FlawResolution.NOTABUG,
                Affect.AffectAffectedness.AFFECTED,
                False,
            ),
            (
                Flaw.FlawState.CLOSED,
                FlawResolution.NEXTRELEASE,
                Affect.AffectAffectedness.AFFECTED,
                False,
            ),
            (
                Flaw.FlawState.CLOSED,
                FlawResolution.NOTABUG,
                Affect.AffectAffectedness.NOTAFFECTED,
                False,
            ),
        ],
    )
    def test_validate_notabug_flaw_affected(
        self, state, resolution, affectedness, should_raise
    ):
        affect = AffectFactory(affectedness=affectedness)
        flaw = FlawFactory(resolution=resolution, state=state)
        flaw.affects.add(affect)
        flaw.save()
        assert should_raise == bool("notabug_affect_ps_component" in flaw._alerts)

    @pytest.mark.parametrize(
        "ps_module,ps_component,alerts",
        [
            ("rhscl-module", "valid-component", []),
            ("rhscl-module", "source-to-image", []),
            ("not-rhscl-module", "valid-component", []),
            ("not-rhscl-module", "valid", []),
            ("not-rhscl-module", "invalid-component", []),
            ("not-rhscl-module", "source-to-image", []),
            (
                "rhscl-module",
                "valid",
                [
                    "flaw_affects_rhscl_collection_only",
                    "flaw_affects_rhscl_invalid_collection",
                ],
            ),
            (
                "rhscl-module",
                "invalid-component",
                ["flaw_affects_rhscl_invalid_collection"],
            ),
        ],
    )
    def test_flaw_affects_rhscl_invalid_collection(
        self, ps_module, ps_component, alerts
    ):
        VALID_COLLECTIONS = ["valid"]
        module_obj = PsModuleFactory(name=ps_module)
        PsUpdateStreamFactory(collections=VALID_COLLECTIONS, ps_module=module_obj)
        affect = AffectFactory(ps_module=ps_module, ps_component=ps_component)
        if alerts:
            assert set(alerts).issubset(affect._alerts)

    @pytest.mark.parametrize(
        "affectedness,resolution,should_raise",
        [
            (
                Affect.AffectAffectedness.NOVALUE,
                Affect.AffectResolution.DEFER,
                True,
            ),
            (
                Affect.AffectAffectedness.NOVALUE,
                Affect.AffectResolution.WONTFIX,
                True,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.DEFER,
                False,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
        ],
    )
    def test_validate_exceptional_affectedness_resolution(
        self, affectedness, resolution, should_raise
    ):
        """
        Test that old flaw with empty affect raises alert
        """
        affect = AffectFactory(resolution=resolution, affectedness=affectedness)
        assert should_raise == bool("flaw_exceptional_affect_status" in affect._alerts)

    @pytest.mark.parametrize(
        "impact,resolution,product,should_raise",
        [
            (
                Affect.AffectImpact.LOW,
                Affect.AffectResolution.WONTREPORT,
                "other-services",
                False,
            ),
            (
                Affect.AffectImpact.MODERATE,
                Affect.AffectResolution.WONTREPORT,
                "other-services",
                False,
            ),
            (
                Affect.AffectImpact.IMPORTANT,
                Affect.AffectResolution.WONTREPORT,
                "other-services",
                True,
            ),
            (
                Affect.AffectImpact.LOW,
                Affect.AffectResolution.WONTREPORT,
                "regular-product",
                True,
            ),
            (
                Affect.AffectImpact.LOW,
                Affect.AffectResolution.WONTREPORT,
                "invalid",
                True,
            ),
        ],
    )
    def test_validate_wontreport_products(
        self, impact, resolution, product, should_raise
    ):
        """
        Tests that only products associated services, having a impact
        of LOW or MODERATE, can be marked as AFFECTED by a WONTREPORT affect
        """
        # Every test should have only one service product/module
        if product != "other-services":
            PsModuleFactory(
                name="other-services-test-module",
                ps_product=PsProductFactory(short_name="other-services-test-product"),
            )

        PsModuleFactory(
            name=product + "-test-module",
            ps_product=PsProductFactory(short_name=product),
        )

        affect = AffectFactory.build(
            impact=impact,
            resolution=resolution,
            ps_module=product + "-test-module",
            flaw=FlawFactory(),
        )

        if should_raise:
            with pytest.raises(ValidationError) as e:
                affect.save()
            assert "wontreport can only be associated with" in str(e)
        else:
            assert affect.save() is None
