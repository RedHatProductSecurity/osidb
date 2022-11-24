import uuid

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from osidb.constants import BZ_ID_SENTINEL
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
        vuln_1 = Flaw(
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
            # META
            meta_attr=meta_attr,
        )

        assert vuln_1.save() is None
        assert vuln_1.is_major_incident

        affect1 = AffectFactory(flaw=vuln_1)
        all_trackers = affect1.trackers.all()
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
        assert len(all_meta) == 2
        assert meta1 in all_meta
        assert meta2 in all_meta

        vuln_2 = Flaw(
            cve_id="CVE-1970-12345",
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
        Flaw.objects.create_flaw(
            bz_id="12345",
            title="first",
            unembargo_dt=tzdatetime(2000, 1, 1),
            description="description",
            acl_read=acls,
            acl_write=acls,
            reported_dt=timezone.now(),
        ).save()
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().meta_attr["bz_id"] == "12345"
        Flaw.objects.create_flaw(
            bz_id="12345",
            title="second",
            description="description",
            acl_read=acls,
            acl_write=acls,
            reported_dt=timezone.now(),
        ).save()
        # no new flaw should be created
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().title == "second"

    def test_multi_affect_tracker(self):
        affect1 = AffectFactory()
        tracker = TrackerFactory.create(affects=(affect1,))
        assert len(tracker.affects.all()) == 1
        affect2 = AffectFactory()
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
        TrackerFactory(affects=(fix_affect,))
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
        )
        TrackerFactory(affects=(delegated_affect,), status="won't fix")
        assert delegated_affect.delegated_resolution == Affect.AffectFix.WONTFIX
        # NOTAFFECTED is ranked higher than WONTFIX
        TrackerFactory(affects=(delegated_affect,), status="done", resolution="notabug")
        assert delegated_affect.delegated_resolution == Affect.AffectFix.NOTAFFECTED
        # DEFER is ranged lower than NOTAFFECTED
        TrackerFactory(
            affects=(delegated_affect,), status="closed", resolution="deferred"
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
    def test_validate_cvss3(self, cvss3):
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
