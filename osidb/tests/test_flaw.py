import uuid

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time

from osidb.models import (
    Affect,
    Flaw,
    FlawComment,
    FlawImpact,
    FlawMeta,
    FlawResolution,
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
            type=FlawType.VULN,
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

        vuln_2 = Flaw.objects.create_flaw(
            "CVE-1970-12345",
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            type=FlawType.VULN,
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
        vuln_1 = Flaw.objects.create_flaw(
            good_cve_id,
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            type=FlawType.VULN,
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

        flaw = Flaw.objects.create_flaw(
            "CVE-1970-12345",
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            type=FlawType.VULN,
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

        flaw = Flaw.objects.create_flaw(
            good_cve_id,
            state=Flaw.FlawState.NEW,
            created_dt=datetime_with_tz,
            type=FlawType.VULN,
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
