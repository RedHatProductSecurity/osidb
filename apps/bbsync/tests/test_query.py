import json

import pytest
from django.utils import timezone
from django.utils.timezone import make_aware
from freezegun import freeze_time

from apps.bbsync.query import BugzillaQueryBuilder
from osidb.models import Affect, Flaw, FlawImpact, FlawSource, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawCommentFactory,
    FlawFactory,
    PsModuleFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestGenerateSRTNotes:
    @freeze_time(timezone.datetime(2022, 11, 25))
    def test_restore_original(self):
        """
        test that the original SRT notes attributes
        are preserved intact being known or unknown
        """
        srtnotes = """
        {
            "affects": [
                {
                    "affectedness": "affected",
                    "cvss2": null,
                    "cvss3": null,
                    "impact": null,
                    "ps_component": "libssh",
                    "ps_module": "fedora-all",
                    "resolution": "fix"
                }
            ],
            "impact": "moderate",
            "jira_trackers": [],
            "public": "2022-11-23",
            "reported": "2022-11-23",
            "source": "customer",
            "unknown": {
                "complex": "value",
                "array": []
            }
        }
        """
        flaw = FlawFactory(
            embargoed=False,
            impact=FlawImpact.MODERATE,
            source=FlawSource.CUSTOMER,
            reported_dt=timezone.datetime(2022, 11, 23, tzinfo=timezone.utc),
            unembargo_dt=timezone.datetime(2022, 11, 23, tzinfo=timezone.utc),
            meta_attr={"original_srtnotes": srtnotes},
        )
        FlawCommentFactory(flaw=flaw)
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            ps_component="libssh",
            ps_module="fedora-all",
            impact=Affect.AffectImpact.NOVALUE,
            cvss2="",
            cvss3="",
        )
        old_flaw = FlawFactory(
            embargoed=False,
            reported_dt=timezone.datetime(2022, 11, 23, tzinfo=timezone.utc),
            unembargo_dt=timezone.datetime(2022, 11, 23, tzinfo=timezone.utc),
        )
        FlawCommentFactory(flaw=old_flaw)
        AffectFactory(flaw=old_flaw)

        bbq = BugzillaQueryBuilder(flaw, old_flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        srtnotes_json = json.loads(srtnotes)
        for key in srtnotes_json.keys():
            assert cf_srtnotes_json[key] == srtnotes_json[key]

    def test_generate_affects(self):
        """
        test generating of SRT affects attribute array
        """
        flaw = FlawFactory()
        FlawCommentFactory(flaw=flaw)
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-6",
            ps_component="ImageMagick",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
            impact=Affect.AffectImpact.CRITICAL,
            cvss2="10.0/AV:N/AC:L/Au:N/C:C/I:C/A:C",
            cvss3="",
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-7",
            ps_component="kernel",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Affect.AffectImpact.MODERATE,
            cvss2="5.2/AV:L/AC:H/Au:N/C:P/I:P/A:C",
            cvss3="7.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="bash",
            affectedness=Affect.AffectAffectedness.NOTAFFECTED,
            resolution=Affect.AffectResolution.NOVALUE,
            impact=Affect.AffectImpact.NOVALUE,
            cvss2="",
            cvss3="",
        )

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert "affects" in cf_srtnotes_json
        affects = cf_srtnotes_json["affects"]
        assert len(affects) == 3

        rhel6affect = rhel7affect = rhel8affect = None
        for affect in affects:
            if affect["ps_module"] == "rhel-6":
                rhel6affect = affect
            if affect["ps_module"] == "rhel-7":
                rhel7affect = affect
            if affect["ps_module"] == "rhel-8":
                rhel8affect = affect
        assert rhel6affect
        assert rhel7affect
        assert rhel8affect

        assert rhel6affect["ps_component"] == "ImageMagick"
        assert rhel6affect["affectedness"] == "affected"
        assert rhel6affect["resolution"] == "fix"
        assert rhel6affect["impact"] == "critical"
        assert rhel6affect["cvss2"] == "10.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"
        assert rhel6affect["cvss3"] is None

        assert rhel7affect["ps_component"] == "kernel"
        assert rhel7affect["affectedness"] == "affected"
        assert rhel7affect["resolution"] == "delegated"
        assert rhel7affect["impact"] == "moderate"
        assert rhel7affect["cvss2"] == "5.2/AV:L/AC:H/Au:N/C:P/I:P/A:C"
        assert (
            rhel7affect["cvss3"] == "7.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
        )

        assert rhel8affect["ps_component"] == "bash"
        assert rhel8affect["affectedness"] == "notaffected"
        assert rhel8affect["resolution"] is None
        assert rhel8affect["impact"] is None
        assert rhel8affect["cvss2"] is None
        assert rhel8affect["cvss3"] is None

    @pytest.mark.parametrize(
        "osidb_cvss2,osidb_cvss3,srtnotes,bz_cvss2_present,bz_cvss3_present,bz_cvss2,bz_cvss3",
        [
            (
                "5.2/AV:L/AC:H/Au:N/C:P/I:P/A:C",
                "7.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                """
                {
                    "cvss2": "5.2/AV:L/AC:H/Au:N/C:P/I:P/A:C",
                    "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
                }
                """,
                True,
                True,
                "5.2/AV:L/AC:H/Au:N/C:P/I:P/A:C",
                "7.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            ),
            (
                "5.2/AV:L/AC:H/Au:N/C:P/I:P/A:C",
                None,
                "",
                True,
                False,
                "5.2/AV:L/AC:H/Au:N/C:P/I:P/A:C",
                None,
            ),
            (
                None,
                None,
                """
                {
                    "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
                }
                """,
                False,
                True,
                None,
                None,
            ),
        ],
    )
    def test_cvss(
        self,
        osidb_cvss2,
        osidb_cvss3,
        srtnotes,
        bz_cvss2_present,
        bz_cvss3_present,
        bz_cvss2,
        bz_cvss3,
    ):
        """
        test generating of SRT notes CVSS attributes
        """
        flaw = FlawFactory.build(
            cvss2=osidb_cvss2,
            cvss3=osidb_cvss3,
            meta_attr={"original_srtnotes": srtnotes},
        )
        flaw.save(raise_validation_error=False)
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_cvss2_present:
            assert "cvss2" in cf_srtnotes_json
            assert cf_srtnotes_json["cvss2"] == bz_cvss2
        else:
            assert "cvss2" not in cf_srtnotes_json
        if bz_cvss3_present:
            assert "cvss3" in cf_srtnotes_json
            assert cf_srtnotes_json["cvss3"] == bz_cvss3
        else:
            assert "cvss3" not in cf_srtnotes_json

    @pytest.mark.parametrize(
        "osidb_cwe,srtnotes,bz_present,bz_cwe",
        [
            (
                "CWE-123",
                """{"cwe": "CWE-123"}""",
                True,
                "CWE-123",
            ),
            (
                "CWE-555",
                """{"cwe": "CWE-123"}""",
                True,
                "CWE-555",
            ),
            (
                "",
                """{"cwe": "CWE-123"}""",
                True,
                None,
            ),
            (
                "CWE-555",
                "",
                True,
                "CWE-555",
            ),
            (
                "",
                "",
                False,
                None,
            ),
        ],
    )
    def test_cwe(self, osidb_cwe, srtnotes, bz_present, bz_cwe):
        """
        test generating of SRT notes CWE attribute
        """
        flaw = FlawFactory(cwe_id=osidb_cwe, meta_attr={"original_srtnotes": srtnotes})
        FlawCommentFactory(flaw=flaw)

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_present:
            assert "cwe" in cf_srtnotes_json
            assert cf_srtnotes_json["cwe"] == bz_cwe
        else:
            assert "cwe" not in cf_srtnotes_json

    @pytest.mark.parametrize(
        "osidb_impact,srtnotes,bz_present,bz_impact",
        [
            (
                FlawImpact.LOW,
                """{"impact": "low"}""",
                True,
                "low",
            ),
            (
                FlawImpact.MODERATE,
                """{"impact": "low"}""",
                True,
                "moderate",
            ),
            (
                FlawImpact.IMPORTANT,
                "",
                True,
                "important",
            ),
            (
                FlawImpact.CRITICAL,
                "{}",
                True,
                "critical",
            ),
            (
                FlawImpact.NOVALUE,
                """{"impact": "critical"}""",
                True,
                "none",
            ),
            (
                FlawImpact.NOVALUE,
                "",
                False,
                None,
            ),
        ],
    )
    def test_impact(self, osidb_impact, srtnotes, bz_present, bz_impact):
        """
        test generating of SRT notes impact attribute
        """
        flaw = FlawFactory(
            impact=osidb_impact, meta_attr={"original_srtnotes": srtnotes}
        )
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_present:
            assert "impact" in cf_srtnotes_json
            assert cf_srtnotes_json["impact"] == bz_impact
        else:
            assert "impact" not in cf_srtnotes_json

    def test_jira_trackers_empty(self):
        """
        test generating SRT notes for with no Jira trackers
        """
        flaw = FlawFactory()
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert "jira_trackers" not in cf_srtnotes_json

    def test_jira_trackers_preserved(self):
        """
        test that empty Jira trackers are preserved when
        there were some Jira trackers there originally
        """
        srtnotes = """{"jira_trackers": []}"""
        flaw = FlawFactory(meta_attr={"original_srtnotes": srtnotes})
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert "jira_trackers" in cf_srtnotes_json
        assert cf_srtnotes_json["jira_trackers"] == []

    def test_jira_trackers_generate(self):
        """
        test that Jira tracker is added to SRT notes
        """
        flaw = FlawFactory()
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)
        TrackerFactory(
            affects=[affect],
            external_system_id="PROJECT-1",
            type=Tracker.TrackerType.JIRA,
        )

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)
        assert "jira_trackers" in cf_srtnotes_json
        assert cf_srtnotes_json["jira_trackers"] == [
            {"bts_name": "jboss", "key": "PROJECT-1"}
        ]

    @freeze_time(timezone.datetime(2022, 12, 30))
    @pytest.mark.parametrize("attribute_name", ["public", "reported"])
    @pytest.mark.parametrize(
        "new_dt,old_dt,old_date,new_date",
        [
            (
                timezone.datetime(2022, 12, 20),
                timezone.datetime(2022, 12, 20),
                "2022-12-20",
                "2022-12-20",
            ),
            (
                timezone.datetime(2022, 12, 20, 14),
                timezone.datetime(2022, 12, 20),
                "2022-12-20",
                "2022-12-20T14:00:00Z",
            ),
            (
                timezone.datetime(2022, 12, 20),
                timezone.datetime(2022, 12, 20),
                "2022-12-20T00:00:00Z",
                "2022-12-20T00:00:00Z",
            ),
        ],
    )
    def test_date_was_present(self, new_dt, old_dt, old_date, new_date, attribute_name):
        """
        test generating of SRT notes date attributes
        when it was present in the old SRT notes
        """
        flaw = FlawFactory(
            embargoed=False,
            meta_attr={
                "original_srtnotes": '{"' + attribute_name + '": "' + old_date + '"}'
            },
            reported_dt=make_aware(new_dt),
            unembargo_dt=make_aware(new_dt),
        )
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        old_flaw = FlawFactory(
            embargoed=False,
            reported_dt=make_aware(old_dt),
            unembargo_dt=make_aware(old_dt),
        )
        FlawCommentFactory(flaw=old_flaw)
        AffectFactory(flaw=old_flaw)

        bbq = BugzillaQueryBuilder(flaw, old_flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        assert attribute_name in cf_srtnotes_json
        assert cf_srtnotes_json[attribute_name] == new_date

    @freeze_time(timezone.datetime(2022, 12, 30))
    @pytest.mark.parametrize("attribute_name", ["public", "reported"])
    @pytest.mark.parametrize(
        "date_obj,present,date_str",
        [
            (
                timezone.datetime(2022, 12, 20),
                True,
                "2022-12-20T00:00:00Z",
            ),
            (
                None,
                False,
                "",
            ),
        ],
    )
    def test_date_was_not_present(self, date_obj, present, date_str, attribute_name):
        """
        test generating of SRT notes date attributes
        when it was not present in the old SRT notes
        """
        flaw = FlawFactory.build(
            meta_attr={"original_srtnotes": ""},
            reported_dt=make_aware(date_obj) if date_obj else None,
            unembargo_dt=make_aware(date_obj) if date_obj else None,
        )
        # reported and unembargo dates have very different validations
        # but these are not the subject of this test so let us ignore them
        flaw.save(raise_validation_error=False)
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        old_flaw = FlawFactory.build(
            reported_dt=make_aware(date_obj) if date_obj else None,
            unembargo_dt=make_aware(date_obj) if date_obj else None,
        )
        # and here we ignore the validations too
        old_flaw.save(raise_validation_error=False)
        FlawCommentFactory(flaw=old_flaw)
        AffectFactory(flaw=old_flaw)

        bbq = BugzillaQueryBuilder(flaw, old_flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if present:
            assert attribute_name in cf_srtnotes_json
            assert cf_srtnotes_json[attribute_name] == date_str
        else:
            assert attribute_name not in cf_srtnotes_json

    @pytest.mark.parametrize(
        "osidb_source,srtnotes,bz_present,bz_source",
        [
            (
                FlawSource.CUSTOMER,
                """{"source": "customer"}""",
                True,
                "customer",
            ),
            (
                FlawSource.CUSTOMER,
                """{"source": "internet"}""",
                True,
                "customer",
            ),
            (
                FlawSource.HW_VENDOR,
                "",
                True,
                "hw-vendor",
            ),
            # this case should never be allowed by the validations
            # but let us consider it from the point of SRT notes builder
            (
                FlawSource.NOVALUE,
                """{"source": "internet"}""",
                True,
                None,
            ),
            (
                FlawSource.NOVALUE,
                "",
                False,
                None,
            ),
        ],
    )
    def test_source(self, osidb_source, srtnotes, bz_present, bz_source):
        """
        test generating of SRT notes source attribute
        """
        flaw = FlawFactory(
            embargoed=False,
            meta_attr={"original_srtnotes": srtnotes},
            source=osidb_source,
        )
        FlawCommentFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_present:
            assert "source" in cf_srtnotes_json
            assert cf_srtnotes_json["source"] == bz_source
        else:
            assert "source" not in cf_srtnotes_json

    @pytest.mark.parametrize(
        "osidb_statement,srtnotes,bz_present,bz_statement",
        [
            (
                "some text",
                """{"statement": "some text"}""",
                True,
                "some text",
            ),
            (
                "other text",
                """{"statement": "some text"}""",
                True,
                "other text",
            ),
            (
                "",
                """{"statement": "some text"}""",
                True,
                None,
            ),
            (
                "",
                "",
                False,
                None,
            ),
        ],
    )
    def test_statement(self, osidb_statement, srtnotes, bz_present, bz_statement):
        """
        test generating of SRT notes statement attribute
        """
        flaw = FlawFactory(
            statement=osidb_statement, meta_attr={"original_srtnotes": srtnotes}
        )
        FlawCommentFactory(flaw=flaw)

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        if bz_present:
            assert "statement" in cf_srtnotes_json
            assert cf_srtnotes_json["statement"] == bz_statement
        else:
            assert "statement" not in cf_srtnotes_json


class TestGenerateGroups:
    def test_create_public(self):
        """
        test that when creating a public flaw
        there are no or empty groups in BZ query
        """
        flaw = FlawFactory(embargoed=False)
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)
        TrackerFactory(affects=[affect])
        PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "private",
                ]
            },
        )

        bbq = BugzillaQueryBuilder(flaw)
        query = bbq.query

        assert not query.get("groups", [])

    def test_create_embargoed(self):
        """
        test that when creating an embargoed flaw
        there are expected groups in BZ query
        """
        flaw = FlawFactory(embargoed=True)
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)
        TrackerFactory(affects=[affect])
        PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "private",
                ]
            },
        )

        bbq = BugzillaQueryBuilder(flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert len(groups) == 3
        assert "private" in groups
        assert "qe_staff" in groups
        assert "security" in groups

    def test_create_embargoed_no_redhat(self):
        """
        test that when creating an embargoed flaw
        the redhat group is never being added
        """
        flaw = FlawFactory(embargoed=True)
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)
        TrackerFactory(affects=[affect])
        PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "redhat",
                ]
            },
        )

        bbq = BugzillaQueryBuilder(flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert "redhat" not in groups

    def test_unembargo(self):
        """
        test that unembargoeing flaw
        removes groups in BZ query
        """
        flaw = FlawFactory(
            embargoed=True, meta_attr={"groups": '["private", "qe_staff", "security"]'}
        )
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)
        TrackerFactory(affects=[affect])
        PsModuleFactory(
            name=affect.ps_module,
            bts_groups={
                "embargoed": [
                    "private",
                ]
            },
        )

        new_flaw = Flaw.objects.first()
        new_flaw.embargoed = False

        bbq = BugzillaQueryBuilder(new_flaw, old_flaw=flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert not groups.get("add")
        remove = groups.get("remove", [])
        assert len(remove) == 3
        assert "private" in remove
        assert "qe_staff" in remove
        assert "security" in remove

    def test_affect_change(self):
        """
        test that affect change is properly reflected
        in added and removed groups in BZ query
        """
        flaw = FlawFactory(
            embargoed=True, meta_attr={"groups": '["private", "qe_staff", "security"]'}
        )
        FlawCommentFactory(flaw=flaw)
        affect1 = AffectFactory(flaw=flaw)
        TrackerFactory(affects=[affect1])
        PsModuleFactory(
            name=affect1.ps_module,
            bts_groups={
                "embargoed": [
                    "private",
                ]
            },
        )

        new_flaw = Flaw.objects.first()
        # remove existing affect
        new_flaw.affects.first().delete()
        # and add a newly created affect
        affect2 = AffectFactory(flaw=new_flaw)
        TrackerFactory(affects=[affect2])
        PsModuleFactory(
            name=affect2.ps_module,
            bts_groups={
                "embargoed": [
                    "secalert",
                ]
            },
        )

        bbq = BugzillaQueryBuilder(new_flaw, old_flaw=flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert ["secalert"] == groups.get("add", [])
        assert ["private"] == groups.get("remove", [])
