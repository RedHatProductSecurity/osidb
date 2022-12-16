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
