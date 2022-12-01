import json

import pytest
from django.utils import timezone
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

        bbq = BugzillaQueryBuilder(flaw)
        cf_srtnotes = bbq.query.get("cf_srtnotes")
        assert cf_srtnotes
        cf_srtnotes_json = json.loads(cf_srtnotes)

        srtnotes_json = json.loads(srtnotes)
        for key in srtnotes_json.keys():
            assert cf_srtnotes_json[key] == srtnotes_json[key]

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
