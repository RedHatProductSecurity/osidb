import pytest

from apps.bbsync.query import BugzillaQueryBuilder
from osidb.models import Flaw
from osidb.tests.factories import (
    AffectFactory,
    FlawCommentFactory,
    FlawFactory,
    PsModuleFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


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
