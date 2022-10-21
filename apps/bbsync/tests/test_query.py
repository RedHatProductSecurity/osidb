import pytest

from apps.bbsync.query import BugzillaQueryBuilder
from osidb.models import Flaw
from osidb.tests.factories import (
    AffectFactory,
    FlawCommentFactory,
    FlawFactory,
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

        bbq = BugzillaQueryBuilder(flaw)
        query = bbq.query

        groups = query.get("groups", [])
        assert "qe_staff" in groups
        assert "security" in groups

    def test_unembargo(self):
        """
        test that unembargoeing flaw
        removes groups in BZ query
        """
        flaw = FlawFactory(
            embargoed=True, meta_attr={"groups": ["qe_staff", "security"]}
        )
        FlawCommentFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)
        TrackerFactory(affects=[affect])

        new_flaw = Flaw.objects.first()
        new_flaw.embargoed = False

        bbq = BugzillaQueryBuilder(new_flaw, old_flaw=flaw)
        query = bbq.query

        groups = query.get("groups", [])
        remove = groups.get("remove", [])
        assert "qe_staff" in remove
        assert "security" in remove
