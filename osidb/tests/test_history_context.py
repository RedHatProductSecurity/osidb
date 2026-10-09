"""
Tests that pghistory context is correctly attached to Flaw updates.
"""

import pghistory
import pytest

from osidb.tests.factories import FlawFactory

pytestmark = [pytest.mark.unit, pytest.mark.enable_signals]

MITIGATION_TEXT = "disable the vulnerable RPC via --block-rpcs"


@pytest.mark.django_db(transaction=True)
class TestSignalHistoryContext:
    def test_direct_pghistory_context_attaches_to_flaw_update(self):
        """Sanity check that pghistory.context works for Flaw updates in this suite."""
        flaw = FlawFactory(mitigation="", embargoed=False)
        with pghistory.context(source="testcase", action="manual"):
            flaw.mitigation = MITIGATION_TEXT
            flaw.save()

        assert (
            pghistory.models.Events.objects.tracks(flaw)
            .filter(pgh_context__source="testcase", pgh_context__action="manual")
            .count()
            >= 1
        )
