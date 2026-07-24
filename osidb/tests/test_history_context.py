"""
Tests that Flaw re-saves from signals carry pghistory context so UI audit
no longer shows an opaque "system"/None writer.

Note: FlawAudit excludes local_updated_dt, so a signal that only bumps that
field creates no Flaw history row. Tests therefore use a stale in-memory Flaw
writeback (tracked field change) to observe context on the resulting event.
"""

import pghistory
import pytest

from osidb.models import Flaw, FlawReference
from osidb.tests.factories import FlawFactory, FlawReferenceFactory

pytestmark = [pytest.mark.unit, pytest.mark.enable_signals]

MITIGATION_TEXT = "disable the vulnerable RPC via --block-rpcs"


@pytest.mark.django_db(transaction=True)
class TestSignalHistoryContext:
    def test_flaw_reference_stale_resave_sets_signal_history_context(self):
        flaw = FlawFactory(mitigation="", embargoed=False)
        ref = FlawReferenceFactory(flaw=flaw)
        loaded_ref = FlawReference.objects.select_related("flaw").get(pk=ref.pk)
        assert loaded_ref.flaw.mitigation == ""

        Flaw.objects.filter(pk=flaw.pk).update(mitigation=MITIGATION_TEXT)
        assert Flaw.objects.get(pk=flaw.pk).mitigation == MITIGATION_TEXT

        loaded_ref.save()

        assert Flaw.objects.get(pk=flaw.pk).mitigation == ""

        events = (
            pghistory.models.Events.objects.tracks(flaw)
            .filter(pgh_context__source="signal")
            .order_by("-pgh_created_at")
        )
        assert events.count() >= 1
        event = events.first()
        assert event.pgh_context["signal"] == "flaw_dependant_update_local_updated_dt"
        assert event.pgh_context["signal_sender"] == FlawReference.__name__
        assert event.pgh_context["user"] == "system"
        assert event.pgh_context["action"] == "flaw_dependant_update_local_updated_dt"
        assert event.pgh_context["instance"] == str(ref.uuid)

    def test_nested_api_context_keeps_user_and_adds_signal(self):
        flaw = FlawFactory(mitigation="", embargoed=False)
        ref = FlawReferenceFactory(flaw=flaw)
        loaded_ref = FlawReference.objects.select_related("flaw").get(pk=ref.pk)

        Flaw.objects.filter(pk=flaw.pk).update(mitigation=MITIGATION_TEXT)

        with pghistory.context(user="analyst@redhat.com", path="/osidb/api/v2/flaws"):
            loaded_ref.save()

        event = (
            pghistory.models.Events.objects.tracks(flaw)
            .filter(pgh_context__source="signal")
            .order_by("-pgh_created_at")
            .first()
        )

        assert event is not None
        assert event.pgh_context["user"] == "analyst@redhat.com"
        assert event.pgh_context["path"] == "/osidb/api/v2/flaws"
        assert event.pgh_context["signal"] == "flaw_dependant_update_local_updated_dt"
        assert "action" not in event.pgh_context

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
