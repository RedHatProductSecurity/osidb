"""
Test to reproduce OSIDB-4985: Flaw fields revert after PUT with many affects
"""

import pytest
from django.db.models import Prefetch

from osidb.models import Affect, Flaw, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)


@pytest.mark.enable_signals
class TestFlawRevertBug:
    """
    Reproduce the bug where flaw.statement reverts to empty string
    after a PUT request with many affects.

    Based on real-world evidence from CVE-2026-39892:
    - PUT with 152 affects
    - statement changes from '' to 'In default configurations...'
    - ~400ms-1.2s later, statement reverts to ''
    - pg_history shows revert with no user/path (internal operation)
    """

    def _create_flaw_and_affects(self) -> Flaw:
        # Create initial flaw
        flaw = FlawFactory(
            cve_id="CVE-2026-39892",
            statement="",
            impact="IMPORTANT",
        )

        # Create affects (fewer for faster test, but same pattern)
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        for i in range(2):
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                ps_module=ps_update_stream.ps_module.name,
                ps_update_stream=ps_update_stream.name,
                ps_component=f"component-{i}",
            )
            tracker = TrackerFactory(
                affects=(affect,),
                ps_update_stream=ps_update_stream.name,
                type=Tracker.TrackerType.JIRA,
                embargoed=flaw.embargoed,
            )
            tracker.save()
        return flaw

    def test_affect_does_not_revert_statement(self):
        """
        Test that affect saves do not revert the flaw statement when saved on signals.
        """
        # Simulate what happens when Django processes a nested serializer update:
        # 1. Affects are loaded (they have references to the OLD flaw)
        flaw = self._create_flaw_and_affects()
        loaded_affects = list(Affect.objects.filter(flaw=flaw).select_related("flaw"))

        # 2. Flaw is updated
        new_statement = "This is the new statement that should not revert"
        flaw.statement = new_statement
        flaw.save()
        flaw.refresh_from_db()
        assert flaw.statement == new_statement
        assert loaded_affects[0].flaw.statement == ""

        for affect in loaded_affects:
            affect.save()

        # 4. Check if statement reverted
        flaw.refresh_from_db()

        assert flaw.statement == new_statement, (
            "Statement reverted when affects were saved!"
        )

    def test_tracker_does_not_revert_statement(self):
        """
        Test that tracker saves do not revert the flaw statement when saved on signals.
        """
        # Simulate what happens when Django processes a nested serializer update:
        # 1. Trackers are loaded (they have references to the OLD flaw)
        flaw = self._create_flaw_and_affects()
        loaded_trackers = list(
            Tracker.objects.filter(affects__flaw__uuid=flaw.uuid)
            .prefetch_related(
                Prefetch("affects", queryset=Affect.objects.select_related("flaw"))
            )
            .distinct()
        )
        # 2. Flaw is updated
        new_statement = "This is the new statement that should not revert"
        flaw.statement = new_statement
        flaw.save()
        flaw.refresh_from_db()
        assert flaw.statement == new_statement
        assert loaded_trackers[0].affects.first().flaw.statement == ""

        for tracker in loaded_trackers:
            tracker.save()

        flaw.refresh_from_db()
        # 4. Check if statement reverted
        assert flaw.statement == new_statement, (
            "Statement reverted when affects were saved"
        )
