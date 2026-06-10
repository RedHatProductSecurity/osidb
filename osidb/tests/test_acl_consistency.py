"""
Test ACL consistency and propagation.

Django's ATOMIC_REQUESTS=True ensures that all HTTP requests are atomic.
These tests verify that ACL updates propagate correctly to all nested entities.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from osidb.models import Affect, Flaw, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)


class TestAtomicRollbackOnFailure:
    """Verify transactions rollback correctly when failures occur during ACL updates."""

    @pytest.mark.django_db
    def test_rollback_when_recursive_unembargo_fails(
        self,
        embargoed_read_groups,
        embargoed_write_groups,
    ):
        """When recursive unembargo of nested entity fails, all changes rollback."""
        ps_module = PsModuleFactory()
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw = FlawFactory(
            embargoed=True,
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            ps_component="test-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=True,
            ps_update_stream=ps_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        original_flaw_acls = (list(flaw.acl_read), list(flaw.acl_write))
        original_affect_acls = (list(affect.acl_read), list(affect.acl_write))
        original_tracker_acls = (list(tracker.acl_read), list(tracker.acl_write))
        original_unembargo = Affect.unembargo

        def failing_unembargo_on_affect(self):
            # Fail when unembargo is called on an Affect
            if isinstance(self, Affect):
                raise Exception("Simulated failure during recursive unembargo")
            return original_unembargo(self)

        with patch.object(Affect, "unembargo", failing_unembargo_on_affect):
            with pytest.raises(Exception, match="Simulated failure during recursive"):
                flaw.unembargo_dt = datetime(2000, 1, 1, tzinfo=timezone.utc)
                flaw.unembargo()

        # Refresh from database
        flaw.refresh_from_db()
        affect.refresh_from_db()
        tracker.refresh_from_db()

        # All should still be embargoed (entire operation rolled back)
        assert (list(flaw.acl_read), list(flaw.acl_write)) == original_flaw_acls
        assert (list(affect.acl_read), list(affect.acl_write)) == original_affect_acls
        assert (
            list(tracker.acl_read),
            list(tracker.acl_write),
        ) == original_tracker_acls

    @pytest.mark.django_db
    def test_set_history_public_failure_during_workflow_transition(
        self,
        internal_read_groups,
        internal_write_groups,
    ):
        """When flaw ACL update fails during workflow transition, all changes rollback."""

        ps_module = PsModuleFactory()
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)

        # Create INTERNAL flaw for workflow transition test
        flaw = FlawFactory(
            embargoed=False,
            unembargo_dt=datetime(2000, 1, 1, tzinfo=timezone.utc),
            task_key="TASK-1",
            workflow_state="TRIAGE",
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
        )

        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            ps_component="test-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
        )

        # Verify flaw is internal
        assert flaw.is_internal

        original_flaw_acls = (list(flaw.acl_read), list(flaw.acl_write))
        original_affect_acls = (list(affect.acl_read), list(affect.acl_write))

        flaw_queryset_class = Flaw.objects.get_queryset().__class__
        original_update = flaw_queryset_class.update

        # Inject failure at the call-site level, after nested ACLs were updated
        # and before the flaw-row ACL update can commit.
        def failing_flaw_acl_update(self, *args, **kwargs):
            if self.model is Flaw and "acl_read" in kwargs and "acl_write" in kwargs:
                raise Exception("Simulated failure during flaw ACL update")
            return original_update(self, *args, **kwargs)

        with patch.object(flaw_queryset_class, "update", failing_flaw_acl_update):
            with pytest.raises(Exception, match="Simulated failure during flaw ACL"):
                flaw.workflow_state = "PRE_SECONDARY_ASSESSMENT"
                flaw.tasksync(
                    jira_token=None,
                    jira_email=None,
                    diff={
                        "workflow_state": {
                            "old": "TRIAGE",
                            "new": "PRE_SECONDARY_ASSESSMENT",
                        },
                    },
                )

        # Refresh from database
        flaw.refresh_from_db()
        affect.refresh_from_db()

        # ACLs should be unchanged (rollback occurred)
        assert (list(flaw.acl_read), list(flaw.acl_write)) == original_flaw_acls
        assert (list(affect.acl_read), list(affect.acl_write)) == original_affect_acls
        # Workflow state should also be unchanged
        assert flaw.workflow_state == "TRIAGE"
