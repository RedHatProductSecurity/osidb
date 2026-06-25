"""
Test ACL consistency and propagation.

Django's ATOMIC_REQUESTS=True ensures that all HTTP requests are atomic.
These tests verify that ACL updates propagate correctly to all nested entities.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from osidb.models import Affect, Tracker
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

    @pytest.mark.enable_signals
    @pytest.mark.django_db
    def test_visibility_auto_adjustment_propagates_to_nested(
        self,
        internal_read_groups,
        internal_write_groups,
    ):
        """When classification crosses a visibility gate, ACLs propagate to nested entities."""
        from apps.workflows.models import Workflow
        from apps.workflows.workflow import WorkflowFramework

        ps_module = PsModuleFactory()
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)

        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []
        workflow_framework.register_workflow(
            Workflow(
                {
                    "name": "DEFAULT",
                    "description": "test workflow",
                    "priority": 0,
                    "conditions": [],
                    "states": [
                        {
                            "name": "NEW",
                            "requirements": [],
                            "jira_state": "New",
                            "jira_resolution": None,
                        },
                        {
                            "name": "PUBLIC_STATE",
                            "requirements": ["has owner"],
                            "jira_state": "To Do",
                            "jira_resolution": None,
                            "visibility": "PUBLIC",
                        },
                    ],
                }
            )
        )

        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-1",
            owner="",
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

        assert flaw.is_internal
        assert affect.is_internal
        assert flaw.workflow_state == "NEW"

        flaw.owner = "analyst@redhat.com"
        flaw.save(raise_validation_error=False)

        affect.refresh_from_db()
        assert flaw.workflow_state == "PUBLIC_STATE"
        assert flaw.is_public
        assert affect.is_public

        workflow_framework._workflows = []
