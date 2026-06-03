"""
Test ACL consistency and propagation.

Django's ATOMIC_REQUESTS=True ensures that all HTTP requests are atomic.
These tests verify that ACL updates propagate correctly to all nested entities.
"""

from datetime import datetime, timezone

import pytest

from osidb.models import Affect, Flaw, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)


class TestACLPropagation:
    """Verify ACL updates propagate correctly to nested entities."""

    @pytest.fixture
    def embargoed_flaw_with_nested_entities(
        self, embargoed_read_groups, embargoed_write_groups
    ):
        """Create an embargoed Flaw with 2 Affects, each with 1 Tracker."""
        ps_module = PsModuleFactory()
        ps_stream_1 = PsUpdateStreamFactory(ps_module=ps_module)
        ps_stream_2 = PsUpdateStreamFactory(ps_module=ps_module)

        flaw = FlawFactory(
            embargoed=True,
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        affect_1 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream_1.name,
            ps_component="component1",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        affect_2 = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream_2.name,
            ps_component="component2",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        tracker_1 = TrackerFactory(
            affects=[affect_1],
            embargoed=True,
            ps_update_stream=ps_stream_1.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        tracker_2 = TrackerFactory(
            affects=[affect_2],
            embargoed=True,
            ps_update_stream=ps_stream_2.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        return {
            "flaw": flaw,
            "affects": [affect_1, affect_2],
            "trackers": [tracker_1, tracker_2],
            "ps_module": ps_module,
        }

    @pytest.mark.django_db
    def test_acl_propagation_to_all_nested_entities(
        self, embargoed_flaw_with_nested_entities, public_read_groups
    ):
        """ACL updates propagate from Flaw to all nested Affects and Trackers."""
        flaw = embargoed_flaw_with_nested_entities["flaw"]
        affects = embargoed_flaw_with_nested_entities["affects"]
        trackers = embargoed_flaw_with_nested_entities["trackers"]

        flaw.unembargo_dt = datetime(2000, 1, 1, tzinfo=timezone.utc)
        flaw.unembargo()

        flaw.refresh_from_db()
        for affect in affects:
            affect.refresh_from_db()
        for tracker in trackers:
            tracker.refresh_from_db()

        assert flaw.acl_read == public_read_groups
        for i, affect in enumerate(affects):
            assert affect.acl_read == public_read_groups, f"Affect {i} must be public"
        for i, tracker in enumerate(trackers):
            assert tracker.acl_read == public_read_groups, f"Tracker {i} must be public"

    @pytest.mark.django_db
    def test_workflow_transition_updates_acls(self, public_read_groups):
        """Workflow state transitions correctly update ACLs."""
        flaw = FlawFactory(
            workflow_state=Flaw.WorkflowState.TRIAGE,
            embargoed=False,
        )

        ps_module = PsModuleFactory()
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_update_stream=ps_stream.name,
            ps_component="test-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        flaw.workflow_state = Flaw.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.adjust_acls(save=True)

        flaw.refresh_from_db()
        affect.refresh_from_db()
        tracker.refresh_from_db()

        assert flaw.acl_read == public_read_groups
        assert affect.acl_read == public_read_groups
        assert tracker.acl_read == public_read_groups


class TestAtomicRequestConfiguration:
    """Verify Django's ATOMIC_REQUESTS is enabled for consistency."""

    def test_atomic_requests_enabled(self, settings):
        """Django ATOMIC_REQUESTS setting ensures all HTTP requests are atomic."""
        assert settings.DATABASES["default"]["ATOMIC_REQUESTS"] is True, (
            "ATOMIC_REQUESTS must be True to ensure ACL update consistency. "
            "This wraps every HTTP request in a database transaction, "
            "guaranteeing all-or-nothing behavior for ACL updates."
        )


class TestAtomicRollbackOnFailure:
    """Verify transactions rollback correctly when failures occur during ACL updates."""

    @pytest.fixture
    def embargoed_flaw_with_nested_entities(
        self, embargoed_read_groups, embargoed_write_groups
    ):
        """Create an embargoed Flaw with Affects and Trackers."""
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

        return {
            "flaw": flaw,
            "affect": affect,
            "tracker": tracker,
        }

    @pytest.mark.django_db
    def test_rollback_when_nested_update_fails(
        self,
        embargoed_read_groups,
        internal_read_groups,
        internal_write_groups,
    ):
        """When set_public_nested fails during workflow transition, all ACL changes rollback."""
        from unittest.mock import patch

        # Create INTERNAL flaw (not embargoed, but internal ACLs) for workflow transition test
        ps_module = PsModuleFactory()
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw = FlawFactory(
            embargoed=False,
            unembargo_dt=datetime(2000, 1, 1, tzinfo=timezone.utc),
            workflow_state=Flaw.WorkflowState.TRIAGE,
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

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=False,
            ps_update_stream=ps_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
        )

        # Store original ACLs
        original_flaw_acls = list(flaw.acl_read)
        original_affect_acls = list(affect.acl_read)
        original_tracker_acls = list(tracker.acl_read)

        # Verify flaw is internal
        assert flaw.is_internal

        # Inject failure in set_public_nested (called by adjust_acls during workflow transition)
        def failing_set_public_nested(self, *args, **kwargs):
            raise Exception("Simulated failure during nested ACL update")

        with patch.object(Flaw, "set_public_nested", failing_set_public_nested):
            with pytest.raises(Exception, match="Simulated failure during nested"):
                flaw.workflow_state = Flaw.WorkflowState.PRE_SECONDARY_ASSESSMENT
                flaw.adjust_acls(save=True)

        # Refresh from database to see actual state
        flaw.refresh_from_db()
        affect.refresh_from_db()
        tracker.refresh_from_db()

        # All should have original ACLs (rollback occurred)
        assert list(flaw.acl_read) == original_flaw_acls, (
            "Flaw ACLs must rollback after failure"
        )
        assert list(affect.acl_read) == original_affect_acls, (
            "Affect ACLs must rollback after failure"
        )
        assert list(tracker.acl_read) == original_tracker_acls, (
            "Tracker ACLs must rollback after failure"
        )
        # Workflow state should also be unchanged
        assert flaw.workflow_state == Flaw.WorkflowState.TRIAGE

    @pytest.mark.django_db
    def test_rollback_when_history_update_fails(
        self,
        embargoed_flaw_with_nested_entities,
        embargoed_read_groups,
    ):
        """When set_history_public fails during unembargo, all ACL changes rollback."""
        from unittest.mock import patch

        flaw = embargoed_flaw_with_nested_entities["flaw"]
        affect = embargoed_flaw_with_nested_entities["affect"]
        tracker = embargoed_flaw_with_nested_entities["tracker"]

        # Store original ACLs
        original_flaw_acls = list(flaw.acl_read)
        original_affect_acls = list(affect.acl_read)
        original_tracker_acls = list(tracker.acl_read)

        # Inject failure in set_history_public
        def failing_set_history_public(self):
            raise Exception("Simulated failure during pghistory ACL update")

        with patch.object(Flaw, "set_history_public", failing_set_history_public):
            with pytest.raises(Exception, match="Simulated failure during pghistory"):
                flaw.unembargo_dt = datetime(2000, 1, 1, tzinfo=timezone.utc)
                flaw.unembargo()

        # Refresh from database
        flaw.refresh_from_db()
        affect.refresh_from_db()
        tracker.refresh_from_db()

        # All should still be embargoed (rollback occurred)
        assert list(flaw.acl_read) == original_flaw_acls
        assert list(affect.acl_read) == original_affect_acls
        assert list(tracker.acl_read) == original_tracker_acls

    @pytest.mark.django_db
    def test_rollback_when_recursive_unembargo_fails(
        self,
        embargoed_flaw_with_nested_entities,
        embargoed_read_groups,
    ):
        """When recursive unembargo of nested entity fails, all changes rollback."""
        from unittest.mock import patch

        flaw = embargoed_flaw_with_nested_entities["flaw"]
        affect = embargoed_flaw_with_nested_entities["affect"]
        tracker = embargoed_flaw_with_nested_entities["tracker"]

        original_flaw_acls = list(flaw.acl_read)
        original_affect_acls = list(affect.acl_read)
        original_tracker_acls = list(tracker.acl_read)

        # Track how many times unembargo is called
        call_count = {"count": 0}
        original_unembargo = Affect.unembargo

        def failing_unembargo_on_affect(self):
            call_count["count"] += 1
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
        assert list(flaw.acl_read) == original_flaw_acls
        assert list(affect.acl_read) == original_affect_acls
        assert list(tracker.acl_read) == original_tracker_acls

    @pytest.mark.django_db
    def test_set_history_public_failure_during_workflow_transition(
        self,
        internal_read_groups,
        internal_write_groups,
    ):
        """When set_history_public fails during workflow transition, all changes rollback."""
        from unittest.mock import patch

        ps_module = PsModuleFactory()
        ps_stream = PsUpdateStreamFactory(ps_module=ps_module)

        # Create INTERNAL flaw for workflow transition test
        flaw = FlawFactory(
            embargoed=False,
            unembargo_dt=datetime(2000, 1, 1, tzinfo=timezone.utc),
            workflow_state=Flaw.WorkflowState.TRIAGE,
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

        original_flaw_acls = list(flaw.acl_read)
        original_affect_acls = list(affect.acl_read)

        # Inject failure in set_history_public during workflow transition
        def failing_set_history_public(self):
            raise Exception("Simulated failure during pghistory update in workflow")

        with patch.object(Flaw, "set_history_public", failing_set_history_public):
            with pytest.raises(Exception, match="Simulated failure during pghistory"):
                flaw.workflow_state = Flaw.WorkflowState.PRE_SECONDARY_ASSESSMENT
                flaw.adjust_acls(save=True)

        # Refresh from database
        flaw.refresh_from_db()
        affect.refresh_from_db()

        # ACLs should be unchanged (rollback occurred)
        assert list(flaw.acl_read) == original_flaw_acls
        assert list(affect.acl_read) == original_affect_acls
        # Workflow state should also be unchanged
        assert flaw.workflow_state == Flaw.WorkflowState.TRIAGE
