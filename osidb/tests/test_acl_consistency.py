"""
Test ACL consistency and propagation.

Django's ATOMIC_REQUESTS=True ensures that all HTTP requests are atomic.
These tests verify that ACL updates propagate correctly to all nested entities.
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from osidb.models import Affect, AliasLabel, Tracker
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


class TestCollectObjectsForAclUpdate:
    """Verify _collect_objects_for_acl_update handles all relation types correctly."""

    @pytest.mark.django_db
    def test_no_typeerror_when_related_name_is_none(
        self,
        internal_read_groups,
        internal_write_groups,
        public_read_groups,
        public_write_groups,
    ):
        """
        Regression test for: TypeError: attribute name must be string, not 'NoneType'

        Polymorphic model subclasses (AliasLabel, BULabel, etc.) inherit from FlawLabelV2
        which is an ACLMixin. Django-polymorphic creates implicit OneToOneField back-pointers
        from each concrete subclass to the parent table. These reverse relations appear in
        FlawLabelV2._meta.related_objects with related_name=None. Since the subclasses ARE
        ACLMixin, they pass the issubclass check, and getattr(self, None).all() crashes.

        The fix filters out related objects where related_name is None.
        """
        flaw = FlawFactory(
            embargoed=False,
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
        )
        affect = AffectFactory(
            flaw=flaw,
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
        )
        AliasLabel.objects.create(
            flaw=flaw,
            name="CVE-2024-12345",
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
        )

        # set_acls_nested traverses into FlawLabelV2 instances, which have polymorphic
        # subclass back-pointers with related_name=None — this must not raise TypeError
        flaw.set_acls_nested(public_read_groups, public_write_groups)

        affect.refresh_from_db()
        assert affect.acl_read == public_read_groups
        assert affect.acl_write == public_write_groups

    @pytest.mark.django_db
    def test_unembargo_no_typeerror_when_related_name_is_none(
        self,
        embargoed_read_groups,
        embargoed_write_groups,
        public_read_groups,
        public_write_groups,
    ):
        """
        Regression test for: TypeError: attribute name must be string, not 'NoneType'
        in the unembargo() path (same root cause as set_acls_nested).

        unembargo() iterates _meta.related_objects to recursively unembargo related
        ACLMixin instances, but polymorphic back-pointers have related_name=None,
        causing getattr(self, None).all() to crash.
        """
        from datetime import datetime
        from datetime import timezone as dt_timezone

        flaw = FlawFactory(
            embargoed=True,
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )
        AliasLabel.objects.create(
            flaw=flaw,
            name="CVE-2024-12345",
            acl_read=embargoed_read_groups,
            acl_write=embargoed_write_groups,
        )

        flaw.unembargo_dt = datetime(2000, 1, 1, tzinfo=dt_timezone.utc)
        # unembargo traverses into FlawLabelV2 instances — must not raise TypeError
        flaw.unembargo()

        flaw.refresh_from_db()
        assert flaw.is_public
