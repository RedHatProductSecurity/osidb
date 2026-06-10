"""
workflow definitions validation tests
"""

import pytest

from apps.workflows.workflow import WorkflowFramework
from osidb.models import Affect, FlawCollaborator, FlawLabel, Impact
from osidb.tests.factories import AffectFactory, FlawFactory, TrackerFactory

pytestmark = pytest.mark.unit


class TestWorkflows:
    @pytest.fixture()
    def workflows(self):
        return WorkflowFramework().workflows

    def test_workflow_framework_uniqueness(self):
        """test that there always exists only one workflow framework"""
        workflow_framework1 = WorkflowFramework()
        workflow_framework2 = WorkflowFramework()
        assert workflow_framework1 is workflow_framework2

    def test_workflow_exists(self, workflows):
        """test that some workflow exists"""
        assert len(workflows)

    def test_workflow_name_unique(self, workflows):
        """test that every workflow has a unique name"""
        assert len(set(w.name for w in workflows)) == len(workflows)

    def test_workflow_priority_unique(self, workflows):
        """test that every workflow has a unique priority"""
        assert len(set(w.priority for w in workflows)) == len(workflows)

    def test_workflow_priority_non_negative(self, workflows):
        """test that every workflow has a non-negative priority"""
        assert all(isinstance(w.priority, int) for w in workflows)
        assert all(w.priority >= 0 for w in workflows)

    def test_workflow_priority_order(self, workflows):
        """test that the workflows are ordered by decreasing priority"""
        for i in range(len(workflows)):
            if i + 1 < len(workflows):
                assert workflows[i].priority > workflows[i + 1].priority

    def test_default_workflow_exists(self, workflows):
        """
        test that there exists a default workflow with empty conditions
        """
        assert any(not workflow.conditions for workflow in workflows)

    def test_non_empty_states(self, workflows):
        """test that every workflow has non-empty states"""
        assert all(w.states for w in workflows)

    def test_draft_state_exists(self, workflows):
        """test that the initial state of every workflow has empty requirements"""
        assert all(not w.states[0].requirements for w in workflows)

    def test_state_name_unique(self, workflows):
        """test that every state in a workflow has a unique name"""
        for workflow in workflows:
            assert len(set(s.name for s in workflow.states)) == len(workflow.states)


class TestDefaultWorkflow:
    """
    Test the DEFAULT workflow end-to-end, walking a flaw through all states
    and verifying that requirements gate each transition correctly.

    Child model operations (creating affects, linking trackers, creating labels)
    should automatically trigger flaw reclassification via signals — no explicit
    flaw.save() needed after them.
    """

    @pytest.mark.enable_signals
    def test_default_workflow_full_traversal(self):
        """
        Walk a flaw through NEW → TRIAGE → PRE_SECONDARY_ASSESSMENT →
        SECONDARY_ASSESSMENT → DONE, verifying each requirement gates progression.

        Note: title and comment_zero must be non-empty at creation time due to
        Django's model-level blank=False constraint. These fields are tested
        for regression in test_default_workflow_regression instead.
        """
        # Start with a minimal flaw — title/comment_zero required by Django,
        # all other fields left empty to test as gates
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-1",
            owner="",
            source="",
            impact="",
            components=[],
            reported_dt=None,
        )
        assert flaw.workflow_name == "DEFAULT"
        assert flaw.workflow_state == "NEW"

        # --- NEW → TRIAGE: requires owner ---
        flaw.owner = "analyst@redhat.com"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        # --- TRIAGE → PRE_SECONDARY_ASSESSMENT: requires affects, impact,
        #     source, components, reported_dt (title already set) ---

        # add requirements one by one, verify flaw stays in TRIAGE until all present
        flaw.source = "INTERNET"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        flaw.impact = Impact.MODERATE
        flaw.cve_description = "A vulnerability in the kernel"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        flaw.components = ["kernel"]
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        flaw.reported_dt = flaw.created_dt
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        # still missing affects — creating one triggers reclassification via signal
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # --- PRE_SECONDARY_ASSESSMENT → SECONDARY_ASSESSMENT: requires trackers ---

        # file a tracker and link it to the affect — signal triggers reclassification
        tracker = TrackerFactory.build(
            embargoed=False,
            ps_update_stream=affect.ps_update_stream,
        )
        tracker.save()
        affect.tracker = tracker
        affect.save(raise_validation_error=False)
        assert flaw.workflow_state == "SECONDARY_ASSESSMENT"

        # --- SECONDARY_ASSESSMENT → DONE: requires label approved ---

        # creating the label triggers reclassification via signal
        FlawCollaborator.objects.create(
            flaw=flaw,
            label="approved",
            type=FlawLabel.FlawLabelType.WORKFLOW,
            contributor="reviewer@redhat.com",
        )
        assert flaw.workflow_state == "DONE"
        assert flaw.workflow_name == "DEFAULT"

    @pytest.mark.enable_signals
    def test_default_workflow_regression(self):
        """
        Verify that removing a previously-satisfied requirement causes
        the flaw to regress to the last valid state.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-2",
            owner="analyst@redhat.com",
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # clear owner — should regress past TRIAGE back to NEW
        flaw.owner = ""
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        # restore owner — should advance back to PRE_SECONDARY_ASSESSMENT
        flaw.owner = "analyst@redhat.com"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # clear source — should regress to TRIAGE
        flaw.source = ""
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        # restore source
        flaw.source = "INTERNET"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # clear components — should regress to TRIAGE
        flaw.components = []
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        # restore components
        flaw.components = ["kernel"]
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

    @pytest.mark.enable_signals
    def test_label_removal_triggers_regression(self):
        """
        Verify that deleting an "approved" label triggers reclassification
        and the flaw regresses from DONE.
        """
        # build a flaw all the way to DONE
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-3",
            owner="analyst@redhat.com",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        tracker = TrackerFactory.build(
            embargoed=False,
            ps_update_stream=affect.ps_update_stream,
        )
        tracker.save()
        affect.tracker = tracker
        affect.save(raise_validation_error=False)
        collaborator = FlawCollaborator.objects.create(
            flaw=flaw,
            label="approved",
            type=FlawLabel.FlawLabelType.WORKFLOW,
            contributor="reviewer@redhat.com",
        )
        assert flaw.workflow_state == "DONE"

        # remove the approved label — should regress
        collaborator.delete()
        flaw.refresh_from_db()
        assert flaw.workflow_state == "SECONDARY_ASSESSMENT"

    @pytest.mark.enable_signals
    def test_cve_description_or_low_impact(self):
        """
        Verify the OR condition: PRE_SECONDARY_ASSESSMENT requires either
        LOW impact or a non-empty cve_description. A MODERATE-impact flaw
        without cve_description stays in TRIAGE; adding the description
        or switching to LOW impact advances it.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OR",
            owner="analyst@redhat.com",
            impact=Impact.MODERATE,
            cve_description="",
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        # adding cve_description satisfies the OR condition
        flaw.cve_description = "A vulnerability in the kernel"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # removing cve_description regresses back to TRIAGE
        flaw.cve_description = ""
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        # switching to LOW impact also satisfies the OR condition
        flaw.impact = Impact.LOW
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

    @pytest.mark.enable_signals
    def test_no_classification_without_task_key(self):
        """
        Verify that a flaw without task_key has empty workflow fields
        regardless of how much data it has.
        """
        flaw = FlawFactory(embargoed=False, task_key="")
        AffectFactory(flaw=flaw)
        flaw.owner = "analyst@redhat.com"
        flaw.save(raise_validation_error=False)

        assert flaw.workflow_name == ""
        assert flaw.workflow_state == ""
