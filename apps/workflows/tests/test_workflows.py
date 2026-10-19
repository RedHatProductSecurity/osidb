"""
workflow definitions validation tests
"""

import threading
import time
from datetime import datetime

import pytest
from django.conf import settings
from django.db import connection, transaction
from django.utils.timezone import make_aware, now

from apps.workflows.workflow import WorkflowFramework
from osidb.core import set_user_acls
from osidb.models import Affect, Flaw, Impact, WorkflowLabel
from osidb.models.flaw import flaw as flaw_module
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
        Walk a flaw through NEW → TRIAGE → ANALYSIS → PRE_SECONDARY_ASSESSMENT →
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
            cwe_id="",
            cve_description="",
        )
        assert flaw.workflow_name == "DEFAULT"
        assert flaw.workflow_state == "NEW"

        # --- NEW → TRIAGE: requires components, CWE, impact, reported_dt,
        #     source, title, and (impact is low OR has cve_description) ---

        # add requirements one by one, verify flaw stays in NEW until all present
        flaw.source = "INTERNET"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        flaw.components = ["kernel"]
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        flaw.cwe_id = "CWE-79"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        flaw.impact = Impact.MODERATE
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        flaw.reported_dt = flaw.created_dt
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        # title is already set by FlawFactory, still missing the OR condition
        # (impact is low OR has cve_description) — MODERATE impact needs cve_description
        flaw.cve_description = "A vulnerability in the kernel"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        # --- TRIAGE → ANALYSIS: requires affects ---

        # creating an affect triggers reclassification via signal
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        assert flaw.workflow_state == "ANALYSIS"

        # --- ANALYSIS → PRE_SECONDARY_ASSESSMENT: requires affects resolved ---

        affect.affectedness = Affect.AffectAffectedness.AFFECTED
        affect.resolution = Affect.AffectResolution.DELEGATED
        affect.save(raise_validation_error=False)
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
        WorkflowLabel.objects.create(
            flaw=flaw,
            name="approved",
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
            impact=Impact.MODERATE,
            task_key="TASK-2",
            owner="analyst@redhat.com",
            cwe_id="CWE-79",
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # clear CWE — should regress past TRIAGE back to NEW
        flaw.cwe_id = ""
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        # restore CWE — should advance back to PRE_SECONDARY_ASSESSMENT
        flaw.cwe_id = "CWE-79"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # clear source — should regress to NEW (source is a TRIAGE requirement)
        flaw.source = ""
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        # restore source — should advance back to PRE_SECONDARY_ASSESSMENT
        flaw.source = "INTERNET"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # clear components — should regress to NEW (components is a TRIAGE requirement)
        flaw.components = []
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        # restore components
        flaw.components = ["kernel"]
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

    @pytest.mark.enable_signals
    def test_notaffected_advances_past_analysis(self):
        """
        Verify that a NOTAFFECTED affect (which has no resolution)
        is treated as resolved and advances the flaw past ANALYSIS.

        NOTAFFECTED also doesn't require trackers so the flaw advances
        all the way to SECONDARY_ASSESSMENT (blocked only by has label approved).
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-100",
            owner="analyst@redhat.com",
            impact=Impact.MODERATE,
            cwe_id="CWE-79",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "ANALYSIS"

        affect.affectedness = Affect.AffectAffectedness.NOTAFFECTED
        affect.save(raise_validation_error=False)
        assert flaw.workflow_state == "SECONDARY_ASSESSMENT"

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
            cwe_id="CWE-79",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        tracker = TrackerFactory.build(
            embargoed=False,
            ps_update_stream=affect.ps_update_stream,
        )
        tracker.save()
        affect.tracker = tracker
        affect.save(raise_validation_error=False)
        label = WorkflowLabel.objects.create(
            flaw=flaw,
            name="approved",
        )
        assert flaw.workflow_state == "DONE"

        # remove the approved label — should regress
        label.delete()
        flaw.refresh_from_db()
        assert flaw.workflow_state == "SECONDARY_ASSESSMENT"

    @pytest.mark.enable_signals
    def test_resolved_dt_being_set_correctly(self):
        """
        resolved_dt is stamped when a flaw enters DONE and cleared when it leaves.
        """
        # build a flaw all the way to DONE
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-123",
            owner="analyst@redhat.com",
            cwe_id="CWE-79",
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        tracker = TrackerFactory.build(
            embargoed=False,
            ps_update_stream=affect.ps_update_stream,
        )
        tracker.save()
        affect.tracker = tracker
        affect.save(raise_validation_error=False)

        # not resolved before reaching DONE
        assert flaw.resolved_dt is None

        before = now()
        label = WorkflowLabel.objects.create(flaw=flaw, name="approved")
        after = now()

        # entering DONE stamps resolved_dt with the current time
        assert flaw.workflow_state == "DONE"
        assert flaw.resolved_dt is not None
        assert before <= flaw.resolved_dt <= after

        flaw.refresh_from_db()
        assert flaw.resolved_dt is not None  # persisted

        # leaving DONE clears it
        label.delete()
        flaw.refresh_from_db()
        assert flaw.workflow_state != "DONE"
        assert flaw.resolved_dt is None

    @pytest.mark.enable_signals
    def test_cwe_requirement_for_triage(self):
        """
        Verify that CWE is required to reach TRIAGE state.
        A flaw with all other TRIAGE requirements but missing CWE stays in NEW.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-CWE",
            source="INTERNET",
            impact=Impact.LOW,
            components=["kernel"],
            cwe_id="",
        )
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        flaw.cwe_id = "CWE-79"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "TRIAGE"

        flaw.cwe_id = ""
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

    @pytest.mark.enable_signals
    def test_cve_description_or_low_impact(self):
        """
        Verify the OR condition: TRIAGE requires either LOW impact or a
        non-empty cve_description. A MODERATE-impact flaw without
        cve_description stays in NEW; adding the description or switching
        to LOW impact advances it.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OR",
            owner="analyst@redhat.com",
            impact=Impact.MODERATE,
            cve_description="",
            cwe_id="CWE-79",
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        # adding cve_description satisfies the OR condition → advances through TRIAGE
        flaw.cve_description = "A vulnerability in the kernel"
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"

        # removing cve_description regresses back to NEW
        flaw.cve_description = ""
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "NEW"

        # switching to LOW impact also satisfies the OR condition
        flaw.impact = Impact.LOW
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_state == "PRE_SECONDARY_ASSESSMENT"


class TestManualWorkflow:
    """
    Test the MANUAL workflow conditions — flaws with manual-triage or
    potential-rejection labels should be classified under MANUAL.
    """

    @pytest.mark.enable_signals
    def test_manual_triage_label_triggers_manual_workflow(self):
        """
        A flaw with a manual-triage label should be classified under the
        MANUAL workflow instead of DEFAULT.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-MANUAL-1",
            impact=Impact.MODERATE,
        )
        assert flaw.workflow_name == "DEFAULT"

        WorkflowLabel.objects.create(flaw=flaw, name="manual-triage")
        flaw.refresh_from_db()
        assert flaw.workflow_name == "MANUAL"
        assert flaw.workflow_state == "NEW"

    @pytest.mark.enable_signals
    def test_potential_rejection_label_triggers_manual_workflow(self):
        """
        A flaw with a potential-rejection label (set by ACE) should be
        classified under the MANUAL workflow for human review.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-MANUAL-2",
            impact=Impact.MODERATE,
        )
        assert flaw.workflow_name == "DEFAULT"

        WorkflowLabel.objects.create(flaw=flaw, name="potential-rejection")
        flaw.refresh_from_db()
        assert flaw.workflow_name == "MANUAL"
        assert flaw.workflow_state == "NEW"

    @pytest.mark.enable_signals
    def test_removing_label_reverts_to_default_workflow(self):
        """
        Removing the potential-rejection label should reclassify the flaw
        back to the DEFAULT workflow.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-MANUAL-3",
            impact=Impact.MODERATE,
        )
        label = WorkflowLabel.objects.create(flaw=flaw, name="potential-rejection")
        flaw.refresh_from_db()
        assert flaw.workflow_name == "MANUAL"

        label.delete()
        flaw.refresh_from_db()
        assert flaw.workflow_name == "DEFAULT"

    @pytest.mark.enable_signals
    def test_either_label_satisfies_manual_condition(self):
        """
        The MANUAL workflow condition is an OR — either manual-triage or
        potential-rejection is sufficient. Having both should also work.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-MANUAL-4",
            impact=Impact.MODERATE,
        )
        label1 = WorkflowLabel.objects.create(flaw=flaw, name="manual-triage")
        flaw.refresh_from_db()
        assert flaw.workflow_name == "MANUAL"

        WorkflowLabel.objects.create(flaw=flaw, name="potential-rejection")
        flaw.refresh_from_db()
        assert flaw.workflow_name == "MANUAL"

        # removing one label should keep it MANUAL (the other still satisfies)
        label1.delete()
        flaw.refresh_from_db()
        assert flaw.workflow_name == "MANUAL"

    @pytest.mark.enable_signals
    def test_critical_impact_triggers_manual_workflow(self):
        """
        A flaw with CRITICAL impact should be classified under the MANUAL
        workflow even without any manual-triage or potential-rejection label.
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-MANUAL-5",
            impact=Impact.CRITICAL,
        )
        assert flaw.workflow_name == "MANUAL"
        assert flaw.workflow_state == "NEW"

    @pytest.mark.enable_signals
    def test_non_critical_impact_stays_default(self):
        """
        A flaw with non-CRITICAL impact and no manual labels should remain
        in the DEFAULT workflow.
        """
        for impact in [Impact.LOW, Impact.MODERATE, Impact.IMPORTANT]:
            flaw = FlawFactory(
                embargoed=False,
                task_key=f"TASK-MANUAL-6-{impact}",
                impact=impact,
            )
            assert flaw.workflow_name == "DEFAULT"

    @pytest.mark.enable_signals
    def test_lowering_impact_from_critical_reverts_to_default(self):
        """
        Changing a flaw's impact from CRITICAL to a lower value should
        reclassify it back to the DEFAULT workflow (if no manual labels).
        """
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-MANUAL-7",
            impact=Impact.CRITICAL,
        )
        assert flaw.workflow_name == "MANUAL"

        flaw.impact = Impact.MODERATE
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_name == "DEFAULT"


class TestNoClassification:
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


class TestReclassificationDateGuard:
    """
    Flaws created before the configured cutoff that are already DONE must not
    be automatically re-classified (which would reopen them).
    """

    CUTOFF = make_aware(datetime(2026, 8, 3))

    @pytest.mark.enable_signals
    def test_old_done_flaw_not_reclassified(self, monkeypatch):
        """a pre-cutoff DONE flaw keeps its DONE state on re-classification"""
        monkeypatch.setattr(
            flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", self.CUTOFF
        )
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OLD-DONE",
            created_dt=make_aware(datetime(2025, 1, 1)),
        )
        # force DONE despite the flaw not qualifying for it
        flaw.classification = {"workflow": "DEFAULT", "state": "DONE"}

        flaw.adjust_classification(save=False)

        assert flaw.workflow_state == "DONE"

    @pytest.mark.enable_signals
    def test_recent_done_flaw_reclassified(self, monkeypatch):
        """a post-cutoff DONE flaw is still re-classified normally"""
        monkeypatch.setattr(
            flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", self.CUTOFF
        )
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-NEW-DONE",
            created_dt=make_aware(datetime(2026, 8, 10)),
        )
        flaw.classification = {"workflow": "DEFAULT", "state": "DONE"}

        flaw.adjust_classification(save=False)

        assert flaw.workflow_state != "DONE"

    @pytest.mark.enable_signals
    def test_no_restriction_when_cutoff_unset(self, monkeypatch):
        """with no cutoff configured even old DONE flaws are re-classified"""
        monkeypatch.setattr(flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", None)
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-UNSET",
            created_dt=make_aware(datetime(2020, 1, 1)),
        )
        flaw.classification = {"workflow": "DEFAULT", "state": "DONE"}

        flaw.adjust_classification(save=False)

        assert flaw.workflow_state != "DONE"

    @pytest.mark.enable_signals
    def test_old_non_done_flaw_reclassified(self, monkeypatch):
        """the guard only protects DONE flaws, not other pre-cutoff states"""
        monkeypatch.setattr(
            flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", self.CUTOFF
        )
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OLD-SA",
            created_dt=make_aware(datetime(2025, 1, 1)),
        )
        flaw.classification = {"workflow": "DEFAULT", "state": "SECONDARY_ASSESSMENT"}

        flaw.adjust_classification(save=False)

        assert flaw.workflow_state != "SECONDARY_ASSESSMENT"

    @pytest.mark.enable_signals
    def test_labeled_old_done_flaw_reclassified(self, monkeypatch):
        """
        a pre-cutoff DONE flaw opted in with the reclassification label is
        brought back under automatic classification
        """
        monkeypatch.setattr(
            flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", self.CUTOFF
        )
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OLD-DONE-OPTIN",
            created_dt=make_aware(datetime(2025, 1, 1)),
        )
        WorkflowLabel.objects.create(
            flaw=flaw, name=flaw_module.WORKFLOW_RECLASSIFICATION_LABEL
        )
        flaw.classification = {"workflow": "DEFAULT", "state": "DONE"}

        flaw.adjust_classification(save=False)

        assert flaw.workflow_state != "DONE"

    @pytest.mark.enable_signals
    def test_removing_label_reexcludes_old_done_flaw(self, monkeypatch):
        """
        removing the reclassification label re-excludes a pre-cutoff DONE flaw
        from automatic classification
        """
        monkeypatch.setattr(
            flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", self.CUTOFF
        )
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OLD-DONE-OPTOUT",
            created_dt=make_aware(datetime(2025, 1, 1)),
        )
        label = WorkflowLabel.objects.create(
            flaw=flaw, name=flaw_module.WORKFLOW_RECLASSIFICATION_LABEL
        )
        label.delete()
        flaw.classification = {"workflow": "DEFAULT", "state": "DONE"}

        flaw.adjust_classification(save=False)

        assert flaw.workflow_state == "DONE"

    @pytest.mark.enable_signals
    def test_excluded_flaw_gets_alert_when_change_suppressed(self, monkeypatch):
        """
        an excluded pre-cutoff DONE flaw carries the alert only when the
        exclusion actually suppresses a classification change
        """
        monkeypatch.setattr(
            flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", self.CUTOFF
        )
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OLD-DONE-ALERT",
            created_dt=make_aware(datetime(2025, 1, 1)),
        )
        flaw.classification = {"workflow": "DEFAULT", "state": "DONE"}
        # automatic classification would move it elsewhere, but it is suppressed
        monkeypatch.setattr(
            flaw, "classify", lambda: {"workflow": "DEFAULT", "state": "TRIAGE"}
        )
        flaw.save()

        assert flaw.valid_alerts.filter(name="flaw_reclassification_excluded").exists()

    @pytest.mark.enable_signals
    def test_excluded_flaw_no_alert_when_no_change(self, monkeypatch):
        """
        an excluded pre-cutoff DONE flaw whose computed classification matches
        the current one does not carry the alert - the exclusion changes nothing
        """
        monkeypatch.setattr(
            flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", self.CUTOFF
        )
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OLD-DONE-NODIFF",
            created_dt=make_aware(datetime(2025, 1, 1)),
        )
        flaw.classification = {"workflow": "DEFAULT", "state": "DONE"}
        # automatic classification agrees with the current state
        monkeypatch.setattr(
            flaw, "classify", lambda: {"workflow": "DEFAULT", "state": "DONE"}
        )
        flaw.save()

        assert not flaw.valid_alerts.filter(
            name="flaw_reclassification_excluded"
        ).exists()

    @pytest.mark.enable_signals
    def test_labeled_flaw_has_no_exclusion_alert(self, monkeypatch):
        """an opted-in flaw does not carry the exclusion alert"""
        monkeypatch.setattr(
            flaw_module, "WORKFLOW_RECLASSIFICATION_START_DATE", self.CUTOFF
        )
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-OLD-DONE-NOALERT",
            created_dt=make_aware(datetime(2025, 1, 1)),
        )
        WorkflowLabel.objects.create(
            flaw=flaw, name=flaw_module.WORKFLOW_RECLASSIFICATION_LABEL
        )
        flaw.classification = {"workflow": "DEFAULT", "state": "DONE"}
        monkeypatch.setattr(
            flaw, "classify", lambda: {"workflow": "DEFAULT", "state": "TRIAGE"}
        )
        flaw.save()

        assert not flaw.valid_alerts.filter(
            name="flaw_reclassification_excluded"
        ).exists()


class TestWorkflowSaveTransactionBoundary:
    """
    WorkflowModel.save() wraps super().save() in a transaction so the row lock
    taken by adjust_classification() in the pre_save is held through the actual
    write. That transaction must NOT span the external Bugzilla/Jira sync, or
    the row lock would be held across network I/O (lock contention / slow
    responses). This relies on the sync mixins sitting ABOVE WorkflowModel in
    the MRO, so their post-super().save() sync runs after the transaction
    commits. Guard that ordering - a reorder would still pass the functional
    tests but silently hold locks across I/O in production.
    """

    def test_sync_mixins_precede_workflow_model_in_mro(self):
        from apps.bbsync.mixins import BugzillaSyncMixin
        from apps.taskman.mixins import JiraTaskSyncMixin
        from apps.workflows.workflow import WorkflowModel

        mro = Flaw.__mro__
        workflow_model_index = mro.index(WorkflowModel)
        for sync_mixin in (BugzillaSyncMixin, JiraTaskSyncMixin):
            assert mro.index(sync_mixin) < workflow_model_index, (
                f"{sync_mixin.__name__} must precede WorkflowModel in Flaw's MRO "
                "so its external I/O runs after WorkflowModel.save()'s transaction "
                "commits, keeping the classification row lock off the network call"
            )


class TestClassificationRace:
    """
    Regression test for the classification race condition where a concurrent
    save could move an auto-rejected flaw back out of REJECTED/DONE (a lost
    update on the workflow_name/workflow_state fields).

    adjust_classification() takes a row lock and re-bases/re-computes the
    classification under it, so the last committer always observes the other
    transaction's committed label and REJECTED/DONE wins.
    """

    @staticmethod
    def _flaw_row_lock_waiters():
        """number of backends (other than this one) blocked writing a flaw row"""
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE wait_event_type = 'Lock' AND pid <> pg_backend_pid() "
                "AND query ILIKE '%osidb_flaw%'"
            )
            return cursor.fetchone()[0]

    @pytest.mark.enable_signals
    @pytest.mark.django_db(transaction=True)
    def test_concurrent_auto_reject_is_not_clobbered(self):
        """
        While one transaction auto-rejects a flaw (creates the terminal label
        and reclassifies to REJECTED/DONE), a second concurrent save that is
        itself a legitimate forward transition (the "bot" fills in the last
        missing datum and would promote the flaw out of NEW) must not overwrite
        the rejection back to DEFAULT/<state>.

        This mirrors the production race: osidb-bot completes the data needed to
        move NEW -> TRIAGE/ANALYSIS at the same time ACE finds the component
        rejectable and applies the terminal label. Without serialization the bot
        computes its classification from a pre-auto-rejection snapshot (no label
        visible), promotes the flaw, and its row UPDATE - committing last -
        clobbers the REJECTED/DONE written by the auto-rejection.

        The bot save skips alert recreation (``no_alerts=True``) so it blocks
        only on the flaw row lock - otherwise both saves would contend on the
        same alert unique index first, serializing them and masking the
        workflow-field race under test.
        """
        set_user_acls(settings.ALL_GROUPS)

        # created without a CWE the flaw misses the last NEW -> TRIAGE
        # requirement and so sits in NEW until the bot supplies it below
        flaw = FlawFactory(
            embargoed=False,
            task_key="TASK-CONCURRENT",
            owner="analyst@redhat.com",
            cwe_id="",
            impact=Impact.MODERATE,
        )
        AffectFactory(flaw=flaw)
        flaw.save(raise_validation_error=False)
        assert flaw.workflow_name == "DEFAULT"
        assert flaw.workflow_state == "NEW"
        flaw_pk = flaw.pk

        # the "bot" holds a copy read before the auto-rejection
        bot_flaw = Flaw.objects.get(pk=flaw_pk)

        errors: dict[str, BaseException] = {}
        system_holds_lock = threading.Event()
        system_can_commit = threading.Event()

        def system_worker():
            """auto-reject the flaw and hold the row lock until released"""
            try:
                set_user_acls(settings.ALL_GROUPS)
                with transaction.atomic():
                    # creating the terminal label reclassifies the flaw to
                    # REJECTED/DONE via the post_save signal, taking (and
                    # holding) the flaw row lock until this transaction commits
                    WorkflowLabel.objects.create(
                        flaw=Flaw.objects.get(pk=flaw_pk), name="auto-rejected"
                    )
                    system_holds_lock.set()
                    system_can_commit.wait(timeout=10)
            except BaseException as exc:  # noqa: BLE001
                errors["system"] = exc
                system_holds_lock.set()
            finally:
                connection.close()

        def bot_worker():
            """
            supply the missing CWE on the stale copy concurrently - this is a
            real forward transition (NEW -> TRIAGE/ANALYSIS), not a no-op edit
            """
            try:
                set_user_acls(settings.ALL_GROUPS)
                bot_flaw.cwe_id = "CWE-79"
                bot_flaw.save(raise_validation_error=False, no_alerts=True)
            except BaseException as exc:  # noqa: BLE001
                errors["bot"] = exc
            finally:
                connection.close()

        system_thread = threading.Thread(target=system_worker)
        system_thread.start()
        assert system_holds_lock.wait(timeout=10)
        assert "system" not in errors

        bot_thread = threading.Thread(target=bot_worker)
        bot_thread.start()

        # wait until the bot is blocked trying to write the flaw row, so that
        # its classification was necessarily computed before the auto-rejection
        # committed, then let the auto-rejection commit
        deadline = time.time() + 10
        blocked = False
        while time.time() < deadline:
            if self._flaw_row_lock_waiters() >= 1:
                blocked = True
                break
            time.sleep(0.05)
        system_can_commit.set()

        system_thread.join(timeout=15)
        bot_thread.join(timeout=15)

        # prove the intended interleaving actually happened: the bot must have
        # blocked on the flaw row lock (otherwise the race was not exercised),
        # and both workers must have finished (a hung worker would leave errors
        # empty and report a misleading pass)
        assert blocked, "bot writer never blocked on the flaw row lock"
        assert not system_thread.is_alive()
        assert not bot_thread.is_alive()
        assert not errors, errors

        final = Flaw.objects.get(pk=flaw_pk)
        # the auto-rejected conclusion must stick despite the concurrent
        # promotion attempt
        assert final.workflow_name == "REJECTED"
        assert final.workflow_state == "DONE"
        # the concurrent edit is still applied (the save was not lost, only its
        # stale classification was corrected)
        assert final.cwe_id == "CWE-79"
