"""
Tests for classification change tracking functionality
"""

import pytest

from apps.workflows.tracking import ClassificationChangeType
from osidb.acls import ACL
from osidb.models import Impact
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestClassificationTracking:
    """Test classification change tracking with reasoning"""

    @pytest.mark.enable_signals
    def test_flaw_without_task_key_no_classification(self):
        """Verify that flaws without task_key don't get classified or tracked"""
        flaw = FlawFactory(
            embargoed=False,
            task_key="",  # No task key
        )

        # Verify no classification history for flaws without task_key
        assert len(flaw.classification_meta) == 0
        assert flaw.workflow_name == ""
        assert flaw.workflow_state == ""

    @pytest.mark.enable_signals
    def test_initial_classification(self):
        """Verify that a newly created flaw has an initial classification record"""
        flaw = FlawFactory(
            embargoed=False,
            task_key="TEST-INITIAL",
        )

        # Verify initial classification was tracked
        assert len(flaw.classification_meta) > 0
        initial_record = flaw.classification_meta[0]

        assert (
            initial_record["change_type"]
            == ClassificationChangeType.INITIAL_CLASSIFICATION
        )
        assert initial_record["workflow"] == flaw.workflow_name
        assert initial_record["state"] == flaw.workflow_state
        assert "reason" in initial_record
        assert "Initial classification" in initial_record["reason"]["explanation"]

    @pytest.mark.enable_signals
    def test_state_progression(self):
        """Verify CWE addition triggers state progression with correct reasoning"""
        flaw = FlawFactory(
            embargoed=False,
            task_key="TEST-1",
            impact=Impact.MODERATE,
            cwe_id="",  # Missing CWE
        )
        initial_state = flaw.workflow_state

        # Add CWE to trigger progression
        flaw.cwe_id = "CWE-79"
        flaw.save(raise_validation_error=False)

        # Verify classification changed
        assert flaw.workflow_state != initial_state

        # Verify change was tracked
        assert len(flaw.classification_meta) > 0
        change = flaw.classification_meta[-1]  # Latest change

        assert change["change_type"] == ClassificationChangeType.STATE_PROGRESSION
        assert change["state"] == flaw.workflow_state
        assert change["workflow"] == flaw.workflow_name
        assert "reason" in change
        assert "requirements_satisfied" in change["reason"]
        # Should mention CWE in the satisfied requirements
        req_names = [r["name"] for r in change["reason"]["requirements_satisfied"]]
        assert any("CWE" in name or "cwe" in name.lower() for name in req_names)
        # Explanation should mention both old and new states for context
        assert initial_state in change["reason"]["explanation"]
        assert flaw.workflow_state in change["reason"]["explanation"]

    @pytest.mark.enable_signals
    def test_state_regression(self):
        """Verify clearing requirements triggers state regression with correct reasoning"""
        # Explicitly set all TRIAGE requirements to ensure we start there
        flaw = FlawFactory(
            embargoed=False,
            task_key="TEST-2",
            impact=Impact.MODERATE,
            cwe_id="CWE-79",  # Ensure CWE is set
            components=["kernel"],
        )
        flaw.save(raise_validation_error=False)
        advanced_state = flaw.workflow_state
        assert advanced_state == "TRIAGE"  # Should be at TRIAGE

        # Clear CWE to trigger regression back to NEW
        flaw.cwe_id = ""
        flaw.save(raise_validation_error=False)

        # Verify state regressed back to NEW
        assert flaw.workflow_state == "NEW"
        assert flaw.workflow_state != advanced_state

        # Verify regression was tracked
        assert len(flaw.classification_meta) > 0
        # Find the regression record (might not be first if progression was also tracked)
        regression_record = next(
            (
                r
                for r in flaw.classification_meta
                if r["change_type"] == ClassificationChangeType.STATE_REGRESSION
            ),
            None,
        )
        assert regression_record is not None
        assert regression_record["state"] == "NEW"
        assert "requirements_unsatisfied" in regression_record["reason"]
        # Should mention CWE in the unsatisfied requirements
        req_names = [
            r["name"] for r in regression_record["reason"]["requirements_unsatisfied"]
        ]
        assert any("CWE" in name or "cwe" in name.lower() for name in req_names)
        # Explanation should mention both states
        assert "TRIAGE" in regression_record["reason"]["explanation"]
        assert "NEW" in regression_record["reason"]["explanation"]

    @pytest.mark.enable_signals
    def test_workflow_promotion(self):
        """Verify embargo triggers workflow change to EMBARGOED"""
        flaw = FlawFactory(
            embargoed=False,
            task_key="TEST-3",
            impact=Impact.MODERATE,
        )
        assert flaw.workflow_name == "DEFAULT"

        # Embargo the flaw to trigger workflow change
        flaw.set_acls(ACL.EMBARGO)
        flaw.save(raise_validation_error=False)

        # Verify workflow changed
        assert flaw.workflow_name == "EMBARGOED"

        # Verify change was tracked
        assert len(flaw.classification_meta) > 0
        change = flaw.classification_meta[-1]  # Latest change

        assert change["change_type"] == ClassificationChangeType.WORKFLOW_PROMOTION
        assert change["workflow"] == "EMBARGOED"
        assert "reason" in change
        # Explanation should mention both workflows
        assert "DEFAULT" in change["reason"]["explanation"]
        assert "EMBARGOED" in change["reason"]["explanation"]

    @pytest.mark.enable_signals
    def test_workflow_demotion(self):
        """Verify unembargo triggers workflow change back to DEFAULT"""
        flaw = FlawFactory(
            embargoed=True,
            task_key="TEST-4",
            impact=Impact.MODERATE,
        )
        assert flaw.workflow_name == "EMBARGOED"

        # Lift embargo to trigger workflow change
        flaw.set_public()
        flaw.save(raise_validation_error=False)

        # Verify workflow changed back
        assert flaw.workflow_name == "DEFAULT"

        # Verify change was tracked
        assert len(flaw.classification_meta) > 0
        change = flaw.classification_meta[-1]  # Latest change

        assert change["change_type"] == ClassificationChangeType.WORKFLOW_DEMOTION
        assert change["workflow"] == "DEFAULT"
        # Explanation should mention both workflows
        assert "EMBARGOED" in change["reason"]["explanation"]
        assert "DEFAULT" in change["reason"]["explanation"]

    @pytest.mark.enable_signals
    def test_no_change_no_record(self):
        """Verify saves without classification change don't add records"""
        flaw = FlawFactory(
            embargoed=False,
            task_key="TEST-5",
        )
        initial_count = len(flaw.classification_meta)

        # Make a change that doesn't affect classification
        flaw.title = flaw.title + " - updated"
        flaw.save(raise_validation_error=False)

        # Verify no new tracking record was added
        assert len(flaw.classification_meta) == initial_count

    @pytest.mark.enable_signals
    def test_multiple_changes_tracked_in_order(self):
        """Verify multiple classification changes are all tracked in chronological order (oldest first)"""
        flaw = FlawFactory(
            embargoed=False,
            task_key="TEST-6",
            impact=Impact.MODERATE,
            cwe_id="",
            components=[],
        )

        # Make first change - add CWE
        flaw.cwe_id = "CWE-79"
        flaw.save(raise_validation_error=False)
        first_change_count = len(flaw.classification_meta)
        assert first_change_count > 0

        # Make second change - add components
        flaw.components = ["kernel"]
        flaw.save(raise_validation_error=False)
        second_change_count = len(flaw.classification_meta)
        assert second_change_count > first_change_count

        # Verify oldest change is first (initial classification)
        oldest_change = flaw.classification_meta[0]
        assert (
            oldest_change["change_type"]
            == ClassificationChangeType.INITIAL_CLASSIFICATION
        )

        # Verify newest change is last (components addition)
        latest_change = flaw.classification_meta[-1]
        assert (
            "components" in str(latest_change).lower()
            or "component"
            in latest_change.get("reason", {}).get("explanation", "").lower()
        )

    @pytest.mark.enable_signals
    def test_change_record_structure(self):
        """Verify change records have all required fields"""
        flaw = FlawFactory(
            embargoed=False,
            task_key="TEST-7",
            impact=Impact.MODERATE,
            cwe_id="",
        )

        # Trigger a change
        flaw.cwe_id = "CWE-79"
        flaw.save(raise_validation_error=False)

        assert len(flaw.classification_meta) > 0
        change = flaw.classification_meta[-1]  # Latest change

        # Verify required fields
        assert "timestamp" in change
        assert "workflow" in change
        assert "state" in change
        assert "change_type" in change
        assert "reason" in change
        assert "explanation" in change["reason"]

    @pytest.mark.enable_signals
    def test_condition_description_in_tracking(self):
        """Verify that OR/AND conditions have composed descriptions in tracking records"""
        # Create flaw with low impact and no CVE description to test OR condition
        # The TRIAGE state has: OR(impact is low, has cve_description)
        flaw = FlawFactory(
            embargoed=False,
            task_key="TEST-8",
            impact="LOW",
            cve_description="",  # Missing CVE description
            cwe_id="",
        )
        initial_state = flaw.workflow_state

        # Add CWE to trigger progression to TRIAGE
        # This will satisfy the OR condition (impact is low)
        flaw.cwe_id = "CWE-79"
        flaw.save(raise_validation_error=False)

        # Verify state progressed to TRIAGE
        assert flaw.workflow_state == "TRIAGE"
        assert flaw.workflow_state != initial_state

        # Verify tracking record exists
        assert len(flaw.classification_meta) > 0
        change = flaw.classification_meta[-1]  # Latest change

        # Find the OR condition in satisfied requirements
        satisfied_reqs = change["reason"]["requirements_satisfied"]
        or_condition = next((r for r in satisfied_reqs if " OR " in r["name"]), None)

        # Verify the OR condition has both name and description composed
        assert or_condition is not None
        assert " OR " in or_condition["name"]
        assert " OR " in or_condition["description"]
        # Description should be composed from individual check descriptions
        assert isinstance(or_condition["description"], str)
        assert len(or_condition["description"]) > 0
