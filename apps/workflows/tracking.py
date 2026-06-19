"""
Classification change tracking logic

Provides functions to track classification changes with human-readable reasoning,
helping users understand why automatic reclassification occurred.
"""

from django.db import models
from django.utils import timezone


class ClassificationChangeType(models.TextChoices):
    """Classification change type constants"""

    INITIAL_CLASSIFICATION = "INITIAL_CLASSIFICATION"
    STATE_PROGRESSION = "STATE_PROGRESSION"
    STATE_REGRESSION = "STATE_REGRESSION"
    WORKFLOW_PROMOTION = "WORKFLOW_PROMOTION"
    WORKFLOW_DEMOTION = "WORKFLOW_DEMOTION"
    NO_CHANGE = "NO_CHANGE"
    UNKNOWN = "UNKNOWN"


def find_requirement_diff(instance, old_state_obj, new_state_obj, workflow_obj):
    """
    Find which requirements changed between two states in the same workflow.

    Returns dict with:
    - requirements_satisfied: List of newly satisfied requirements
    - requirements_unsatisfied: List of newly unsatisfied requirements
    """
    # Get all states between old and new to find what was gained/lost
    state_names = [s.name for s in workflow_obj.states]

    try:
        old_idx = state_names.index(old_state_obj.name)
        new_idx = state_names.index(new_state_obj.name)
    except ValueError:
        # State not found in workflow (shouldn't happen)
        return {"requirements_satisfied": [], "requirements_unsatisfied": []}

    if new_idx > old_idx:
        # Progression - requirements between old and new were satisfied
        requirements_satisfied = []
        for i in range(old_idx + 1, new_idx + 1):
            state = workflow_obj.states[i]
            for req in state.requirements:
                if req(instance):  # Check if satisfied
                    requirements_satisfied.append(
                        {
                            "name": req.name,
                            "description": req.description,
                        }
                    )
        return {
            "requirements_satisfied": requirements_satisfied,
            "requirements_unsatisfied": [],
        }
    else:
        # Regression - requirements in new state's successors are no longer met
        requirements_unsatisfied = []
        for i in range(new_idx + 1, old_idx + 1):
            state = workflow_obj.states[i]
            for req in state.requirements:
                if not req(instance):  # Check if unsatisfied
                    requirements_unsatisfied.append(
                        {
                            "name": req.name,
                            "description": req.description,
                        }
                    )
        return {
            "requirements_satisfied": [],
            "requirements_unsatisfied": requirements_unsatisfied,
        }


def find_condition_diff(instance, old_workflow_obj, new_workflow_obj):
    """
    Find which conditions changed between two workflows.

    Returns dict with:
    - conditions_satisfied: List of newly satisfied conditions
    - conditions_unsatisfied: List of newly unsatisfied conditions
    """
    conditions_satisfied = []
    conditions_unsatisfied = []

    # Check which conditions in new workflow are now satisfied
    for condition in new_workflow_obj.conditions:
        if condition(instance):
            conditions_satisfied.append(
                {
                    "name": condition.name,
                    "description": condition.description,
                }
            )

    # Check which conditions in old workflow are no longer satisfied
    for condition in old_workflow_obj.conditions:
        if not condition(instance):
            conditions_unsatisfied.append(
                {
                    "name": condition.name,
                    "description": condition.description,
                }
            )

    return {
        "conditions_satisfied": conditions_satisfied,
        "conditions_unsatisfied": conditions_unsatisfied,
    }


def build_change_reason(
    change_type, diff, old_state, new_state, old_workflow, new_workflow
):
    """
    Build human-readable reason for the classification change.

    Returns dict with the reason structure for classification_meta.
    """
    reason = {}

    if change_type == ClassificationChangeType.INITIAL_CLASSIFICATION:
        reason["explanation"] = f"Initial classification: {new_workflow}:{new_state}"

    elif change_type == ClassificationChangeType.STATE_PROGRESSION:
        reason["requirements_satisfied"] = diff["requirements_satisfied"]
        req_names = [r["name"] for r in diff["requirements_satisfied"]]
        explanation = f"State progressed from {old_state} to {new_state}"
        reason["explanation"] = (
            f"{explanation} by satisfying: {', '.join(req_names)}"
            if req_names
            else f"{explanation}: requirements met"
        )

    elif change_type == ClassificationChangeType.STATE_REGRESSION:
        reason["requirements_unsatisfied"] = diff["requirements_unsatisfied"]
        req_names = [r["name"] for r in diff["requirements_unsatisfied"]]
        explanation = f"State regressed from {old_state} to {new_state}"
        reason["explanation"] = (
            f"{explanation} because these requirements are no longer satisfied: {', '.join(req_names)}"
            if req_names
            else f"{explanation}: requirements no longer met"
        )

    elif change_type == ClassificationChangeType.WORKFLOW_PROMOTION:
        reason["conditions_satisfied"] = diff["conditions_satisfied"]
        cond_names = [c["name"] for c in diff["conditions_satisfied"]]
        explanation = f"Workflow promoted from {old_workflow} to {new_workflow}"
        reason["explanation"] = (
            f"{explanation} by satisfying: {', '.join(cond_names)}"
            if cond_names
            else f"{explanation}: workflow conditions met"
        )

    elif change_type == ClassificationChangeType.WORKFLOW_DEMOTION:
        reason["conditions_unsatisfied"] = diff["conditions_unsatisfied"]
        cond_names = [c["name"] for c in diff["conditions_unsatisfied"]]
        explanation = f"Workflow demoted from {old_workflow} to {new_workflow}"
        reason["explanation"] = (
            f"{explanation} because these conditions are no longer satisfied: {', '.join(cond_names)}"
            if cond_names
            else f"{explanation}: workflow conditions no longer met"
        )

    return reason


def create_change_record(old_classification, new_classification, instance, framework):
    """
    Create a complete classification change record with reasoning.

    Args:
        old_classification: dict with 'workflow' and 'state' keys
        new_classification: dict with 'workflow' and 'state' keys
        instance: The model instance (e.g., Flaw)
        framework: WorkflowFramework instance

    Returns:
        dict: Complete change record ready to be added to classification_meta
    """
    old_workflow_name = old_classification.get("workflow", "")
    old_state_name = old_classification.get("state", "")
    new_workflow_name = new_classification.get("workflow", "")
    new_state_name = new_classification.get("state", "")

    # Find workflow objects
    old_workflow_obj = None
    new_workflow_obj = None

    for wf in framework.workflows:
        if wf.name == old_workflow_name:
            old_workflow_obj = wf
        if wf.name == new_workflow_name:
            new_workflow_obj = wf

    # Determine change type and compute diff
    change_type = None
    diff = {}

    # Check for initial classification (no previous classification)
    if not old_workflow_name or not old_state_name:
        change_type = ClassificationChangeType.INITIAL_CLASSIFICATION
        diff = {}

    elif old_workflow_name == new_workflow_name and old_workflow_obj:
        # Same workflow - state change
        old_state_obj = next(
            (s for s in old_workflow_obj.states if s.name == old_state_name), None
        )
        new_state_obj = next(
            (s for s in old_workflow_obj.states if s.name == new_state_name), None
        )

        if old_state_obj and new_state_obj:
            # Determine if progression or regression
            state_names = [s.name for s in old_workflow_obj.states]
            old_idx = state_names.index(old_state_name)
            new_idx = state_names.index(new_state_name)

            if new_idx > old_idx:
                change_type = ClassificationChangeType.STATE_PROGRESSION
            else:
                change_type = ClassificationChangeType.STATE_REGRESSION

            diff = find_requirement_diff(
                instance, old_state_obj, new_state_obj, old_workflow_obj
            )

    elif old_workflow_obj and new_workflow_obj:
        # Workflow changed
        if new_workflow_obj.priority > old_workflow_obj.priority:
            change_type = ClassificationChangeType.WORKFLOW_PROMOTION
        else:
            change_type = ClassificationChangeType.WORKFLOW_DEMOTION

        diff = find_condition_diff(instance, old_workflow_obj, new_workflow_obj)

    # Build the change record
    # Store only the new state - old state is in the previous record in the list
    record = {
        "timestamp": timezone.now().isoformat(),
        "change_type": change_type or ClassificationChangeType.UNKNOWN,
        "workflow": new_workflow_name,
        "state": new_state_name,
    }

    # Add reasoning
    if change_type and (
        diff or change_type == ClassificationChangeType.INITIAL_CLASSIFICATION
    ):
        record["reason"] = build_change_reason(
            change_type,
            diff,
            old_state_name,
            new_state_name,
            old_workflow_name,
            new_workflow_name,
        )
    else:
        record["reason"] = {
            "explanation": f"Classification changed from {old_workflow_name}:{old_state_name} to {new_workflow_name}:{new_state_name}"
        }

    return record


def add_classification_change(instance, change_record):
    """
    Add a classification change record to the instance's classification_meta.

    Records are appended (oldest first, newest last).
    Does NOT save the instance - caller is responsible for saving.

    Args:
        instance: The model instance with classification_meta field
        change_record: dict returned by create_change_record()
    """
    if not hasattr(instance, "classification_meta"):
        return

    # Ensure classification_meta is a list
    if instance.classification_meta is None:
        instance.classification_meta = []

    # Append the new record (oldest first, newest last)
    instance.classification_meta.append(change_record)
