"""
Workflows Framework

    this is the heard of this app implementing the logic over the workflow models
    the workflows themselves are defined separately in WORKFLOW_DIR defined in constants
"""
import logging
from os import listdir
from os.path import join

import yaml
from django.db import models

from .constants import WORKFLOW_DIR
from .exceptions import (
    LastStateException,
    MissingRequirementsException,
    MissingStateException,
    MissingWorkflowException,
    WorkflowDefinitionError,
)
from .helpers import singleton
from .models import Workflow

logger = logging.getLogger(__name__)


@singleton
class WorkflowFramework:
    """
    workflow operating framework

    loads and provides all available workflows
    and implements all workflow operating logic
    """

    _workflows = []

    @property
    def workflows(self):
        """
        workflows getter

        loads the workflows on the first run
        """
        if not self._workflows:
            self.load_workflows()

        return self._workflows

    def load_workflows(self):
        """workflows loader"""
        for file in listdir(WORKFLOW_DIR):
            if not file.endswith(".yml"):
                continue

            try:
                with open(
                    file=join(WORKFLOW_DIR, file), mode="r", encoding="utf8"
                ) as stream:
                    # create and register workflow instance
                    logger.info(f"Processing workflow definition: {file}")
                    self.register_workflow(Workflow(yaml.safe_load(stream)))

            except (KeyError, ValueError) as exception:
                raise WorkflowDefinitionError(
                    f"Invalid workflow definition {file}"
                ) from exception

    def register_workflow(self, workflow):
        """
        workflow registration

        keeps the workflows sorted according to the highest priority
        """
        self._workflows.append(workflow)
        self._workflows.sort(reverse=True)

    def classify(self, instance, state=True):
        """
        classify the instance in the proper workflow
        and optionally in the proper state too (by default)

        the proper workflow is the most prior accepting workflow

        the workflows are required to contain a default workflow with empty conditions
        so there is always at least one applicable workflow to classify an instance in

        returns:

            (workflow, state) classification by default
            or only workflow classification if requested by state param set to False
        """
        for workflow in self.workflows:
            if workflow.accepts(instance):
                return (workflow, workflow.classify(instance)) if state else workflow

    def validate_classification(self, instance, target_workflow, target_state):
        """
        This method will evaluate if it is possible to classify the current
        instance as a target state

        Raise exception if instance lacks requirements for the target state

        This method does NOT update the flaw classification
        """
        for workflow in self.workflows:
            if workflow.name == target_workflow:
                not_met_reqs = workflow.validate_classification(instance, target_state)
                if len(not_met_reqs) > 0:
                    error_message = ",".join(not_met_reqs)
                    error_message = f'Requirements for state "{target_state}" from "{target_workflow}" workflow are missing: [{error_message}].'
                    raise MissingRequirementsException(error_message)
                else:
                    return
        raise MissingStateException(
            f"Workflow ({target_workflow}) was not found in WorkflowFramework."
        )

    def jira_status(self, instance):
        """
        Given a instance, return expected jira status and resolution
        """
        for workflow in self.workflows:
            if workflow.name == instance.workflow_name:
                for state in workflow.states:
                    if state.name == instance.workflow_state:
                        return state.jira_state, state.jira_resolution

        raise MissingStateException(
            f"Combination of workflow ({instance.workflow_name}) and state ({instance.workflow_state}) was not found in WorkflowFramework."
        )


class WorkflowModel(models.Model):
    """workflow model base class"""

    class WorkflowState(models.TextChoices):
        """allowable workflow states"""

        NEW = "NEW"
        TRIAGE = "TRIAGE"
        PRE_SECONDARY_ASSESSMENT = "PRE_SECONDARY_ASSESSMENT"
        SECONDARY_ASSESSMENT = "SECONDARY_ASSESSMENT"
        DONE = "DONE"
        REJECTED = "REJECTED"

    workflow_name = models.CharField(max_length=50, blank=True, default="DEFAULT")
    workflow_state = models.CharField(
        choices=WorkflowState.choices,
        max_length=24,
        blank=True,
        default=WorkflowState.NEW,
    )
    owner = models.CharField(max_length=60, blank=True)
    group_key = models.CharField(max_length=60, blank=True)
    task_key = models.CharField(max_length=60, blank=True)
    team_id = models.CharField(max_length=8, blank=True)

    class Meta:
        abstract = True

    def classify(self):
        """computed workflow classification"""
        workflow, state = WorkflowFramework().classify(self)
        return {
            "workflow": workflow.name,
            "state": state.name,
        }

    @property
    def classification(self):
        """stored workflow classification"""
        return {
            "workflow": self.workflow_name,
            "state": self.workflow_state,
        }

    @classification.setter
    def classification(self, classification):
        """
        setter for stored workflow classification

        may be given by either tuple or dictionary where its values
        may be either workflow objects or their names
        """
        if isinstance(classification, dict):
            workflow = classification["workflow"]
            state = classification["state"]
        else:
            workflow, state = classification

        self.workflow_name = workflow if isinstance(workflow, str) else workflow.name
        self.workflow_state = state if isinstance(state, str) else state.name

    def adjust_classification(self, save=True):
        """
        this method will identify and adjust to the higher state the instance can be

        this is the automatic way to update state, currently we are adopting a manual
        state change, please consider using promote method from this mixin instead

        workflow model is by default saved on change which can be turned off by argument
        """
        classification = self.classify()

        if classification == self.classification:
            # no change to be stored
            return

        self.classification = classification

        if not save:
            return

        self.save()

    def validate_classification(self, target_workflow, target_state):
        """
        This method will evaluate if it is possible to classify the current
        instance as a target state and raise exception if instance lacks
        requirements for the target state

        This method does NOT update the flaw classification
        """
        WorkflowFramework().validate_classification(self, target_workflow, target_state)

    def promote(self, save=True, jira_token=None):
        """
        this is the cannonical way of changing classification

        This method will change instance state to the next available state

        Raise exception if instance lacks requirements for the target state
        """
        workflow_obj = None
        workflows = WorkflowFramework().workflows
        for workflow in workflows:
            if workflow.name == self.workflow_name:
                workflow_obj = workflow
                break

        if not workflow_obj:
            raise MissingWorkflowException(
                f"Instance is classified with a non-registered workflow ({self.workflow_name})."
            )

        state_obj = None
        state_count = len(workflow_obj.states)
        for i in range(state_count):
            if workflow_obj.states[i].name == self.workflow_state:
                if i + 1 >= state_count:
                    raise LastStateException(
                        f"Instance is already in the last state ({self.workflow_state}) from its workflow ({self.workflow_name})."
                    )
                state_obj = workflow_obj.states[i + 1]
                break

        if not state_obj:
            raise MissingStateException(
                f"Instance is classified with a non-registered state ({self.workflow_state})."
            )

        WorkflowFramework().validate_classification(
            self, self.workflow_name, state_obj.name
        )

        self.workflow_state = state_obj.name

        if not save:
            return

        self.save(jira_token=jira_token)

    def reject(self, save=True, jira_token=None):
        """
        this is the cannonical way of rejecting a flaw / task

        This method will change instance state to rejected if all conditions are met

        Raise exception if instance lacks requirements for the rejected state
        """
        reject_workflow = "REJECTED"
        WorkflowFramework().validate_classification(
            self, reject_workflow, WorkflowModel.WorkflowState.REJECTED
        )

        self.workflow_name = reject_workflow
        self.workflow_state = WorkflowModel.WorkflowState.REJECTED

        if not save:
            return

        self.save(jira_token=jira_token)

    def jira_status(self):
        return WorkflowFramework().jira_status(self)
