"""
Workflows Framework

    this is the heart of this app implementing the logic over the workflow models
    the workflows themselves are defined separately in WORKFLOW_DIR defined in constants
"""

import logging
from os import listdir
from os.path import join

import yaml
from django.db import models

from osidb.helpers import deprecate_field

from .constants import WORKFLOW_DIR
from .exceptions import WorkflowDefinitionError
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

    def get_effective_visibility(self, workflow_name, state_name):
        """
        Get the effective visibility for a state within a workflow.

        The effective visibility is the widest visibility defined across
        all states from the beginning up to and including the given state
        in the workflow's state sequence. This ensures that visibility
        gates are not skipped when a flaw is classified multiple states
        ahead, and that a later state cannot narrow visibility set by
        an earlier one.
        """
        from osidb.mixins import ACLMixinVisibility

        for workflow in self.workflows:
            if workflow.name == workflow_name:
                effective = None
                for state in workflow.states:
                    if state.visibility:
                        visibility = ACLMixinVisibility(state.visibility)
                        if effective is None or visibility > effective:
                            effective = visibility
                    if state.name == state_name:
                        return effective

    def jira_status(self, instance):
        """
        Given an instance, return expected jira status and resolution
        """
        _, state = self.classify(instance)
        return state.jira_state, state.jira_resolution


class WorkflowModelManager(models.Manager):
    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .annotate(
                workflow_classification=models.Func(
                    models.Value("workflow"),
                    models.F("workflow_name"),
                    models.Value("state"),
                    models.F("workflow_state"),
                    function="jsonb_build_object",
                    output_field=models.JSONField(),
                )
            )
            .all()
        )


class WorkflowModel(models.Model):
    """workflow model base class"""

    workflow_name = models.CharField(max_length=50, blank=True)
    workflow_state = models.CharField(max_length=50, blank=True)
    owner = models.CharField(max_length=60, blank=True)
    group_key = deprecate_field(models.CharField(max_length=60, blank=True))
    task_key = models.CharField(max_length=60, blank=True)
    task_updated_dt = models.DateTimeField(null=True, blank=True)
    team_id = deprecate_field(models.CharField(max_length=8, blank=True))

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
        return getattr(
            self,
            "workflow_classification",
            {
                "workflow": self.workflow_name,
                "state": self.workflow_state,
            },
        )

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
        self.workflow_classification = {
            "workflow": self.workflow_name,
            "state": self.workflow_state,
        }

    def adjust_classification(self, save=True):
        """
        this method will identify and adjust to the higher state the instance can be

        this is the automatic way to update state, currently we are adopting a manual
        state change, please consider using promote method from this mixin instead

        workflow model is by default saved on change which can be turned off by argument
        """
        # Only classify if there is a task associated, otherwise workflow fields
        # should remain empty
        if not self.task_key:
            return

        classification = self.classify()

        if classification == self.classification:
            # no change to be stored
            return

        self.classification = classification
        self.adjust_acls()  # possibly adjust ACLs too

        if not save:
            return

        self.save()

    def jira_status(self):
        return WorkflowFramework().jira_status(self)

    def adjust_acls(self):
        visibility = WorkflowFramework().get_effective_visibility(
            self.workflow_name, self.workflow_state
        )
        if visibility:
            self.visibility = visibility
