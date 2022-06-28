"""
OSIM Workflow Framework

    this is the heard of this app implementing the logic over the workflow models
    the workflows themselves are defined separately in WORKFLOW_DIR defined in constants
"""
import logging
from os import listdir
from os.path import join

import yaml
from django.db import models

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


class WorkflowModel(models.Model):
    """workflow model base class"""

    class OSIMState(models.TextChoices):
        """allowable workflow states"""

        DRAFT = "DRAFT"
        NEW = "NEW"
        ANALYSIS = "ANALYSIS"
        REVIEW = "REVIEW"
        FIX = "FIX"
        DONE = "DONE"

    # workflow metadata
    osim_workflow = models.CharField(max_length=50, blank=True)
    osim_state = models.CharField(choices=OSIMState.choices, max_length=10, blank=True)

    class Meta:
        abstract = True

    def __init__(self, *args, **kwargs):
        """initiate workflow model"""
        super().__init__(*args, **kwargs)
        # every workflow model has to be always classified and if it is not it means
        # that it is newly created one so we need to perform initial classification
        if not all([self.osim_workflow, self.osim_state]):
            self.adjust_classification(save=False)

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
            "workflow": self.osim_workflow,
            "state": self.osim_state,
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

        self.osim_workflow = workflow if isinstance(workflow, str) else workflow.name
        self.osim_state = state if isinstance(state, str) else state.name

    def adjust_classification(self, save=True):
        """
        this is the cannonical way of changing classification

        consider carefully when changing it different way
        as it might get out of sync with the reality

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
