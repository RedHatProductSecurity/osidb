"""
Task Manager API endpoints
"""
import json
import logging
from typing import List, Optional, Tuple

from django.db import models
from django.utils import timezone
from jira import Issue
from jira.exceptions import JIRAError

from apps.trackers.jira.query import JiraPriority
from collectors.jiraffe.core import JiraQuerier
from osidb.helpers import safe_get_response_content
from osidb.models import Flaw, Impact, PsProduct

from .constants import (
    JIRA_STORY_ISSUE_TYPE_ID,
    JIRA_SUMMARY_MAX_LENGTH,
    JIRA_TASKMAN_PROJECT_ID,
    JIRA_TASKMAN_PROJECT_KEY,
    JIRA_TASKMAN_URL,
)
from .exceptions import JiraTaskErrorException, TaskWritePermissionsException

logger = logging.getLogger(__name__)

# mapping task management Jira project
IMPACT_TO_JIRA_PRIORITY = {
    Impact.CRITICAL: JiraPriority.CRITICAL,
    Impact.IMPORTANT: JiraPriority.MAJOR,
    Impact.MODERATE: JiraPriority.NORMAL,
    Impact.LOW: JiraPriority.MINOR,
    Impact.NOVALUE: JiraPriority.UNDEFINED,
}


class TaskStatus(models.TextChoices):
    """allowable workflow states"""

    NEW = "New"
    IN_PROGRESS = "In Progress"
    REFINEMENT = "Refinement"
    CLOSED = "Closed"


class TaskResolution(models.TextChoices):
    """
    allowable resolution for tasks in Jira
    This uses the OJA naming convention, which uses "Won't Do" for rejected tasks
    https://docs.engineering.redhat.com/display/PPE/TEST+COPY+Opinionated+Guidance%3A+Resolutions
    """

    DONE = "Done"
    WONT_DO = "Won't Do"
    CANNOT_REPRODUCE = "Cannot Reproduce"
    CANT_DO = "Can't Do"
    DUPLICATE = "Duplicate"
    NOT_A_BUG = "Not a Bug"
    DONE_ERRATA = "Done-Errata"
    MIRROR_ORPHAN = "MirrorOrphan"
    OBSOLETE = "Obsolete"
    TEST_PENDING = "Test Pending"


class JiraTaskmanQuerier(JiraQuerier):
    """
    Jira query handler for task management.
    This class encapsulates calls for Jira doing validations
    and it methods return data requested with HTTP status code
    """

    def __init__(self, token) -> None:
        """
        Instantiate a new JiraTaskmanQuerier object.

        Keyword arguments:
        token -- user token used in every request to Jira
                 the service one is used if not provided
        """
        super().__init__()
        self._jira_server = JIRA_TASKMAN_URL
        if token:
            self._jira_token = token

    def _check_token(self) -> None:
        """
        check the validity of the used API token
        raise exception if invalid one was given
        """
        token_validation_url = f"{self.jira_conn._get_url('mypermissions')}?projectKey={JIRA_TASKMAN_PROJECT_KEY}"

        # This request raises exception for unauthenticated users
        permission_response = self.jira_conn._session.get(token_validation_url)

        permissions = permission_response.json().get(
            "permissions", {"CREATE_ISSUES": {"havePermission": False}}
        )
        if not permissions["CREATE_ISSUES"]["havePermission"]:
            raise TaskWritePermissionsException(
                f"Token is valid for {JIRA_TASKMAN_URL} but user doesn't have write permission in {JIRA_TASKMAN_PROJECT_KEY} project."
            )

    def create_or_update_task(
        self, flaw: Flaw, check_token: bool = True
    ) -> Optional[str]:
        """
        Creates or updates a task using Flaw data
        returns the Jira task ID if newly created

        by default the user tokens are being checked for validity which can
        be turned off by parameter if not necessary to lower the Jira load
        """
        # check the token validity in case the user token is used
        # assuming the service token is valid lowering Jira load
        if check_token and not self.is_service_account():
            self._check_token()

        data = self._generate_task_data(flaw)
        data["fields"]["issuetype"]["id"] = JIRA_STORY_ISSUE_TYPE_ID
        data["fields"]["project"]["id"] = JIRA_TASKMAN_PROJECT_ID

        try:
            if not flaw.task_key:  # create task
                issue = self.jira_conn.create_issue(
                    fields=data["fields"], prefetch=True
                )
                flaw.task_key = issue.key
                if flaw.team_id:  # Jira does not allow setting team during creation
                    self.create_or_update_task(
                        flaw, check_token=False  # no need to check the token again
                    )
                return flaw.task_key
            else:  # task exists; update
                url = f"{self.jira_conn._get_url('issue')}/{flaw.task_key}"
                if flaw.team_id:
                    data["fields"]["customfield_12313240"] = flaw.team_id
                self.jira_conn._session.put(url, json.dumps(data))
        except JIRAError as e:
            creating = not flaw.task_key
            creating_updating_word = "creating" if creating else "updating"
            message = (
                f"Jira error when {creating_updating_word} "
                f"Task for Flaw UUID {flaw.uuid} cve_id {flaw.cve_id}. "
                f"Jira HTTP status code {e.status_code}, "
                f"Jira response {safe_get_response_content(e.response)}"
            )

            # Raising so that the error from Jira is communicated to the client.
            # All uses of create_or_update_task require success as of 2024-05.
            # If it starts getting used in other contexts where success is only optional,
            # replace raise with logger.error(message) and raise selectively where
            # create_or_update_task is used.
            raise JiraTaskErrorException(message)

    def transition_task(self, flaw: Flaw, check_token: bool = True) -> None:
        """
        transition a task through the Jira workflow using Flaw data

        by default the user tokens are being checked for validity which can
        be turned off by parameter if not necessary to lower the Jira load
        """
        # check the token validity in case the user token is used
        # assuming the service token is valid lowering Jira load
        if check_token and not self.is_service_account():
            self._check_token()

        # when there is no task we assume that the caller
        # made a mistake and simply refuse the operation
        if not flaw.task_key:
            raise JiraTaskErrorException(
                f"Cannot promote flaw {flaw.cve_id or flaw.uuid} without an associated task."
            )

        try:
            status, resolution = flaw.jira_status()
            resolution_data = {"resolution": {"name": resolution}} if resolution else {}
            self.jira_conn.transition_issue(
                issue=flaw.task_key,
                transition=status,
                **resolution_data,
            )
        except JIRAError as e:
            # raising so that the error from Jira is communicated to the client
            raise JiraTaskErrorException(
                f"Jira error when transitioning "
                f"Task for Flaw UUID {flaw.uuid} cve_id {flaw.cve_id}. "
                f"Jira HTTP status code {e.status_code}, "
                f"Jira response {safe_get_response_content(e.response)}"
            )

    def _generate_task_data(self, flaw: Flaw):
        modules = flaw.affects.values_list("ps_module", flat=True).distinct()
        products = PsProduct.objects.filter(ps_modules__name__in=modules)
        labels = [f"flawuuid:{str(flaw.uuid)}", f"impact:{flaw.impact}"]
        for product in products:
            if product.team:
                labels.append(f"team:{product.team}")
        if flaw.major_incident_state in [
            Flaw.FlawMajorIncident.APPROVED,
            Flaw.FlawMajorIncident.CISA_APPROVED,
            Flaw.FlawMajorIncident.MINOR,
            Flaw.FlawMajorIncident.ZERO_DAY,
        ]:
            labels.append("major_incident")
        if flaw.cve_id:
            labels.append(flaw.cve_id)
        if not flaw.cve_id or flaw.cve_id in flaw.title:
            summary = flaw.title
        else:
            summary = f"{flaw.cve_id} {flaw.title}"

        if len(summary) > JIRA_SUMMARY_MAX_LENGTH:
            # Trim the maximum summary length by 3 to account for the triple dots
            summary = f"{summary[:JIRA_SUMMARY_MAX_LENGTH-3]}..."

        data = {
            "fields": {
                "issuetype": {},
                "project": {},
                "summary": summary,
                "description": flaw.comment_zero,
                "labels": labels,
                "priority": {"name": IMPACT_TO_JIRA_PRIORITY[flaw.impact]},
                "assignee": {"name": flaw.owner},
            }
        }

        if flaw.group_key:
            data["fields"]["customfield_12311140"] = flaw.group_key

        return data

    def query_tasks(
        self, query_list: List[Tuple[str, str, str]]
    ) -> List[Tuple[str, str, str]]:
        """
        update query dictionary to query tasks
        """
        query_list.append(("project", "=", JIRA_TASKMAN_PROJECT_KEY))
        query_list.append(("type", "=", "Story"))
        return query_list

    def get_task_period(
        self, updated_after: timezone.datetime, updated_before: timezone.datetime
    ) -> List[Issue]:
        """
        get list of tasks updated during the given period
        """
        query_list = []
        query_list = self.query_tasks(query_list)
        query_list = self.query_updated(query_list, updated_after, updated_before)
        return self.run_query(query_list)
