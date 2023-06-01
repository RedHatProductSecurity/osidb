"""
Task Manager API endpoints
"""
import json
import logging
from typing import Optional

from django.db import models
from jira.exceptions import JIRAError
from rest_framework.response import Response

from collectors.jiraffe.core import JiraQuerier
from osidb.models import Affect, Flaw

from .constants import JIRA_TASKMAN_PROJECT_KEY, JIRA_TASKMAN_URL

logger = logging.getLogger(__name__)


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
        """
        self._jira_server = JIRA_TASKMAN_URL
        self._jira_token = token

    def get_task_by_flaw(self, flaw_uuid: str) -> Response:
        """search Jira task given a flaw UUID"""
        try:
            issues = self.run_query(
                [
                    ("PROJECT", "=", JIRA_TASKMAN_PROJECT_KEY),
                    ("labels", "=", f"flawuuid:{flaw_uuid}"),
                    ("type", "=", "Story"),
                ]
            )
            if len(issues) == 0:
                return Response(data=None, status=404)
            else:
                return Response(data=issues[0].raw, status=200)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def get_task(self, task_key: str) -> Response:
        """get Jira task given its string key or integer id"""
        try:
            return Response(data=self.jira_conn.issue(task_key).raw, status=200)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def create_or_update_task(self, flaw: Flaw, fail_if_exists=False) -> Response:
        """Creates a task using Flaw data"""
        task = self.get_task_by_flaw(flaw_uuid=flaw.uuid).data
        if fail_if_exists and task:
            res = {
                "error": "Task representing this flaw already exists",
                "existing_task": task,
            }
            return Response(data=res, status=409)

        try:
            if task:
                data = {
                    "fields": {
                        "summary": flaw.title,
                        "description": flaw.description,
                    }
                }
                url = f"{self.jira_conn._get_url('issue')}/{task['key']}"
                self.jira_conn._session.put(url, json.dumps(data))
                return Response(
                    data=self.jira_conn.issue(task["key"]).raw,
                    status=200,
                )
            else:
                data = {
                    "fields": {
                        "issuetype": {
                            "id": self.jira_conn.issue_type_by_name("Story").id
                        },
                        "project": {
                            "id": self.jira_conn.project(JIRA_TASKMAN_PROJECT_KEY).id
                        },
                        "summary": flaw.title,
                        "description": flaw.description,
                        "labels": [f"flawuuid:{str(flaw.uuid)}"],
                    }
                }

                issue = self.jira_conn.create_issue(
                    fields=data["fields"], prefetch=True
                )
                return Response(data=issue.raw, status=201)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def update_task_status(
        self,
        issue_key: str,
        status: TaskStatus,
        resolution: Optional[TaskResolution] = None,
    ) -> Response:
        """Transition a task to a new state"""
        try:
            if status == TaskStatus.CLOSED and resolution == TaskResolution.WONT_DO:
                issue = self.jira_conn.issue(issue_key)
                uuid_labels = [
                    label for label in issue.fields.labels if "flawuuid:" in label
                ]
                if len(uuid_labels) == 0:
                    return Response(
                        data="Task was found but does not contains label with flaw uuid.",
                        status=409,
                    )
                flaw_uuid = uuid_labels[0].split(":")[1]
                flaw = Flaw.objects.get(uuid=flaw_uuid)
                any_affected = flaw.affects.exclude(
                    affectedness=Affect.AffectAffectedness.NOTAFFECTED
                ).exists()

                if any_affected:
                    return Response(
                        data="Trying to reject an affected Flaw. Please validate flaw's affects before rejecting the task.",
                        status=409,
                    )

            if resolution:
                self.jira_conn.transition_issue(
                    issue=issue_key,
                    transition=status,
                    resolution={"name": resolution},
                )
            else:
                self.jira_conn.transition_issue(
                    issue=issue_key,
                    transition=status,
                )
            return Response(data=self.jira_conn.issue(issue_key).raw, status=200)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def create_comment(self, issue_key: str, body: str):
        """Add a comment in a task"""
        try:
            comment = self.jira_conn.add_comment(issue_key, body)
            return Response(data=comment.raw, status=201)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def update_comment(self, issue_key, comment_id, body: str):
        """Edit a comment in a task"""
        try:
            comment = self.jira_conn.comment(issue=issue_key, comment=comment_id)
            comment.update(body=body)
            return Response(data=comment.raw, status=200)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def add_task_into_group(self, issue_key, group_key):
        """Associates a task (issue) with a group (epic)"""
        try:
            data = {
                # Custom field that represents issue's parent key
                "customfield_12311140": group_key,
            }
            issue = self.jira_conn.issue(id=issue_key)
            issue.update(data)
            return Response(data=issue.raw, status=200)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def create_group(self, name, description=""):
        """Creates a group (epic) in Jira"""
        try:
            data = {
                "fields": {
                    "issuetype": {"id": self.jira_conn.issue_type_by_name("Epic").id},
                    "project": {
                        "id": self.jira_conn.project(JIRA_TASKMAN_PROJECT_KEY).id
                    },
                    "description": description,
                    "summary": name,
                    # Mandatory custom field called "Epic Name"
                    "customfield_12311141": name,
                }
            }
            url = self.jira_conn._get_url("issue")
            r = self.jira_conn._session.post(url, data=json.dumps(data))
            return Response(data=r.json(), status=r.status_code)
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def search_task_by_group(self, group_key: str) -> Response:
        """search Jira task given a flaw UUID"""

        jql_query = f'PROJECT={JIRA_TASKMAN_PROJECT_KEY} \
                AND cf[12311140]="{group_key}"'
        try:
            return Response(
                data=self.jira_conn.search_issues(jql_query, json_result=True),
                status=200,
            )
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def assign_task(self, task_key: str, assignee: str) -> Response:
        """set Jira task assignee"""
        try:
            self.jira_conn.assign_issue(task_key, assignee)

            return Response(
                data=self.jira_conn.issue(task_key).raw,
                status=200,
            )
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)

    def search_tasks_by_assignee(self, assignee: str) -> Response:
        """search Jira task by its assignee"""
        user_query = f'assignee="{assignee}"' if assignee else "assignee is EMPTY"
        jql_query = f'PROJECT={JIRA_TASKMAN_PROJECT_KEY} \
                AND {user_query} \
                AND type="Story"'
        try:
            return Response(
                data=self.jira_conn.search_issues(jql_query, json_result=True),
                status=200,
            )
        except JIRAError as e:
            return Response(data=e.response.json(), status=e.status_code)
