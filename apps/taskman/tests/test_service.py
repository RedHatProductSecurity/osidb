"""
Tests of Jira Task Manager service (Taskman)
This class uses VCR in order to not call real Jira endpoints
during regular tests, and it is recommendend to use Stage Jira
instance for generating new cassettes.
"""

import pytest

from apps.taskman.service import JiraTaskmanQuerier
from apps.workflows.workflow import WorkflowModel
from osidb.models import Flaw
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestTaskmanService(object):
    def test_jira_connection(self, user_token):
        """
        Test that taskman is able to instantiate a Jira connection object
        """
        assert JiraTaskmanQuerier(token=user_token).jira_conn

    @pytest.mark.vcr
    @pytest.mark.enable_signals
    def test_create_or_update_task(self, user_token):
        """
        Test that service is able to create and update regular fields, team, assignment and status
        """
        # Remove randomness to reuse VCR every possible time
        flaw = FlawFactory(
            embargoed=False,
            uuid="9d9b3b14-0c44-4030-883c-8610f7e2879b",
            workflow_state=WorkflowModel.WorkflowState.NEW,
        )
        AffectFactory(flaw=flaw)
        taskman = JiraTaskmanQuerier(token=user_token)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1.status_code == 201

        old_title = response1.data["fields"]["summary"]
        new_title = f"{old_title} edited title"

        flaw.title = new_title
        flaw.owner = "concosta@redhat.com"
        flaw.team_id = "2861"
        flaw.workflow_state = WorkflowModel.WorkflowState.TRIAGE
        flaw.save()

        response2 = taskman.create_or_update_task(flaw=flaw)
        status, _ = flaw.jira_status()
        assert response2.status_code == 200
        assert response2.data["fields"]["summary"] == new_title
        assert response2.data["fields"]["customfield_12313240"]["id"] == 2861
        assert response2.data["fields"]["customfield_12313240"]["name"] == "OSIDB"
        assert response2.data["fields"]["assignee"]["name"] == "concosta@redhat.com"
        assert response2.data["fields"]["status"]["name"] == status

        assert flaw.workflow_state == WorkflowModel.WorkflowState.TRIAGE
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.save(raise_validation_error=False)
        response3 = taskman.create_or_update_task(flaw=flaw)
        assert response3.status_code == 200
        status, _ = flaw.jira_status()
        assert response3.data["fields"]["status"]["name"] == status

        # test unassign
        flaw.owner = ""
        flaw.save(raise_validation_error=False)
        response4 = taskman.create_or_update_task(flaw=flaw)
        assert response4.status_code == 200
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert flaw.owner == ""
        issue = taskman.jira_conn.issue(flaw.task_key).raw
        assert not issue["fields"]["assignee"]

    @pytest.mark.vcr
    def test_comments(self, user_token):
        """
        Test that service is able to create comment in Jira
        """
        # Remove randomness to reuse VCR every possible time
        flaw = FlawFactory(embargoed=False, uuid="99cce9ba-829d-4933-b4c1-44533d819e77")
        AffectFactory(flaw=flaw)
        taskman = JiraTaskmanQuerier(token=user_token)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1.status_code == 201

        response2 = taskman.create_comment(response1.data["key"], "New comment")
        assert response2.status_code == 201

    @pytest.mark.vcr
    def test_add_link(self, user_token):
        """
        Test that service is able to create remote links in Jira issues.
        """
        flaw = FlawFactory(embargoed=False, uuid="b47f7912-7011-463a-b861-6d7dca13aa3c")
        AffectFactory(flaw=flaw)
        taskman = JiraTaskmanQuerier(token=user_token)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1.status_code == 201

        response2 = taskman.add_link(
            response1.data["key"], "https://www.redhat.com", "Red Hat Webpage"
        )
        assert response2.status_code == 201
