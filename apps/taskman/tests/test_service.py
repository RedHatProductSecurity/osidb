"""
Tests of Jira Task Manager service (Taskman)
This class uses VCR in order to not call real Jira endpoints
during regular tests, and it is recommendend to use Stage Jira
instance for generating new cassettes.
"""

import pytest

from apps.taskman.service import JiraTaskmanQuerier
from apps.workflows.workflow import WorkflowModel
from osidb.models import Affect
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
        flaw = FlawFactory(embargoed=False, uuid="9d9b3b14-0c44-4030-883c-8610f7e2879b")
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        taskman = JiraTaskmanQuerier(token=user_token)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1.status_code == 201

        old_title = response1.data["fields"]["summary"]
        new_title = f"{old_title} edited title"

        flaw.title = new_title
        flaw.owner = "concosta@redhat.com"
        flaw.team_id = "2861"
        flaw.save()

        response2 = taskman.create_or_update_task(flaw=flaw)
        assert response2.status_code == 200
        assert response2.data["fields"]["summary"] == new_title
        assert response2.data["fields"]["customfield_12313240"]["id"] == 2861
        assert response2.data["fields"]["customfield_12313240"]["name"] == "OSIDB"
        assert response2.data["fields"]["assignee"]["name"] == "concosta@redhat.com"

        assert flaw.workflow_state == WorkflowModel.WorkflowState.TRIAGE
        flaw.workflow_state = WorkflowModel.WorkflowState.PRE_SECONDARY_ASSESSMENT
        flaw.save()
        response3 = taskman.create_or_update_task(flaw=flaw)
        assert response3.status_code == 200
        status, _ = flaw.jira_status()
        assert response3.data["fields"]["status"]["name"] == status

    @pytest.mark.vcr
    def test_comments(self, user_token):
        """
        Test that service is able to create and update a comment from Jira
        """
        # Remove randomness to reuse VCR every possible time
        flaw = FlawFactory(embargoed=False, uuid="99cce9ba-829d-4933-b4c1-44533d819e77")
        AffectFactory(flaw=flaw)
        taskman = JiraTaskmanQuerier(token=user_token)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1.status_code == 201

        response2 = taskman.create_comment(response1.data["key"], "New comment")
        assert response2.status_code == 201

        response3 = taskman.update_comment(
            response1.data["key"],
            response2.data["id"],
            "Edited comment",
        )
        assert response3.status_code == 200
