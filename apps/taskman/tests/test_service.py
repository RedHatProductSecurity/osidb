"""
    tests of Jira Task Manager service (Taskman)

    This class uses VCR in order to not call real Jira endpoints
    during regular tests, and it is recommendend to use Stage Jira instance for
    generating new cassettes.
"""

import pytest

from apps.taskman.constants import HTTPS_PROXY
from apps.taskman.service import JiraTaskmanQuerier, TaskStatus
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestTaskmanService(object):
    @pytest.mark.vcr
    def test_create_or_update_task(self, monkeypatch, user_token):
        """
        Test that service is able to create, get and sync a task from Jira
        """
        monkeypatch.setenv("HTTPS_PROXY", HTTPS_PROXY)

        # Remove randomness to reuse VCR every possible time
        flaw = FlawFactory(embargoed=False, uuid="9d9b3b14-0c44-4030-883c-8610f7e2879b")
        AffectFactory(flaw=flaw)
        taskman = JiraTaskmanQuerier(token=user_token)

        response1 = taskman.create_or_update_task(flaw=flaw, fail_if_exists=True)
        assert response1.status_code == 201

        response2 = taskman.get_task(response1.data["id"])
        assert response2.status_code == 200

        response3 = taskman.get_task(response1.data["key"])
        assert response3.status_code == 200

        response4 = taskman.get_task_by_flaw(flaw.uuid)
        assert response4.status_code == 200

        response5 = taskman.get_task("ERRORKEY123")
        assert response5.status_code == 404

        old_title = response1.data["fields"]["summary"]
        new_title = f"{old_title} edited title"

        flaw.title = new_title
        flaw.save()

        response6 = taskman.create_or_update_task(flaw=flaw, fail_if_exists=True)
        assert response6.status_code == 409
        assert response6.data["existing_task"]["fields"]["summary"] == old_title

        response7 = taskman.create_or_update_task(flaw=flaw, fail_if_exists=False)
        assert response7.status_code == 204

        response8 = taskman.get_task_by_flaw(flaw.uuid)
        assert response8.data["fields"]["summary"] == new_title

    @pytest.mark.vcr
    def test_update_task_status(self, monkeypatch, user_token):
        """
        Test that service is able to update task workflow status from Jira
        """
        monkeypatch.setenv("HTTPS_PROXY", HTTPS_PROXY)

        # Remove randomness to reuse VCR every possible time
        flaw = FlawFactory(embargoed=False, uuid="4823d62a-a59f-49f4-8d79-be9f7d792dfa")
        taskman = JiraTaskmanQuerier(token=user_token)

        response1 = taskman.create_or_update_task(flaw=flaw)
        assert response1.status_code == 204

        response2 = taskman.get_task_by_flaw(flaw.uuid)

        response3 = taskman.update_task_status(response2.data["key"], TaskStatus.CLOSED)
        assert response3.status_code == 200

        response4 = taskman.get_task(response2.data["key"])
        assert response4.status_code == 200
        assert response4.data["fields"]["status"]["name"] == TaskStatus.CLOSED

    @pytest.mark.vcr
    def test_comments(self, monkeypatch, user_token):
        """
        Test that service is able to create and update a comment from Jira
        """
        monkeypatch.setenv("HTTPS_PROXY", HTTPS_PROXY)

        # Remove randomness to reuse VCR every possible time
        flaw = FlawFactory(embargoed=False, uuid="99cce9ba-829d-4933-b4c1-44533d819e77")
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

    @pytest.mark.vcr
    def test_groups(self, monkeypatch, user_token):
        """
        Test that service is able to create and update a group (epic) from Jira
        """
        monkeypatch.setenv("HTTPS_PROXY", HTTPS_PROXY)

        # Remove randomness to reuse VCR every possible time
        flaw1 = FlawFactory(
            embargoed=False, uuid="f49b20b2-b9ba-47d7-bf17-b7685f484f51"
        )
        taskman = JiraTaskmanQuerier(token=user_token)
        response1 = taskman.create_or_update_task(flaw=flaw1)
        assert response1.status_code == 201

        flaw2 = FlawFactory(
            embargoed=False, uuid="8c502e80-768d-4534-bb02-4db747611319"
        )
        response2 = taskman.create_or_update_task(flaw=flaw2)
        assert response2.status_code == 201

        response3 = taskman.create_group(
            name="curl issues group", description="group for issues related to curl lib"
        )
        assert response3.status_code == 201

        response4 = taskman.add_task_into_group(
            issue_key=response1.data["key"], group_key=response3.data["key"]
        )
        assert response4.status_code == 200

        response5 = taskman.add_task_into_group(
            issue_key=response2.data["key"], group_key=response3.data["key"]
        )
        assert response5.status_code == 200

        response6 = taskman.search_task_by_group(response3.data["key"])
        assert response6.data["total"] == 2
