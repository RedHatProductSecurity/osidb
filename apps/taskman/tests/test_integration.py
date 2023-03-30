"""
    Integration tests to validate Taskman REST API endpoints
"""
import pytest

from apps.taskman.constants import HTTPS_PROXY
from apps.taskman.service import TaskStatus
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.integration


class TestIntegration(object):
    @pytest.mark.vcr
    def test_task(self, monkeypatch, user_token, auth_client, test_api_uri):
        """
        Test CRUD operations using REST APIs for task management.

        POST -> /task/flaw/<str:flaw_uuid>
        PUT -> /task/flaw/<str:flaw_uuid>
        GET -> /task/flaw/<str:flaw_uuid>
        GET -> /task/<str:task_key>
        PUT -> /task/<str:task_key>/status
        """
        monkeypatch.setenv("HTTPS_PROXY", HTTPS_PROXY)

        # remove randomness from flaw
        flaw = FlawFactory(uuid="0a9d00d7-b846-4840-abe5-becda57f0a14", embargoed=False)
        AffectFactory(flaw=flaw)

        headers = {"HTTP_JiraAuthentication": user_token}
        response1 = auth_client.post(
            f"{test_api_uri}/task/flaw/{flaw.uuid}",
            data={},
            format="json",
            **headers,
        )

        issue = response1.json()
        assert response1.status_code == 201
        assert "fields" in issue
        assert "issuetype" in issue["fields"]
        assert "summary" in issue["fields"]
        assert "description" in issue["fields"]
        assert "assignee" in issue["fields"]
        assert "customfield_12311140" in issue["fields"]

        flaw.title = f"{flaw.title} modified"
        flaw.save()

        response2 = auth_client.post(
            f"{test_api_uri}/task/flaw/{flaw.uuid}",
            data={},
            format="json",
            **headers,
        )
        assert response2.status_code == 409

        response3 = auth_client.put(
            f"{test_api_uri}/task/flaw/{flaw.uuid}",
            data={},
            format="json",
            **headers,
        )
        assert response3.status_code == 204

        response4 = auth_client.get(
            f"{test_api_uri}/task/flaw/{flaw.uuid}",
            format="json",
            **headers,
        )

        issue2 = response4.json()
        assert response4.status_code == 200
        assert "fields" in issue2
        assert "issuetype" in issue2["fields"]
        assert "summary" in issue2["fields"]
        assert "description" in issue2["fields"]
        assert "assignee" in issue2["fields"]
        assert "customfield_12311140" in issue2["fields"]

        response5 = auth_client.put(
            f"{test_api_uri}/task/{issue['key']}/status",
            data={"status": TaskStatus.IN_PROGRESS},
            format="json",
            **headers,
        )
        assert response5.status_code == 204

        response6 = auth_client.get(
            f"{test_api_uri}/task/{issue['key']}",
            format="json",
            **headers,
        )
        issue3 = response6.json()
        assert response6.status_code == 200
        assert issue3["fields"]["status"]["name"] == TaskStatus.IN_PROGRESS
        assert "fields" in issue3
        assert "issuetype" in issue3["fields"]
        assert "summary" in issue3["fields"]
        assert "description" in issue3["fields"]
        assert "assignee" in issue3["fields"]
        assert "customfield_12311140" in issue3["fields"]

    @pytest.mark.vcr
    def test_comment(self, monkeypatch, user_token, auth_client, test_api_uri):
        """
        Test CRUD operations using REST APIs for comment management.

        POST -> /task/<str:task_key>/comment
        PUT -> /task/<str:task_key>/comment/<str:comment_id>
        """
        monkeypatch.setenv("HTTPS_PROXY", HTTPS_PROXY)

        # remove randomness from flaw
        flaw = FlawFactory(uuid="98c0c5fd-b2fc-46cb-adf4-5de2bdce2737", embargoed=False)

        headers = {"HTTP_JiraAuthentication": user_token}
        response1 = auth_client.post(
            f"{test_api_uri}/task/flaw/{flaw.uuid}",
            data={},
            format="json",
            **headers,
        )
        issue = response1.json()

        comment_content = "This is a new comment"
        response2 = auth_client.post(
            f"{test_api_uri}/task/{issue['key']}/comment",
            data={"content": comment_content},
            format="json",
            **headers,
        )
        assert response2.status_code == 201
        assert response2.json()["body"] == comment_content

        new_comment_content = "This is a edited comment"
        response3 = auth_client.put(
            f"{test_api_uri}/task/{issue['key']}/comment/{response2.json()['id']}",
            data={"content": new_comment_content},
            format="json",
            **headers,
        )
        assert response3.status_code == 200
        assert response3.json()["body"] == new_comment_content

    @pytest.mark.vcr
    def test_group(self, monkeypatch, user_token, auth_client, test_api_uri):
        """
        Test CRUD operations using REST APIs for group of tasks management.

        POST -> /group
        PUT -> /group/<str:group_key>
        GET -> /group/<str:group_key>
        """
        monkeypatch.setenv("HTTPS_PROXY", HTTPS_PROXY)
        headers = {"HTTP_JiraAuthentication": user_token}
        response1 = auth_client.post(
            f"{test_api_uri}/group",
            data={
                "name": "curl issues group",
                "description": "group for issues related to curl lib",
            },
            format="json",
            **headers,
        )
        assert response1.status_code == 201

        # remove randomness from flaw
        flaw1 = FlawFactory(
            uuid="08b02ba4-d80e-4b3c-9a08-b86229f5f83c", embargoed=False
        )
        flaw2 = FlawFactory(
            uuid="faaeaab0-e470-4a45-94ab-28dc06044161", embargoed=False
        )

        response2 = auth_client.post(
            f"{test_api_uri}/task/flaw/{flaw1.uuid}",
            data={},
            format="json",
            **headers,
        )
        response3 = auth_client.post(
            f"{test_api_uri}/task/flaw/{flaw2.uuid}",
            data={},
            format="json",
            **headers,
        )

        issue1 = response2.json()
        issue2 = response3.json()

        response4 = auth_client.put(
            f"{test_api_uri}/group/{response1.json()['key']}",
            data={"task_key": issue1["key"]},
            format="json",
            **headers,
        )
        assert response4.status_code == 204

        response5 = auth_client.put(
            f"{test_api_uri}/group/{response1.json()['key']}",
            data={"task_key": issue2["key"]},
            format="json",
            **headers,
        )
        assert response5.status_code == 204

        response6 = auth_client.get(
            f"{test_api_uri}/group/{response1.json()['key']}",
            format="json",
            **headers,
        )
        assert response6.status_code == 200
        assert response6.json()["total"] == 2
