from unittest.mock import Mock

import pytest

from collectors.jiraffe.constants import JIRA_SERVER

pytestmark = pytest.mark.unit


class TestJiraStageForwarder:
    @pytest.mark.parametrize("method", ["get", "post", "put"])
    def test_forwards_basic_authorization(
        self, client, test_api_uri, monkeypatch, method
    ):
        authorization = "Basic fake=="
        path = "/rest/api/3/issue/OSIDB-1"
        response_mock = Mock(status_code=200, text='{"ok": true}')
        response_mock.json.return_value = {"ok": True}
        request_mock = Mock(return_value=response_mock)
        monkeypatch.setattr(f"osidb.api_views.requests.{method}", request_mock)

        url = f"{test_api_uri}/jira_stage_forwarder?path={path}"
        if method == "get":
            response = client.get(url, HTTP_AUTHORIZATION=authorization)
        else:
            response = getattr(client, method)(
                url,
                data=b'{"body": "test"}',
                content_type="application/json",
                HTTP_AUTHORIZATION=authorization,
            )

        assert response.status_code == 200
        assert response.json() == {"ok": True}
        request_mock.assert_called_once()
        assert request_mock.call_args.args[0] == f"{JIRA_SERVER.rstrip('/')}{path}"
        assert (
            request_mock.call_args.kwargs["headers"]["Authorization"] == authorization
        )

    def test_get_falls_back_to_jira_api_key(self, client, test_api_uri, monkeypatch):
        path = "/rest/api/3/myself"
        response_mock = Mock(status_code=200)
        response_mock.json.return_value = {"ok": True}
        request_mock = Mock(return_value=response_mock)
        monkeypatch.setattr("osidb.api_views.requests.get", request_mock)

        response = client.get(
            f"{test_api_uri}/jira_stage_forwarder?path={path}",
            HTTP_JIRA_API_KEY="jira-token",
        )

        assert response.status_code == 200
        assert response.json() == {"ok": True}
        request_mock.assert_called_once()
        assert request_mock.call_args.kwargs["headers"]["Authorization"] == (
            "Bearer jira-token"
        )

    @pytest.mark.parametrize(
        "path",
        [
            "https://evil.example/rest/api/3/myself",
            f"{JIRA_SERVER}/rest/api/3/myself",
            "//evil.example/rest/api/3/myself",
            "@evil.example/rest/api/3/myself",
        ],
    )
    def test_post_rejects_unsafe_basic_authorization_path(
        self, client, test_api_uri, monkeypatch, path
    ):
        request_mock = Mock()
        monkeypatch.setattr("osidb.api_views.requests.post", request_mock)

        response = client.post(
            f"{test_api_uri}/jira_stage_forwarder?path={path}",
            data=b'{"body": "test"}',
            content_type="application/json",
            HTTP_AUTHORIZATION="Basic fake==",
        )

        assert response.status_code == 400
        assert response.json() == {"path": ["A Jira-relative path is required."]}
        request_mock.assert_not_called()

    def test_get_rejects_unsafe_jira_api_key_path(
        self, client, test_api_uri, monkeypatch
    ):
        request_mock = Mock()
        monkeypatch.setattr("osidb.api_views.requests.get", request_mock)

        response = client.get(
            f"{test_api_uri}/jira_stage_forwarder?path=@evil.example/rest/api/3/myself",
            HTTP_JIRA_API_KEY="jira-token",
        )

        assert response.status_code == 400
        assert response.json() == {"path": ["A Jira-relative path is required."]}
        request_mock.assert_not_called()

    def test_get_requires_jira_authorization(self, client, test_api_uri, monkeypatch):
        request_mock = Mock()
        monkeypatch.setattr("osidb.api_views.requests.get", request_mock)

        response = client.get(
            f"{test_api_uri}/jira_stage_forwarder?path=/rest/api/3/myself"
        )

        assert response.status_code == 400
        assert response.json() == {"Jira-Api-Key": ["This HTTP header is required."]}
        request_mock.assert_not_called()
