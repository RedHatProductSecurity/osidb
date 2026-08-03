"""Tests for apps.ace.client."""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
import requests

from apps.ace.client import (
    AffectAutomationConnector,
    AffectAutomationQuerier,
)

pytestmark = pytest.mark.unit


class TestAffectAutomationConnector:
    def test_session_creates_on_first_access(self):
        connector = AffectAutomationConnector()
        assert connector._session is None

        session = connector.session
        assert session is not None
        assert isinstance(session, requests.Session)
        assert connector._session_timestamp is not None

    def test_session_reuses_within_max_age(self):
        connector = AffectAutomationConnector()
        first_session = connector.session
        second_session = connector.session
        assert first_session is second_session

    @patch("apps.ace.client.AFFECT_AUTOMATION_MAX_CONNECTION_AGE", "1")
    def test_session_recreates_after_max_age(self):
        connector = AffectAutomationConnector()
        first_session = connector.session
        connector._session_timestamp = datetime.now() - timedelta(seconds=2)
        second_session = connector.session
        assert first_session is not second_session

    def test_session_sets_auth_header(self):
        connector = AffectAutomationConnector()
        connector._token = "test-token-123"
        session = connector._create_session()
        assert session.headers["Authorization"] == "Bearer test-token-123"
        assert session.headers["Content-Type"] == "application/json"
        assert session.headers["Accept"] == "application/json"


class TestAffectAutomationQuerier:
    @patch("apps.ace.client.AFFECT_AUTOMATION_URL", "https://aa.example.com")
    def test_request_affects_posts_to_correct_url(self):
        querier = AffectAutomationQuerier()
        querier._base_url = "https://aa.example.com"

        mock_response = MagicMock()
        mock_response.json.return_value = {"affects": [], "status": "completed"}
        mock_response.raise_for_status = MagicMock()

        with patch.object(querier, "session") as mock_session:
            mock_session.post.return_value = mock_response
            result = querier.request_affects("flaw-uuid", {"flaw_id": "flaw-uuid"})

        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        assert call_args[0][0] == "https://aa.example.com/api/v1/affects/"
        assert call_args[1]["json"] == {"flaw_id": "flaw-uuid"}
        assert result == {"affects": [], "status": "completed"}

    @patch("apps.ace.client.AFFECT_AUTOMATION_URL", "https://aa.example.com/")
    def test_request_affects_strips_trailing_slash(self):
        querier = AffectAutomationQuerier()
        querier._base_url = "https://aa.example.com/"

        mock_response = MagicMock()
        mock_response.json.return_value = {"affects": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(querier, "session") as mock_session:
            mock_session.post.return_value = mock_response
            querier.request_affects("flaw-uuid", {})

        url = mock_session.post.call_args[0][0]
        assert url == "https://aa.example.com/api/v1/affects/"

    def test_request_affects_raises_on_http_error(self):
        querier = AffectAutomationQuerier()
        querier._base_url = "https://aa.example.com"

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "500 Server Error"
        )

        with patch.object(querier, "session") as mock_session:
            mock_session.post.return_value = mock_response
            with pytest.raises(requests.HTTPError):
                querier.request_affects("flaw-uuid", {})

    def test_health_check_returns_true_on_200(self):
        querier = AffectAutomationQuerier()
        querier._base_url = "https://aa.example.com"

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch.object(querier, "session") as mock_session:
            mock_session.get.return_value = mock_response
            assert querier.health_check() is True

    def test_health_check_returns_false_on_error(self):
        querier = AffectAutomationQuerier()
        querier._base_url = "https://aa.example.com"

        with patch.object(querier, "session") as mock_session:
            mock_session.get.side_effect = requests.ConnectionError()
            assert querier.health_check() is False
