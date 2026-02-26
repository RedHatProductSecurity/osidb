from unittest.mock import MagicMock, patch

import pytest

from collectors.jira_user_mapping.collectors import JiraUserMappingCollector
from osidb.models.jira_user_mapping import JiraUserMapping

pytestmark = pytest.mark.unit

SAMPLE_RESPONSE = [
    {
        "associate_uuid": "3cb04a80-eed2-11e9-b12d-001a4a0b004e",
        "associate_kerberos_id": "jdoe",
        "atlassian_cloud_id": "712020:1f8238fb-e977-4851-83f1-9763f3101776",
        "is_employed": True,
        "name": "John Doe",
    },
    {
        "associate_uuid": "4db15b91-ffd3-22fa-c23e-112b5b1c115f",
        "associate_kerberos_id": "asmith",
        "atlassian_cloud_id": "712020:2a9349gc-f088-5962-94g2-0874g4212887",
        "is_employed": False,
        "name": "Alice Smith",
    },
]


@pytest.fixture
def mock_response():
    response = MagicMock()
    response.json.return_value = SAMPLE_RESPONSE
    response.raise_for_status.return_value = None
    return response


class TestJiraUserMappingCollector:
    @patch("collectors.jira_user_mapping.collectors.requests.get")
    def test_collect_creates_mappings(self, mock_get, mock_response):
        mock_get.return_value = mock_response

        collector_obj = JiraUserMappingCollector()
        collector_obj.name = "jira_user_mapping_collector"
        msg = collector_obj.collect()

        assert JiraUserMapping.objects.count() == 2
        assert "created 2" in msg

        mapping = JiraUserMapping.objects.get(
            associate_uuid="3cb04a80-eed2-11e9-b12d-001a4a0b004e"
        )
        assert mapping.associate_kerberos_id == "jdoe"
        assert (
            mapping.atlassian_cloud_id == "712020:1f8238fb-e977-4851-83f1-9763f3101776"
        )
        assert mapping.is_employed is True
        assert mapping.name == "John Doe"

    @patch("collectors.jira_user_mapping.collectors.requests.get")
    def test_collect_updates_existing_mappings(self, mock_get, mock_response):
        mock_get.return_value = mock_response

        # Create initial data
        JiraUserMapping.objects.create(
            associate_uuid="3cb04a80-eed2-11e9-b12d-001a4a0b004e",
            associate_kerberos_id="jdoe_old",
            atlassian_cloud_id="cloud-id-old",
            is_employed=False,
            name="Old Name",
        )

        collector_obj = JiraUserMappingCollector()
        collector_obj.name = "jira_user_mapping_collector"
        msg = collector_obj.collect()

        assert JiraUserMapping.objects.count() == 2
        assert "updated 1" in msg
        assert "created 1" in msg

        mapping = JiraUserMapping.objects.get(
            associate_uuid="3cb04a80-eed2-11e9-b12d-001a4a0b004e"
        )
        assert mapping.associate_kerberos_id == "jdoe"
        assert (
            mapping.atlassian_cloud_id == "712020:1f8238fb-e977-4851-83f1-9763f3101776"
        )
        assert mapping.is_employed is True
        assert mapping.name == "John Doe"

    @patch("collectors.jira_user_mapping.collectors.requests.get")
    def test_collect_empty_response(self, mock_get):
        response = MagicMock()
        response.json.return_value = []
        response.raise_for_status.return_value = None
        mock_get.return_value = response

        collector_obj = JiraUserMappingCollector()
        collector_obj.name = "jira_user_mapping_collector"
        msg = collector_obj.collect()

        assert JiraUserMapping.objects.count() == 0
        assert "created 0" in msg
        assert "updated 0" in msg
