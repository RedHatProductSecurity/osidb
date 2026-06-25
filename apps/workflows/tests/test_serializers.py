import pytest

from apps.workflows.models import Workflow
from apps.workflows.serializers import (
    ClassificationWorkflowSerializer,
    WorkflowSerializer,
)

pytestmark = pytest.mark.unit


class TestSerializerFieldOrder:
    """Test that serializers produce fields in the expected order for browser readability"""

    @pytest.fixture
    def workflow(self):
        return Workflow(
            {
                "name": "test workflow",
                "description": "test description",
                "priority": 0,
                "conditions": ["has cve_id"],
                "states": [
                    {
                        "name": "NEW",
                        "jira_state": "New",
                        "jira_resolution": None,
                        "requirements": [],
                    },
                ],
            }
        )

    def test_workflow_serializer_field_order(self, workflow):
        data = WorkflowSerializer(workflow).data
        assert list(data.keys()) == [
            "name",
            "description",
            "priority",
            "conditions",
            "states",
        ]

    def test_classification_workflow_serializer_field_order(self, workflow):
        data = ClassificationWorkflowSerializer(workflow).data
        assert list(data.keys()) == [
            "accepts",
            "name",
            "description",
            "priority",
            "conditions",
            "states",
            "classified_state",
        ]
