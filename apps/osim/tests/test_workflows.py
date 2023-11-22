"""
workflow definitions validation tests
"""

import pytest

from apps.osim.workflow import WorkflowFramework, WorkflowModel

pytestmark = pytest.mark.unit


class TestWorkflows:
    @pytest.fixture()
    def workflows(self):
        return WorkflowFramework().workflows

    def test_workflow_framework_uniqueness(self):
        """test that there always exists only one workflow framework"""
        workflow_framework1 = WorkflowFramework()
        workflow_framework2 = WorkflowFramework()
        assert workflow_framework1 is workflow_framework2

    def test_workflow_exists(self, workflows):
        """test that some workflow exists"""
        assert len(workflows)

    def test_workflow_name_unique(self, workflows):
        """test that every workflow has a unique name"""
        assert len(set(w.name for w in workflows)) == len(workflows)

    def test_workflow_priority_unique(self, workflows):
        """test that every workflow has a unique priority"""
        assert len(set(w.priority for w in workflows)) == len(workflows)

    def test_workflow_priority_non_negative(self, workflows):
        """test that every workflow has a non-negative priority"""
        assert all(isinstance(w.priority, int) for w in workflows)
        assert all(w.priority >= 0 for w in workflows)

    def test_workflow_priority_order(self, workflows):
        """test that the workflows are ordered by decreasing priority"""
        for i in range(len(workflows)):
            if i + 1 < len(workflows):
                assert workflows[i].priority > workflows[i + 1].priority

    def test_default_workflow_exists(self, workflows):
        """
        test that there exists a default workflow with empty conditions
        """
        assert any(not workflow.conditions for workflow in workflows)

    def test_non_empty_states(self, workflows):
        """test that every workflow has non-empty states"""
        assert all(w.states for w in workflows)

    def test_draft_state_exists(self, workflows):
        """test that the initial state of every workflow has empty requirements"""
        assert all(not w.states[0].requirements for w in workflows)

    def test_state_name_unique(self, workflows):
        """test that every state in a workflow has a unique name"""
        for workflow in workflows:
            assert len(set(s.name for s in workflow.states)) == len(workflow.states)

    def test_state_name_allowed(self, workflows):
        """test that every state in a workflow has a name which is allowed"""
        for workflow in workflows:
            for state in workflow.states:
                assert state.name in WorkflowModel.OSIMState.values
