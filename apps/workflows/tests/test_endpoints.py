import pytest

from apps.taskman.service import JiraTaskmanQuerier
from apps.workflows.models import State, Workflow
from apps.workflows.serializers import WorkflowSerializer
from apps.workflows.urls import urlpatterns
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from osidb.models import Flaw
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestEndpoints(object):
    # workflows/
    def test_index_auth(self, auth_client, test_scheme_host):
        """test authenticated index API endpoint"""
        response = auth_client.get(f"{test_scheme_host}/")
        assert response.status_code == 200
        body = response.json()
        assert body["index"] == [f"/{url.pattern}" for url in urlpatterns]

    def test_index_no_auth(self, client, test_scheme_host):
        """test authenticated index API endpoint without authenticating"""
        response = client.get(f"{test_scheme_host}/")
        assert response.status_code == 401

    # workflows/healthy
    def test_health(self, client, test_scheme_host):
        """test health API endpoint"""
        response = client.get(f"{test_scheme_host}/healthy")
        assert response.status_code == 200

    # workflows
    def test_workflows_auth(self, auth_client, test_api_uri):
        """test authenticated workflows API endpoint"""
        response = auth_client.get(f"{test_api_uri}")
        assert response.status_code == 200
        body = response.json()
        workflows = WorkflowSerializer(WorkflowFramework().workflows, many=True).data
        assert body["workflows"] == workflows

    def test_workflows_no_auth(self, client, test_api_uri):
        """test authenticated workflows API endpoint without authenticating"""
        response = client.get(f"{test_api_uri}")
        assert response.status_code == 401

    def test_workflows_cve(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint"""
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/{flaw.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" not in body

    # workflows/{flaw}
    def test_workflows_uuid(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint"""
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/{flaw.uuid}")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" not in body

    def test_workflows_uuid_verbose(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint with verbose parameter"""
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/{flaw.uuid}?verbose=true")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" in body

    def test_workflows_uuid_non_existing(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint with non-exising flaw"""
        response = auth_client.get(
            f"{test_api_uri}/35d1ad45-0dba-41a3-bad6-5dd36d624ead"
        )
        assert response.status_code == 404

    def test_workflows_uuid_no_auth(self, client, test_api_uri):
        """test authenticated workflow classification API endpoint without authenticating"""
        flaw = FlawFactory()
        response = client.get(f"{test_api_uri}/{flaw.uuid}")
        assert response.status_code == 401

    # workflows/{flaw}/adjust
    def test_workflows_uuid_adjusting(self, auth_client, test_api_uri):
        """test flaw classification adjustion after metadata change"""
        workflow_framework = WorkflowFramework()
        state_new = State(
            {
                "name": WorkflowModel.WorkflowState.NEW,
                "requirements": [],
                "jira_state": "New",
                "jira_resolution": None,
            }
        )
        state_first = State(
            {
                "name": WorkflowModel.WorkflowState.TRIAGE,
                "requirements": ["has description"],
                "jira_state": "To Do",
                "jira_resolution": None,
            }
        )
        state_second = State(
            {
                "name": WorkflowModel.WorkflowState.DONE,
                "requirements": ["has title"],
                "jira_state": "In Progress",
                "jira_resolution": None,
            }
        )

        states = [state_new, state_first, state_second]

        # initialize default workflow first so there is
        # always some workflow to classify the flaw in
        workflow = Workflow(
            {
                "name": "default workflow",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        # major incident workflow
        workflow = Workflow(
            {
                "name": "major incident workflow",
                "description": "random description",
                "priority": 1,  # is more prior than default one
                "conditions": [
                    "is major incident"
                ],  # major incident flaws are classified here
                "states": [],  # this is not valid but OK for this test
            }
        )
        workflow.states = states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory.build(major_incident_state=Flaw.FlawMajorIncident.APPROVED)
        flaw.save(raise_validation_error=False)
        AffectFactory(flaw=flaw)

        assert flaw.classification == {
            "workflow": "major incident workflow",
            "state": "DONE",
        }

        flaw.major_incident_state = Flaw.FlawMajorIncident.NOVALUE
        flaw.save()

        response = auth_client.post(f"{test_api_uri}/{flaw.uuid}/adjust")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert body["classification"] == {
            "workflow": "default workflow",
            "state": "DONE",
        }

        # reload flaw DB
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert flaw.classification == {
            "workflow": "default workflow",
            "state": "DONE",
        }

    def test_workflows_uuid_adjusting_no_modification(self, auth_client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint with no flaw modification
        """
        flaw = FlawFactory()
        response = auth_client.post(f"{test_api_uri}/{flaw.uuid}/adjust")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert body["classification"] == flaw.classification

    def test_workflows_uuid_adjust_non_existing(self, auth_client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint with non-exising flaw
        """
        response = auth_client.post(
            f"{test_api_uri}/35d1ad45-0dba-41a3-bad6-5dd36d624ead/adjust"
        )
        assert response.status_code == 404

    def test_workflows_uuid_adjust_no_auth(self, client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint without authenticating
        """
        flaw = FlawFactory()
        response = client.post(f"{test_api_uri}/{flaw.uuid}/adjust")
        assert response.status_code == 401

    def test_promote_endpoint(self, auth_client, test_api_uri_osidb, user_token):
        """test flaw state promotion after data change"""
        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_first = {
            "name": WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            "requirements": ["has cwe"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }

        state_second = {
            "name": WorkflowModel.WorkflowState.DONE,
            "requirements": ["has summary"],
            "jira_state": "In Progress",
            "jira_resolution": None,
        }

        workflow = Workflow(
            {
                "name": "default workflow",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [state_new, state_first, state_second],
            }
        )
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory(cwe_id="", summary="")
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "default workflow"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW
        headers = {"HTTP_JIRA_API_KEY": user_token}
        response = auth_client.post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 409
        body = response.json()
        assert "has cwe" in body["errors"]

        flaw = Flaw.objects.get(pk=flaw.pk)
        flaw.cwe_id = "CWE-1"
        flaw.save()

        response = auth_client.post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert (
            body["classification"]["state"]
            == WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT
        )

        flaw = Flaw.objects.get(pk=flaw.pk)
        flaw.summary = "valid summary"
        flaw.save()

        response = auth_client.post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert response.status_code == 200
        body = response.json()
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.DONE

        response = auth_client.post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 409
        body = response.json()
        assert "already in the last state" in body["errors"]

    def test_reject_endpoint(
        self,
        monkeypatch,
        auth_client,
        test_api_uri_osidb,
        user_token,
    ):
        """test flaw state promotion after data change"""

        def mock_create_comment(self, issue_key: str, body: str):
            return

        monkeypatch.setattr(JiraTaskmanQuerier, "create_comment", mock_create_comment)

        workflow_framework = WorkflowFramework()
        workflow_framework._workflows = []

        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        state_first = {
            "name": WorkflowModel.WorkflowState.SECONDARY_ASSESSMENT,
            "requirements": ["has cwe"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }

        workflow = Workflow(
            {
                "name": "DEFAULT",
                "description": "random description",
                "priority": 1,
                "conditions": [],
                "states": [state_new, state_first],
            }
        )
        state_reject = {
            "name": WorkflowModel.WorkflowState.REJECTED,
            "requirements": [],
            "jira_state": "Closed",
            "jira_resolution": "Won't Do",
        }
        reject_workflow = Workflow(
            {
                "name": "REJECTED",
                "description": "random description",
                "priority": 0,
                "conditions": [],
                "states": [state_reject],
            }
        )
        workflow_framework.register_workflow(workflow)
        workflow_framework.register_workflow(reject_workflow)

        flaw = FlawFactory(cwe_id="")
        AffectFactory(flaw=flaw)

        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW
        headers = {"HTTP_JIRA_API_KEY": user_token}

        response = auth_client.post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reject",
            data={},
            format="json",
            **headers,
        )
        assert response.status_code == 400
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert flaw.classification["workflow"] == "DEFAULT"
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW

        response = auth_client.post(
            f"{test_api_uri_osidb}/flaws/{flaw.uuid}/reject",
            data={"reason": "This was a spam."},
            format="json",
            **headers,
        )

        body = response.json()

        assert response.status_code == 200
        assert body["classification"]["workflow"] == "REJECTED"
        assert body["classification"]["state"] == WorkflowModel.WorkflowState.REJECTED
