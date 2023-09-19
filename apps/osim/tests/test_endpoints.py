import pytest

from apps.osim.models import Workflow
from apps.osim.serializers import WorkflowSerializer
from apps.osim.tests.test_models import StateFactory
from apps.osim.urls import urlpatterns
from apps.osim.workflow import WorkflowFramework
from osidb.models import Flaw
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestEndpoints(object):
    # osim/
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

    # osim/healthy
    def test_health(self, client, test_scheme_host):
        """test health API endpoint"""
        response = client.get(f"{test_scheme_host}/healthy")
        assert response.status_code == 200

    # osim/workflows
    def test_workflows_auth(self, auth_client, test_api_uri):
        """test authenticated workflows API endpoint"""
        response = auth_client.get(f"{test_api_uri}/workflows")
        assert response.status_code == 200
        body = response.json()
        workflows = WorkflowSerializer(WorkflowFramework().workflows, many=True).data
        assert body["workflows"] == workflows

    def test_workflows_no_auth(self, client, test_api_uri):
        """test authenticated workflows API endpoint without authenticating"""
        response = client.get(f"{test_api_uri}/workflows")
        assert response.status_code == 401

    def test_workflows_cve(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint"""
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/workflows/{flaw.cve_id}")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" not in body

    # osim/workflows/{flaw}
    def test_workflows_uuid(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint"""
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/workflows/{flaw.uuid}")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" not in body

    def test_workflows_uuid_verbose(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint with verbose parameter"""
        flaw = FlawFactory()
        response = auth_client.get(f"{test_api_uri}/workflows/{flaw.uuid}?verbose=true")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert "workflows" in body

    def test_workflows_uuid_non_existing(self, auth_client, test_api_uri):
        """test authenticated workflow classification API endpoint with non-exising flaw"""
        response = auth_client.get(
            f"{test_api_uri}/workflows/35d1ad45-0dba-41a3-bad6-5dd36d624ead"
        )
        assert response.status_code == 404

    def test_workflows_uuid_no_auth(self, client, test_api_uri):
        """test authenticated workflow classification API endpoint without authenticating"""
        flaw = FlawFactory()
        response = client.get(f"{test_api_uri}/workflows/{flaw.uuid}")
        assert response.status_code == 401

    # osim/workflows/{flaw}/adjust
    def test_workflows_uuid_adjusting(self, auth_client, test_api_uri):
        """test flaw classification adjustion after metadata change"""
        workflow_framework = WorkflowFramework()
        random_states, _ = StateFactory().generate(count=1)
        random_states[0].requirements = []  # default state

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
        workflow.states = random_states
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
        workflow.states = random_states
        workflow_framework.register_workflow(workflow)

        flaw = FlawFactory.build(major_incident_state=Flaw.FlawMajorIncident.APPROVED)
        flaw.save(raise_validation_error=False)
        AffectFactory(flaw=flaw)

        assert flaw.classification == {
            "workflow": "major incident workflow",
            "state": "DRAFT",
        }

        flaw.major_incident_state = Flaw.FlawMajorIncident.NOVALUE
        flaw.save()

        response = auth_client.post(f"{test_api_uri}/workflows/{flaw.uuid}/adjust")
        assert response.status_code == 200
        body = response.json()
        assert body["flaw"] == str(flaw.uuid)
        assert "classification" in body
        assert body["classification"] == {
            "workflow": "default workflow",
            "state": "DRAFT",
        }

        # reload flaw DB
        flaw = Flaw.objects.get(pk=flaw.pk)
        assert flaw.classification == {
            "workflow": "default workflow",
            "state": "DRAFT",
        }

    def test_workflows_uuid_adjusting_no_modification(self, auth_client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint with no flaw modification
        """
        flaw = FlawFactory()
        response = auth_client.post(f"{test_api_uri}/workflows/{flaw.uuid}/adjust")
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
            f"{test_api_uri}/workflows/35d1ad45-0dba-41a3-bad6-5dd36d624ead/adjust"
        )
        assert response.status_code == 404

    def test_workflows_uuid_adjust_no_auth(self, client, test_api_uri):
        """
        test authenticated workflow classification adjusting API endpoint without authenticating
        """
        flaw = FlawFactory()
        response = client.post(f"{test_api_uri}/workflows/{flaw.uuid}/adjust")
        assert response.status_code == 401
