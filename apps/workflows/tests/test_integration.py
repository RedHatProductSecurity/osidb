"""
Integration tests assume access to running

    * osidb-service
    * osidb-data

curl is used to independently test API

"""

import json
import subprocess

import pytest

from apps.workflows.models import Workflow
from apps.workflows.serializers import WorkflowSerializer
from apps.workflows.urls import urlpatterns
from apps.workflows.workflow import WorkflowFramework, WorkflowModel
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.integration


class TestIntegration(object):
    def test_index_with_curl(self, command_curl, live_server, tokens):
        """access index API using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            "-H",
            f"Authorization: Bearer {tokens['access']}",
            f"{live_server.url}/workflows/",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        assert json_body["index"] == [f"/{url.pattern}" for url in urlpatterns]

    def test_healthy_with_curl(self, command_curl, live_server):
        """access healthy API endpoint using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            f"{live_server.url}/workflows/healthy",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0

    def test_workflows_with_curl(
        self,
        command_curl,
        live_server,
        tokens,
    ):
        """access workflows API using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            "-H",
            f"Authorization: Bearer {tokens['access']}",
            f"{live_server.url}/workflows/api/v1/graph/workflows",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        # FIXME
        # json_body = json.loads(curl_result.stdout)
        # workflows = WorkflowSerializer(WorkflowFramework().workflows, many=True).data
        # assert json_body["workflows"] == workflows

    def get_flaw_if_exists(
        self,
        command_curl,
        live_server,
        tokens,
    ):
        """get flaw UUID from flaw API using curl if one exists"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            "-H",
            f"Authorization: Bearer {tokens['access']}",
            f"{live_server.url}/osidb/api/v2/flaws?limit=1&include_fields=uuid",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)

        # the DB may actually contain no flaws
        try:
            return json_body["results"][0]["uuid"]
        except IndexError:
            return "CVE-2000-12345"

    def test_workflows_flaw_with_curl(
        self,
        command_curl,
        live_server,
        tokens,
    ):
        """access workflows classification API using curl"""
        uuid = self.get_flaw_if_exists(
            command_curl,
            live_server,
            tokens,
        )

        # get flaw workflow:state classification
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            "-H",
            f"Authorization: Bearer {tokens['access']}",
            f"{live_server.url}/workflows/api/v1/{uuid}",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        # FIXME
        # json_body = json.loads(curl_result.stdout)

        # if uuid:
        #    assert "uuid" in json_body
        #    assert json_body["uuid"] == uuid
        #    assert "classification" in json_body
        #    assert "workflow" in json_body["classification"]
        #    assert "state" in json_body["classification"]

        # else:
        #    assert "detail" in json_body
        #    assert json_body["detail"] == "Not found."

    def test_workflows_flaw_adjust_with_curl(
        self,
        command_curl,
        live_server,
        tokens,
    ):
        """access workflows classification adjustion API using curl"""
        uuid = self.get_flaw_if_exists(
            command_curl,
            live_server,
            tokens,
        )

        # adjust flaw workflow:state classification
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            "-H",
            f"Authorization: Bearer {tokens['access']}",
            "-X POST",  # ???: no payload?
            # substitute UUID with dummy CVE ID if no UUID exists
            f"{live_server.url}/workflows/api/v1/{uuid}/adjust",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        # FIXME
        # json_body = json.loads(curl_result.stdout)

        # if uuid:
        #    assert "uuid" in json_body
        #    assert json_body["uuid"] == uuid
        #    assert "classification" in json_body
        #    assert "workflow" in json_body["classification"]
        #    assert "state" in json_body["classification"]

        # else:
        #    assert "detail" in json_body
        #    assert json_body["detail"] == "Not found."


class TestRestApi(object):
    def test_index(self, auth_client, test_scheme_host):
        """test access index API"""
        response = auth_client().get(
            f"{test_scheme_host}/",
            data={},
            format="json",
        )
        assert response.status_code == 200

        json_body = response.json()
        assert json_body["index"] == [f"/{url.pattern}" for url in urlpatterns]

    def test_healthy(self, auth_client, test_scheme_host):
        """test access healthy API"""
        response = auth_client().get(
            f"{test_scheme_host}/healthy",
            data={},
            format="json",
        )
        assert response.status_code == 200

    def test_adjust(self, auth_client, test_api_uri):
        """test refreshing/adjusting a flaw state through API"""
        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }
        state_first = {
            "name": WorkflowModel.WorkflowState.TRIAGE,
            "requirements": ["has cwe"],
            "jira_state": "To Do",
            "jira_resolution": None,
        }

        workflow_main = Workflow(
            {
                "name": "main workflow",
                "description": "a workflow to test classification",
                "priority": 100,
                "conditions": [],
                "states": [state_new, state_first],
            }
        )

        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(workflow_main)

        flaw = FlawFactory()
        AffectFactory(flaw=flaw)
        flaw.cwe_id = ""
        flaw.save(raise_validation_error=False)
        flaw.adjust_classification()
        assert flaw.classification["state"] == WorkflowModel.WorkflowState.NEW

        flaw.cwe_id = "CWE-1"
        flaw.save(raise_validation_error=False)

        response = auth_client().post(
            f"{test_api_uri}/workflows/{flaw.uuid}/adjust",
            data={},
            format="json",
        )
        assert response.status_code == 200

        json_body = response.json()
        assert str(flaw.uuid) == json_body["flaw"]
        assert (
            WorkflowModel.WorkflowState.TRIAGE == json_body["classification"]["state"]
        )

    def test_classification(self, auth_client, test_api_uri):
        state_new = {
            "name": WorkflowModel.WorkflowState.NEW,
            "requirements": [],
            "jira_state": "New",
            "jira_resolution": None,
        }

        workflow_main = Workflow(
            {
                "name": "main workflow",
                "description": "a workflow to test classification",
                "priority": 100,
                "conditions": [],
                "states": [state_new],
            }
        )

        workflow_framework = WorkflowFramework()
        workflow_framework.register_workflow(workflow_main)
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)

        response = auth_client().get(
            f"{test_api_uri}/workflows/{flaw.uuid}",
            data={},
            format="json",
        )
        assert response.status_code == 200
        json_body = response.json()
        assert "classification" in json_body
        assert "workflow" in json_body["classification"]
        assert "state" in json_body["classification"]

        assert json_body["classification"]["workflow"] == "main workflow"
        assert json_body["classification"]["state"] == WorkflowModel.WorkflowState.NEW

    def test_workflows(self, auth_client, test_api_uri):
        response = auth_client().get(
            f"{test_api_uri}/workflows",
            data={},
            format="json",
        )
        json_body = response.json()
        workflows = WorkflowSerializer(WorkflowFramework().workflows, many=True).data
        assert json_body["workflows"] == workflows
