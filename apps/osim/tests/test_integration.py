"""
    Integration tests assume access to running

        * osidb-service
        * osidb-data

    curl is used to independently test API

"""
import json
import subprocess

import pytest

from apps.osim.models import Workflow
from apps.osim.serializers import WorkflowSerializer
from apps.osim.urls import urlpatterns
from apps.osim.workflow import WorkflowFramework, WorkflowModel
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.integration


@pytest.mark.skip(reason="No support for this type test in the current environment.")
class TestIntegration(object):
    def test_index_with_curl(self, command_curl, test_scheme_host, tokens):
        """access index API using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            "-H",
            f"Authorization: Bearer {tokens['access']}",
            f"{test_scheme_host}/",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        assert json_body["index"] == [f"/{url.pattern}" for url in urlpatterns]

    def test_healthy_with_curl(self, command_curl, test_scheme_host):
        """access healthy API endpoint using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            f"{test_scheme_host}/healthy",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        assert json_body["status"] == "ok"

    def test_workflows_with_curl(
        self,
        command_curl,
        test_api_uri,
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
            f"{test_api_uri}/workflows",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        workflows = WorkflowSerializer(WorkflowFramework().workflows, many=True).data
        assert json_body["workflows"] == workflows

    def get_flaw_if_exists(
        self,
        command_curl,
        test_api_uri_osidb,
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
            f"{test_api_uri_osidb}/flaws?limit=1&include_fields=uuid",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)

        # the DB may actually contain no flaws
        try:
            return json_body["results"][0]["uuidd"]
        except (IndexError, KeyError):
            return None

    def test_workflows_flaw_with_curl(
        self,
        command_curl,
        test_api_uri,
        test_api_uri_osidb,
        tokens,
    ):
        """access workflows classification API using curl"""
        uuid = self.get_flaw_if_exists(
            command_curl,
            test_api_uri_osidb,
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
            # substitute UUID with dummy CVE ID if no UUID exists
            f"{test_api_uri}/workflows/{uuid or 'CVE-2000-12345'}",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)

        if uuid:
            assert "uuid" in json_body
            assert json_body["uuid"] == uuid
            assert "classification" in json_body
            assert "workflow" in json_body["classification"]
            assert "state" in json_body["classification"]

        else:
            assert "detail" in json_body
            assert json_body["detail"] == "Not found."

    def test_workflows_flaw_adjust_with_curl(
        self,
        command_curl,
        test_api_uri,
        test_api_uri_osidb,
        tokens,
    ):
        """access workflows classification adjustion API using curl"""
        uuid = self.get_flaw_if_exists(
            command_curl,
            test_api_uri_osidb,
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
            f"{test_api_uri}/workflows/{uuid or 'CVE-2000-12345'}/adjust",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)

        if uuid:
            assert "uuid" in json_body
            assert json_body["uuid"] == uuid
            assert "classification" in json_body
            assert "workflow" in json_body["classification"]
            assert "state" in json_body["classification"]

        else:
            assert "detail" in json_body
            assert json_body["detail"] == "Not found."


class TestRestApi(object):
    def test_index(self, auth_client, test_scheme_host):
        """test access index API"""
        response = auth_client.get(
            f"{test_scheme_host}/",
            data={},
            format="json",
        )
        assert response.status_code == 200

        json_body = response.json()
        assert json_body["index"] == [f"/{url.pattern}" for url in urlpatterns]

    def test_healthy(self, auth_client, test_scheme_host):
        """test access healthy API"""
        response = auth_client.get(
            f"{test_scheme_host}/healthy",
            data={},
            format="json",
        )
        assert response.status_code == 200

    def test_adjust(self, auth_client, test_api_uri):
        """test refreshing/adjusting a flaw state through API"""
        state_new = {
            "name": WorkflowModel.OSIMState.DRAFT,
            "requirements": [],
        }
        state_first = {
            "name": WorkflowModel.OSIMState.ANALYSIS,
            "requirements": ["has cwe"],
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
        assert flaw.classification["state"] == WorkflowModel.OSIMState.DRAFT

        flaw.cwe_id = "CWE-1"
        flaw.save(raise_validation_error=False)

        response = auth_client.post(
            f"{test_api_uri}/workflows/{flaw.uuid}/adjust",
            data={},
            format="json",
        )
        assert response.status_code == 200

        json_body = response.json()
        assert str(flaw.uuid) == json_body["flaw"]
        assert WorkflowModel.OSIMState.ANALYSIS == json_body["classification"]["state"]

    def test_classification(self, auth_client, test_api_uri):
        state_new = {
            "name": WorkflowModel.OSIMState.DRAFT,
            "requirements": [],
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

        response = auth_client.get(
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
        assert json_body["classification"]["state"] == WorkflowModel.OSIMState.DRAFT

    def test_workflows(self, auth_client, test_api_uri):
        response = auth_client.get(
            f"{test_api_uri}/workflows",
            data={},
            format="json",
        )
        json_body = response.json()
        workflows = WorkflowSerializer(WorkflowFramework().workflows, many=True).data

        assert json_body["workflows"] == workflows
