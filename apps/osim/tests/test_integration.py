"""
    Integration tests assume access to running

        * osidb-service
        * osidb-data

    curl is used to independently test API

"""

import json
import logging
import subprocess

import pytest

from apps.osim.serializers import WorkflowSerializer
from apps.osim.urls import urlpatterns
from apps.osim.workflow import WorkflowFramework

pytestmark = pytest.mark.integration

logger = logging.getLogger(__name__)
pytestmark = pytest.mark.integration


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
