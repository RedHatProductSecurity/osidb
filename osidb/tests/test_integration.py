"""
Integration tests assume access to running osidb-service and osidb-data tiers

Curl is used to independently test api

"""

import json
import subprocess

import pytest

pytestmark = pytest.mark.integration


class TestIntegration(object):
    def test_healthy_with_curl(self, command_curl, live_server):
        """access healthy using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            f"{live_server.url}/osidb/healthy",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        assert json_body["env"] == "local"

    def test_status_with_curl(
        self,
        command_curl,
        live_server,
    ):
        """access status api using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            f"{live_server.url}/osidb/api/v1/status",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        assert json_body["env"] == "local"

    def test_flaws_with_curl(
        self,
        command_curl,
        live_server,
    ):
        """access status api using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            f"{live_server.url}/osidb/api/v1/flaws",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        assert "count" in json_body
