"""
    Integration tests assume access to running osidb-service and osidb-data tiers

    Curl is used to independently test api

"""
import json
import subprocess

import pytest

pytestmark = pytest.mark.integration


class TestIntegration(object):
    def test_healthy_with_curl(self, command_curl, test_scheme_host):
        """access healthy using curl"""
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

    def test_status_with_curl(
        self,
        command_curl,
        test_api_uri,
        tokens,
    ):
        """access status api using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            "-H",
            f"Authorization: Bearer {tokens['access']}",
            f"{test_api_uri}/status",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        assert json_body["status"] == "ok"

    def test_flaws_with_curl(
        self,
        command_curl,
        test_api_uri,
        tokens,
    ):
        """access status api using curl"""
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            "-H",
            f"Authorization: Bearer {tokens['access']}",
            f"{test_api_uri}/flaws",
        ]
        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )
        assert curl_result.returncode == 0
        json_body = json.loads(curl_result.stdout)
        assert "count" in json_body
