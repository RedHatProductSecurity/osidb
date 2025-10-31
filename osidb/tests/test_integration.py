"""
Integration tests assume access to running osidb-service and osidb-data tiers

Curl is used to independently test api

"""

import json
import subprocess

import pytest

pytestmark = pytest.mark.integration


class TestIntegration(object):
    def _test_with_curl(self, command_curl, live_server, endpoint):
        cmd = [
            command_curl,
            "-v",
            "-H",
            "Content-type: application/json",
            f"{live_server.url}/osidb/{endpoint}",
        ]

        curl_result = subprocess.run(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE
        )

        assert curl_result.returncode == 0
        return json.loads(curl_result.stdout)

    def test_healthy_with_curl(self, command_curl, live_server):
        """access healthy using curl"""
        json_body = self._test_with_curl(command_curl, live_server, "healthy")
        assert json_body["env"] == "local"

    def test_status_with_curl(self, command_curl, live_server):
        """access status api using curl"""
        json_body = self._test_with_curl(command_curl, live_server, "api/v1/status")
        assert json_body["env"] == "local"

    def test_flaws_with_curl(self, command_curl, live_server):
        """access flaw api v1 using curl"""
        json_body = self._test_with_curl(command_curl, live_server, "api/v1/flaws")
        assert "count" in json_body

    def test_flaws_with_curl_v2(self, command_curl, live_server):
        """access flaw api v2 using curl"""
        json_body = self._test_with_curl(command_curl, live_server, "api/v2/flaws")
        assert "count" in json_body
