"""Tests for apps.ace.microservice."""

from unittest.mock import MagicMock, patch

import pytest

from apps.ace.microservice import (
    _build_payload,
    _persist_affects,
    dispatch_to_microservice,
)
from osidb.models.affect import Affect
from osidb.models.flaw.label_v2 import WorkflowLabel
from osidb.tests.factories import FlawFactory, UpstreamDataFactory

pytestmark = pytest.mark.unit


class TestBuildPayload:
    def test_basic_payload_shape(self):
        flaw = FlawFactory(
            components=["urllib3"],
            cve_id="CVE-2025-12345",
            impact="MODERATE",
        )

        payload = _build_payload(flaw, ["hummingbird-1"])

        assert payload["flaw_id"] == str(flaw.uuid)
        assert payload["cve_id"] == "CVE-2025-12345"
        assert payload["components"] == ["urllib3"]
        assert payload["ps_modules"] == ["hummingbird-1"]
        assert payload["impact"] == "MODERATE"
        assert isinstance(payload["upstream_purls"], list)
        assert isinstance(payload["component_ecosystems"], (dict, list))
        assert isinstance(payload["references"], list)

    def test_payload_with_upstream_data(self):
        flaw = FlawFactory(components=["openssl"])
        UpstreamDataFactory(
            flaw=flaw,
            source="OSV",
            upstream_purls=[
                {
                    "purl": "pkg:pypi/openssl",
                    "name": "openssl",
                    "ecosystem": "PyPI",
                    "ranges": [],
                    "versions": [],
                }
            ],
        )

        payload = _build_payload(flaw, ["hummingbird-1"])

        assert len(payload["upstream_purls"]) == 1
        assert payload["upstream_purls"][0]["purl"] == "pkg:pypi/openssl"

    def test_payload_without_upstream_data(self):
        flaw = FlawFactory(components=["urllib3"])

        payload = _build_payload(flaw, ["hummingbird-1"])

        assert payload["upstream_purls"] == []
        assert payload["component_ecosystems"] == {}

    def test_payload_with_empty_components(self):
        flaw = FlawFactory(components=[])

        payload = _build_payload(flaw, [])

        assert payload["components"] == []

    def test_payload_with_no_cve_id(self):
        flaw = FlawFactory(components=["urllib3"], cve_id=None)

        payload = _build_payload(flaw, ["hummingbird-1"])

        assert payload["cve_id"] == ""


class TestPersistAffects:
    def test_creates_affects_from_response(self):
        flaw = FlawFactory(components=["urllib3"])
        response = {
            "affects": [
                {
                    "ps_update_stream": "hummingbird-1",
                    "purl": "pkg:oci/python-cryptography",
                    "ps_component": "python-cryptography",
                    "affectedness": "AFFECTED",
                    "resolution": "DELEGATED",
                    "impact": "MODERATE",
                    "assist_meta": {"tool_name": "aa-service", "workflow": "standard"},
                }
            ],
            "labels": ["auto-affects"],
        }

        stats = _persist_affects(flaw, response)

        assert stats["created"] == 1
        assert stats["skipped_existing"] == 0
        assert flaw.affects.count() == 1

        affect = flaw.affects.first()
        assert affect.ps_update_stream == "hummingbird-1"
        assert affect.ps_component == "python-cryptography"
        assert affect.affectedness == "AFFECTED"
        assert affect.resolution == "DELEGATED"
        assert affect.created_by == "AffectCreationEngine"

    def test_skips_existing_affects(self):
        flaw = FlawFactory(components=["urllib3"])
        Affect.objects.create(
            flaw=flaw,
            ps_update_stream="hummingbird-1",
            ps_component="python-cryptography",
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )

        response = {
            "affects": [
                {
                    "ps_update_stream": "hummingbird-1",
                    "ps_component": "python-cryptography",
                    "purl": "pkg:oci/python-cryptography",
                }
            ],
            "labels": [],
        }

        stats = _persist_affects(flaw, response)

        assert stats["created"] == 0
        assert stats["skipped_existing"] == 1
        assert flaw.affects.count() == 1

    def test_applies_labels(self):
        flaw = FlawFactory(components=["urllib3"])
        response = {
            "affects": [],
            "labels": ["auto-affects", "auto-rejected"],
        }

        _persist_affects(flaw, response)

        labels = WorkflowLabel.objects.filter(flaw=flaw).values_list("name", flat=True)
        assert set(labels) == {"auto-affects", "auto-rejected"}

    def test_empty_response(self):
        flaw = FlawFactory(components=["urllib3"])
        response = {"affects": [], "labels": []}

        stats = _persist_affects(flaw, response)

        assert stats["created"] == 0
        assert stats["skipped_existing"] == 0
        assert flaw.affects.count() == 0

    def test_sets_not_affected_justification(self):
        flaw = FlawFactory(components=["urllib3"])
        response = {
            "affects": [
                {
                    "ps_update_stream": "hummingbird-1",
                    "ps_component": "python-cryptography",
                    "purl": "pkg:oci/python-cryptography",
                    "affectedness": "NOT_AFFECTED",
                    "resolution": "",
                    "not_affected_justification": "Vulnerable Code not Present",
                }
            ],
            "labels": [],
        }

        _persist_affects(flaw, response)

        affect = flaw.affects.first()
        assert affect.affectedness == "NOT_AFFECTED"
        assert affect.not_affected_justification == "Vulnerable Code not Present"


class TestDispatchToMicroservice:
    @patch("apps.ace.microservice.AffectAutomationQuerier")
    def test_dispatches_and_persists(self, MockQuerier):
        flaw = FlawFactory(components=["urllib3"], impact="MODERATE")
        mock_client = MagicMock()
        MockQuerier.return_value = mock_client
        mock_client.request_affects.return_value = {
            "flaw_id": str(flaw.uuid),
            "status": "completed",
            "affects": [
                {
                    "ps_update_stream": "hummingbird-1",
                    "purl": "pkg:oci/python-cryptography",
                    "ps_component": "python-cryptography",
                    "affectedness": "AFFECTED",
                    "resolution": "DELEGATED",
                    "impact": "MODERATE",
                    "assist_meta": {},
                }
            ],
            "labels": ["auto-affects"],
        }

        result = dispatch_to_microservice(str(flaw.uuid))

        assert result["created"] == 1
        mock_client.request_affects.assert_called_once()
        payload = mock_client.request_affects.call_args[0][1]
        assert payload["flaw_id"] == str(flaw.uuid)
        assert payload["components"] == ["urllib3"]
