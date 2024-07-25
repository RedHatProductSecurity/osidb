import json

import pytest
from django.utils.timezone import datetime, make_aware
from jira.exceptions import JIRAError

from apps.taskman.service import JiraTaskmanQuerier
from collectors.osv.collectors import OSVCollector, OSVCollectorException
from osidb import models
from osidb.models import Flaw, Snippet
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.integration


class TestOSVCollector:
    # NOTE: cassette updates may be required to comply with published date
    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestOSVCollector.test_collect_osv_record.yaml")
    @pytest.mark.parametrize("start_date", [None, make_aware(datetime(2023, 1, 1))])
    def test_collect_osv_record(self, start_date):
        """Test fetching a single OSV record."""
        osv_id = "GO-2023-1494"
        cve_id = "CVE-2014-125064"

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        # when start date is set to None, all snippets are collected
        osvc.snippet_creation_start_date = start_date
        osvc.collect(osv_id=osv_id)

        snippet = Snippet.objects.last()
        assert Snippet.objects.count() == 1
        assert snippet.external_id == f"{osv_id}/{cve_id}"
        assert snippet.content["references"]
        assert snippet.content["cve_id"] == f"{cve_id}"

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.all().first()
        assert flaw.task_key == "OSIM-16311"
        assert json.loads(flaw.meta_attr["alias"]) == [cve_id]
        assert json.loads(flaw.meta_attr["external_ids"]) == [f"{osv_id}/{cve_id}"]
        assert flaw.reported_dt

    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestOSVCollector.test_collect_osv_record.yaml")
    def test_collect_osv_record_when_flaw_exists(self):
        """Test fetching a single OSV record when a flaw already exists."""
        flaw = FlawFactory(cve_id="CVE-2014-125064", meta_attr={})
        assert Flaw.objects.count() == 1

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id="GO-2023-1494")

        snippet = Snippet.objects.last()
        assert Snippet.objects.count() == 1
        assert snippet.flaw == flaw
        assert snippet.content["cve_id"] == flaw.cve_id
        assert Flaw.objects.count() == 1

    @pytest.mark.vcr
    def test_collect_osv_record_without_cve(self):
        """Test fetching a single OSV record without cve."""
        osv_id = "GHSA-3hwm-922r-47hw"

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id=osv_id)

        assert Snippet.objects.count() == 1
        snippet = Snippet.objects.first()
        assert snippet.external_id == osv_id
        assert snippet.content["cve_id"] is None

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id is None
        assert flaw.task_key == "OSIM-497"
        assert json.loads(flaw.meta_attr["alias"]) == [osv_id]
        assert json.loads(flaw.meta_attr["external_ids"]) == [osv_id]

    @pytest.mark.vcr
    def test_collect_multi_cve_osv_record(self):
        """Test fetching a single OSV record that points to multiple CVEs."""
        osv_id = "GO-2022-0646"
        cve_ids = ["CVE-2020-8911", "CVE-2020-8912"]

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id=osv_id)

        assert Snippet.objects.count() == 2
        snippet_1 = Snippet.objects.get(external_id=f"{osv_id}/{cve_ids[0]}")
        assert snippet_1.content["cve_id"] == f"{cve_ids[0]}"

        snippet_2 = Snippet.objects.get(external_id=f"{osv_id}/{cve_ids[1]}")
        assert snippet_2.content["cve_id"] == f"{cve_ids[1]}"

        assert snippet_1.content["title"] == snippet_2.content["title"]
        assert Flaw.objects.count() == 2

    @pytest.mark.vcr
    def test_historical_osv_record(self):
        """Test not fetching a historical OSV record."""
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = make_aware(datetime(2024, 1, 1))
        osvc.collect(osv_id="GO-2023-1602")  # published in 2023
        assert Snippet.objects.count() == 0
        assert Flaw.objects.count() == 0

    @pytest.mark.vcr
    def test_atomicity(self, monkeypatch):
        """Test that flaw and snippet are not created if any error occurs during the flaw creation."""

        def mock_create_or_update_task(self, flaw):
            raise JIRAError(status_code=401)

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None

        with pytest.raises(OSVCollectorException):
            osvc.collect(osv_id="GO-2023-1602")

        assert Snippet.objects.all().count() == 0
        assert Flaw.objects.all().count() == 0

    @pytest.mark.vcr
    def test_no_bz(self, monkeypatch):
        """Test that external id is included even if BZ sync is disabled."""
        monkeypatch.setattr(models, "BZ_API_KEY", None)

        osv_id = "GHSA-3hwm-922r-47hw"

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id=osv_id)

        assert Snippet.objects.count() == 1
        assert Snippet.objects.first().external_id == osv_id
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().meta_attr == {"external_ids": f"{osv_id}"}

        # Snippet disappeared and OSV is trying to create a flaw which already exists
        Snippet.objects.all().delete()
        assert Snippet.objects.count() == 0
        assert Flaw.objects.count() == 1

        osvc.collect(osv_id=osv_id)

        assert Snippet.objects.count() == 1
        assert Snippet.objects.first().external_id == osv_id
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().meta_attr == {"external_ids": f"{osv_id}"}
