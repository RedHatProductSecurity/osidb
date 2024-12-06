import json
from datetime import datetime, timezone

import pytest
from freezegun import freeze_time
from jira.exceptions import JIRAError

from apps.taskman.service import JiraTaskmanQuerier
from collectors.osv.collectors import OSVCollector, OSVCollectorException
from osidb.models import Flaw, FlawCVSS, Impact, Snippet
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.integration


class TestOSVCollector:
    @freeze_time(datetime(2020, 12, 12))  # freeze against top of the second crossing
    @pytest.mark.vcr
    def test_collect_osv_record_without_cve(self):
        """
        Test that snippet and flaw are created if OSV record does not contain CVE ID.
        """
        osv_id = "GHSA-3hwm-922r-47hw"

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id=osv_id)

        assert Flaw.objects.count() == 1
        flaw = Flaw.objects.first()
        assert flaw.cve_id is None
        assert json.loads(flaw.meta_attr["external_ids"]) == [osv_id]

        assert Snippet.objects.count() == 1
        snippet = Snippet.objects.first()
        assert snippet.content["cve_id"] is None
        assert snippet.external_id == osv_id
        assert snippet.flaw == flaw

    @pytest.mark.vcr
    @pytest.mark.default_cassette("osv_record_with_cve.yaml")
    def test_collect_osv_record_with_cve(self):
        """
        Test that only a snippet is created if a flaw already exists.
        """
        osv_id = "GO-2023-1494"
        cve_id = "CVE-2014-125064"
        flaw = FlawFactory(cve_id=cve_id)

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id=osv_id)

        assert Flaw.objects.count() == 1

        assert Snippet.objects.count() == 1
        snippet = Snippet.objects.first()
        assert snippet.content["cve_id"] == cve_id
        assert snippet.external_id == f"{osv_id}/{cve_id}"
        assert snippet.flaw == flaw

    @pytest.mark.vcr
    def test_collect_multi_osv_record_with_cves(self):
        """
        Test that only snippets are created if flaws already exist.
        """
        osv_id = "GO-2022-0646"
        cve_id_1 = "CVE-2020-8911"
        cve_id_2 = "CVE-2020-8912"
        flaw_1 = FlawFactory(cve_id=cve_id_1)
        flaw_2 = FlawFactory(cve_id=cve_id_2)

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id=osv_id)

        assert Flaw.objects.count() == 2
        assert Snippet.objects.count() == 2

        snippet_1 = Snippet.objects.get(external_id=f"{osv_id}/{cve_id_1}")
        assert snippet_1.content["cve_id"] == cve_id_1
        assert snippet_1.flaw == flaw_1

        snippet_2 = Snippet.objects.get(external_id=f"{osv_id}/{cve_id_2}")
        assert snippet_2.content["cve_id"] == cve_id_2
        assert snippet_2.flaw == flaw_2

    @pytest.mark.vcr
    @pytest.mark.default_cassette("osv_record_with_cve.yaml")
    def test_ignore_osv_record_with_cve(self):
        """
        Test that snippet and flaw are not created if CVE ID of OSV record is not in DB.
        """
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id="GO-2023-1494")

        assert Snippet.objects.count() == 0
        assert Flaw.objects.count() == 0

    @pytest.mark.vcr
    @pytest.mark.default_cassette("osv_record_without_cve.yaml")
    def test_ignore_osv_record_historical(self):
        """
        Test that snippets and flaws are not created if OSV record is historical.
        """
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
        osvc.collect(osv_id="GHSA-3hwm-922r-47hw")

        assert Snippet.objects.count() == 0
        assert Flaw.objects.count() == 0

    @pytest.mark.enable_signals
    @pytest.mark.vcr
    def test_collect_osv_record_with_cvss(self):
        """
        Test that snippet, flaw, flaw impact and cvss scores are correctly created.
        """
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id="GHSA-75qh-gg76-p2w4")

        assert Snippet.objects.count() == 1
        assert Flaw.objects.count() == 1
        assert Flaw.objects.first().impact == Impact.MODERATE
        assert Flaw.objects.first().cvss_scores.count() == 2
        assert FlawCVSS.objects.count() == 2


class TestOSVCollectorException:
    @pytest.mark.vcr
    @pytest.mark.default_cassette("osv_record_without_cve.yaml")
    def test_atomicity(self, monkeypatch):
        """
        Test that flaw and snippet are not created if any error occurs during the flaw creation.
        """

        def mock_create_or_update_task(self, flaw):
            raise JIRAError(status_code=401)

        monkeypatch.setattr(
            JiraTaskmanQuerier, "create_or_update_task", mock_create_or_update_task
        )

        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None

        with pytest.raises(OSVCollectorException):
            osvc.collect(osv_id="GHSA-3hwm-922r-47hw")

        assert Snippet.objects.all().count() == 0
        assert Flaw.objects.all().count() == 0
