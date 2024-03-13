import pytest
from django.utils.timezone import datetime, make_aware

from collectors.osv.collectors import OSVCollector
from osidb.models import Snippet

pytestmark = pytest.mark.integration


class TestOSVCollector:
    # NOTE: cassette updates may be required to comply with published date
    @pytest.mark.vcr
    @pytest.mark.default_cassette("TestOSVCollector.test_collect_osv_record.yaml")
    @pytest.mark.parametrize("start_date", [None, make_aware(datetime(2024, 1, 1))])
    def test_collect_osv_record(self, start_date):
        """Test fetching a single OSV record."""
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        # when start date is set to None, all snippets are collected
        osvc.snippet_creation_start_date = start_date
        osvc.collect(osv_id="GO-2023-2400")

        snippet = Snippet.objects.last()
        assert Snippet.objects.count() == 1
        assert snippet.external_id == "GO-2023-2400/CVE-2023-50424"
        assert snippet.content["references"]
        assert snippet.content["cve_id"] == "CVE-2023-50424"

    @pytest.mark.vcr
    def test_collect_osv_record_without_cve(self):
        """Test fetching a single OSV record without cve."""
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = None
        osvc.collect(osv_id="GHSA-w4f8-fxq2-j35v")

        assert Snippet.objects.count() == 1
        snippet = Snippet.objects.first()
        assert snippet.external_id == "GHSA-w4f8-fxq2-j35v"
        assert snippet.content["cve_id"] is None

    # NOTE: cassette updates may be required to comply with published date
    @pytest.mark.vcr
    def test_collect_multi_cve_osv_record(self):
        """Test fetching a single OSV record that points to multiple CVEs."""
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.collect(osv_id="PYSEC-2022-245")

        assert Snippet.objects.count() == 2
        snippet_1 = Snippet.objects.get(external_id="PYSEC-2022-245/CVE-2022-36359")
        assert snippet_1.content["cve_id"] == "CVE-2022-36359"

        snippet_2 = Snippet.objects.get(external_id="PYSEC-2022-245/CVE-2022-45442")
        assert snippet_2.content["cve_id"] == "CVE-2022-45442"

        assert snippet_1.content["title"] == snippet_2.content["title"]

    @pytest.mark.vcr
    def test_historical_osv_record(self):
        """Test not fetching a historical OSV record."""
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.snippet_creation_start_date = make_aware(datetime(2024, 1, 1))
        osvc.collect(osv_id="GO-2023-1602")  # published in 2023
        assert Snippet.objects.count() == 0
