import pytest

from collectors.osv.collectors import OSVCollector
from osidb.models import Snippet

pytestmark = pytest.mark.integration


class TestOSVCollector:
    @pytest.mark.vcr
    def test_collect_osv_record(self):
        """Test fetching a single OSV record."""
        osvc = OSVCollector()
        osvc.snippet_creation_enabled = True
        osvc.collect(osv_id="GO-2023-2400")

        snippet = Snippet.objects.last()
        assert Snippet.objects.count() == 1
        assert snippet.external_id == "GO-2023-2400/CVE-2023-50424"
        assert snippet.content["references"]
        assert snippet.content["cve_id"] == "CVE-2023-50424"

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
