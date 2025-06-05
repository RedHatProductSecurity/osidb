from typing import Optional

import pytest

from collectors.cveorg.collectors import CVEorgCollector
from osidb.models.flaw.cvss import FlawCVSS
from osidb.models.flaw.flaw import Flaw

pytestmark = pytest.mark.unit


class TestCVEorgProcessing:
    def test_cna_cvss_processing(self, cna_cvss_content):
        collector = CVEorgCollector()
        content = collector.extract_content(cna_cvss_content)
        [cvss_score] = content["cvss_scores"]

        assert cvss_score["issuer"] == FlawCVSS.CVSSIssuer.CVEORG
        assert cvss_score["version"] == FlawCVSS.CVSSVersion.VERSION3
        assert cvss_score["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"

    def test_cisa_cvss_processing(self, cisa_cvss_content):
        collector = CVEorgCollector()
        content = collector.extract_content(cisa_cvss_content)
        [cvss_score] = content["cvss_scores"]

        assert cvss_score["issuer"] == FlawCVSS.CVSSIssuer.CISA
        assert cvss_score["version"] == FlawCVSS.CVSSVersion.VERSION3
        assert cvss_score["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    def test_updates(self, cisa_cvss_content):
        collector = CVEorgCollector()
        collector.keywords_check_enabled = False
        content = collector.extract_content(cisa_cvss_content)
        assert Flaw.objects.count() == 0

        # create the flaw per the content
        collector.save_snippet_and_flaw(content)
        flaw: Optional[Flaw] = Flaw.objects.first()
        assert flaw

        cvss: Optional[FlawCVSS] = FlawCVSS.objects.get(flaw=flaw)
        assert cvss and cvss.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

        # edit the content with a modified CVSS score and check that it's *not* reflected in the flaw
        content["cvss_scores"][0][
            "vector"
        ] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        collector.save_snippet_and_flaw(content)
        cvss: Optional[FlawCVSS] = FlawCVSS.objects.get(flaw=flaw)
        assert cvss and cvss.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

    def test_upsert_cvss_scores(self, cisa_cvss_content):
        collector = CVEorgCollector()
        collector.keywords_check_enabled = False
        content = collector.extract_content(cisa_cvss_content)
        original_cvss_scores = content.pop("cvss_scores")

        # let's start with no CVSS scores initially
        content["cvss_scores"] = []
        collector.save_snippet_and_flaw(content)
        flaw: Optional[Flaw] = Flaw.objects.first()
        assert flaw and flaw.cvss_scores.count() == 0

        # now we add a cvss score on a second pass
        collector.upsert_cvss_scores(content["cve_id"], original_cvss_scores)
        cvss: Optional[FlawCVSS] = FlawCVSS.objects.first()
        assert flaw.cvss_scores.count() == 1
        assert cvss and cvss.vector == original_cvss_scores[0]["vector"]

        # finally we update the existing CVSS score
        original_cvss_scores[0][
            "vector"
        ] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        collector.upsert_cvss_scores(content["cve_id"], original_cvss_scores)
        cvss: Optional[FlawCVSS] = FlawCVSS.objects.first()
        assert flaw.cvss_scores.count() == 1
        assert cvss and cvss.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_upsert_cvss_scores_no_cve_id(self):
        collector = CVEorgCollector()
        collector.upsert_cvss_scores("", [{"foo": "bar"}])

        assert FlawCVSS.objects.count() == 0

    def test_get_comment_zero_missing(self, no_descriptions_content):
        collector = CVEorgCollector()
        collector.keywords_check_enabled = False

        assert (
            collector.extract_content(no_descriptions_content)["comment_zero"] == "N/A"
        )
