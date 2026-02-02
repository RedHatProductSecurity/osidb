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
        content["cvss_scores"][0]["vector"] = (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
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
        assert (
            cvss
            and cvss.vector == original_cvss_scores[0]["vector"]
            and cvss.score == 9.1
        )

        # finally we update the existing CVSS score
        original_cvss_scores[0]["vector"] = (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        collector.upsert_cvss_scores(content["cve_id"], original_cvss_scores)
        cvss: Optional[FlawCVSS] = FlawCVSS.objects.first()
        assert flaw.cvss_scores.count() == 1
        assert (
            cvss
            and cvss.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            and cvss.score == 9.8
        )

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

    def test_mitre_cve_description_populated(self, cisa_cvss_content):
        """Test that mitre_cve_description is populated from CVE.org description."""
        collector = CVEorgCollector()
        collector.keywords_check_enabled = False
        content = collector.extract_content(cisa_cvss_content)

        assert "mitre_cve_description" in content
        assert content["mitre_cve_description"] == content["comment_zero"]

        collector.save_snippet_and_flaw(content)
        flaw = Flaw.objects.first()
        assert flaw

        assert flaw.comment_zero
        assert flaw.mitre_cve_description
        assert flaw.mitre_cve_description == flaw.comment_zero

    def test_mitre_cve_description_updates_existing_flaw(self, cisa_cvss_content):
        """Test that mitre_cve_description is updated for existing flaws."""
        collector = CVEorgCollector()
        collector.keywords_check_enabled = False
        content = collector.extract_content(cisa_cvss_content)

        collector.save_snippet_and_flaw(content)
        flaw = Flaw.objects.first()
        assert flaw
        original_description = flaw.mitre_cve_description

        flaw.mitre_cve_description = ""
        flaw.save(raise_validation_error=False)
        assert Flaw.objects.get(uuid=flaw.uuid).mitre_cve_description == ""

        collector.update_mitre_cve_description(
            content["cve_id"], content["mitre_cve_description"]
        )

        updated_flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert updated_flaw.mitre_cve_description == original_description
        assert updated_flaw.mitre_cve_description == content["mitre_cve_description"]
