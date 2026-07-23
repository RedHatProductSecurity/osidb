import copy
from typing import Optional

import pytest

from collectors.cveorg.collectors import (
    CVEorgCollector,
    CVEorgCollectorValidationError,
    _is_windows_only_cve,
)
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


class TestWindowsOnlyCPEFilter:
    """
    Unit tests for _is_windows_only_cve and its integration into the collector.
    """

    def test_windows_os_only_cve_is_blocked(self, windows_os_only_cve_content):
        """CVE-2026-50462 — all CPEs are cpe:2.3:o:microsoft:windows_*."""
        assert _is_windows_only_cve(windows_os_only_cve_content) is True

    def test_windows_with_application_cpe_passes(self, windows_with_dotnet_cve_content):
        """CVE-2026-50355 — mixes Windows OS CPEs with cpe:2.3:a:microsoft:.net.
        Must not be filtered: .NET is a cross-platform Microsoft application."""
        assert _is_windows_only_cve(windows_with_dotnet_cve_content) is False

    def test_no_cpe_applicability_passes(self, windows_os_only_cve_content):
        """CVEs without cpeApplicability should not be filtered out."""
        content = copy.deepcopy(windows_os_only_cve_content)
        del content["containers"]["cna"]["cpeApplicability"]
        assert _is_windows_only_cve(content) is False

    def test_empty_cpe_applicability_passes(self, windows_os_only_cve_content):
        """An empty cpeApplicability list is treated as no CPE data — do not filter."""
        content = copy.deepcopy(windows_os_only_cve_content)
        content["containers"]["cna"]["cpeApplicability"] = []
        assert _is_windows_only_cve(content) is False

    def test_non_microsoft_vendor_passes(self, windows_os_only_cve_content):
        """A single non-Microsoft CPE is enough to let the CVE through."""
        content = copy.deepcopy(windows_os_only_cve_content)
        content["containers"]["cna"]["cpeApplicability"][0]["nodes"][0][
            "cpeMatch"
        ].append(
            {
                "vulnerable": True,
                "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
            }
        )
        assert _is_windows_only_cve(content) is False

    def test_negated_node_passes(self, windows_os_only_cve_content):
        """A negated node means 'all platforms except these' — semantics we cannot
        evaluate without full boolean CPE logic, so bail out conservatively."""
        content = copy.deepcopy(windows_os_only_cve_content)
        content["containers"]["cna"]["cpeApplicability"][0]["nodes"][0]["negate"] = True
        assert _is_windows_only_cve(content) is False

    def test_negated_applicability_passes(self, windows_os_only_cve_content):
        """negate at the cpeApplicability (configuration) level inverts the entire
        node set — bail out conservatively for the same reason as node-level negate."""
        content = copy.deepcopy(windows_os_only_cve_content)
        content["containers"]["cna"]["cpeApplicability"][0]["negate"] = True
        assert _is_windows_only_cve(content) is False

    def test_microsoft_non_windows_os_cpe_passes(self, windows_os_only_cve_content):
        """A Microsoft OS CPE that is not a Windows family is not filtered."""
        content = copy.deepcopy(windows_os_only_cve_content)
        content["containers"]["cna"]["cpeApplicability"] = [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:o:microsoft:azure_sphere:*:*:*:*:*:*:*:*",
                            }
                        ],
                    }
                ]
            }
        ]
        assert _is_windows_only_cve(content) is False

    def test_upsert_raises_for_windows_only_cve(
        self, windows_os_only_cve_content, tmp_path
    ):
        """_upsert_from_file_content must raise CVEorgCollectorValidationError for Windows-only CVEs."""
        import json

        fixture = tmp_path / "CVE-2026-50462.json"
        fixture.write_text(json.dumps(windows_os_only_cve_content))

        collector = CVEorgCollector()
        collector.snippet_creation_enabled = True
        collector.snippet_creation_start_date = None

        with pytest.raises(CVEorgCollectorValidationError, match="Windows OS"):
            collector._upsert_from_file_content(str(fixture))

        assert Flaw.objects.count() == 0
