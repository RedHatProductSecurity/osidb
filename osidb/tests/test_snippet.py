import uuid

import pytest
from django.conf import settings

from apps.osim.workflow import WorkflowModel
from osidb.core import generate_acls
from osidb.models import Flaw, FlawCVSS, FlawReference, FlawSource, FlawType, Snippet

pytestmark = pytest.mark.unit


def get_nvd_snippet(cve_id="CVE-2023-0001"):
    """
    Example snippet getter with a customizable `cve_id`.
    """
    content = {
        "cve_id": cve_id,
        "cvss_scores": [
            {
                "score": 8.1,
                "issuer": FlawCVSS.CVSSIssuer.NIST,
                "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "version": FlawCVSS.CVSSVersion.VERSION3,
            },
        ],
        "cwe_id": "CWE-110",
        "description": "some description",
        "references": [
            {
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "type": FlawReference.FlawReferenceType.SOURCE,
            },
        ],
        "source": Snippet.Source.NVD,
        "title": "placeholder only, see description",
    }

    snippet = Snippet(source=Snippet.Source.NVD, external_id=cve_id, content=content)
    snippet.save()

    return snippet


class TestSnippet:
    def test_create_snippet(self):
        """
        Tests the creation of a snippet.
        """
        snippet = get_nvd_snippet()

        assert snippet
        assert snippet.acl_read == [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])
        ]
        assert snippet.acl_write == [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])
        ]
        assert Snippet.objects.count() == 1

    def test_create_flaw_from_snippet(self):
        """
        Tests the creation of a flaw from a snippet.
        """
        snippet = get_nvd_snippet()
        content = snippet.content

        created_flaw = snippet._create_flaw()

        all_flaws = Flaw.objects.filter(cve_id=content["cve_id"])
        assert all_flaws.count() == 1

        flaw = all_flaws.first()
        assert flaw == created_flaw
        assert flaw.cve_id == content["cve_id"]
        assert flaw.cvss_scores.count() == 1
        assert flaw.cwe_id == content["cwe_id"]
        assert flaw.description == content["description"]
        assert flaw.osim_state == WorkflowModel.OSIMState.NEW
        assert flaw.references.count() == 1
        assert flaw.snippets.count() == 0
        assert flaw.source == snippet.source
        assert flaw.title == content["title"]
        assert flaw.type == FlawType.VULNERABILITY

        flaw_cvss = flaw.cvss_scores.all().first()
        assert flaw_cvss.issuer == FlawCVSS.CVSSIssuer.NIST
        assert flaw_cvss.score == 8.1
        assert flaw_cvss.vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert flaw_cvss.version == FlawCVSS.CVSSVersion.VERSION3

        flaw_ref = flaw.references.all().first()
        assert flaw_ref.type == FlawReference.FlawReferenceType.SOURCE
        assert flaw_ref.url == "https://nvd.nist.gov/vuln/detail/CVE-2023-0001"

        # check ACLs
        assert flaw.acl_read == [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])
        ]
        assert flaw.acl_write == [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])
        ]
        assert flaw.acl_read == flaw_cvss.acl_read == flaw_ref.acl_read
        assert flaw.acl_write == flaw_cvss.acl_write == flaw_ref.acl_write

    @pytest.mark.parametrize(
        "cve_id,has_flaw,has_snippet",
        [
            ("CVE-2023-0001", False, False),
            ("CVE-2023-0001", True, False),
            ("CVE-2023-0001", True, True),
        ],
    )
    def test_convert_nvd_snippet_to_flaw(self, cve_id, has_flaw, has_snippet):
        """
        Tests the conversion of a NVD snippet into a flaw and their linking.
        """
        snippet = get_nvd_snippet(cve_id)

        if has_flaw:
            f = snippet._create_flaw()
            if has_snippet:
                snippet.flaw = f
                snippet.save()

        snippet.convert_nvd_snippet_to_flaw()

        flaws = Flaw.objects.filter(cve_id=cve_id, source=FlawSource.NVD)
        assert flaws.count() == 1

        flaw = flaws.first()
        assert flaw.snippets.count() == 1
        assert flaw.snippets.first() == snippet

        assert snippet.flaw == flaw
