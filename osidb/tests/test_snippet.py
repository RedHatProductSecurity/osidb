import uuid

import pytest
from django.conf import settings

from osidb.core import generate_acls
from osidb.models import FlawCVSS, FlawReference, Snippet

pytestmark = pytest.mark.unit


def get_snippet(cve_id="CVE-2023-0001"):
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

    snippet = Snippet(source=Snippet.Source.NVD, content=content)
    snippet.save()

    return snippet


class TestSnippet:
    def test_create_snippet(self):
        """
        Tests the creation of a snippet.
        """
        snippet = get_snippet()

        assert snippet
        assert snippet.acl_read == [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])
        ]
        assert snippet.acl_write == [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])
        ]
        assert Snippet.objects.count() == 1
