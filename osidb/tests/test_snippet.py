import pytest

from apps.workflows.workflow import WorkflowModel
from osidb.models import Flaw, FlawCVSS, FlawReference, FlawType, Snippet
from osidb.tests.factories import FlawFactory, SnippetFactory

pytestmark = pytest.mark.unit


class TestSnippet:
    def test_create_snippet(self, internal_read_groups, internal_write_groups):
        """
        Tests the creation of a snippet.
        """
        snippet = SnippetFactory()

        assert snippet
        assert snippet.acl_read == internal_read_groups
        assert snippet.acl_write == internal_write_groups
        assert Snippet.objects.count() == 1

    @pytest.mark.enable_signals
    def test_create_flaw_from_snippet(
        self, internal_read_groups, internal_write_groups
    ):
        """
        Tests the creation of a flaw from a snippet.
        """
        snippet = SnippetFactory(source=Snippet.Source.NVD)
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
        assert flaw.meta_attr == {}
        assert flaw.references.count() == 1
        assert flaw.snippets.count() == 1
        assert flaw.source == snippet.source
        assert flaw.title == content["title"]
        assert flaw.type == FlawType.VULNERABILITY
        assert flaw.workflow_state == WorkflowModel.WorkflowState.NEW

        flaw_cvss = flaw.cvss_scores.all().first()
        assert flaw_cvss.issuer == FlawCVSS.CVSSIssuer.NIST
        assert flaw_cvss.score == 8.1
        assert flaw_cvss.vector == "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert flaw_cvss.version == FlawCVSS.CVSSVersion.VERSION3

        flaw_ref = flaw.references.all().first()
        assert flaw_ref.type == FlawReference.FlawReferenceType.SOURCE
        assert flaw_ref.url == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"

        flaw_snippet = flaw.snippets.all().first()
        assert flaw_snippet == snippet
        assert flaw_snippet.content == content
        assert flaw_snippet.external_id == snippet.external_id
        assert flaw_snippet.source == snippet.source

        # check ACLs
        for i in [snippet, flaw, flaw_cvss, flaw_ref, flaw_snippet]:
            assert internal_read_groups == i.acl_read
            assert internal_write_groups == i.acl_write

    @pytest.mark.parametrize(
        "flaw_present,identifier,source",
        [
            (True, "cve_id", Snippet.Source.NVD),
            (True, "external_id", Snippet.Source.NVD),
            (False, "cve_id", Snippet.Source.NVD),
            (False, "external_id", Snippet.Source.NVD),
            (True, "cve_id", Snippet.Source.OSV),
            (True, "external_id", Snippet.Source.OSV),
            (False, "cve_id", Snippet.Source.OSV),
            (False, "external_id", Snippet.Source.OSV),
        ],
    )
    def test_convert_snippet_to_flaw(self, flaw_present, identifier, source):
        """
        Tests the conversion of a snippet into a flaw (if a flaw does not exist) and their linking.
        """
        if source == Snippet.Source.OSV and identifier == "external_id":
            snippet = SnippetFactory(source=source, cve_id=None)
        else:
            snippet = SnippetFactory(source=source)

        cve_id = snippet.content["cve_id"]
        ext_id = snippet.external_id

        if flaw_present:
            if identifier == "cve_id":
                FlawFactory(cve_id=cve_id, meta_attr={})
            if identifier == "external_id":
                # here we expect that a flaw already got synced to BZ, so meta_attr is present
                FlawFactory(cve_id=cve_id, meta_attr={"external_ids": [ext_id]})
            assert Flaw.objects.count() == 1

        created = snippet.convert_snippet_to_flaw()

        if not flaw_present:
            assert created
        else:
            assert created is None

        flaws = Flaw.objects.all()
        assert flaws.count() == 1

        flaw = flaws.first()
        assert flaw.snippets.count() == 1
        assert flaw.snippets.first() == snippet

        assert snippet.flaw == flaw

        if identifier == "cve_id":
            assert snippet.content["cve_id"] == flaw.cve_id
        # flaw is newly created, so meta_attr is empty
        if identifier == "external_id" and not flaw_present:
            assert flaw.meta_attr == {}
        # flaw already got synced to BZ, so meta_attr is present
        if identifier == "external_id" and flaw_present:
            assert flaw.meta_attr == {"external_ids": f"['{ext_id}']"}
