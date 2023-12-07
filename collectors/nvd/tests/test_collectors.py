import pytest
from django.utils import timezone

from collectors.framework.models import CollectorMetadata
from collectors.nvd.collectors import NVDCollector
from osidb.models import Flaw, FlawCVSS, FlawReference, FlawSource, Snippet
from osidb.tests.factories import FlawCVSSFactory, FlawFactory

pytestmark = pytest.mark.integration


class TestNVDCollector:
    """
    NVDCollector test cases
    """

    @pytest.mark.vcr
    def test_collect_batch(self):
        """
        test that collecting a batch of CVEs works
        """
        # let us use existing CVE data as a real-world example
        # https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2010-01-01T00:00:00&lastModEndDate=2010-04-11T00:00:00

        nvdc = NVDCollector()
        nvdc.metadata.updated_until_dt = timezone.datetime(
            2010, 1, 1, 0, 0, tzinfo=timezone.utc
        )

        # test that the batch is correctly selected
        batch, period_end = nvdc.get_batch()
        assert len(batch) == 296
        assert period_end == timezone.datetime(2010, 4, 11, 0, 0, tzinfo=timezone.utc)

        # test that the batch collection works
        # randomly select a few flaws - not all 296
        #
        # we do not test CVSS3 as these old flaws do not have it
        # but more recent batches are too huge (a few MB cassettes)
        # it is going to be tested by another test case
        FlawFactory(
            cve_id="CVE-2000-0835",
            nvd_cvss2=None,
        )
        FlawFactory(
            cve_id="CVE-2010-0977",
            nvd_cvss2=None,
        )
        FlawFactory(
            cve_id="CVE-2010-1313",
            nvd_cvss2=None,
        )

        nvdc.collect()

        flaw = Flaw.objects.get(cve_id="CVE-2000-0835")
        assert flaw.nvd_cvss2 == "5.0/AV:N/AC:L/Au:N/C:P/I:N/A:N"

        flaw = Flaw.objects.get(cve_id="CVE-2010-0977")
        assert flaw.nvd_cvss2 == "5.0/AV:N/AC:L/Au:N/C:P/I:N/A:N"

        flaw = Flaw.objects.get(cve_id="CVE-2010-1313")
        assert flaw.nvd_cvss2 == "4.3/AV:N/AC:M/Au:N/C:P/I:N/A:N"

    @pytest.mark.vcr
    def test_collect_cve(self):
        """
        test that collecting a given CVE works
        """
        # let us use existing CVE data as a real-world example
        # https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-1234
        cve = "CVE-2020-1234"

        FlawFactory(
            cve_id=cve,
            nvd_cvss2=None,
            nvd_cvss3=None,
        )

        nvdc = NVDCollector()
        nvdc.collect(cve)

        flaw = Flaw.objects.first()
        assert flaw.cve_id == cve
        assert flaw.nvd_cvss2 == "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P"
        assert flaw.nvd_cvss3 == "7.8/CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"

    @pytest.mark.vcr
    def test_collect_updated(self):
        """
        test that collecting updated CVE works
        """
        # let us use existing CVE data as a real-world examples
        # https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-1234
        cve1 = "CVE-2020-1234"
        # https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-1235
        cve2 = "CVE-2020-1235"

        # let us define a time of last collection
        # and one timestamp before and one after
        before_collector_run = timezone.datetime(2022, 1, 1, 0, 0, tzinfo=timezone.utc)
        last_collector_run = timezone.datetime(2022, 2, 1, 0, 0, tzinfo=timezone.utc)
        after_collector_run = timezone.datetime(2022, 3, 1, 0, 0, tzinfo=timezone.utc)

        FlawFactory(
            cve_id=cve1,
            nvd_cvss2=None,
            nvd_cvss3=None,
            updated_dt=before_collector_run,
        )
        FlawFactory(
            cve_id=cve2,
            nvd_cvss2=None,
            nvd_cvss3=None,
            updated_dt=after_collector_run,
        )

        nvdc = NVDCollector()
        nvdc.metadata.updated_until_dt = last_collector_run
        # no change should happen when not complete
        nvdc.collect_updated()

        flaw = Flaw.objects.get(cve_id=cve1)
        assert not flaw.nvd_cvss2
        assert not flaw.nvd_cvss3

        flaw = Flaw.objects.get(cve_id=cve2)
        assert not flaw.nvd_cvss2
        assert not flaw.nvd_cvss3

        # make data complete
        nvdc.metadata.data_state = CollectorMetadata.DataState.COMPLETE
        nvdc.collect_updated()

        # first CVE was not updated after the
        # collector run so should be unchanged
        flaw = Flaw.objects.get(cve_id=cve1)
        assert not flaw.nvd_cvss2
        assert not flaw.nvd_cvss3

        flaw = Flaw.objects.get(cve_id=cve2)
        assert flaw.nvd_cvss2 == "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P"
        assert flaw.nvd_cvss3 == "7.8/CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"

    @pytest.mark.vcr
    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "cve_id,original_cvss2,original_cvss3,new_cvss2,new_cvss3",
        [
            # without changes
            (
                "CVE-2014-0148",
                [None, None],
                [5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"],
                [None, None],
                [5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"],
            ),
            (
                "CVE-2020-1234",
                [6.8, "AV:N/AC:M/Au:N/C:P/I:P/A:P"],
                [7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"],
                [6.8, "AV:N/AC:M/Au:N/C:P/I:P/A:P"],
                [7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"],
            ),
            # new CVSSv2
            (
                "CVE-2000-0835",
                [None, None],
                [None, None],
                [5.0, "AV:N/AC:L/Au:N/C:P/I:N/A:N"],
                [None, None],
            ),
            # different CVSSv3
            (
                "CVE-2020-1235",
                [6.8, "AV:N/AC:M/Au:N/C:P/I:P/A:P"],
                [7.4, "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"],
                [6.8, "AV:N/AC:M/Au:N/C:P/I:P/A:P"],
                [7.8, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"],
            ),
            # removed CVSSv2
            (
                "CVE-2014-0148",
                [6.8, "AV:N/AC:M/Au:N/C:P/I:P/A:P"],
                [5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"],
                [None, None],
                [5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"],
            ),
        ],
    )
    def test_flawcvss_model(
        self, cve_id, original_cvss2, original_cvss3, new_cvss2, new_cvss3
    ):
        """
        Test that CVSSv2 and CVSSv3 scores are correctly loaded and updated
        in the FlawCVSS model.
        """
        # do not care about nvd_cvss2 and nvd_cvss3 as they will be deprecated
        flaw = FlawFactory(cve_id=cve_id, nvd_cvss2="", nvd_cvss3="")

        for vector, version in [
            (original_cvss2[1], FlawCVSS.CVSSVersion.VERSION2),
            (original_cvss3[1], FlawCVSS.CVSSVersion.VERSION3),
        ]:
            if vector:
                FlawCVSSFactory(
                    flaw=flaw,
                    issuer=FlawCVSS.CVSSIssuer.NIST,
                    version=version,
                    vector=vector,
                )

        nvdc = NVDCollector()
        nvdc.collect(cve_id)

        flaw = Flaw.objects.get(cve_id=cve_id)

        for score, vector, version in [
            (new_cvss2[0], new_cvss2[1], FlawCVSS.CVSSVersion.VERSION2),
            (new_cvss3[0], new_cvss3[1], FlawCVSS.CVSSVersion.VERSION3),
        ]:
            if vector:
                assert flaw.cvss_scores.filter(version=version).first().score == score
                assert flaw.cvss_scores.filter(version=version).first().vector == vector
            else:
                assert flaw.cvss_scores.filter(version=version).first() is None

    @pytest.mark.default_cassette("TestNVDCollector.test_snippet_and_flaw_created.yaml")
    @pytest.mark.vcr
    @pytest.mark.parametrize(
        "has_flaw,has_snippet",
        [
            (False, False),
            (True, False),
            (True, True),
            # (True, False) cannot happen (if a snippet is present, a flaw must be too)
        ],
    )
    def test_snippet_and_flaw_created(self, has_flaw, has_snippet):
        """
        Test that a snippet and flaw are created if they do not exist.
        """
        snippet_content = {
            "cve_id": "CVE-2017-7542",
            "cvss_scores": [
                {
                    "score": 4.9,
                    "issuer": FlawCVSS.CVSSIssuer.NIST,
                    "vector": "AV:L/AC:L/Au:N/C:N/I:N/A:C",
                    "version": FlawCVSS.CVSSVersion.VERSION2,
                },
                {
                    "score": 5.5,
                    "issuer": FlawCVSS.CVSSIssuer.NIST,
                    "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                    "version": FlawCVSS.CVSSVersion.VERSION3,
                },
            ],
            "cwe_id": "(CWE-190|CWE-835)",
            "description": "The ip6_find_1stfragopt function in net/ipv6/output_core.c in the Linux kernel through 4.12.3 allows local users to cause a denial of service (integer overflow and infinite loop) by leveraging the ability to open a raw socket.",
            "references": [
                {
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-7542",
                    "type": FlawReference.FlawReferenceType.SOURCE,
                },
                {
                    "url": "http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=6399f1fae4ec29fab5ec76070435555e256ca3a6",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "http://www.debian.org/security/2017/dsa-3927",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "http://www.debian.org/security/2017/dsa-3945",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {"url": "http://www.securityfocus.com/bid/99953", "type": "EXTERNAL"},
                {
                    "url": "https://access.redhat.com/errata/RHSA-2017:2918",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "https://access.redhat.com/errata/RHSA-2017:2930",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "https://access.redhat.com/errata/RHSA-2017:2931",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "https://access.redhat.com/errata/RHSA-2018:0169",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "https://github.com/torvalds/linux/commit/6399f1fae4ec29fab5ec76070435555e256ca3a6",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "https://help.ecostruxureit.com/display/public/UADCE725/Security+fixes+in+StruxureWare+Data+Center+Expert+v7.6.0",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "https://usn.ubuntu.com/3583-1/",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
                {
                    "url": "https://usn.ubuntu.com/3583-2/",
                    "type": FlawReference.FlawReferenceType.EXTERNAL,
                },
            ],
            "source": Snippet.Source.NVD,
            "title": "placeholder only, see description",
        }
        cve_id = snippet_content["cve_id"]

        # Default data
        if has_flaw:
            FlawFactory(cve_id=cve_id, source=FlawSource.NVD)

        if has_snippet:
            s = Snippet(source=Snippet.Source.NVD, content=snippet_content)
            s.save()

        nvdc = NVDCollector()
        # snippet creation is disabled by default, so enable it
        nvdc.snippet_creation_enabled = True
        nvdc.collect(cve_id)

        snippets = Snippet.objects.filter(
            content__cve_id=cve_id, source=Snippet.Source.NVD
        )
        snippet = snippets.first()

        flaws = Flaw.objects.filter(cve_id=cve_id, source=FlawSource.NVD)
        flaw = flaws.first()

        assert len(snippets) == len(flaws) == 1
        assert snippet.flaw == flaw
        assert flaw.snippets.count() == 1
        assert flaw.snippets.first() == snippet

    @pytest.mark.vcr
    @pytest.mark.parametrize(
        "cve_id,snippet_enabled",
        [
            # CVE complies with the keywords check, but snippet creation is disabled
            ("CVE-2017-9627", False),
            # snippet creation is enabled, but CVE does not comply with the keywords check
            ("CVE-2017-9629", True),
        ],
    )
    def test_snippet_and_flaw_not_created(self, cve_id, snippet_enabled):
        """
        Test that a snippet and flaw are not created.
        """
        nvdc = NVDCollector()
        nvdc.snippet_creation_enabled = snippet_enabled
        nvdc.collect(cve_id)

        snippets = Snippet.objects.filter(
            content__cve_id=cve_id, source=Snippet.Source.NVD
        )
        flaws = Flaw.objects.filter(cve_id=cve_id, source=FlawSource.NVD)

        assert len(snippets) == len(flaws) == 0
