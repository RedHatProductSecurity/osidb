from datetime import datetime, timezone

import pytest

from collectors.framework.models import CollectorMetadata
from collectors.nvd.collectors import NVDCollector
from osidb.models import Flaw, FlawCVSS, Impact
from osidb.tests.factories import FlawCVSSFactory, FlawFactory

pytestmark = pytest.mark.integration


class TestNVDCollector:
    """
    NVDCollector test cases
    """

    @pytest.mark.vcr
    @pytest.mark.enable_signals
    def test_collect_batch(self):
        """
        test that collecting a batch of CVEs works
        """
        # let us use existing CVE data as a real-world example
        # https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate=2010-01-01T00:00:00&lastModEndDate=2010-04-11T00:00:00

        nvdc = NVDCollector()
        nvdc.metadata.updated_until_dt = datetime(2010, 1, 1, 0, 0, tzinfo=timezone.utc)

        # test that the batch is correctly selected
        batch, period_end = nvdc.get_batch()
        assert len(batch) == 296
        assert period_end == datetime(2010, 4, 11, 0, 0, tzinfo=timezone.utc)

        # test that the batch collection works
        # randomly select a few flaws - not all 296
        #
        # we do not test CVSS3 as these old flaws do not have it
        # but more recent batches are too huge (a few MB cassettes)
        # it is going to be tested by another test case
        FlawFactory(cve_id="CVE-2000-0835")
        FlawFactory(cve_id="CVE-2010-0977")
        FlawFactory(cve_id="CVE-2010-1313")

        nvdc.collect()

        flaw = Flaw.objects.get(cve_id="CVE-2000-0835")
        cvss = flaw.cvss_scores.all().filter(
            issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION2
        )[0]
        assert str(cvss) == "5.0/AV:N/AC:L/Au:N/C:P/I:N/A:N"

        flaw = Flaw.objects.get(cve_id="CVE-2010-0977")
        cvss = flaw.cvss_scores.all().filter(
            issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION2
        )[0]
        assert str(cvss) == "5.0/AV:N/AC:L/Au:N/C:P/I:N/A:N"

        flaw = Flaw.objects.get(cve_id="CVE-2010-1313")
        cvss = flaw.cvss_scores.all().filter(
            issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION2
        )[0]
        assert str(cvss) == "4.3/AV:N/AC:M/Au:N/C:P/I:N/A:N"

    @pytest.mark.vcr
    @pytest.mark.enable_signals
    def test_collect_cve(self):
        """
        test that collecting a given CVE works
        """
        # let us use existing CVE data as a real-world example
        # https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-1234
        cve = "CVE-2020-1234"

        FlawFactory(cve_id=cve)

        nvdc = NVDCollector()
        nvdc.collect(cve)

        flaw = Flaw.objects.first()
        cvss_v2 = flaw.cvss_scores.all().filter(
            issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION2
        )[0]
        cvss_v3 = flaw.cvss_scores.all().filter(
            issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION3
        )[0]
        assert flaw.cve_id == cve
        assert str(cvss_v2) == "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P"
        assert str(cvss_v3) == "7.8/CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"

    @pytest.mark.vcr
    @pytest.mark.enable_signals
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
        before_collector_run = datetime(2022, 1, 1, 0, 0, tzinfo=timezone.utc)
        last_collector_run = datetime(2022, 2, 1, 0, 0, tzinfo=timezone.utc)
        after_collector_run = datetime(2022, 3, 1, 0, 0, tzinfo=timezone.utc)

        FlawFactory(cve_id=cve1, updated_dt=before_collector_run)
        FlawFactory(cve_id=cve2, updated_dt=after_collector_run)

        nvdc = NVDCollector()
        nvdc.metadata.updated_until_dt = last_collector_run
        # no change should happen when not complete
        nvdc.collect_updated()

        flaw = Flaw.objects.get(cve_id=cve1)
        assert not flaw.cvss_scores.all()

        flaw = Flaw.objects.get(cve_id=cve2)
        assert not flaw.cvss_scores.all()

        # make data complete
        nvdc.metadata.data_state = CollectorMetadata.DataState.COMPLETE
        nvdc.collect_updated()

        # first CVE was not updated after the
        # collector run so should be unchanged
        flaw = Flaw.objects.get(cve_id=cve1)
        assert not flaw.cvss_scores.all()

        flaw = Flaw.objects.get(cve_id=cve2)
        cvss_v2 = flaw.cvss_scores.all().filter(
            issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION2
        )[0]
        cvss_v3 = flaw.cvss_scores.all().filter(
            issuer=FlawCVSS.CVSSIssuer.NIST, version=FlawCVSS.CVSSVersion.VERSION3
        )[0]
        assert str(cvss_v2) == "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P"
        assert str(cvss_v3) == "7.8/CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"

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
        flaw = FlawFactory(cve_id=cve_id)

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

    @pytest.mark.vcr
    @pytest.mark.enable_signals
    def test_cvss4(self):
        """
        Test that CVSSv4 score is correctly loaded in the FlawCVSS model.
        """
        cve_id = "CVE-2024-7450"
        FlawFactory(cve_id=cve_id)

        nvdc = NVDCollector()
        nvdc.collect(cve_id)

        flaw = Flaw.objects.get(cve_id=cve_id)
        assert flaw.cvss_scores.filter(version=FlawCVSS.CVSSVersion.VERSION4)

    @pytest.mark.parametrize(
        "old_flag,new_flag",
        [
            (
                Flaw.FlawNistCvssValidation.APPROVED,
                Flaw.FlawNistCvssValidation.APPROVED,
            ),
            (
                Flaw.FlawNistCvssValidation.REJECTED,
                Flaw.FlawNistCvssValidation.APPROVED,
            ),
            (
                Flaw.FlawNistCvssValidation.REQUESTED,
                Flaw.FlawNistCvssValidation.APPROVED,
            ),
            (
                Flaw.FlawNistCvssValidation.NOVALUE,
                Flaw.FlawNistCvssValidation.NOVALUE,
            ),
        ],
    )
    def test_reset_flag_on_removal(self, old_flag, new_flag):
        """
        test that NIST CVSS validation flag is correctly adjusted when NVD CVSSv3 is removed
        """
        flaw = FlawFactory(impact=Impact.LOW)
        FlawCVSSFactory(
            flaw=flaw,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            version=FlawCVSS.CVSSVersion.VERSION3,
        )
        FlawCVSSFactory(
            flaw=flaw,
            issuer=FlawCVSS.CVSSIssuer.NIST,
            vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
            version=FlawCVSS.CVSSVersion.VERSION3,
        )
        flaw.nist_cvss_validation = old_flag
        flaw.save()

        nvdc = NVDCollector()
        empty_scores = {"cvss_scores": []}
        # the CVSS score was removed from NVD database
        nvdc.update_cvss_via_flawcvss(flaw, empty_scores)

        flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert flaw.cvss_scores.count() == 1
        assert flaw.cvss_scores.first().issuer == FlawCVSS.CVSSIssuer.REDHAT
        assert flaw.nist_cvss_validation == new_flag

    @pytest.mark.vcr
    @pytest.mark.enable_signals
    @pytest.mark.parametrize("impact", [Impact.NOVALUE, Impact.MODERATE])
    @pytest.mark.default_cassette("TestNVDCollector.test_cvss4.yaml")
    def test_cvss_and_impact(self, impact):
        """
        Test that flaw impact is set if CVSS was changed, and the impact was originally empty.
        """
        cve_id = "CVE-2024-7450"
        FlawFactory(cve_id=cve_id, impact=impact)

        nvdc = NVDCollector()
        nvdc.collect(cve_id)

        flaw = Flaw.objects.get(cve_id=cve_id)
        assert flaw.cvss_scores.count() == 2
        if not impact:
            # impact was set
            assert flaw.impact == Impact.IMPORTANT
        else:
            # original impact
            assert flaw.impact == Impact.MODERATE
