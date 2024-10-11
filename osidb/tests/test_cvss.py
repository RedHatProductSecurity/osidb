import pytest
from cvss import CVSS3
from django.core.exceptions import ValidationError

from osidb.models import CVSS
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
)

pytestmark = pytest.mark.unit


class TestCVSS:
    def test_create(self):
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)

        flaw_cvss2 = FlawCVSSFactory(
            flaw=flaw, version=CVSS.CVSSVersion.VERSION2, issuer=CVSS.CVSSIssuer.REDHAT
        )
        flaw_cvss3 = FlawCVSSFactory(flaw=flaw, version=CVSS.CVSSVersion.VERSION3)

        affect_cvss2 = AffectCVSSFactory(
            affect=affect, version=CVSS.CVSSVersion.VERSION2
        )
        affect_cvss3 = AffectCVSSFactory(
            affect=affect,
            version=CVSS.CVSSVersion.VERSION3,
            issuer=CVSS.CVSSIssuer.NIST,
        )

        all_flaw_cvss_scores = flaw.cvss_scores.all()
        assert len(all_flaw_cvss_scores) == 2
        assert flaw_cvss2 in all_flaw_cvss_scores
        assert flaw_cvss3 in all_flaw_cvss_scores

        all_affect_cvss_scores = affect.cvss_scores.all()
        assert len(all_affect_cvss_scores) == 2
        assert affect_cvss2 in all_affect_cvss_scores
        assert affect_cvss3 in all_affect_cvss_scores

        # Test flaw/affect-version-issuer uniqueness constraint.
        with pytest.raises(
            ValidationError,
            match="Flaw cvss with this Flaw, Version and Issuer already exists.",
        ):
            duplicite_flaw_cvss2 = FlawCVSSFactory.build(
                flaw=flaw,
                version=CVSS.CVSSVersion.VERSION2,
                issuer=CVSS.CVSSIssuer.REDHAT,
            )
            duplicite_flaw_cvss2.save()

        with pytest.raises(
            ValidationError,
            match="Affect cvss with this Affect, Version and Issuer already exists.",
        ):
            duplicite_affect_cvss3 = AffectCVSSFactory.build(
                affect=affect,
                version=CVSS.CVSSVersion.VERSION3,
                issuer=CVSS.CVSSIssuer.NIST,
            )
            duplicite_affect_cvss3.save()

    @pytest.mark.parametrize(
        "cvss3_vector",
        [
            "test",
            "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # wrong metric value Z
            "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # missing header
            "AV:N/AC:L/Au:N/C:N/I:N/A:C",  # CVSSv2
        ],
    )
    def test_validate_cvss3_string(self, cvss3_vector):
        flaw = FlawFactory()
        with pytest.raises(ValidationError, match="Invalid CVSS"):
            FlawCVSSFactory(
                flaw=flaw,
                version=CVSS.CVSSVersion.VERSION3,
                vector=cvss3_vector,
            )

    @pytest.mark.parametrize(
        "cvss2_vector",
        [
            "test",
            "AV:Z/AC:L/Au:N/C:N/I:N/A:C",  # wrong metric value Z
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # CVSSv3
        ],
    )
    def test_validate_cvss2_string(self, cvss2_vector):
        with pytest.raises(ValidationError, match="Invalid CVSS"):
            FlawCVSSFactory(version=CVSS.CVSSVersion.VERSION2, vector=cvss2_vector)

    @pytest.mark.enable_signals
    def test_cvss3_recalculation(self):
        cvss = FlawCVSSFactory(
            vector="CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L",
            version=CVSS.CVSSVersion.VERSION3,
        )
        assert cvss.score == CVSS3(cvss.vector).scores()[0]
        prev_score = cvss.score

        # Change the vector and check whether the score was updated after save.
        cvss.vector = "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:H"
        cvss.save()
        assert cvss.score == CVSS3(cvss.vector).scores()[0]
        # This probably won't work for CVSSv4 as multiple vectors might have the same score.
        assert cvss.score != prev_score

    def test_validate_cvss_comment(self):
        with pytest.raises(
            ValidationError,
            match="CVSS comment can be set only for CVSSs issued by Red Hat.",
        ):
            FlawCVSSFactory(
                issuer=CVSS.CVSSIssuer.NIST,
                comment="Smoke me a kipper, I'll be back for breakfast.",
            )

        FlawCVSSFactory(issuer=CVSS.CVSSIssuer.NIST, comment="")

    def test_str_representation(self):
        cvss = FlawCVSSFactory()
        assert str(cvss) == f"{cvss.score}/{cvss.vector}"
