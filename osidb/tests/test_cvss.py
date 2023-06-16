import pytest
from django.core.exceptions import ValidationError

from osidb.models import CVSS
from osidb.tests.factories import AffectFactory, CVSSFactory, FlawFactory


class TestCVSS:

    def test_create(self, datetime_with_tz):
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)

        cvss1 = CVSSFactory(flaw=flaw, affect=affect)
        cvss2 = CVSSFactory(
            flaw=flaw,
            vector="AV:N/AC:L/Au:N/C:N/I:N/A:C",
            version=CVSS.CVSSVersion.VERSION2,
        )
        cvss3 = CVSS.objects.create_cvss(
            flaw=flaw,
            affect=None,
            vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            issuer=CVSS.CVSSIssuer.NIST,
            version=CVSS.CVSSVersion.VERSION3,
            created_dt=datetime_with_tz,
            updated_dt=datetime_with_tz,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        cvss4 = CVSSFactory(
            affect=affect,
            vector="AV:N/AC:H/Au:N/C:N/I:N/A:C",
            version=CVSS.CVSSVersion.VERSION2,
        )

        flaw.save()
        affect.save()
        assert cvss1.save() is None
        assert cvss2.save() is None
        assert cvss3.save() is None
        assert cvss4.save() is None

        all_flaw_cvss_scores = flaw.cvss_scores.all()

        assert len(all_flaw_cvss_scores) == 3
        assert cvss1 in all_flaw_cvss_scores
        assert cvss2 in all_flaw_cvss_scores
        assert cvss3 in all_flaw_cvss_scores

        all_affect_cvss_scores = affect.cvss_scores.all()

        assert len(all_affect_cvss_scores) == 2
        assert cvss1 in all_affect_cvss_scores
        assert cvss4 in all_affect_cvss_scores

        # Test flaw/affect-version-issuer uniqueness constraint.
        with pytest.raises(ValidationError) as e:
            _ = CVSSFactory(
                flaw=flaw,
                vector="AV:N/AC:L/Au:N/C:N/I:N/A:C",
                version=CVSS.CVSSVersion.VERSION2,
            )
        assert "Cvss with this Flaw, Version and Issuer already exists." in str(e)

        with pytest.raises(ValidationError) as e:
            _ = CVSSFactory(affect=affect)
        assert "Cvss with this Affect, Version and Issuer already exists." in str(e)

    @pytest.mark.parametrize(
        "cvss3",
        [
            "test",
            "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # wrong metric value Z
            "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # missing header
            "AV:N/AC:L/Au:N/C:N/I:N/A:C",  # CVSSv2
        ],
    )
    def test_validate_cvss3_string(self, cvss3):
        with pytest.raises(ValidationError) as e:
            CVSSFactory(vector=cvss3)
        assert "Invalid CVSS" in str(e)

    @pytest.mark.parametrize(
        "cvss2",
        [
            "test",
            "AV:Z/AC:L/Au:N/C:N/I:N/A:C",  # wrong metric value Z
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",  # CVSSv3
        ],
    )
    def test_validate_cvss2_string(self, cvss2):
        with pytest.raises(ValidationError) as e:
            CVSSFactory(version=CVSS.CVSSVersion.VERSION2, vector=cvss2)
        assert "Invalid CVSS" in str(e)

    def test_cvss_recalculation(self):
        cvss = CVSSFactory()
        cvss_handle, _ = cvss._version()
        assert cvss_handle(cvss.vector).scores()[0] == cvss.score
        prev_score = cvss.score

        # Change the vector and check whether the score was updated after save.
        cvss.vector = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
        cvss.save()
        assert cvss_handle(cvss.vector).scores()[0] == cvss.score
        # This probably won't work for CVSSv4 as multiple vectors might have the same score.
        assert cvss.score != prev_score

    def test_validate_cvss_comment(self):
        with pytest.raises(ValidationError) as e:
            CVSSFactory(issuer=CVSS.CVSSIssuer.NIST)
        assert "CVSS comment can be set only for CVSSs issued by Red Hat." in str(e)

        CVSSFactory(issuer=CVSS.CVSSIssuer.NIST, comment="")

    def test_str_representation(self):
        cvss = CVSSFactory()
        assert str(cvss) == cvss.vector
