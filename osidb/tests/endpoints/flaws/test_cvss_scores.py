import pytest
from rest_framework import status

from osidb.models import FlawCVSS
from osidb.tests.factories import AffectFactory, FlawCVSSFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestEndpointsFlawsCVSSScores:
    """
    tests specific to /flaws/.../cvss_scores endpoint
    """

    @pytest.mark.enable_signals
    def test_flawcvss_create(self, auth_client, test_api_uri):
        """
        Test the creation of FlawCVSS records via a REST API POST request.
        """
        flaw = FlawFactory()
        cvss_data = {
            "issuer": FlawCVSS.CVSSIssuer.REDHAT,
            "cvss_version": FlawCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/cvss_scores
        response = auth_client().post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/cvss_scores
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid

    @pytest.mark.enable_signals
    def test_flawcvss_update(self, auth_client, test_api_uri):
        """
        Test the update of FlawCVSS records via a REST API PUT request.
        """
        flaw = FlawFactory()
        cvss = FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.REDHAT, comment="")

        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

        updated_data = response.json().copy()
        updated_data["comment"] = "text"

        # Tests "PUT" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == "text"

    @pytest.mark.enable_signals
    def test_flawcvss_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of FlawCVSS records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)
        cvss = FlawCVSSFactory(flaw=flaw)

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert FlawCVSS.objects.count() == 0
