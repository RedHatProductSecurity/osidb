import pytest
from rest_framework import status

from osidb.models import Affect, AffectCVSS
from osidb.tests.factories import AffectCVSSFactory, AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestEndpointsAffects:
    """
    tests specific to /affects endpoint
    """

    @pytest.mark.enable_signals
    def test_get_affect_with_cvss(self, auth_client, test_api_uri):
        """retrieve specific affect with affectcvss from endpoint"""
        affect = AffectFactory()

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 0

        AffectCVSSFactory(affect=affect)

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 1

    @pytest.mark.parametrize(
        "flaw_embargo,affect_embargo,fails",
        [
            (False, False, False),
            (True, True, False),
            (False, True, True),
            (True, False, True),
        ],
    )
    def test_affect_create(
        self,
        auth_client,
        test_api_uri,
        flaw_embargo,
        affect_embargo,
        fails,
    ):
        """
        test the creation of Affect records via a REST API POST request
        also with respect to the flaw and affect visibility (which should be equal in Buzilla world)
        """
        flaw = FlawFactory(embargoed=flaw_embargo)
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_module": "rhacm-2",
            "ps_component": "curl",
            "embargoed": affect_embargo,
        }
        response = auth_client().post(
            f"{test_api_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        if fails:
            assert response.status_code == 400
            assert "ACLs must correspond to the parent flaw:" in str(response.content)

        else:
            assert response.status_code == 201
            body = response.json()
            created_uuid = body["uuid"]

            response = auth_client().get(f"{test_api_uri}/affects/{created_uuid}")
            assert response.status_code == 200
            body = response.json()
            assert body["ps_module"] == "rhacm-2"

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_affect_update(self, auth_client, test_api_uri, embargoed):
        """
        Test the update of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(embargoed=embargoed)
        affect = AffectFactory(flaw=flaw)
        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_uri}/affects/{affect.uuid}",
            {
                **original_body,
                "ps_module": f"different {affect.ps_module}",
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["ps_module"] != body["ps_module"]

    def test_affect_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of Affect records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        affect_url = f"{test_api_uri}/affects/{affect.uuid}"
        response = auth_client().get(affect_url)
        assert response.status_code == 200

        response = auth_client().delete(affect_url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == 200

        response = auth_client().get(affect_url)
        assert response.status_code == 404

    @pytest.mark.enable_signals
    def test_affectcvss_create(self, auth_client, test_api_uri):
        """
        Test the creation of AffectCVSS records via a REST API POST request.
        """
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss_data = {
            "issuer": AffectCVSS.CVSSIssuer.REDHAT,
            "cvss_version": AffectCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on affects/{uuid}/cvss_scores
        response = auth_client().post(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]

        # Tests "GET" on affects/{uuid}/cvss_scores
        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid

    @pytest.mark.enable_signals
    def test_affectcvss_update(self, auth_client, test_api_uri):
        """
        Test the update of AffectCVSS records via a REST API PUT request.
        """
        affect = AffectFactory()
        cvss = AffectCVSSFactory(
            affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT, comment=""
        )

        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

        updated_data = response.json().copy()
        updated_data["comment"] = "text"

        # Tests "PUT" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == "text"

    @pytest.mark.enable_signals
    def test_affectcvss_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of AffectCVSS records via a REST API DELETE request.
        """
        affect = AffectFactory()
        cvss = AffectCVSSFactory(affect=affect)

        url = f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert AffectCVSS.objects.count() == 0
