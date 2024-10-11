import pytest
from rest_framework import status

from osidb.dmodels.flaw.reference import FlawReference
from osidb.tests.factories import AffectFactory, FlawFactory, FlawReferenceFactory

pytestmark = pytest.mark.unit


class TestEndpointsFlawsReferences:
    """
    tests specific to /flaws/.../references endpoint
    """

    def test_flawreference_create(self, auth_client, test_api_uri):
        """
        Test the creation of FlawReference records via a REST API POST request.
        """
        flaw = FlawFactory()

        flawreference_data = {
            "flaw": str(flaw.uuid),
            "type": "EXTERNAL",
            "url": "https://httpd.apache.org/link123",
            "description": "link description",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/references
        response = auth_client().post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references",
            flawreference_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        reference_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/references
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/references/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references/{reference_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == reference_uuid

    def test_flawreference_update(self, auth_client, test_api_uri):
        """
        Test the update of FlawReference records via a REST API PUT request.
        """
        flaw = FlawFactory()
        flawreference = FlawReferenceFactory(flaw=flaw)

        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references/{flawreference.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["url"] == "https://httpd.apache.org/link123"

        updated_data = response.json().copy()
        updated_data["url"] = "https://httpd.apache.org/link456"

        # Tests "PUT" on flaws/{uuid}/references/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/references/{flawreference.uuid}",
            {**updated_data},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["url"] == "https://httpd.apache.org/link456"

    def test_flawreference_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of FlawReference records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        flawreference = FlawReferenceFactory(flaw=flaw)
        AffectFactory(flaw=flaw)

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/references/{flawreference.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on flaws/{uuid}/references/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert FlawReference.objects.count() == 0
