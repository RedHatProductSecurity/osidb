import pytest
from rest_framework import status

from osidb.dmodels import FlawSource
from osidb.models import FlawAcknowledgment
from osidb.tests.factories import AffectFactory, FlawAcknowledgmentFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestEndpointsFlawsAcknowledgments:
    """
    tests specific to /flaws/.../acknowledgments endpoint
    """

    def test_flawacknowledgment_create(self, auth_client, test_api_uri):
        """
        Test the creation of FlawAcknowledgment records via a REST API POST request.
        """
        # Source must be private in order for validation to pass.
        flaw = FlawFactory(source=FlawSource.CUSTOMER)

        flawacknowledgment_data = {
            "name": "John Doe",
            "affiliation": "Acme Corp.",
            "from_upstream": False,
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/acknowledgments
        response = auth_client().post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments",
            flawacknowledgment_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        acknowledgment_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/acknowledgments
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/acknowledgments/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments/{acknowledgment_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == acknowledgment_uuid

    def test_flawacknowledgment_update(self, auth_client, test_api_uri):
        """
        Test the update of FlawAcknowledgment records via a REST API PUT request.
        """
        # Source must be private in order for validation to pass.
        flaw = FlawFactory(source=FlawSource.CUSTOMER)
        flawacknowledgment = FlawAcknowledgmentFactory(flaw=flaw)

        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments/{flawacknowledgment.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["name"] == "John Doe"

        updated_data = response.json().copy()
        updated_data["name"] = "Jon A"

        # Tests "PUT" on flaws/{uuid}/acknowledgments/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments/{flawacknowledgment.uuid}",
            {**updated_data},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["name"] == "Jon A"

    def test_flawacknowledgment_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of FlawAcknowledgment records via a REST API DELETE request.
        """
        # Source must be private in order for validation to pass.
        flaw = FlawFactory(source=FlawSource.CUSTOMER)
        flawacknowledgment = FlawAcknowledgmentFactory(flaw=flaw)

        # Necessary for Flaw validation
        AffectFactory(flaw=flaw)

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/acknowledgments/{flawacknowledgment.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on flaws/{uuid}/acknowledgments/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert FlawAcknowledgment.objects.count() == 0
