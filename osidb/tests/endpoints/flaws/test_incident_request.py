"""
Tests for the IncidentRequestView endpoint.
"""

import pytest
from rest_framework import status

from osidb.models import Flaw, FlawComment
from osidb.tests.factories import FlawFactory

pytestmark = pytest.mark.unit


class TestIncidentRequestView:
    """
    Tests for the incident request endpoint.
    """

    @pytest.mark.parametrize(
        "request_state,comment_text",
        [
            (
                Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
                "This is a valid comment for major incident request",
            ),
            (
                Flaw.FlawMajorIncident.EXPLOITS_KEV_REQUESTED,
                "This is a valid comment for exploits KEV request",
            ),
            (
                Flaw.FlawMajorIncident.MINOR_INCIDENT_REQUESTED,
                "This is a valid comment for minor incident request",
            ),
        ],
    )
    def test_incident_request_happy_path(
        self, auth_client, test_api_uri, request_state, comment_text
    ):
        """
        Test the happy path: Flaw with major_incident_state = NOVALUE
        requesting to set it to a valid request state with a valid comment.
        """
        # Create a flaw with NOVALUE major incident state
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            embargoed=False,
        )

        # Prepare request data
        request_data = {"kind": request_state, "comment": comment_text}

        # Make POST request to incident request endpoint
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/incident-requests",
            request_data,
            format="json",
        )

        # Assert successful response
        assert response.status_code == status.HTTP_200_OK

        # Refresh flaw from database and verify state change
        flaw.refresh_from_db()
        assert flaw.major_incident_state == request_state

        # Verify comment was created
        comments = FlawComment.objects.filter(flaw=flaw)
        assert comments.count() == 1
        comment = comments.first()
        assert comment is not None
        assert comment.text == comment_text
        assert comment.is_private is True

    def test_incident_request_invalid_state(self, auth_client, test_api_uri):
        """
        Test unhappy path: Flaw with major_incident_state = NOVALUE
        requesting to set it to an invalid major_incident_state.
        """
        # Create a flaw with NOVALUE major incident state
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            embargoed=False,
        )

        # Prepare request data with invalid state (not in request_states())
        request_data = {
            "kind": Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,  # This is not a valid request state
            "comment": "This is a valid comment",
        }

        # Make POST request to incident request endpoint
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/incident-requests",
            request_data,
            format="json",
        )

        # Assert validation error
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Verify flaw state was not changed
        flaw.refresh_from_db()
        assert flaw.major_incident_state == Flaw.FlawMajorIncident.NOVALUE

        # Verify no comment was created
        comments = FlawComment.objects.filter(flaw=flaw)
        assert comments.count() == 0

    def test_incident_request_missing_comment(self, auth_client, test_api_uri):
        """
        Test unhappy path: Flaw with major_incident_state = NOVALUE
        requesting to set it to MAJOR_INCIDENT_REQUESTED without a comment.
        """
        # Create a flaw with NOVALUE major incident state
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            embargoed=False,
        )

        # Prepare request data without comment
        request_data = {
            "kind": Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
            # Missing "comment" field
        }

        # Make POST request to incident request endpoint
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/incident-requests",
            request_data,
            format="json",
        )

        # Assert validation error
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Verify flaw state was not changed
        flaw.refresh_from_db()
        assert flaw.major_incident_state == Flaw.FlawMajorIncident.NOVALUE

        # Verify no comment was created
        comments = FlawComment.objects.filter(flaw=flaw)
        assert comments.count() == 0

    def test_incident_request_empty_comment(self, auth_client, test_api_uri):
        """
        Test unhappy path: Flaw with major_incident_state = NOVALUE
        requesting to set it to MAJOR_INCIDENT_REQUESTED with an empty comment.
        """
        # Create a flaw with NOVALUE major incident state
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            embargoed=False,
        )

        # Prepare request data with empty comment
        request_data = {
            "kind": Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
            "comment": "",  # Empty comment
        }

        # Make POST request to incident request endpoint
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/incident-requests",
            request_data,
            format="json",
        )

        # Assert validation error
        assert response.status_code == status.HTTP_400_BAD_REQUEST

        # Verify flaw state was not changed
        flaw.refresh_from_db()
        assert flaw.major_incident_state == Flaw.FlawMajorIncident.NOVALUE

        # Verify no comment was created
        comments = FlawComment.objects.filter(flaw=flaw)
        assert comments.count() == 0
