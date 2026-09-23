import pytest
from rest_framework import status

from apps.regulatory_reporting.models import (
    AdditionalInformationRequest,
    SRPReportMilestone,
)
from apps.regulatory_reporting.tests.factories import (
    AdditionalInformationRequestFactory,
)


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestAdditionalInformationRequestCreate:
    def test_create_air(self, authenticated_client, create_flaw_report):
        """Can create an AIR under a milestone via POST."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = authenticated_client.post(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
            f"/milestones/{milestone.uuid}/additional-information-requests",
            {
                "manual_completion_notes": "Initial notes",
                "owner": "analyst@redhat.com",
                "request_source": "ENISA Portal",
                "request_text": "Please provide additional details.",
                "response_text": "Here are the additional details.",
                "status": SRPReportMilestone.SRPReportMilestoneStatus.IN_PROGRESS,
            },
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["manual_completion_notes"] == "Initial notes"
        assert response.data["owner"] == "analyst@redhat.com"
        assert response.data["request_source"] == "ENISA Portal"
        assert response.data["request_text"] == "Please provide additional details."
        assert response.data["response_text"] == "Here are the additional details."
        assert (
            response.data["status"]
            == SRPReportMilestone.SRPReportMilestoneStatus.IN_PROGRESS
        )

        air = AdditionalInformationRequest.objects.get(pk=response.data["uuid"])
        assert air.milestone == milestone
        assert air.manual_completion_notes == "Initial notes"
        assert air.owner == "analyst@redhat.com"
        assert air.response_text == "Here are the additional details."
        assert air.status == SRPReportMilestone.SRPReportMilestoneStatus.IN_PROGRESS

    def test_update_air(self, authenticated_client, create_flaw_report):
        """Can update AIR add/edit popup fields via PUT."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        air = AdditionalInformationRequestFactory(milestone=milestone)
        data = {
            "manual_completion_notes": "Updated notes",
            "manual_due_at": None,
            "owner": "owner@redhat.com",
            "request_received_at": None,
            "request_source": "ENISA Portal",
            "request_text": "Please provide additional details.",
            "response_text": "The requested details are included here.",
            "status": SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW,
            "updated_dt": air.updated_dt,
        }

        response = authenticated_client.put(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
            f"/milestones/{milestone.uuid}/additional-information-requests/{air.uuid}",
            data,
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data["manual_completion_notes"] == "Updated notes"
        assert response.data["owner"] == "owner@redhat.com"
        assert response.data["request_source"] == "ENISA Portal"
        assert response.data["request_text"] == "Please provide additional details."
        assert response.data["response_text"] == (
            "The requested details are included here."
        )
        assert (
            response.data["status"]
            == SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW
        )

        air.refresh_from_db()
        assert air.manual_completion_notes == "Updated notes"
        assert air.owner == "owner@redhat.com"
        assert air.request_source == "ENISA Portal"
        assert air.request_text == "Please provide additional details."
        assert air.response_text == "The requested details are included here."
        assert air.status == SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW

    def test_create_air_invalid_milestone_404(
        self, authenticated_client, create_flaw_report
    ):
        """404 when milestone doesn't exist."""
        report = create_flaw_report()
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"

        response = authenticated_client.post(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
            f"/milestones/{fake_uuid}/additional-information-requests",
            {"request_text": "Additional information requested"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_create_air_unauthenticated_fails(self, api_client, create_flaw_report):
        """Unauthenticated users cannot create AIRs."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = api_client.post(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
            f"/milestones/{milestone.uuid}/additional-information-requests",
            {"request_text": "Additional information requested"},
        )

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_create_multiple_airs_allowed(
        self, authenticated_client, create_flaw_report
    ):
        """Multiple AIRs are allowed on the same milestone."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        for i in range(2):
            response = authenticated_client.post(
                f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
                f"/milestones/{milestone.uuid}/additional-information-requests",
                {"request_text": f"Request {i}"},
            )
            assert response.status_code == status.HTTP_201_CREATED

        assert (
            AdditionalInformationRequest.objects.filter(milestone=milestone).count()
            == 2
        )

    def test_create_air_mismatched_report_404(
        self, authenticated_client, create_flaw_report
    ):
        """404 when milestone doesn't belong to the report in the URL."""
        report = create_flaw_report()
        other_report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = authenticated_client.post(
            f"/regulatory-reporting/api/v1/srp-reports/{other_report.uuid}"
            f"/milestones/{milestone.uuid}/additional-information-requests",
            {"request_text": "Additional information requested"},
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestAdditionalInformationRequestStr:
    def test_str_numbers_siblings_in_creation_order(self, create_flaw_report):
        """__str__ numbers AIRs by creation order within a milestone."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        first = AdditionalInformationRequestFactory(
            milestone=milestone, request_text="First"
        )
        second = AdditionalInformationRequestFactory(
            milestone=milestone, request_text="Second"
        )

        assert str(first) == f"Additional Information Request 1 - {milestone}"
        assert str(second) == f"Additional Information Request 2 - {milestone}"
