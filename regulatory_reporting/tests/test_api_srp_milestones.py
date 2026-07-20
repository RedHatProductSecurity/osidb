"""
Tests for top-level SRP Milestone API endpoints (nested under reports).

Tests list, retrieve, update operations for milestones.
"""

import pytest
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.tests.factories import (
    NonReportableFlawFactory,
    SRPReportFactory,
    SRPReportMilestoneFactory,
)

pytestmark = pytest.mark.unit


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPMilestoneList:
    """Tests for GET /regulatory-reporting/api/v1/srp-reports/{uuid}/milestones (list)."""

    def test_list_milestones_for_report(self, api_client, create_flaw_report):
        """Can list milestones for a specific report."""

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{create_flaw_report().uuid}/milestones"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 3

    def test_list_milestones_filters_to_report(self, api_client, create_flaw_report):
        """Milestones are filtered to the specified report only."""
        report1 = create_flaw_report()

        flaw2 = FlawFactory(
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            major_incident_start_dt=timezone.now(),
        )
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report1.uuid}/milestones"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 3
        srp_report_milestone = {
            milestone["srp_report"] for milestone in response.data["results"]
        }
        assert srp_report_milestone == {report1.uuid}

    def test_list_milestones_empty(self, api_client):
        """Empty list when report has no milestones."""
        report = SRPReportFactory()
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 0

    def test_list_milestones_invalid_report_404(self, api_client):
        """404 when report doesn't exist."""
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{fake_uuid}/milestones"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_milestones_includes_computed_fields(self, api_client):
        """Response includes computed fields."""
        report = SRPReportFactory()
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones"
        )
        assert response.status_code == status.HTTP_200_OK
        result = response.data["results"][0]
        assert "due_at" in result
        assert "hours_remaining" in result
        assert "days_remaining" in result
        assert "is_overdue" in result


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPMilestoneRetrieve:
    """Tests for GET /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones/{uuid}."""

    def test_retrieve_milestone(self, api_client):
        """Can retrieve single milestone by UUID."""
        report = SRPReportFactory()
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones/{milestone.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == str(milestone.uuid)
        assert response.data["milestone_type"] == milestone.milestone_type

    def test_retrieve_milestone_not_found(self, api_client):
        """404 when milestone doesn't exist."""
        report = SRPReportFactory()
        fake_uuid = "770e8400-e29b-41d4-a716-446655440002"

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones/{fake_uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_milestone_wrong_report_404(self, api_client):
        """404 when milestone belongs to different report."""
        report1 = SRPReportFactory()
        report2 = SRPReportFactory()
        milestone = SRPReportMilestoneFactory(srp_report=report2)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report1.uuid}/milestones/{milestone.uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_milestone_includes_all_fields(self, api_client):
        """Response includes all expected fields."""
        report = SRPReportFactory()
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones/{milestone.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.data
        assert "uuid" in data
        assert "srp_report" in data
        assert "milestone_type" in data
        assert "status" in data
        assert "request_received_at" in data
        assert "request_source" in data
        assert "request_text" in data
        assert "created_dt" in data
        assert "updated_dt" in data
        assert "due_at" in data
        assert "hours_remaining" in data
        assert "days_remaining" in data
        assert "is_overdue" in data


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPMilestoneUpdate:
    """Tests for PUT/PATCH /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones/{uuid}."""

    def test_update_milestone_unauthenticated_fails(self, api_client):
        """Unauthenticated users cannot update milestones."""
        report = SRPReportFactory()
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = api_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones/{milestone.uuid}",
            {"status": SRPReportMilestone.SRPReportStatus.PREPARED},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_partial_update_milestone(self, authenticated_client, create_flaw_report):
        """Can partially update milestone fields."""
        milestones_report = create_flaw_report()

        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones/{milestone.uuid}",
            {"status": SRPReportMilestone.SRPReportStatus.PREPARED},
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.status == SRPReportMilestone.SRPReportStatus.PREPARED

    def test_update_multiple_fields(self, authenticated_client, create_flaw_report):
        """Can update multiple fields at once."""
        milestones_report = create_flaw_report()

        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        now = timezone.now()
        update_data = {
            "status": SRPReportMilestone.SRPReportStatus.PREPARED,
            "request_source": "ENISA Portal",
            "request_text": "Additional information requested",
        }

        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones/{milestone.uuid}",
            update_data,
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.status == SRPReportMilestone.SRPReportStatus.PREPARED
        assert milestone.request_source == "ENISA Portal"
        assert milestone.request_text == "Additional information requested"

    def test_update_read_only_field_ignored(
        self, authenticated_client, create_flaw_report
    ):
        """Read-only fields are ignored in updates."""
        milestones_report = create_flaw_report()

        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones/{milestone.uuid}",
            {
                "milestone_type": SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
            },
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.milestone_type == SRPReportMilestone.MilestoneType.LEVEL_24H

    def test_update_acl_fields_ignored(self, authenticated_client, create_flaw_report):
        """ACL fields are not mutable via PATCH."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        original_acl_read = list(milestone.acl_read)
        original_acl_write = list(milestone.acl_write)

        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones/{milestone.uuid}",
            {
                "acl_read": ["00000000-0000-0000-0000-000000000001"],
                "acl_write": ["00000000-0000-0000-0000-000000000002"],
                "status": SRPReportMilestone.SRPReportStatus.PREPARED,
            },
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert list(milestone.acl_read) == original_acl_read
        assert list(milestone.acl_write) == original_acl_write
        assert milestone.status == SRPReportMilestone.SRPReportStatus.PREPARED

    def test_full_update_milestone(self, authenticated_client, create_flaw_report):
        """Can perform full update with PUT."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        milestone_data = authenticated_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones/{milestone.uuid}"
        ).data
        update_data = {
            "status": SRPReportMilestone.SRPReportStatus.SUBMITTED,
            "request_source": "ENISA Portal",
            "request_text": "Additional information requested",
        }
        milestone_data.update(update_data)
        response = authenticated_client.put(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones/{milestone.uuid}",
            milestone_data,
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.status == SRPReportMilestone.SRPReportStatus.SUBMITTED
        assert milestone.request_source == "ENISA Portal"
        assert milestone.request_text == "Additional information requested"


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPMilestoneFiltering:
    """Tests for filtering milestones."""

    def test_filter_by_status(self, api_client, create_flaw_report):
        """Can filter milestones by status."""
        milestones_report = create_flaw_report()

        first_milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        first_milestone.status = SRPReportMilestone.SRPReportStatus.SUBMITTED
        first_milestone.save()

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones?status=submitted"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert (
            response.data["results"][0]["status"]
            == SRPReportMilestone.SRPReportStatus.SUBMITTED
        )

    def test_filter_by_milestone_type(self, api_client, create_flaw_report):
        """Can filter by milestone_type."""
        milestones_report = create_flaw_report()

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones?milestone_type=24h"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert (
            response.data["results"][0]["milestone_type"]
            == SRPReportMilestone.MilestoneType.LEVEL_24H
        )


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPMilestoneCreate:
    """Tests for POST /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones."""

    def test_create_additional_information_response_milestone(
        self, authenticated_client, create_flaw_report
    ):
        """Can create additional_information_response milestones via POST."""
        milestones_report = create_flaw_report()

        now = timezone.now()
        data = {
            "request_received_at": now.isoformat(),
            "request_source": "ENISA Portal",
            "request_text": "Please provide additional details.",
        }

        response = authenticated_client.post(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones",
            data,
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert (
            response.data["milestone_type"]
            == SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        )
        assert response.data["request_source"] == "ENISA Portal"
        assert response.data["srp_report"] == milestones_report.uuid

        milestone = SRPReportMilestone.objects.get(uuid=response.data["uuid"])
        assert milestone.acl_read == milestones_report.acl_read
        assert milestone.acl_write == milestones_report.acl_write

    def test_create_multiple_additional_information_response_allowed(
        self, authenticated_client, create_flaw_report
    ):
        """Multiple additional_information_response milestones are allowed."""
        milestones_report = create_flaw_report()

        milestone_type = (
            SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        )

        for i in range(2):
            response = authenticated_client.post(
                f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones",
                {"request_text": f"Request {i}"},
            )
            assert response.status_code == status.HTTP_201_CREATED

        assert (
            milestones_report.milestones.filter(milestone_type=milestone_type).count()
            == 2
        )

    def test_create_ignores_milestone_type_in_request_body(
        self, authenticated_client, create_flaw_report
    ):
        """POST always creates additional_information_response regardless of body."""
        milestones_report = create_flaw_report()

        response = authenticated_client.post(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones",
            {"milestone_type": SRPReportMilestone.MilestoneType.LEVEL_24H},
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert (
            response.data["milestone_type"]
            == SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        )

    def test_create_milestone_unauthenticated_fails(
        self, api_client, create_flaw_report
    ):
        """Unauthenticated users cannot create milestones."""
        milestones_report = create_flaw_report()

        response = api_client.post(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones",
            {"request_text": "Additional information requested"},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_create_milestone_invalid_report_404(self, authenticated_client):
        """404 when report doesn't exist."""
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"
        response = authenticated_client.post(
            f"/regulatory-reporting/api/v1/srp-reports/{fake_uuid}/milestones",
            {"request_text": "Additional information requested"},
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPMilestoneHTTPMethods:
    """Tests for unsupported HTTP methods."""

    def test_delete_not_allowed(self, authenticated_client, create_flaw_report):
        """DELETE is not allowed (milestones are permanent)."""
        milestones_report = create_flaw_report()

        milestone_1 = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = authenticated_client.delete(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones/{milestone_1.uuid}"
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
