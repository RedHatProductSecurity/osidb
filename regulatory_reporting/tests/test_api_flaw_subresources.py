"""
Tests for flaw subresource SRP endpoints (read-only convenience wrappers).

Tests read-only access to reports and milestones via flaw context.
"""

import pytest
from django.conf import settings
from rest_framework import status

from osidb.models import Flaw
from regulatory_reporting.tests.factories import (
    NonReportableFlawFactory,
    SRPReportFactory,
    SRPReportMilestoneFactory,
)

pytestmark = pytest.mark.unit

MALFORMED_UUID = "not-a-uuid"


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestFlawSRPReportList:
    """Tests for GET /regulatory-reporting/api/v1/flaws/{flaw_id}/srp-reports (list)."""

    def test_list_reports_for_flaw(self, api_client, create_flaw_report):
        """Can list SRP reports for a specific flaw."""
        report1 = create_flaw_report(
            incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        )
        _ = create_flaw_report(
            flaw=report1.flaw,
            incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
        )  # second, independent report

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{report1.flaw_id}/srp-reports"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 2
        for result in response.data["results"]:
            assert result["flaw_id"] == report1.flaw_id

    def test_list_reports_empty_when_no_reports(self, api_client):
        """Empty list when flaw has no SRP reports."""
        flaw = NonReportableFlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED
        )
        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 0

    def test_list_reports_flaw_not_found(self, api_client):
        """404 when flaw doesn't exist."""
        fake_uuid = "660e8400-e29b-41d4-a716-446655440001"
        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{fake_uuid}/srp-reports"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_reports_malformed_flaw_id(self, api_client):
        """404 when flaw_id path param is not a valid UUID."""
        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{MALFORMED_UUID}/srp-reports"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestFlawSRPReportRetrieve:
    """Tests for GET /regulatory-reporting/api/v1/flaws/{flaw_id}/srp-reports/{uuid}."""

    def test_retrieve_report_for_flaw(self, api_client, create_flaw_report):
        """Can retrieve specific report for a flaw."""
        report = create_flaw_report()
        flaw_uuid = report.flaw_id
        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw_uuid}/srp-reports/{report.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == str(report.uuid)
        assert response.data["flaw_id"] == flaw_uuid

    def test_retrieve_report_not_found(self, api_client):
        """404 when report doesn't exist."""
        flaw = NonReportableFlawFactory()
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{fake_uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_report_wrong_flaw_404(self, api_client):
        """404 when report doesn't belong to specified flaw."""
        flaw1 = NonReportableFlawFactory()
        flaw2 = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw2)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw1.uuid}/srp-reports/{report.uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_report_malformed_flaw_id(self, api_client, create_flaw_report):
        """404 when flaw_id path param is not a valid UUID."""
        report = create_flaw_report()
        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{MALFORMED_UUID}/srp-reports/{report.uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestFlawSRPReportReadOnly:
    """Tests that flaw subresource endpoints are read-only."""

    def test_post_not_allowed(self, authenticated_client):
        """POST is not allowed on flaw subresource."""
        flaw = NonReportableFlawFactory()
        data = {"title": "New Report"}

        response = authenticated_client.post(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports", data
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_put_not_allowed(self, authenticated_client, create_flaw_report):
        """PUT is not allowed on flaw subresource."""
        report = create_flaw_report()
        flaw_uuid = report.flaw_id
        data = {"title": "Updated Title"}

        response = authenticated_client.put(
            f"/regulatory-reporting/api/v1/flaws/{flaw_uuid}/srp-reports/{report.uuid}",
            data,
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_patch_not_allowed(self, authenticated_client):
        """PATCH is not allowed on flaw subresource."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        data = {"title": "Updated Title"}

        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report.uuid}",
            data,
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_delete_not_allowed(self, authenticated_client, create_flaw_report):
        """DELETE is not allowed on flaw subresource."""
        report = create_flaw_report()
        flaw_uuid = report.flaw_id
        response = authenticated_client.delete(
            f"/regulatory-reporting/api/v1/flaws/{flaw_uuid}/srp-reports/{report.uuid}"
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestFlawSRPMilestoneList:
    """Tests for GET /regulatory-reporting/api/v1/flaws/{flaw_id}/srp-reports/{report_uuid}/milestones."""

    def test_list_milestones_for_flaw_report(self, api_client, create_flaw_report):
        """Can list milestones for a flaw's report."""
        report = create_flaw_report()
        flaw_uuid = report.flaw_id

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw_uuid}/srp-reports/{report.uuid}/milestones"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 3

    def test_list_milestones_filters_correctly(self, api_client, create_flaw_report):
        """Milestones filtered to correct flaw and report."""
        report1 = create_flaw_report()
        _ = create_flaw_report()
        flaw1_uuid = report1.flaw_id

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw1_uuid}/srp-reports/{report1.uuid}/milestones"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 3
        assert all(
            result["srp_report"] == report1.uuid for result in response.data["results"]
        )

    def test_list_milestones_empty(self, api_client):
        """Empty list when report has no milestones."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report.uuid}/milestones"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 0

    def test_list_milestones_flaw_not_found(self, api_client):
        """404 when flaw doesn't exist."""
        fake_flaw_uuid = "660e8400-e29b-41d4-a716-446655440001"
        fake_report_uuid = "550e8400-e29b-41d4-a716-446655440000"

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{fake_flaw_uuid}/srp-reports/{fake_report_uuid}/milestones"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_milestones_malformed_flaw_id(self, api_client, create_flaw_report):
        """404 when flaw_id path param is not a valid UUID."""
        report = create_flaw_report()
        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{MALFORMED_UUID}/srp-reports/{report.uuid}/milestones"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_milestones_malformed_report_uuid(self, api_client):
        """404 when report_uuid path param is not a valid UUID."""
        flaw = NonReportableFlawFactory()
        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{MALFORMED_UUID}/milestones"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_milestones_report_not_found(self, api_client):
        """404 when report doesn't exist."""
        flaw = NonReportableFlawFactory()
        fake_report_uuid = "550e8400-e29b-41d4-a716-446655440000"

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{fake_report_uuid}/milestones"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_list_milestones_report_wrong_flaw_404(self, api_client):
        """404 when report doesn't belong to specified flaw."""
        flaw1 = NonReportableFlawFactory()
        flaw2 = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw2)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw1.uuid}/srp-reports/{report.uuid}/milestones"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestFlawSRPMilestoneRetrieve:
    """Tests for GET /regulatory-reporting/api/v1/flaws/{flaw_id}/srp-reports/{report_uuid}/milestones/{uuid}."""

    def test_retrieve_milestone_for_flaw_report(self, api_client):
        """Can retrieve specific milestone for a flaw's report."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report.uuid}/milestones/{milestone.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == str(milestone.uuid)

    def test_retrieve_milestone_not_found(self, api_client):
        """404 when milestone doesn't exist."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        fake_uuid = "770e8400-e29b-41d4-a716-446655440002"

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report.uuid}/milestones/{fake_uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_milestone_wrong_report_404(self, api_client):
        """404 when milestone belongs to different report."""
        flaw = NonReportableFlawFactory()
        report1 = SRPReportFactory(flaw=flaw)
        report2 = SRPReportFactory(flaw=flaw)
        milestone = SRPReportMilestoneFactory(srp_report=report2)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report1.uuid}/milestones/{milestone.uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_milestone_malformed_flaw_id(self, api_client):
        """404 when flaw_id path param is not a valid UUID."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{MALFORMED_UUID}/srp-reports/{report.uuid}/milestones/{milestone.uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_milestone_malformed_report_uuid(self, api_client):
        """404 when report_uuid path param is not a valid UUID."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{MALFORMED_UUID}/milestones/{milestone.uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestFlawSRPMilestoneReadOnly:
    """Tests that flaw milestone endpoints are read-only."""

    def test_post_not_allowed(self, authenticated_client):
        """POST is not allowed on flaw milestone subresource."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        data = {"milestone_type": "24H"}

        response = authenticated_client.post(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report.uuid}/milestones",
            data,
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_put_not_allowed(self, authenticated_client):
        """PUT is not allowed on flaw milestone subresource."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        milestone = SRPReportMilestoneFactory(srp_report=report)
        data = {"status": "COMPLETED"}

        response = authenticated_client.put(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report.uuid}/milestones/{milestone.uuid}",
            data,
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_patch_not_allowed(self, authenticated_client):
        """PATCH is not allowed on flaw milestone subresource."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        milestone = SRPReportMilestoneFactory(srp_report=report)
        data = {"status": "COMPLETED"}

        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report.uuid}/milestones/{milestone.uuid}",
            data,
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_delete_not_allowed(self, authenticated_client):
        """DELETE is not allowed on flaw milestone subresource."""
        flaw = NonReportableFlawFactory()
        report = SRPReportFactory(flaw=flaw)
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = authenticated_client.delete(
            f"/regulatory-reporting/api/v1/flaws/{flaw.uuid}/srp-reports/{report.uuid}/milestones/{milestone.uuid}"
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
