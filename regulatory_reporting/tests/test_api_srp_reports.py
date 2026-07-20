"""
Tests for top-level SRP Report API endpoints.

Tests list, retrieve, update operations and filtering.
"""

import pytest
from django.conf import settings
from django.utils import timezone
from freezegun import freeze_time
from rest_framework import status

from regulatory_reporting.models import SRPReport
from regulatory_reporting.tests.factories import (
    NonReportableFlawFactory,
    SRPReportFactory,
)

pytestmark = [
    pytest.mark.unit,
]


@pytest.mark.django_db
class TestSRPReportList:
    """Tests for GET /regulatory-reporting/api/v1/srp-reports (list)."""

    def test_list_reports_unauthenticated(self, api_client, create_flaw_report):
        """Unauthenticated users can list reports."""
        create_flaw_report()
        create_flaw_report()
        create_flaw_report()
        response = api_client.get("/regulatory-reporting/api/v1/srp-reports")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 3

    def test_list_reports_authenticated(self, authenticated_client):
        """Authenticated users can list reports."""
        SRPReportFactory.create_batch(2)
        response = authenticated_client.get("/regulatory-reporting/api/v1/srp-reports")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 2

    def test_list_reports_empty(self, api_client):
        """Empty list when no reports exist."""
        response = api_client.get("/regulatory-reporting/api/v1/srp-reports")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 0

    def test_list_reports_includes_computed_fields(self, api_client):
        """Response includes computed fields."""
        SRPReportFactory()
        response = api_client.get("/regulatory-reporting/api/v1/srp-reports")
        assert response.status_code == status.HTTP_200_OK
        result = response.data["results"][0]
        assert "uuid" in result
        assert "flaw_id" in result
        assert "title" in result
        assert "status" in result
        assert "milestones" in result

    def test_list_reports_includes_nested_milestones(self, api_client):
        """Response includes nested milestones."""
        SRPReportFactory()
        response = api_client.get("/regulatory-reporting/api/v1/srp-reports")
        assert response.status_code == status.HTTP_200_OK
        result = response.data["results"][0]
        assert isinstance(result["milestones"], list)

    def test_retrieve_report(self, api_client):
        """Can retrieve single report by UUID."""
        report = SRPReportFactory()
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == str(report.uuid)
        assert response.data["title"] == report.title

    def test_retrieve_report_not_found(self, api_client):
        """404 when report doesn't exist."""
        fake_uuid = "550e8400-e29b-41d4-a716-446655440000"
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{fake_uuid}"
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_report_includes_all_fields(self, api_client):
        """Response includes all expected fields."""
        report = SRPReportFactory()
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        data = response.data
        assert "uuid" in data
        assert "flaw_id" in data
        assert "title" in data
        assert "manufacturer_or_steward_name" in data
        assert "responsibility_scope" in data
        assert "reportable_event_type" in data
        assert "status" in data
        assert "timer_started_at" in data
        assert "created_dt" in data
        assert "updated_dt" in data
        assert "milestones" in data


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPReportUpdate:
    """Tests for PUT/PATCH /regulatory-reporting/api/v1/srp-reports/{uuid} (update)."""

    def test_update_report_unauthenticated_fails(self, api_client, create_flaw_report):
        """Unauthenticated users cannot update reports."""
        report = create_flaw_report()
        response = api_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}",
            {"status": SRPReport.SRPReportStatus.SUBMITTED},
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_partial_update_report(self, authenticated_client, create_flaw_report):
        """Can partially update report fields."""

        report = create_flaw_report()
        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}",
            {"status": SRPReport.SRPReportStatus.DEFERRED},
        )
        assert response.status_code == status.HTTP_200_OK
        report.refresh_from_db()
        assert report.status == SRPReport.SRPReportStatus.DEFERRED

    def test_update_multiple_fields(self, authenticated_client, create_flaw_report):
        """Can update multiple fields at once."""

        report = create_flaw_report()
        update_data = {
            "status": SRPReport.SRPReportStatus.SUBMITTED,
            "srp_reference_id": "SRP-2026-001",
            "srp_reference_url": "https://enisa.europa.eu/reports/SRP-2026-001",
        }
        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}", update_data
        )
        assert response.status_code == status.HTTP_200_OK
        report.refresh_from_db()
        assert report.status == SRPReport.SRPReportStatus.SUBMITTED
        assert report.srp_reference_id == "SRP-2026-001"
        assert (
            report.srp_reference_url == "https://enisa.europa.eu/reports/SRP-2026-001"
        )

    def test_update_read_only_field_ignored(
        self, authenticated_client, create_flaw_report
    ):
        """Read-only fields are ignored in updates."""

        report = create_flaw_report()
        original_flaw_id = report.flaw_id

        fake_flaw_id = "660e8400-e29b-41d4-a716-446655440001"
        response = authenticated_client.patch(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}",
            {"flaw_id": fake_flaw_id},
        )
        # Should succeed but flaw_id unchanged
        assert response.status_code == status.HTTP_200_OK
        report.refresh_from_db()
        assert report.flaw_id == original_flaw_id

    def test_full_update_report(self, authenticated_client, create_flaw_report):
        """Can perform full update with PUT."""
        report = create_flaw_report()

        report_data = authenticated_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
        ).data

        update_data = {
            "title": "Updated Title",
            "manufacturer_or_steward_name": "Updated Manufacturer",
            "responsibility_scope": SRPReport.ResponsibilityScope.STEWARD,
            "reportable_event_type": report.reportable_event_type,
            "status": SRPReport.SRPReportStatus.SUBMITTED,
            "srp_reference_id": "SRP-2026-001",
            "updated_dt": report.updated_dt,
        }

        report_data.update(update_data)

        response = authenticated_client.put(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}", report_data
        )
        assert response.status_code == status.HTTP_200_OK
        report.refresh_from_db()
        assert report.title == "Updated Title"
        assert report.responsibility_scope == SRPReport.ResponsibilityScope.STEWARD
        assert report.status == SRPReport.SRPReportStatus.SUBMITTED
        assert report.srp_reference_id == "SRP-2026-001"


@pytest.mark.django_db
class TestSRPReportFiltering:
    """Tests for filtering /regulatory-reporting/api/v1/srp-reports."""

    def test_filter_by_status(self, api_client):
        """Can filter reports by status."""

        SRPReportFactory(status=SRPReport.SRPReportStatus.REQUIRED)
        SRPReportFactory(status=SRPReport.SRPReportStatus.PREPARED)
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports?status={SRPReport.SRPReportStatus.REQUIRED}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert (
            response.data["results"][0]["status"] == SRPReport.SRPReportStatus.REQUIRED
        )

    def test_filter_by_reportable_event_type(self, api_client):
        """Can filter by reportable_event_type."""
        SRPReportFactory(
            reportable_event_type=SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
        )
        SRPReportFactory(
            reportable_event_type=SRPReport.ReportableEventType.SEVERE_INCIDENT
        )

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports?reportable_event_type={SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert (
            response.data["results"][0]["reportable_event_type"]
            == SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
        )

    def test_filter_by_flaw_id(self, api_client):
        """Can filter by flaw_id."""
        flaw1 = NonReportableFlawFactory()
        flaw2 = NonReportableFlawFactory()
        report1 = SRPReportFactory(flaw=flaw1)
        report2 = SRPReportFactory(flaw=flaw2)

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports?flaw_id={flaw1.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["flaw_id"] == flaw1.uuid

    def test_filter_by_title(self, api_client):
        """Can filter by title (case-insensitive contains)."""
        SRPReportFactory(title="CVE-2024-1234 Critical Vulnerability")
        SRPReportFactory(title="CVE-2024-5678 Low Severity Issue")

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?title=critical"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert "Critical" in response.data["results"][0]["title"]

    def test_filter_by_created_date_range(self, api_client):
        """Can filter by created_dt range."""
        old_date = timezone.now() - timezone.timedelta(days=10)
        recent_date = timezone.now() - timezone.timedelta(days=2)
        with freeze_time(old_date):
            _ = SRPReportFactory()

        with freeze_time(recent_date):
            recent_report = SRPReportFactory()

        cutoff = timezone.now() - timezone.timedelta(days=5)
        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports",
            {"created_dt__gte": cutoff.isoformat()},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["uuid"] == str(recent_report.uuid)


@pytest.mark.django_db
@pytest.mark.no_cra_reporting
class TestSRPReportAPIDisabled:
    """Tests that SRP reporting endpoints are unavailable when
    CRA_REPORTING_ENABLED is off (see ``cra_reporting_signals`` in conftest)."""

    def test_list_reports_returns_404_when_disabled(self, api_client):
        """/regulatory-reporting/api/v1/srp-reports 404s when CRA_REPORTING_ENABLED is False."""
        response = api_client.get("/regulatory-reporting/api/v1/srp-reports")
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
class TestSRPReportHTTPMethods:
    """Tests for unsupported HTTP methods."""

    def test_post_not_allowed(self, authenticated_client):
        """POST is not allowed (reports auto-created by signals)."""
        data = {"title": "New Report"}
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports", data
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_delete_not_allowed(self, authenticated_client):
        """DELETE is not allowed (reports are permanent)."""
        report = SRPReportFactory()
        response = authenticated_client.delete(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
