"""
Tests for top-level SRP Report API endpoints.

Tests list, retrieve, create, update operations and filtering.
"""

from datetime import datetime
from datetime import timezone as dt_timezone

import pytest
from django.utils import timezone
from freezegun import freeze_time
from rest_framework import status

from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.tests.factories import (
    NonReportableFlawFactory,
    SRPReportFactory,
    SRPReportMilestoneFactory,
    SRPReportWithMilestonesFactory,
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
        assert "evidence" in data
        assert "created_dt" in data
        assert "updated_dt" in data
        assert "milestones" in data


@pytest.mark.django_db
class TestSRPReportCreate:
    """Tests for POST /regulatory-reporting/api/v1/srp-reports (manual create)."""

    @staticmethod
    def _create_payload(flaw, **overrides):
        data = {
            "flaw_id": str(flaw.uuid),
            "reportable_event_type": SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            "evidence": "Operator decided to report despite no MI approval.",
            "srp_reference_id": "SRP-2026-001",
            "srp_reference_url": "https://enisa.europa.eu/reports/SRP-2026-001",
        }
        data.update(overrides)
        return data

    def test_create_report_unauthenticated_fails(self, api_client):
        """Unauthenticated users cannot create reports."""
        flaw = NonReportableFlawFactory()
        response = api_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw),
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_create_report_without_flaw_write_acl_fails(
        self, api_client, django_user_model
    ):
        """Authenticated users without flaw write ACL cannot create reports."""
        user = django_user_model.objects.create_user(username="readonly-user")
        api_client.force_authenticate(user=user)
        flaw = NonReportableFlawFactory()
        response = api_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw),
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "flaw_id" in response.data

    def test_create_report_without_critter_criteria(self, authenticated_client):
        """Can manually create a report when Critter criteria are not met."""
        flaw = NonReportableFlawFactory(title="Manual ENISA report flaw")
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw),
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED, response.data
        assert response.data["status"] == (
            f"{SRPReport.MilestoneType.LEVEL_24H}:"
            f"{SRPReport.SRPReportStatus.PRE_REQUIRED}"
        )
        assert response.data["flaw_id"] == flaw.uuid
        assert (
            response.data["evidence"]
            == "Operator decided to report despite no MI approval."
        )
        assert response.data["srp_reference_id"] == "SRP-2026-001"
        assert (
            response.data["srp_reference_url"]
            == "https://enisa.europa.eu/reports/SRP-2026-001"
        )
        assert response.data["title"] == "Manual ENISA report flaw"
        assert (
            response.data["responsibility_scope"]
            == SRPReport.ResponsibilityScope.MANUFACTURER
        )
        assert response.data["timer_started_at"] is None

        report = SRPReport.objects.get(uuid=response.data["uuid"])
        assert report.acl_read == flaw.acl_read
        assert report.acl_write == flaw.acl_write

        milestones = list(report.milestones.order_by("milestone_type"))
        assert len(milestones) == 3
        assert {m.milestone_type for m in milestones} == {
            SRPReportMilestone.MilestoneType.LEVEL_24H,
            SRPReportMilestone.MilestoneType.LEVEL_72H,
            SRPReportMilestone.MilestoneType.LEVEL_FINAL,
        }
        assert all(
            m.status == SRPReport.SRPReportStatus.PRE_REQUIRED for m in milestones
        )
        assert len(response.data["milestones"]) == 3

    def test_create_additional_information_request_creates_only_air_milestone(
        self, authenticated_client
    ):
        """ADDITIONAL_INFORMATION_REQUEST reports get only an AIR milestone."""
        flaw = NonReportableFlawFactory()
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(
                flaw,
                reportable_event_type=(
                    SRPReport.ReportableEventType.ADDITIONAL_INFORMATION_REQUEST
                ),
            ),
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED, response.data
        assert response.data["status"] == (
            f"{SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE}:"
            f"{SRPReport.SRPReportStatus.PRE_REQUIRED}"
        )
        assert (
            response.data["reportable_event_type"]
            == SRPReport.ReportableEventType.ADDITIONAL_INFORMATION_REQUEST
        )

        report = SRPReport.objects.get(uuid=response.data["uuid"])
        milestones = list(report.milestones.all())
        assert len(milestones) == 1
        assert (
            milestones[0].milestone_type
            == SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        )
        assert milestones[0].status == SRPReport.SRPReportStatus.PRE_REQUIRED
        assert len(response.data["milestones"]) == 1

    def test_create_report_defaults_long_flaw_title(self, authenticated_client):
        """Default title accepts Flaw.title longer than former CharField(255)."""
        long_title = "A" * 300
        flaw = NonReportableFlawFactory(title=long_title)
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw),
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED, response.data
        assert response.data["title"] == long_title

    def test_create_report_ignores_timer_started_at(self, authenticated_client):
        """timer_started_at is read-only on create and stays null for PRE_REQUIRED."""
        flaw = NonReportableFlawFactory()
        backdated = timezone.now() - timezone.timedelta(days=3)
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw, timer_started_at=backdated.isoformat()),
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED, response.data
        assert response.data["timer_started_at"] is None
        report = SRPReport.objects.get(uuid=response.data["uuid"])
        assert report.timer_started_at is None

    def test_create_report_missing_evidence_fails(self, authenticated_client):
        """evidence is required for manual create."""
        flaw = NonReportableFlawFactory()
        payload = self._create_payload(
            flaw,
            reportable_event_type=(SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED),
        )
        del payload["evidence"]
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            payload,
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "evidence" in response.data

    def test_create_report_blank_evidence_fails(self, authenticated_client):
        """Blank evidence is rejected."""
        flaw = NonReportableFlawFactory()
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw, evidence="   "),
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "evidence" in response.data

    def test_create_report_missing_srp_reference_fields_fails(
        self, authenticated_client
    ):
        """srp_reference_id and srp_reference_url are required for manual create."""
        flaw = NonReportableFlawFactory()
        payload = self._create_payload(flaw)
        del payload["srp_reference_id"]
        del payload["srp_reference_url"]
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            payload,
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "srp_reference_id" in response.data
        assert "srp_reference_url" in response.data

    def test_create_report_blank_srp_reference_id_fails(self, authenticated_client):
        """Blank srp_reference_id is rejected."""
        flaw = NonReportableFlawFactory()
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw, srp_reference_id="   "),
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "srp_reference_id" in response.data

    def test_create_report_blank_srp_reference_url_fails(self, authenticated_client):
        """Blank srp_reference_url is rejected."""
        flaw = NonReportableFlawFactory()
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw, srp_reference_url="   "),
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "srp_reference_url" in response.data

    def test_create_report_srp_reference_url_too_long_fails(self, authenticated_client):
        """srp_reference_url longer than 200 characters is rejected."""
        flaw = NonReportableFlawFactory()
        long_url = "https://enisa.europa.eu/" + ("a" * 200)
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw, srp_reference_url=long_url),
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "srp_reference_url" in response.data

    def test_create_report_duplicate_event_type_fails(self, authenticated_client):
        """Duplicate (flaw, reportable_event_type) is rejected."""
        flaw = NonReportableFlawFactory()
        SRPReportFactory(
            flaw=flaw,
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
        )
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(flaw, evidence="Second attempt."),
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "reportable_event_type" in response.data

    def test_create_report_allows_second_event_type(self, authenticated_client):
        """Same flaw can have a second report with a different event type."""
        flaw = NonReportableFlawFactory()
        SRPReportFactory(
            flaw=flaw,
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
        )
        response = authenticated_client.post(
            "/regulatory-reporting/api/v1/srp-reports",
            self._create_payload(
                flaw,
                reportable_event_type=(
                    SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED
                ),
                evidence="Also reporting as KEV.",
                srp_reference_id="SRP-2026-002",
                srp_reference_url="https://enisa.europa.eu/reports/SRP-2026-002",
            ),
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert (
            response.data["reportable_event_type"]
            == SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED
        )


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPReportUpdate:
    """Tests for PUT /regulatory-reporting/api/v1/srp-reports/{uuid} (update)."""

    def _put_report(self, client, report, **updates):
        """PUT update using current representation as base (PATCH is blacklisted)."""
        report_data = client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
        ).data
        report_data.update(updates)
        report_data["updated_dt"] = report.updated_dt
        return client.put(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}",
            report_data,
            format="json",
        )

    def test_update_report_unauthenticated_fails(self, api_client, create_flaw_report):
        """Unauthenticated users cannot update reports."""
        report = create_flaw_report()
        response = api_client.put(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}",
            {
                "status": SRPReport.SRPReportStatus.SUBMITTED,
                "updated_dt": report.updated_dt,
            },
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_multiple_fields(self, authenticated_client, create_flaw_report):
        """Can update multiple fields at once."""
        report = create_flaw_report()
        response = self._put_report(
            authenticated_client,
            report,
            srp_reference_id="SRP-2026-001",
            srp_reference_url="https://enisa.europa.eu/reports/SRP-2026-001",
        )
        assert response.status_code == status.HTTP_200_OK
        report.refresh_from_db()
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
        response = self._put_report(
            authenticated_client,
            report,
            flaw_id=fake_flaw_id,
        )
        assert response.status_code == status.HTTP_200_OK
        report.refresh_from_db()
        assert report.flaw_id == original_flaw_id

    def test_full_update_report(self, authenticated_client, create_flaw_report):
        """Can perform full update with PUT."""
        report = create_flaw_report()
        response = self._put_report(
            authenticated_client,
            report,
            title="Updated Title",
            manufacturer_or_steward_name="Updated Manufacturer",
            responsibility_scope=SRPReport.ResponsibilityScope.STEWARD,
            reportable_event_type=report.reportable_event_type,
            srp_reference_id="SRP-2026-001",
        )
        assert response.status_code == status.HTTP_200_OK
        report.refresh_from_db()
        assert report.title == "Updated Title"
        assert report.responsibility_scope == SRPReport.ResponsibilityScope.STEWARD
        assert report.srp_reference_id == "SRP-2026-001"


@pytest.mark.django_db
class TestSRPReportFiltering:
    """Tests for filtering /regulatory-reporting/api/v1/srp-reports."""

    def test_filter_by_status(self, api_client):
        """Can filter reports by derived composite status."""
        report_24h_required = SRPReportWithMilestonesFactory()
        # Defaults leave 24h as REQUIRED → status "24h:required"

        report_72h_prepared = SRPReportWithMilestonesFactory()
        m24 = report_72h_prepared.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        m72 = report_72h_prepared.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        m24.status = SRPReport.SRPReportStatus.SUBMITTED
        m24.save()
        m72.status = SRPReport.SRPReportStatus.PREPARED
        m72.save()

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?status=24h:required"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["uuid"] == str(report_24h_required.uuid)
        assert response.data["results"][0]["status"] == "24h:required"

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?status=72h:prepared"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["uuid"] == str(report_72h_prepared.uuid)
        assert response.data["results"][0]["status"] == "72h:prepared"

    def test_filter_by_status_fallback_when_all_closed(self, api_client):
        """Composite status filter matches furthest closed milestone."""
        report_all_submitted = SRPReportWithMilestonesFactory()
        for milestone in report_all_submitted.milestones.all():
            milestone.status = SRPReport.SRPReportStatus.SUBMITTED
            milestone.save()

        report_still_active = SRPReportWithMilestonesFactory()

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?status=final:submitted"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["uuid"] == str(report_all_submitted.uuid)
        assert response.data["results"][0]["status"] == "final:submitted"

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?status=24h:required"
        )
        assert response.status_code == status.HTTP_200_OK
        result_uuids = {r["uuid"] for r in response.data["results"]}
        assert str(report_still_active.uuid) in result_uuids
        assert str(report_all_submitted.uuid) not in result_uuids

    def test_filter_by_status_fallback_additional_equal_request_time(self, api_client):
        """Equal request_received_at: newer created_dt wins; filter matches status."""
        request_at = datetime(2026, 1, 1, 10, 0, 0, tzinfo=dt_timezone.utc)
        report = SRPReportFactory()
        additional = (
            SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        )

        with freeze_time("2026-01-01 12:00:00"):
            SRPReportMilestoneFactory(
                srp_report=report,
                milestone_type=additional,
                status=SRPReport.SRPReportStatus.SUBMITTED,
                request_received_at=request_at,
            )
        with freeze_time("2026-01-01 12:00:01"):
            SRPReportMilestoneFactory(
                srp_report=report,
                milestone_type=additional,
                status=SRPReport.SRPReportStatus.DEFERRED,
                request_received_at=request_at,
            )

        expected = f"{additional}:{SRPReport.SRPReportStatus.DEFERRED}"
        report = SRPReport.objects.get(pk=report.pk)
        assert report.status == expected

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports?status={expected}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["uuid"] == str(report.uuid)
        assert response.data["results"][0]["status"] == expected

        older_status = f"{additional}:{SRPReport.SRPReportStatus.SUBMITTED}"
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports?status={older_status}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert str(report.uuid) not in {r["uuid"] for r in response.data["results"]}

    def test_filter_by_last_active_status(self, api_client):
        """last_active_status matches derived milestone status, any type."""
        report_required = SRPReportWithMilestonesFactory()

        report_prepared = SRPReportWithMilestonesFactory()
        m24 = report_prepared.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        m72 = report_prepared.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        m24.status = SRPReport.SRPReportStatus.SUBMITTED
        m24.save()
        m72.status = SRPReport.SRPReportStatus.PREPARED
        m72.save()

        report_submitted = SRPReportWithMilestonesFactory()
        for milestone in report_submitted.milestones.all():
            milestone.status = SRPReport.SRPReportStatus.SUBMITTED
            milestone.save()

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?last_active_status=required"
        )
        assert response.status_code == status.HTTP_200_OK
        result_uuids = {r["uuid"] for r in response.data["results"]}
        assert str(report_required.uuid) in result_uuids
        assert str(report_prepared.uuid) not in result_uuids
        assert str(report_submitted.uuid) not in result_uuids

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?last_active_status=prepared"
        )
        assert response.status_code == status.HTTP_200_OK
        result_uuids = {r["uuid"] for r in response.data["results"]}
        assert str(report_prepared.uuid) in result_uuids
        assert str(report_required.uuid) not in result_uuids

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?last_active_status=submitted"
        )
        assert response.status_code == status.HTTP_200_OK
        result_uuids = {r["uuid"] for r in response.data["results"]}
        assert str(report_submitted.uuid) in result_uuids
        assert str(report_required.uuid) not in result_uuids
        assert str(report_prepared.uuid) not in result_uuids

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?last_active_status=not_a_status"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 0

    def test_filter_by_milestone_status(self, api_client):
        """Can filter reports that have any milestone in the given status."""
        report_with_submitted = SRPReportWithMilestonesFactory()
        m24 = report_with_submitted.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        m24.status = SRPReport.SRPReportStatus.SUBMITTED
        m24.save()

        report_all_required = SRPReportWithMilestonesFactory()
        # Defaults leave milestones as REQUIRED

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?milestone_status=submitted"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["uuid"] == str(report_with_submitted.uuid)

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?milestone_status=required"
        )
        assert response.status_code == status.HTTP_200_OK
        result_uuids = {r["uuid"] for r in response.data["results"]}
        assert str(report_all_required.uuid) in result_uuids
        # report_with_submitted still has other REQUIRED milestones (72h/final)
        assert str(report_with_submitted.uuid) in result_uuids

        response = api_client.get(
            "/regulatory-reporting/api/v1/srp-reports?milestone_status=not_a_status"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 0

    def test_filter_by_reportable_event_type(self, api_client):
        """Can filter by reportable_event_type."""
        SRPReportFactory(
            reportable_event_type=SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED
        )
        SRPReportFactory(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports?reportable_event_type={SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert (
            response.data["results"][0]["reportable_event_type"]
            == SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED
        )

    def test_filter_by_flaw_id(self, api_client):
        """Can filter by flaw_id."""
        flaw1 = NonReportableFlawFactory()
        flaw2 = NonReportableFlawFactory()
        SRPReportFactory(flaw=flaw1)
        SRPReportFactory(flaw=flaw2)

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

    def test_delete_not_allowed(self, authenticated_client):
        """DELETE is not allowed (reports are permanent)."""
        report = SRPReportFactory()
        response = authenticated_client.delete(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
