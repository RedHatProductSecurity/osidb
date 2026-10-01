"""
Tests for top-level SRP Milestone API endpoints (nested under reports).

Tests list, retrieve, update operations for milestones.
"""

from datetime import timedelta

import pytest
from django.utils import timezone
from freezegun import freeze_time
from rest_framework import status

from apps.regulatory_reporting.models import SRPReportMilestone
from apps.regulatory_reporting.tests.factories import (
    SRPReportFactory,
    SRPReportMilestoneFactory,
)
from osidb.models import Flaw
from osidb.tests.factories import FlawFactory

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

        FlawFactory(
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
        SRPReportMilestoneFactory(srp_report=report)

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
        assert "additional_details" in data
        assert "payload_fields" in data
        assert "missing_required_fields" in data
        assert "created_dt" in data
        assert "updated_dt" in data
        assert "owner" in data
        assert "mitigation_created_at" in data
        assert "mitigation_link" in data
        assert "submitted_at" in data
        assert "due_at" in data
        assert "hours_remaining" in data
        assert "days_remaining" in data
        assert "is_overdue" in data

    def test_retrieve_milestone_includes_payload_field_schema(
        self, api_client, create_flaw_report
    ):
        """Payload fields include order, labels, values, editability, and options."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones/{milestone.uuid}"
        )

        assert response.status_code == status.HTTP_200_OK
        payload_fields = response.data["payload_fields"]
        keys = [field["key"] for field in payload_fields]
        assert keys[:4] == [
            "notification_type",
            "report_title",
            "summary",
            "manufacturer_or_steward_name",
        ]
        assert "product_identity" not in keys

        member_states = next(
            field
            for field in payload_fields
            if field["key"] == "member_states_available"
        )
        assert member_states["input_type"] == "multi_select"
        assert member_states["editable"] is True
        assert "EL" in member_states["options"]

        notification_type = payload_fields[0]
        assert notification_type["label"] == "Notification Type"
        assert notification_type["editable"] is False
        assert notification_type["requirement"] == "required"

    def test_retrieve_payload_fields_inherit_draft_previous_details(
        self, api_client, create_flaw_report
    ):
        """Clients get inherited values without copying previous details forward."""
        report = create_flaw_report()
        m24 = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        m24.additional_details = {"product_type": "firmware"}
        m24.save()
        assert m24.meta_attr.get("payload_snapshot") is None

        m72 = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones/{m72.uuid}"
        )

        assert response.status_code == status.HTTP_200_OK
        product_type = next(
            field
            for field in response.data["payload_fields"]
            if field["key"] == "product_type"
        )
        assert product_type["requirement"] == "copied_or_updated"
        assert product_type["value"] == "firmware"


@pytest.mark.django_db
@pytest.mark.enable_signals
class TestSRPMilestoneUpdate:
    """Tests for PUT /regulatory-reporting/api/v1/srp-reports/{report_uuid}/milestones/{uuid}."""

    def _put_milestone(self, client, report, milestone, **updates):
        """PUT update using current representation as base (PATCH is blacklisted)."""
        url = (
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}"
            f"/milestones/{milestone.uuid}"
        )
        milestone_data = client.get(url).data
        milestone_data.update(updates)
        milestone_data["updated_dt"] = milestone.updated_dt
        return client.put(url, milestone_data, format="json")

    def test_update_milestone_unauthenticated_fails(self, api_client):
        """Unauthenticated users cannot update milestones."""
        report = SRPReportFactory()
        milestone = SRPReportMilestoneFactory(srp_report=report)

        response = api_client.put(
            f"/regulatory-reporting/api/v1/srp-reports/{report.uuid}/milestones/{milestone.uuid}",
            {
                "status": SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW,
                "updated_dt": milestone.updated_dt,
            },
            format="json",
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_update_milestone_status(self, authenticated_client, create_flaw_report):
        """Can update milestone status."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            status=SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW,
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.status == SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW

    def test_update_multiple_fields(self, authenticated_client, create_flaw_report):
        """Can update multiple fields at once."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            status=SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW,
            owner="jdoe",
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.status == SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW
        assert milestone.owner == "jdoe"

    def test_update_read_only_field_ignored(
        self, authenticated_client, create_flaw_report
    ):
        """Read-only fields are ignored in updates."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.milestone_type == SRPReportMilestone.MilestoneType.LEVEL_24H

    def test_update_acl_fields_ignored(self, authenticated_client, create_flaw_report):
        """ACL fields are not mutable via PUT."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        original_acl_read = list(milestone.acl_read)
        original_acl_write = list(milestone.acl_write)

        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            acl_read=["00000000-0000-0000-0000-000000000001"],
            acl_write=["00000000-0000-0000-0000-000000000002"],
            status=SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW,
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert list(milestone.acl_read) == original_acl_read
        assert list(milestone.acl_write) == original_acl_write
        assert milestone.status == SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW

    def test_full_update_milestone(self, authenticated_client, create_flaw_report):
        """Can perform full update with PUT."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            status=SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED,
            owner="jdoe",
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.status == SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        assert milestone.owner == "jdoe"
        assert milestone.meta_attr.get("payload_snapshot")
        assert "prepared_at" in milestone.meta_attr
        assert milestone.submitted_at is not None
        assert response.data["submitted_at"] is not None

    def test_update_owner(self, authenticated_client, create_flaw_report):
        """Can assign a milestone owner."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            owner="analyst@redhat.com",
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.owner == "analyst@redhat.com"
        assert response.data["owner"] == "analyst@redhat.com"

    def test_update_submitted_at_correction(
        self, authenticated_client, create_flaw_report
    ):
        """submitted_at can be corrected after auto-stamp on submit."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )

        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            status=SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED,
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        auto_stamped = milestone.submitted_at
        assert auto_stamped is not None

        correction = (auto_stamped - timedelta(hours=2)).replace(microsecond=0)
        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            submitted_at=correction.isoformat(),
        )
        assert response.status_code == status.HTTP_200_OK
        milestone.refresh_from_db()
        assert milestone.submitted_at == correction

    def test_update_manual_completion_notes(
        self, authenticated_client, create_flaw_report
    ):
        """Can update manual_completion_notes and value is returned in response."""
        milestones_report = create_flaw_report()
        milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        response = self._put_milestone(
            authenticated_client,
            milestones_report,
            milestone,
            manual_completion_notes="some notes",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["manual_completion_notes"] == "some notes"
        milestone.refresh_from_db()
        assert milestone.manual_completion_notes == "some notes"

    def test_update_aev_final_mitigation_fields_sets_due_at(
        self, authenticated_client, create_flaw_report
    ):
        """AEV final due date is 14 days after mitigation availability."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        mitigation_created_at = timezone.now().replace(microsecond=0)

        response = self._put_milestone(
            authenticated_client,
            report,
            milestone,
            mitigation_created_at=mitigation_created_at.isoformat(),
            mitigation_link="https://access.redhat.com/security/updates/example",
        )

        assert response.status_code == status.HTTP_200_OK, response.data
        milestone.refresh_from_db()
        assert milestone.mitigation_created_at == mitigation_created_at
        assert (
            milestone.mitigation_link
            == "https://access.redhat.com/security/updates/example"
        )
        assert milestone.due_at == mitigation_created_at + timedelta(days=14)
        payload_by_key = {
            field["key"]: field for field in response.data["payload_fields"]
        }
        assert (
            payload_by_key["corrective_or_mitigating_measure_available_at"]["value"]
            == mitigation_created_at.isoformat()
        )
        assert (
            payload_by_key["security_update_or_corrective_measure_details"]["value"]
            == "https://access.redhat.com/security/updates/example"
        )

    def test_update_aev_72h_mitigation_fields_sets_final_due_at(
        self, authenticated_client, create_flaw_report
    ):
        """AEV 72h mitigation availability updates the final due date."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        final = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        mitigation_created_at = timezone.now().replace(microsecond=0)

        response = self._put_milestone(
            authenticated_client,
            report,
            milestone,
            mitigation_created_at=mitigation_created_at.isoformat(),
            mitigation_link="https://access.redhat.com/security/updates/example",
        )

        assert response.status_code == status.HTTP_200_OK, response.data
        milestone.refresh_from_db()
        final.refresh_from_db()
        assert milestone.mitigation_created_at == mitigation_created_at
        assert final.mitigation_created_at == mitigation_created_at
        assert (
            final.mitigation_link
            == "https://access.redhat.com/security/updates/example"
        )
        assert final.due_at == mitigation_created_at + timedelta(days=14)

    def test_update_aev_72h_mitigation_fields_overwrites_final_values(
        self, authenticated_client, create_flaw_report
    ):
        """AEV final reuses the 72h mitigation date/link, not separate values."""
        report = create_flaw_report()
        milestone = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        final = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        old_mitigation_created_at = timezone.now().replace(microsecond=0)
        mitigation_created_at = old_mitigation_created_at + timedelta(days=7)
        final.mitigation_created_at = old_mitigation_created_at
        final.mitigation_link = "https://access.redhat.com/security/updates/old"
        final.due_at = old_mitigation_created_at + timedelta(days=14)
        final.save()

        response = self._put_milestone(
            authenticated_client,
            report,
            milestone,
            mitigation_created_at=mitigation_created_at.isoformat(),
            mitigation_link="https://access.redhat.com/security/updates/new",
        )

        assert response.status_code == status.HTTP_200_OK, response.data
        final.refresh_from_db()
        assert final.mitigation_created_at == mitigation_created_at
        assert final.mitigation_link == "https://access.redhat.com/security/updates/new"
        assert final.due_at == mitigation_created_at + timedelta(days=14)

    def test_update_aev_final_preserves_manual_due_at_when_mitigation_unchanged(
        self, authenticated_client, create_flaw_report
    ):
        """Full PUT should not recalculate final due_at for unchanged mitigation."""
        report = create_flaw_report()
        final = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        mitigation_created_at = timezone.now().replace(microsecond=0)
        manual_due_at = mitigation_created_at + timedelta(days=20)
        final.mitigation_created_at = mitigation_created_at
        final.due_at = manual_due_at
        final.save()

        response = self._put_milestone(
            authenticated_client,
            report,
            final,
            owner="analyst@example.com",
        )

        assert response.status_code == status.HTTP_200_OK, response.data
        final.refresh_from_db()
        assert final.mitigation_created_at == mitigation_created_at
        assert final.due_at == manual_due_at

    def test_update_aev_72h_preserves_final_manual_due_at_when_mitigation_unchanged(
        self, authenticated_client, create_flaw_report
    ):
        """Full PUT of 72h should not recalculate final due_at for unchanged mitigation."""
        report = create_flaw_report()
        m72 = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        final = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        mitigation_created_at = timezone.now().replace(microsecond=0)
        manual_due_at = mitigation_created_at + timedelta(days=20)
        m72.mitigation_created_at = mitigation_created_at
        m72.mitigation_link = "https://access.redhat.com/security/updates/old"
        m72.save()
        final.mitigation_created_at = mitigation_created_at
        final.mitigation_link = "https://access.redhat.com/security/updates/old"
        final.due_at = manual_due_at
        final.save()

        response = self._put_milestone(
            authenticated_client,
            report,
            m72,
            mitigation_link="https://access.redhat.com/security/updates/new",
        )

        assert response.status_code == status.HTTP_200_OK, response.data
        final.refresh_from_db()
        assert final.mitigation_created_at == mitigation_created_at
        assert final.mitigation_link == "https://access.redhat.com/security/updates/new"
        assert final.due_at == manual_due_at

    def test_update_aev_72h_unchanged_mitigation_link_does_not_save_final(
        self, authenticated_client, create_flaw_report
    ):
        """Full PUT of 72h avoids saving final when mitigation values are unchanged."""
        report = create_flaw_report()
        m72 = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        final = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        mitigation_created_at = timezone.now().replace(microsecond=0)
        mitigation_link = "https://access.redhat.com/security/updates/example"
        m72.mitigation_created_at = mitigation_created_at
        m72.mitigation_link = mitigation_link
        m72.save()
        final.mitigation_created_at = mitigation_created_at
        final.mitigation_link = mitigation_link
        final.due_at = mitigation_created_at + timedelta(days=14)
        final.save()
        final_updated_dt = final.updated_dt

        response = self._put_milestone(
            authenticated_client,
            report,
            m72,
            owner="analyst@example.com",
        )

        assert response.status_code == status.HTTP_200_OK, response.data
        final.refresh_from_db()
        assert final.updated_dt == final_updated_dt
        assert final.mitigation_created_at == mitigation_created_at
        assert final.mitigation_link == mitigation_link
        assert final.due_at == mitigation_created_at + timedelta(days=14)

    def test_si_final_due_at_starts_when_72h_submitted(
        self, authenticated_client, create_flaw_report
    ):
        """SI final due date starts 30 days after the 72h report is submitted."""
        report = create_flaw_report(
            incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        )
        m72 = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        final = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        submitted_at = timezone.now().replace(microsecond=0)

        response = self._put_milestone(
            authenticated_client,
            report,
            m72,
            status=SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED,
            submitted_at=submitted_at.isoformat(),
        )

        assert response.status_code == status.HTTP_200_OK, response.data
        final.refresh_from_db()
        assert final.due_at == submitted_at + timedelta(days=30)

    def test_si_final_due_at_correction_updates_legacy_timer_default(
        self, authenticated_client, create_flaw_report
    ):
        """Submitted-at corrections update final due_at when it still has timer default."""
        report = create_flaw_report(
            incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        )
        m72 = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        final = report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        initial_submitted_at = report.timer_started_at + timedelta(days=4)
        corrected_submitted_at = initial_submitted_at + timedelta(days=1)
        SRPReportMilestone.objects.filter(pk=m72.pk).update(
            status=SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED,
            submitted_at=initial_submitted_at,
        )
        m72.refresh_from_db()
        final.refresh_from_db()
        assert final.due_at == report.timer_started_at + timedelta(days=30)

        response = self._put_milestone(
            authenticated_client,
            report,
            m72,
            submitted_at=corrected_submitted_at.isoformat(),
        )

        assert response.status_code == status.HTTP_200_OK, response.data
        final.refresh_from_db()
        assert final.due_at == corrected_submitted_at + timedelta(days=30)


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
        first_milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        first_milestone.save()

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones?status=submitted"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert (
            response.data["results"][0]["status"]
            == SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
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

    def test_filter_by_owner(self, api_client, create_flaw_report):
        """Can filter milestones by owner."""
        milestones_report = create_flaw_report()
        owned = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        owned.owner = "analyst@redhat.com"
        owned.save()

        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones?owner=analyst@redhat.com"
        )
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["owner"] == "analyst@redhat.com"

    def test_filter_by_created_date_range(self, api_client, create_flaw_report):
        """Can filter milestones by created_dt range."""
        old_date = timezone.now() - timedelta(days=10)
        recent_date = timezone.now() - timedelta(days=2)

        with freeze_time(old_date):
            milestones_report = create_flaw_report()

        recent_milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        SRPReportMilestone.objects.filter(pk=recent_milestone.pk).update(
            created_dt=recent_date
        )
        recent_milestone.refresh_from_db()

        cutoff = timezone.now() - timedelta(days=5)
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones",
            {"created_dt__gte": cutoff.isoformat()},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["uuid"] == str(recent_milestone.uuid)

    def test_filter_by_submitted_at_range(self, api_client, create_flaw_report):
        """Can filter milestones by submitted_at range."""
        milestones_report = create_flaw_report()
        old_milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        recent_milestone = milestones_report.milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )

        old_date = timezone.now() - timedelta(days=10)
        recent_date = timezone.now() - timedelta(days=2)
        with freeze_time(old_date):
            old_milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
            old_milestone.save()
        with freeze_time(recent_date):
            recent_milestone.status = (
                SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
            )
            recent_milestone.save()

        cutoff = timezone.now() - timedelta(days=5)
        response = api_client.get(
            f"/regulatory-reporting/api/v1/srp-reports/{milestones_report.uuid}/milestones",
            {"submitted_at__gte": cutoff.isoformat()},
        )

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["results"]) == 1
        assert response.data["results"][0]["uuid"] == str(recent_milestone.uuid)


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
