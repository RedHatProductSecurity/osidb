"""
Tests for automatic SRP Milestone creation when SRP Report is created.

These tests verify that when an SRP Report is created (via OSIDB-5067),
the appropriate milestones (24h, 72h, final) are automatically created
with correct due dates based on the event type.

OSIDB-5068: Trigger SRP Milestone Creation on Reportability Change
"""

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.models.abstracts import SRPReportBase
from regulatory_reporting.services import (
    create_srp_report,
    create_srp_report_milestones,
)
from regulatory_reporting.tests.factories import SRPReportFactory

pytestmark = [pytest.mark.unit, pytest.mark.enable_signals, pytest.mark.cra_reporting]


class TestSRPMilestoneAutoCreation:
    """Test automatic SRP Milestone creation when SRP Report is created"""

    def test_milestones_created_for_kev_report(self, create_flaw_report):
        """
        When SRP Report is created for KEV, create 24h, 72h, and final milestones
        with correct due dates (14 days for final).
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-1234",
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        )
        assert (
            srp_report.reportable_event_type
            == SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED
        )

        # Exactly 3 milestones created
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)
        assert milestones.count() == 3, (
            "Should create exactly 3 milestones (24h, 72h, final)"
        )

        # All expected milestone types present
        milestone_types = {m.milestone_type for m in milestones}
        assert SRPReportMilestone.MilestoneType.LEVEL_24H in milestone_types
        assert SRPReportMilestone.MilestoneType.LEVEL_72H in milestone_types
        assert SRPReportMilestone.MilestoneType.LEVEL_FINAL in milestone_types

        # Additional information response NOT created
        assert (
            SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
            not in milestone_types
        )

    def test_milestones_created_for_severe_incident_report(self, create_flaw_report):
        """
        When SRP Report is created for Severe Incident, create 24h, 72h, and final milestones.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-5678",
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Assert - SRP Report was created
        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        )
        assert (
            srp_report.reportable_event_type
            == SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )

        # Assert - Exactly 3 milestones created
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)
        assert milestones.count() == 3, "Should create exactly 3 milestones"

        # Assert - Correct milestone types
        milestone_types = {m.milestone_type for m in milestones}
        assert SRPReportMilestone.MilestoneType.LEVEL_24H in milestone_types
        assert SRPReportMilestone.MilestoneType.LEVEL_72H in milestone_types
        assert SRPReportMilestone.MilestoneType.LEVEL_FINAL in milestone_types

    def test_milestone_due_dates_for_kev(self, create_flaw_report):
        """
        Verify correct due dates for KEV milestones:
        - 24h milestone: start_time + 24 hours
        - 72h milestone: start_time + 72 hours
        - Final milestone: start_time + 14 days
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Assert
        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        )
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)

        # Check 24h milestone
        milestone_24h = milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        expected_24h = start_time + timedelta(hours=24)
        assert milestone_24h.due_at == expected_24h, (
            "24h milestone should be due 24 hours after start"
        )

        # Check 72h milestone
        milestone_72h = milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        expected_72h = start_time + timedelta(hours=72)
        assert milestone_72h.due_at == expected_72h, (
            "72h milestone should be due 72 hours after start"
        )

        # Check final milestone - 14 days for KEV
        milestone_final = milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        expected_final = start_time + timedelta(days=14)
        assert milestone_final.due_at == expected_final, (
            "Final milestone for KEV should be due 14 days after start"
        )

    def test_milestone_due_dates_for_severe_incident(self, create_flaw_report):
        """
        Verify correct due dates for Severe Incident milestones:
        - 24h milestone: start_time + 24 hours
        - 72h milestone: start_time + 72 hours
        - Final milestone: start_time + 30 days (1 month)
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Assert
        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        )
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)

        # Check 24h milestone
        milestone_24h = milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H
        )
        expected_24h = start_time + timedelta(hours=24)
        assert milestone_24h.due_at == expected_24h

        # Check 72h milestone
        milestone_72h = milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H
        )
        expected_72h = start_time + timedelta(hours=72)
        assert milestone_72h.due_at == expected_72h

        # Check final milestone - 30 days for Severe Incident
        milestone_final = milestones.get(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL
        )
        expected_final = start_time + timedelta(days=30)
        assert milestone_final.due_at == expected_final, (
            "Final milestone for Severe Incident should be due 30 days after start"
        )

    def test_milestones_inherit_acl_from_srp_report(self, create_flaw_report):
        """
        All milestones should inherit ACL permissions from their parent SRP Report.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Assert
        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        )
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)

        for milestone in milestones:
            assert milestone.acl_read == srp_report.acl_read, (
                f"{milestone.milestone_type} should inherit acl_read"
            )
            assert milestone.acl_write == srp_report.acl_write, (
                f"{milestone.milestone_type} should inherit acl_write"
            )

    def test_milestone_status_defaults_to_required(self, create_flaw_report):
        """
        All auto-created milestones should have status = REQUIRED by default.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        )
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)

        for milestone in milestones:
            assert milestone.status == SRPReportBase.SRPReportStatus.REQUIRED, (
                f"{milestone.milestone_type} should have REQUIRED status"
            )

    def test_additional_information_response_not_auto_created(self, create_flaw_report):
        """
        For KEV / severe-incident reports, LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        should NOT be created automatically with the standard 24h/72h/final set.
        Extra AIR milestones are created on-demand when authorities send follow-ups.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        )

        # Should have no additional_information_response milestones
        additional_info_milestones = SRPReportMilestone.objects.filter(
            srp_report=srp_report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
        )
        assert additional_info_milestones.count() == 0, (
            "Additional information response milestones should NOT be auto-created"
        )

    @pytest.mark.parametrize(
        "milestone_type",
        [
            SRPReportMilestone.MilestoneType.LEVEL_24H,
            SRPReportMilestone.MilestoneType.LEVEL_72H,
            SRPReportMilestone.MilestoneType.LEVEL_FINAL,
        ],
    )
    def test_milestone_uniqueness_constraint(self, milestone_type, create_flaw_report):
        """
        Each SRP Report should only have ONE milestone of each type (24h, 72h, final).
        The uniqueness constraint should prevent duplicates.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        )

        assert (
            SRPReportMilestone.objects.filter(
                srp_report=srp_report,
                milestone_type=milestone_type,
            ).count()
            == 1
        )
        with pytest.raises(
            ValidationError, match="unique_srp_report_milestone_type_level"
        ):
            SRPReportMilestone.objects.create(
                srp_report=srp_report,
                milestone_type=milestone_type,
                status=SRPReportBase.SRPReportStatus.REQUIRED,
                acl_read=srp_report.acl_read,
                acl_write=srp_report.acl_write,
            )

    def test_milestone_relationships_to_srp_report(self, create_flaw_report):
        """
        Verify the relationship between milestones and their parent SRP Report works correctly.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        )

        # Test forward relationship (milestones -> report)
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)
        for milestone in milestones:
            assert milestone.srp_report == srp_report

        # Test reverse relationship (report -> milestones)
        assert srp_report.milestones.count() == 3
        milestone_types_via_reverse = {
            m.milestone_type for m in srp_report.milestones.all()
        }
        assert SRPReportMilestone.MilestoneType.LEVEL_24H in milestone_types_via_reverse
        assert SRPReportMilestone.MilestoneType.LEVEL_72H in milestone_types_via_reverse
        assert (
            SRPReportMilestone.MilestoneType.LEVEL_FINAL in milestone_types_via_reverse
        )

    def test_milestones_not_created_when_cra_reporting_is_disabled(self):
        """
        Milestones should not be created when CRA reporting is disabled.
        """
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        assert SRPReport.objects.filter(flaw=flaw).count() == 0, (
            "No SRP Report should be created"
        )
        assert SRPReportMilestone.objects.filter(srp_report__flaw=flaw).count() == 0, (
            "No milestones should be created"
        )


class TestMilestoneDueDateProperty:
    """Test the due_at property calculation for different milestone types"""

    def test_due_at_calculation_uses_timer_started_at(self, create_flaw_report):
        srp_report = create_flaw_report()
        assert srp_report.timer_started_at == srp_report.flaw.major_incident_start_dt

        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)
        for milestone in milestones:
            # All due dates should be calculated from the same start time
            assert milestone.due_at > srp_report.flaw.major_incident_start_dt, (
                f"{milestone.milestone_type} due_at should be after start time"
            )

    def test_milestone_string_representation(self, create_flaw_report):
        srp_report = create_flaw_report()
        milestone_24h = SRPReportMilestone.objects.get(
            srp_report=srp_report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H,
        )

        milestone_str = str(milestone_24h)
        assert "24h" in milestone_str
        assert srp_report.flaw.cve_id in milestone_str

    def test_additional_information_response_due_at_uses_request_received_at(
        self, create_flaw_report
    ):
        """
        LEVEL_ADDITIONAL_INFORMATION_RESPONSE milestones should calculate due_at
        from request_received_at (not timer_started_at) and use 30 days duration.
        """
        srp_report = create_flaw_report()

        # Act - manually create additional information response milestone
        request_time = timezone.now() + timedelta(
            days=5
        )  # Request comes 5 days after report
        additional_info_milestone = SRPReportMilestone.objects.create(
            srp_report=srp_report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
            status=SRPReport.SRPReportStatus.REQUIRED,
            request_received_at=request_time,
            request_source="ENISA",
            request_text="Please provide additional technical details",
            acl_read=srp_report.acl_read,
            acl_write=srp_report.acl_write,
        )

        # Assert - due_at should be 30 days from request_received_at
        expected_due_at = request_time + timedelta(days=30)
        assert additional_info_milestone.due_at == expected_due_at, (
            "Additional info milestone should be due 30 days from request_received_at"
        )

        # Verify it's NOT calculated from timer_started_at
        wrong_due_at = srp_report.flaw.major_incident_start_dt + timedelta(days=30)
        assert additional_info_milestone.due_at != wrong_due_at, (
            "Should NOT use timer_started_at for additional info milestones"
        )

    def test_additional_information_response_due_at_returns_none_without_request_time(
        self,
        create_flaw_report,
    ):
        """
        LEVEL_ADDITIONAL_INFORMATION_RESPONSE milestone with no request_received_at
        should return None for due_at (can't calculate deadline without request time).
        """
        # Arrange - create SRP Report
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = create_flaw_report(flaw=flaw)
        # Act - create additional info milestone WITHOUT request_received_at
        additional_info_milestone = SRPReportMilestone.objects.create(
            srp_report=srp_report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
            status=SRPReport.SRPReportStatus.REQUIRED,
            request_received_at=None,  # No request time set yet
            acl_read=srp_report.acl_read,
            acl_write=srp_report.acl_write,
        )

        # Assert - due_at should be None
        assert additional_info_milestone.due_at is None, (
            "due_at should be None when request_received_at is not set"
        )

    def test_additional_information_response_milestone_for_severe_incident(
        self, create_flaw_report
    ):
        """
        LEVEL_ADDITIONAL_INFORMATION_RESPONSE should work the same for
        Severe Incident reports (30 days from request, not affected by
        parent report's event type).
        """
        # Arrange - create Severe Incident report
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = create_flaw_report(
            flaw=flaw, incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        )
        assert (
            srp_report.reportable_event_type
            == SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )

        # Act - create additional info milestone
        request_time = timezone.now() + timedelta(days=10)
        additional_info_milestone = SRPReportMilestone.objects.create(
            srp_report=srp_report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
            status=SRPReport.SRPReportStatus.REQUIRED,
            request_received_at=request_time,
            acl_read=srp_report.acl_read,
            acl_write=srp_report.acl_write,
        )

        # Assert - still 30 days from request (not affected by parent's 30-day final deadline)
        expected_due_at = request_time + timedelta(days=30)
        assert additional_info_milestone.due_at == expected_due_at, (
            "Additional info response should always be 30 days from request, "
            "regardless of parent report type"
        )


class TestCreateSrpReportIncidentState:
    @pytest.mark.parametrize(
        "incident_state",
        [
            Flaw.FlawMajorIncident.NOVALUE,
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_REQUESTED,
            Flaw.FlawMajorIncident.MAJOR_INCIDENT_REJECTED,
            Flaw.FlawMajorIncident.EXPLOITS_KEV_REQUESTED,
            Flaw.FlawMajorIncident.EXPLOITS_KEV_REJECTED,
            Flaw.FlawMajorIncident.MINOR_INCIDENT_APPROVED,
        ],
    )
    def test_rejects_unsupported_incident_state_before_creating_report(
        self, incident_state
    ):
        flaw = FlawFactory(
            embargoed=False,
            major_incident_state=incident_state,
            major_incident_start_dt=timezone.now(),
        )

        with pytest.raises(ValueError, match="Unsupported incident_state"):
            create_srp_report(flaw, incident_state)

        assert not SRPReport.objects.filter(flaw=flaw).exists()

    def test_rejects_stale_approved_state_when_persisted_state_is_rejected(self):
        flaw = FlawFactory(
            embargoed=False,
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=timezone.now(),
        )
        Flaw.objects.filter(pk=flaw.pk).update(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_REJECTED
        )

        with pytest.raises(ValueError, match="does not match persisted"):
            create_srp_report(flaw, Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED)

        assert not SRPReport.objects.filter(flaw=flaw).exists()
