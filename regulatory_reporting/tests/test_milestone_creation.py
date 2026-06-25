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

pytestmark = pytest.mark.unit


class TestSRPMilestoneAutoCreation:
    """Test automatic SRP Milestone creation when SRP Report is created"""

    @pytest.mark.enable_signals
    def test_milestones_created_for_kev_report(self):
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
        srp_report = SRPReport.objects.get(flaw=flaw)
        assert (
            srp_report.reportable_event_type
            == SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
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

    @pytest.mark.enable_signals
    def test_milestones_created_for_severe_incident_report(self):
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
        srp_report = SRPReport.objects.get(flaw=flaw)
        assert (
            srp_report.reportable_event_type
            == SRPReport.ReportableEventType.SEVERE_INCIDENT
        )

        # Assert - Exactly 3 milestones created
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)
        assert milestones.count() == 3, "Should create exactly 3 milestones"

        # Assert - Correct milestone types
        milestone_types = {m.milestone_type for m in milestones}
        assert SRPReportMilestone.MilestoneType.LEVEL_24H in milestone_types
        assert SRPReportMilestone.MilestoneType.LEVEL_72H in milestone_types
        assert SRPReportMilestone.MilestoneType.LEVEL_FINAL in milestone_types

    @pytest.mark.enable_signals
    def test_milestone_due_dates_for_kev(self):
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
        srp_report = SRPReport.objects.get(flaw=flaw)
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

    @pytest.mark.enable_signals
    def test_milestone_due_dates_for_severe_incident(self):
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
        srp_report = SRPReport.objects.get(flaw=flaw)
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

    @pytest.mark.enable_signals
    def test_milestones_inherit_acl_from_srp_report(self):
        """
        All milestones should inherit ACL permissions from their parent SRP Report.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Assert
        srp_report = SRPReport.objects.get(flaw=flaw)
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)

        for milestone in milestones:
            assert milestone.acl_read == srp_report.acl_read, (
                f"{milestone.milestone_type} should inherit acl_read"
            )
            assert milestone.acl_write == srp_report.acl_write, (
                f"{milestone.milestone_type} should inherit acl_write"
            )

    @pytest.mark.enable_signals
    def test_milestone_status_defaults_to_required(self):
        """
        All auto-created milestones should have status = REQUIRED by default.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = SRPReport.objects.get(flaw=flaw)
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)

        for milestone in milestones:
            assert milestone.status == SRPReportBase.SRPReportStatus.REQUIRED, (
                f"{milestone.milestone_type} should have REQUIRED status"
            )

    @pytest.mark.enable_signals
    def test_milestones_not_duplicated_on_flaw_resave(self):
        """
        If a flaw is saved again without state changes, milestones should not be duplicated.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Verify initial milestones created
        srp_report = SRPReport.objects.get(flaw=flaw)
        initial_count = SRPReportMilestone.objects.filter(srp_report=srp_report).count()
        assert initial_count == 3

        # Act - save flaw again without changes
        flaw.save()

        # Assert no duplicates
        final_count = SRPReportMilestone.objects.filter(srp_report=srp_report).count()
        assert final_count == 3, "Should not create duplicate milestones on flaw resave"

    @pytest.mark.enable_signals
    def test_additional_information_response_not_auto_created(self):
        """
        LEVEL_ADDITIONAL_INFORMATION_RESPONSE should NOT be created automatically.
        It's only created on-demand when authorities send follow-up requests.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = SRPReport.objects.get(flaw=flaw)

        # Should have no additional_information_response milestones
        additional_info_milestones = SRPReportMilestone.objects.filter(
            srp_report=srp_report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
        )
        assert additional_info_milestones.count() == 0, (
            "Additional information response milestones should NOT be auto-created"
        )

    @pytest.mark.enable_signals
    def test_milestones_created_for_both_event_types_on_state_transition(self):
        """
        If a flaw transitions from MAJOR_INCIDENT_APPROVED to EXPLOITS_KEV_APPROVED,
        both SRP Reports should get their own sets of milestones.
        """
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Verify first report and milestones created
        severe_report = SRPReport.objects.get(
            flaw=flaw,
            reportable_event_type=SRPReport.ReportableEventType.SEVERE_INCIDENT,
        )
        severe_milestones = SRPReportMilestone.objects.filter(srp_report=severe_report)
        assert severe_milestones.count() == 3

        # Act - transition to KEV approved
        flaw.major_incident_state = Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        flaw.save()

        # KEV report created with its own milestones
        kev_report = SRPReport.objects.get(
            flaw=flaw,
            reportable_event_type=SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY,
        )
        kev_milestones = SRPReportMilestone.objects.filter(srp_report=kev_report)
        assert kev_milestones.count() == 3, (
            "KEV report should have its own 3 milestones"
        )

        # both sets of milestones exist
        total_milestones = SRPReportMilestone.objects.filter(srp_report__flaw=flaw)
        assert total_milestones.count() == 6, (
            "Should have 6 total milestones (3 per report)"
        )

    @pytest.mark.enable_signals
    def test_milestone_creation_on_flaw_creation_with_approved_state(self):
        """
        If a flaw is created with major_incident_state already set to an approved state,
        milestones should be created immediately.
        """
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Assert - milestones created
        srp_report = SRPReport.objects.get(flaw=flaw)
        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)
        assert milestones.count() == 3, (
            "Milestones should be created even on initial flaw creation"
        )

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "milestone_type",
        [
            SRPReportMilestone.MilestoneType.LEVEL_24H,
            SRPReportMilestone.MilestoneType.LEVEL_72H,
            SRPReportMilestone.MilestoneType.LEVEL_FINAL,
        ],
    )
    def test_milestone_uniqueness_constraint(self, milestone_type):
        """
        Each SRP Report should only have ONE milestone of each type (24h, 72h, final).
        The uniqueness constraint should prevent duplicates.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = SRPReport.objects.get(flaw=flaw)

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

    @pytest.mark.enable_signals
    def test_milestone_relationships_to_srp_report(self):
        """
        Verify the relationship between milestones and their parent SRP Report works correctly.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = SRPReport.objects.get(flaw=flaw)

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

    @pytest.mark.enable_signals
    def test_milestones_not_created_for_non_approved_states(self):
        """
        Milestones should only be created when major_incident_state is APPROVED.
        Not for REQUESTED or REJECTED states.
        """
        flaw = FlawFactory(
            major_incident_state="EXPLOITS_KEV_REQUESTED",  # Not approved yet
            major_incident_start_dt=timezone.now(),
        )
        assert SRPReport.objects.filter(flaw=flaw).count() == 0
        assert SRPReportMilestone.objects.filter(srp_report__flaw=flaw).count() == 0


class TestMilestoneDueDateProperty:
    """Test the due_at property calculation for different milestone types"""

    @pytest.mark.enable_signals
    def test_due_at_calculation_uses_timer_started_at(self):
        """
        The due_at property should calculate from srp_report.timer_started_at,
        which comes from flaw.major_incident_start_dt.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = SRPReport.objects.get(flaw=flaw)
        assert srp_report.timer_started_at == start_time

        milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)
        for milestone in milestones:
            # All due dates should be calculated from the same start time
            assert milestone.due_at > start_time, (
                f"{milestone.milestone_type} due_at should be after start time"
            )

    @pytest.mark.enable_signals
    def test_milestone_string_representation(self):
        """
        Test the __str__ method of milestones includes milestone type and CVE ID.
        """

        start_time = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-9999",
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        srp_report = SRPReport.objects.get(flaw=flaw)
        milestone_24h = SRPReportMilestone.objects.get(
            srp_report=srp_report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H,
        )

        milestone_str = str(milestone_24h)
        assert "24h" in milestone_str
        assert "CVE-2024-9999" in milestone_str

    @pytest.mark.enable_signals
    def test_additional_information_response_due_at_uses_request_received_at(self):
        """
        LEVEL_ADDITIONAL_INFORMATION_RESPONSE milestones should calculate due_at
        from request_received_at (not timer_started_at) and use 30 days duration.
        """
        # Arrange - create SRP Report
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )
        srp_report = SRPReport.objects.get(flaw=flaw)

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
        wrong_due_at = start_time + timedelta(days=30)
        assert additional_info_milestone.due_at != wrong_due_at, (
            "Should NOT use timer_started_at for additional info milestones"
        )

    @pytest.mark.enable_signals
    def test_additional_information_response_due_at_returns_none_without_request_time(
        self,
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
        srp_report = SRPReport.objects.get(flaw=flaw)

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

    @pytest.mark.enable_signals
    def test_additional_information_response_milestone_for_severe_incident(self):
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
        srp_report = SRPReport.objects.get(flaw=flaw)
        assert (
            srp_report.reportable_event_type
            == SRPReport.ReportableEventType.SEVERE_INCIDENT
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
