"""
Create with Claude code Sonnet 4.5

Tests for automatic SRP Report creation based on Flaw major incident state.

These tests verify that SRP Reports are automatically created or updated when
a Flaw's major_incident_state meets the criteria for CRA reporting:
- EXPLOITS_KEV_APPROVED (actively exploited vulnerability)
- MAJOR_INCIDENT_APPROVED (severe incident)
"""

import pytest
from django.utils import timezone

from osidb.models import Flaw
from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import SRPReport

pytestmark = [
    pytest.mark.unit,
    pytest.mark.enable_signals,
    pytest.mark.cra_reporting,
]


class TestSRPReportAutoCreation:
    """Test automatic SRP Report creation via signals"""

    def test_srp_report_created_when_kev_approved(self):
        """
        When a flaw's major_incident_state is set to EXPLOITS_KEV_APPROVED,
        an SRP Report should be automatically created with:
        - reportable_event_type = ACTIVELY_EXPLOITED_VULNERABILITY
        - timer_started_at = flaw.major_incident_start_dt
        - status = REQUIRED
        - responsibility_scope = MANUFACTURER
        - title populated from flaw
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-1234",
            title="Test vulnerability title",
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            major_incident_start_dt=None,
        )

        # Act - update flaw to KEV approved
        flaw.major_incident_state = Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        flaw.major_incident_start_dt = start_time
        flaw.save()

        # Assert
        reports = SRPReport.objects.filter(flaw=flaw)
        assert reports.count() == 1

        report = reports.first()
        assert (
            report.reportable_event_type
            == SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
        )
        assert report.timer_started_at == start_time
        assert report.status == SRPReport.SRPReportStatus.REQUIRED
        assert report.responsibility_scope == SRPReport.ResponsibilityScope.MANUFACTURER
        assert report.title  # Title should be populated from flaw
        assert flaw.cve_id in report.title or flaw.title in report.title

    def test_srp_report_created_when_major_incident_approved(self):
        """
        When a flaw's major_incident_state is set to MAJOR_INCIDENT_APPROVED,
        an SRP Report should be automatically created with:
        - reportable_event_type = SEVERE_INCIDENT
        - timer_started_at = flaw.major_incident_start_dt
        - status = REQUIRED
        - responsibility_scope = MANUFACTURER
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-5678",
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            major_incident_start_dt=None,
        )

        # Act - update flaw to major incident approved
        flaw.major_incident_state = Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
        flaw.major_incident_start_dt = start_time
        flaw.save()

        # Assert
        reports = SRPReport.objects.filter(flaw=flaw)
        assert reports.count() == 1

        report = reports.first()
        assert (
            report.reportable_event_type
            == SRPReport.ReportableEventType.SEVERE_INCIDENT
        )
        assert report.timer_started_at == start_time
        assert report.status == SRPReport.SRPReportStatus.REQUIRED
        assert report.responsibility_scope == SRPReport.ResponsibilityScope.MANUFACTURER

    def test_srp_report_created_on_flaw_creation_with_kev_approved(self):
        """
        When a flaw is created with major_incident_state already set to
        EXPLOITS_KEV_APPROVED, an SRP Report should be automatically created.
        """
        # Arrange & Act
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Assert
        reports = SRPReport.objects.filter(flaw=flaw)
        assert reports.count() == 1

        report = reports.first()
        assert (
            report.reportable_event_type
            == SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
        )
        assert report.timer_started_at == start_time

    def test_srp_report_not_created_for_other_states(self):
        """
        When a flaw's major_incident_state is set to values other than
        EXPLOITS_KEV_APPROVED or MAJOR_INCIDENT_APPROVED, no SRP Report
        should be created automatically.
        """
        # Arrange & Act - create flaw with non-triggering state
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )

        # Assert
        assert SRPReport.objects.filter(flaw=flaw).count() == 0

    def test_srp_report_not_duplicated_if_already_exists(self):
        """
        If an SRP Report already exists for a flaw with the same
        reportable_event_type, a duplicate should not be created when
        the flaw is saved again.
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Verify initial report was created
        assert SRPReport.objects.filter(flaw=flaw).count() == 1

        # Act - save the flaw again without changes
        flaw.save()

        # Assert - no duplicate created
        assert SRPReport.objects.filter(flaw=flaw).count() == 1

    def test_srp_report_uses_major_incident_start_dt(self):
        """
        The timer_started_at field should use the flaw's major_incident_start_dt
        as per the acceptance criteria.
        """
        # Arrange
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            major_incident_start_dt=None,
        )

        # Act
        flaw.major_incident_state = Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        flaw.major_incident_start_dt = start_time
        flaw.save()

        # Assert
        report = SRPReport.objects.get(flaw=flaw)
        assert report.timer_started_at == start_time
        assert report.timer_started_at == flaw.major_incident_start_dt

    def test_srp_report_inherits_acl_from_flaw(self):
        """
        The automatically created SRP Report should inherit ACL permissions
        from its parent flaw.
        """
        # Arrange & Act
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=start_time,
        )

        # Assert
        report = SRPReport.objects.get(flaw=flaw)
        assert report.acl_read == flaw.acl_read
        assert report.acl_write == flaw.acl_write

    def test_srp_report_created_when_transitioning_states(self):
        """
        Test that SRP Reports are created when transitioning from one
        major incident state to another triggering state.
        """
        # Arrange - start with rejected KEV
        start_time = timezone.now()
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            major_incident_start_dt=None,
        )

        # Act - transition to approved
        flaw.major_incident_state = Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        flaw.major_incident_start_dt = start_time
        flaw.save()

        # Assert
        reports = SRPReport.objects.filter(flaw=flaw)
        assert reports.count() == 1
        assert (
            reports.first().reportable_event_type
            == SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
        )

    def test_flaw_can_have_both_event_type_reports(self):
        """
        A flaw could theoretically transition from MAJOR_INCIDENT_APPROVED
        to EXPLOITS_KEV_APPROVED (or vice versa). Each creates
        a separate SRP Report with different reportable_event_types.
        """
        # Arrange - create flaw with Major Incident approved
        start_time_mi = timezone.now()
        flaw = FlawFactory(
            cve_id="CVE-2024-9999",
            title="Critical security incident",
            major_incident_state=Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
            major_incident_start_dt=start_time_mi,
        )

        # Verify first report created for SEVERE_INCIDENT
        assert SRPReport.objects.filter(flaw=flaw).count() == 1
        severe_report = SRPReport.objects.get(flaw=flaw)
        assert (
            severe_report.reportable_event_type
            == SRPReport.ReportableEventType.SEVERE_INCIDENT
        )
        assert severe_report.timer_started_at == start_time_mi

        # Act - transition to KEV approved (state changes)
        # Note: In reality, major_incident_state can only hold one value,
        # but if it changes from one APPROVED state to another, we should
        # create a separate report
        flaw.major_incident_state = Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
        # In real OSIDB behavior, major_incident_start_dt doesn't overwrite if already set
        # but for this test we're checking the signal handles both event types
        flaw.save()

        # Assert - should have TWO separate reports now
        reports = SRPReport.objects.filter(flaw=flaw).order_by("created_dt")
        assert reports.count() == 2, "Should have separate reports for each event type"

        # Verify both event types are present
        event_types = {r.reportable_event_type for r in reports}
        assert SRPReport.ReportableEventType.SEVERE_INCIDENT in event_types, (
            "Should have severe incident report"
        )
        assert (
            SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
            in event_types
        ), "Should have KEV report"

        # Verify the KEV report has correct data
        kev_report = SRPReport.objects.get(
            flaw=flaw,
            reportable_event_type=SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY,
        )
        assert kev_report.status == SRPReport.SRPReportStatus.REQUIRED
        assert (
            kev_report.responsibility_scope
            == SRPReport.ResponsibilityScope.MANUFACTURER
        )
        assert kev_report.timer_started_at == start_time_mi  # Uses same timestamp
        assert kev_report.acl_read == flaw.acl_read
        assert kev_report.acl_write == flaw.acl_write


class TestSRPReportNoAutoCreation:
    """Test cases where SRP Reports should NOT be auto-created"""

    @pytest.mark.parametrize(
        "state",
        [
            Flaw.FlawMajorIncident.NOVALUE,
            "MAJOR_INCIDENT_REQUESTED",
            "MAJOR_INCIDENT_REJECTED",
            "EXPLOITS_KEV_REQUESTED",
            "EXPLOITS_KEV_REJECTED",
        ],
    )
    def test_srp_report_not_created_for_non_approved_states(self, state):
        """
        SRP Reports should only be created for APPROVED states, not for
        REQUESTED, REJECTED, or NOVALUE states.
        """
        # Arrange & Act
        flaw = FlawFactory(
            major_incident_state=state,
            major_incident_start_dt=(
                timezone.now() if state != Flaw.FlawMajorIncident.NOVALUE else None
            ),
        )

        # Assert
        assert SRPReport.objects.filter(flaw=flaw).count() == 0

    def test_srp_report_not_created_when_only_start_dt_changes(self):
        """
        If only major_incident_start_dt changes but major_incident_state
        is not an approved state, no SRP Report should be created.
        """
        # Arrange
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            major_incident_start_dt=None,
        )

        # Act - update only the start time
        flaw.major_incident_start_dt = timezone.now()
        flaw.save()

        # Assert
        assert SRPReport.objects.filter(flaw=flaw).count() == 0

    def test_srp_report_status_is_not_changed_when_flaw_is_saved(self):
        """
        The status of the SRP Report should not be changed when the flaw is saved.
        """
        # Arrange
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=None,
        )

        # Act
        flaw.save()
        srp_report = SRPReport.objects.get(flaw=flaw)
        assert srp_report.status == SRPReport.SRPReportStatus.REQUIRED
        srp_report.status = SRPReport.SRPReportStatus.PREPARED
        srp_report.save()
        flaw.title = "New title"
        flaw.save()
        # Assert
        srp_report.refresh_from_db()
        assert srp_report.status == SRPReport.SRPReportStatus.PREPARED

    def test_srp_report_title_is_updated_when_flaw_is_saved(self):
        """
        The title of the SRP Report should be updated when the flaw is saved.
        """
        # Arrange
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=None,
        )

        # Act
        flaw.title = "New title"
        flaw.save()

        # Assert
        assert SRPReport.objects.filter(flaw=flaw).count() == 1
        assert SRPReport.objects.get(flaw=flaw).title == "New title"

    def test_srp_report_acl_is_updated_when_flaw_is_saved(
        self,
        internal_read_groups,
        internal_write_groups,
        public_read_groups,
        public_write_groups,
    ):
        """
        The ACL of the SRP Report should be updated when the flaw is saved.
        """
        # Arrange
        flaw = FlawFactory(
            major_incident_state=Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
            major_incident_start_dt=None,
            embargoed=False,
            acl_read=internal_read_groups,
            acl_write=internal_write_groups,
        )

        assert SRPReport.objects.filter(flaw=flaw).count() == 1
        srp_report = SRPReport.objects.get(flaw=flaw)
        assert srp_report.acl_read == internal_read_groups
        assert srp_report.acl_write == internal_write_groups

        flaw.acl_read = public_read_groups
        flaw.acl_write = public_write_groups
        flaw.save()

        # Assert
        srp_report.refresh_from_db()
        assert SRPReport.objects.filter(flaw=flaw).count() == 1
        srp_report = SRPReport.objects.get(flaw=flaw)
        assert srp_report.acl_read == public_read_groups
        assert srp_report.acl_write == public_write_groups
