from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.db.models.deletion import ProtectedError
from django.test import TestCase
from django.utils import timezone
from freezegun import freeze_time

from apps.regulatory_reporting.models import (
    FlawUpstreamMapping,
    SRPReport,
    SRPReportMilestone,
    UpstreamNotification,
    UpstreamProject,
)
from apps.regulatory_reporting.tests.factories import (
    AdditionalInformationRequestFactory,
    SRPReportFactory,
    SRPReportMilestoneFactory,
)
from osidb.tests.factories import FlawFactory

pytestmark = [
    pytest.mark.unit,
    pytest.mark.no_cra_notifications,
]


def _report_kwargs(**overrides):
    flaw = overrides.pop("flaw", None) or FlawFactory()
    defaults = {
        "flaw": flaw,
        "title": "Test report",
        "responsibility_scope": SRPReport.ResponsibilityScope.MANUFACTURER,
        "reportable_event_type": (SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED),
        "timer_started_at": timezone.now(),
        "status": SRPReport.SRPReportStatus.IN_PROGRESS,
        "acl_read": flaw.acl_read,
        "acl_write": flaw.acl_write,
    }
    defaults.update(overrides)
    return defaults


def _milestone_kwargs(srp_report, **overrides):
    defaults = {
        "srp_report": srp_report,
        "milestone_type": SRPReportMilestone.MilestoneType.LEVEL_24H,
        "acl_read": srp_report.acl_read,
        "acl_write": srp_report.acl_write,
    }
    defaults.update(overrides)
    return defaults


class TestSRPReport:
    def test_create_and_save(self):
        report = SRPReportFactory()

        assert report.uuid is not None
        assert report.status == SRPReport.SRPReportStatus.EMPTY
        assert report.timer_started_at is not None

    def test_str(self):
        flaw = FlawFactory(cve_id="CVE-2024-1234")
        report = SRPReportFactory(flaw=flaw)

        assert str(report) == f"SRP Report {report.uuid} for CVE-2024-1234"

    def test_flaw_reverse_relation(self):
        report = SRPReportFactory()

        assert list(report.flaw.srp_reports.all()) == [report]

    @pytest.mark.parametrize(
        "status",
        [SRPReport.SRPReportStatus.IN_PROGRESS, SRPReport.SRPReportStatus.SUBMITTED],
    )
    def test_timer_started_required(self, status):
        kwargs = {"status": status, "timer_started_at": None}
        if status == SRPReport.SRPReportStatus.SUBMITTED:
            kwargs["srp_reference_id"] = "SRP-123"
        report = SRPReport(**_report_kwargs(**kwargs))

        with pytest.raises(
            ValidationError,
            match="timer_started_at must be set",
        ):
            report.save()

    def test_timer_started_not_required_for_empty_status(self):
        report = SRPReportFactory(
            status=SRPReport.SRPReportStatus.EMPTY, timer_started_at=None
        )
        assert report.timer_started_at is None

    def test_srp_reference_required_when_submitted(self):
        report = SRPReport(
            **_report_kwargs(
                status=SRPReport.SRPReportStatus.SUBMITTED,
                timer_started_at=timezone.now(),
                srp_reference_id="",
            )
        )

        with pytest.raises(
            ValidationError,
            match="srp_reference_id must be set when status is SUBMITTED",
        ):
            report.save()

    def test_srp_reference_not_required_when_prepared(self):
        report = SRPReportFactory(
            status=SRPReport.SRPReportStatus.EMPTY,
            timer_started_at=timezone.now(),
            srp_reference_id="",
        )

        assert report.srp_reference_id == ""

    @pytest.mark.parametrize("evidence", ["", "   "])
    def test_evidence_required_when_status_is_empty(self, evidence):
        report = SRPReport(
            **_report_kwargs(
                status=SRPReport.SRPReportStatus.EMPTY,
                timer_started_at=None,
                evidence=evidence,
            )
        )

        with pytest.raises(
            ValidationError,
            match="evidence must be set when status is EMPTY",
        ):
            report.save()

    def test_evidence_not_required_when_required(self):
        report = SRPReportFactory(
            status=SRPReport.SRPReportStatus.IN_PROGRESS,
            evidence="",
        )

        assert report.evidence == ""

    def test_flaw_protect_on_delete(self):
        flaw = FlawFactory()
        SRPReportFactory(flaw=flaw)

        with pytest.raises(ProtectedError):
            flaw.delete()


class TestSRPReportMilestone:
    def test_create_and_save(self):
        milestone = SRPReportMilestoneFactory()

        assert milestone.uuid is not None
        assert milestone.status == SRPReportMilestone.SRPReportMilestoneStatus.REQUIRED
        assert milestone.due_at is not None

    def test_str(self):
        flaw = FlawFactory(cve_id="CVE-2024-5678")
        report = SRPReportFactory(flaw=flaw)
        milestone = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H,
        )

        assert str(milestone) == "24h - CVE-2024-5678"

    def test_srp_report_reverse_relation(self):
        milestone = SRPReportMilestoneFactory()

        assert list(milestone.srp_report.milestones.all()) == [milestone]

    def test_unique_milestone_type_level(self):
        report = SRPReportFactory()
        SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H,
        )
        duplicate = SRPReportMilestone(
            **_milestone_kwargs(
                report,
                milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H,
            )
        )

        with pytest.raises(
            ValidationError,
            match="already exists",
        ):
            duplicate.save()

    def test_due_at_editable_after_creation(self):
        """
        due_at defaults to the computed 14-day KEV timer at creation,
        and can be edited directly afterwards.
        """
        report = SRPReportFactory()  # defaults to EXPLOITS_KEV_APPROVED
        seventy_two_h = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
        )
        milestone = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL,
        )

        seventy_two_h.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        seventy_two_h.save()
        seventy_two_h.refresh_from_db()
        milestone.refresh_from_db()
        computed_due_at = milestone.due_at
        assert computed_due_at == seventy_two_h.submitted_at + timedelta(days=14)

        override_date = timezone.now() + timedelta(days=100)
        milestone.due_at = override_date
        milestone.save(update_fields=["due_at"])
        milestone.refresh_from_db()
        assert milestone.due_at == override_date

    def test_final_milestone_allows_null_due_at_before_72h_submission(self):
        """
        LEVEL_FINAL milestones can be moved to IN_PROGRESS/IN_REVIEW with
        due_at still None, as long as the 72h sibling hasn't been submitted.
        """
        report = SRPReportFactory()
        SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
        )
        final_milestone = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL,
        )
        assert final_milestone.due_at is None

        final_milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.IN_PROGRESS
        final_milestone.save()

    def test_final_due_at_recomputed_on_submission_time_correction(self):
        report = SRPReportFactory()
        milestone_72h = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
        )
        final_milestone = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL,
        )

        milestone_72h.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone_72h.save()
        milestone_72h.refresh_from_db()
        final_milestone.refresh_from_db()
        assert final_milestone.due_at == milestone_72h.submitted_at + timedelta(days=14)

        corrected_time = milestone_72h.submitted_at - timedelta(hours=3)
        milestone_72h.submitted_at = corrected_time
        milestone_72h.save(update_fields=["submitted_at"])
        final_milestone.refresh_from_db()

        assert final_milestone.due_at == corrected_time + timedelta(days=14)

    def test_final_due_at_override_survives_submission_time_correction(self):
        report = SRPReportFactory()
        milestone_72h = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
        )
        final_milestone = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL,
        )

        milestone_72h.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone_72h.save()
        milestone_72h.refresh_from_db()

        manual_due_at = timezone.now() + timedelta(days=100)
        final_milestone.refresh_from_db()
        final_milestone.due_at = manual_due_at
        final_milestone.save(update_fields=["due_at"])

        milestone_72h.submitted_at = milestone_72h.submitted_at - timedelta(hours=3)
        milestone_72h.save(update_fields=["submitted_at"])
        final_milestone.refresh_from_db()

        assert final_milestone.due_at == manual_due_at

    def test_72h_milestone_requires_due_at_when_not_required_status(self):
        report = SRPReportFactory()
        milestone_72h = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
            due_at=None,
        )
        milestone_72h.due_at = None
        milestone_72h.status = SRPReportMilestone.SRPReportMilestoneStatus.IN_PROGRESS

        with pytest.raises(ValidationError, match="due_at must be set"):
            milestone_72h._validate_due_at_required()

    def test_final_due_at_not_set_when_72h_has_submitted_at_but_not_submitted(self):
        report = SRPReportFactory()
        milestone_72h = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
        )
        final_milestone = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL,
        )

        milestone_72h.submitted_at = timezone.now()
        milestone_72h.save(update_fields=["submitted_at"])
        milestone_72h.refresh_from_db()
        assert (
            milestone_72h.status
            != SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        )

        final_milestone.save()
        final_milestone.refresh_from_db()
        assert final_milestone.due_at is None

    def test_due_at_explicit_value_persisted_on_creation(self):
        """
        An explicit due_at passed at creation is kept and not
        replaced by the computed KEV default.
        """
        report = SRPReportFactory()  # KEV event type, timer already started
        override_date = timezone.now() + timedelta(days=100)
        milestone = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL,
            due_at=override_date,
        )
        milestone.refresh_from_db()

        assert milestone.due_at == override_date
        assert milestone.due_at != report.timer_started_at + timedelta(days=14)

    def test_multiple_additional_information_requests_allowed(self):
        """
        Multiple AdditionalInformationRequest entries can exist under
        a single milestone.
        """
        milestone = SRPReportMilestoneFactory()
        first = AdditionalInformationRequestFactory(milestone=milestone)
        second = AdditionalInformationRequestFactory(milestone=milestone)

        assert milestone.additional_information_requests.count() == 2
        assert str(first) == f"Additional Information Request 1 - {milestone}"
        assert str(second) == f"Additional Information Request 2 - {milestone}"

    def test_due_at_uses_request_received_at(self):
        """AdditionalInformationRequest.due_at is 30 days from request_received_at."""
        milestone = SRPReportMilestoneFactory()
        request_time = timezone.now() + timedelta(days=5)
        air = AdditionalInformationRequestFactory(
            milestone=milestone,
            request_received_at=request_time,
        )
        assert air.due_at == request_time + timedelta(days=30)

    def test_due_at_returns_none_without_request_received_at(self):
        """due_at is None when request_received_at is not set."""
        milestone = SRPReportMilestoneFactory()
        air = AdditionalInformationRequestFactory(milestone=milestone)
        assert air.due_at is None

    def test_cascade_delete_with_srp_report(self):
        milestone = SRPReportMilestoneFactory()
        report_uuid = milestone.srp_report.uuid
        milestone_uuid = milestone.uuid

        milestone.srp_report.delete()

        assert not SRPReport.objects.filter(uuid=report_uuid).exists()
        assert not SRPReportMilestone.objects.filter(uuid=milestone_uuid).exists()

    def test_owner_defaults_to_empty(self):
        milestone = SRPReportMilestoneFactory()

        assert milestone.owner == ""

    def test_owner_can_be_set(self):
        milestone = SRPReportMilestoneFactory()
        milestone.owner = "analyst@redhat.com"
        milestone.save()
        milestone.refresh_from_db()

        assert milestone.owner == "analyst@redhat.com"

    def test_submitted_at_defaults_to_none(self):
        milestone = SRPReportMilestoneFactory()

        assert milestone.submitted_at is None

    def test_submitted_at_set_on_first_submitted_transition(self):
        milestone = SRPReportMilestoneFactory()
        submitted_time = timezone.now()

        with freeze_time(submitted_time):
            milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
            milestone.save()

        milestone.refresh_from_db()
        assert milestone.submitted_at == submitted_time

    def test_submitted_at_not_overwritten_on_later_save(self):
        milestone = SRPReportMilestoneFactory()
        first_time = timezone.now()

        with freeze_time(first_time):
            milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
            milestone.save()
        milestone.refresh_from_db()

        later = first_time + timedelta(hours=1)
        with freeze_time(later):
            milestone.request_source = "ENISA Portal"
            milestone.save()
        milestone.refresh_from_db()

        assert milestone.submitted_at == first_time

    def test_submitted_at_writable_for_corrections(self):
        milestone = SRPReportMilestoneFactory()
        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone.save()
        milestone.refresh_from_db()
        original = milestone.submitted_at
        assert original is not None

        correction = original - timedelta(hours=3)
        milestone.submitted_at = correction
        milestone.save()
        milestone.refresh_from_db()

        assert milestone.submitted_at == correction

    def test_submitted_at_preserved_when_status_leaves_submitted(self):
        milestone = SRPReportMilestoneFactory()
        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone.save()
        milestone.refresh_from_db()
        stamped = milestone.submitted_at

        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW
        milestone.save()
        milestone.refresh_from_db()

        assert milestone.submitted_at == stamped

    def test_submitted_at_explicit_value_kept_on_submit(self):
        explicit = timezone.now() - timedelta(days=1)
        milestone = SRPReportMilestoneFactory(
            status=SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED,
            submitted_at=explicit,
        )

        assert milestone.submitted_at == explicit


class TestUpstreamProject(TestCase):
    def test_create_upstream_project(self):
        project = UpstreamProject.objects.create(
            component_name="test-component",
        )
        assert project.component_name == "test-component"
        assert project.uuid is not None


class TestUpstreamNotification(TestCase):
    def test_create_upstream_notification(self):
        flaw = FlawFactory()
        project = UpstreamProject.objects.create(
            component_name="test-component",
        )
        notification = UpstreamNotification.objects.create(
            flaw=flaw,
            upstream_project=project,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        assert notification.uuid is not None
        assert notification.status == UpstreamNotification.NotificationStatus.REQUIRED
        assert notification.flaw == flaw


class TestFlawUpstreamMapping(TestCase):
    def test_create_flaw_upstream_mapping(self):
        flaw = FlawFactory()
        project = UpstreamProject.objects.create(
            component_name="test-component",
        )
        mapping = FlawUpstreamMapping.objects.create(
            flaw=flaw,
            upstream_project=project,
        )
        assert mapping.uuid is not None
        assert mapping.flaw == flaw

    def test_mapping_independent_of_affects(self):
        flaw = FlawFactory()
        project = UpstreamProject.objects.create(
            component_name="test-component",
        )
        mapping = FlawUpstreamMapping.objects.create(
            flaw=flaw,
            upstream_project=project,
        )
        assert not hasattr(mapping, "affect")
        assert not hasattr(mapping, "tracker")
