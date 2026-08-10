import pytest
from django.core.exceptions import ValidationError
from django.db.models.deletion import ProtectedError
from django.test import TestCase
from django.utils import timezone

from osidb.tests.factories import FlawFactory
from regulatory_reporting.models import (
    FlawUpstreamMapping,
    SRPReport,
    SRPReportMilestone,
    UpstreamNotification,
    UpstreamProject,
)
from regulatory_reporting.tests.factories import (
    SRPReportFactory,
    SRPReportMilestoneFactory,
    SRPReportWithMilestonesFactory,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.no_cra_reporting,
    pytest.mark.no_cra_notifications,
]


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
        report = SRPReportWithMilestonesFactory()
        milestone_24h = report.milestones.get(
            milestone_type=SRPReport.MilestoneType.LEVEL_24H
        )

        assert report.uuid is not None
        assert (
            report.status
            == f"{SRPReport.MilestoneType.LEVEL_24H}:{SRPReport.SRPReportStatus.REQUIRED}"
        )
        assert report.active_due_at() == milestone_24h.due_at
        assert report.timer_started_at is not None

    def test_status_falls_back_to_furthest_closed_milestone(self):
        """When no milestone is active, status uses furthest closed (final)."""
        report = SRPReportWithMilestonesFactory()
        for milestone in report.milestones.all():
            milestone.status = SRPReport.SRPReportStatus.SUBMITTED
            milestone.save()

        report = SRPReport.objects.get(pk=report.pk)
        milestone_final = report.milestones.get(
            milestone_type=SRPReport.MilestoneType.LEVEL_FINAL
        )
        assert (
            report.status
            == f"{SRPReport.MilestoneType.LEVEL_FINAL}:{SRPReport.SRPReportStatus.SUBMITTED}"
        )
        assert report.active_due_at() == milestone_final.due_at

    def test_status_and_active_due_at_follow_next_active_milestone(self):
        """After 24h is closed, status and due date follow the 72h milestone."""
        report = SRPReportWithMilestonesFactory()
        milestone_24h = report.milestones.get(
            milestone_type=SRPReport.MilestoneType.LEVEL_24H
        )
        milestone_24h.status = SRPReport.SRPReportStatus.SUBMITTED
        milestone_24h.save()

        report = SRPReport.objects.get(pk=report.pk)
        milestone_72h = report.milestones.get(
            milestone_type=SRPReport.MilestoneType.LEVEL_72H
        )
        assert (
            report.status
            == f"{SRPReport.MilestoneType.LEVEL_72H}:{SRPReport.SRPReportStatus.REQUIRED}"
        )
        assert report.active_due_at() == milestone_72h.due_at

    def test_status_and_active_due_at_none_without_milestones(self):
        report = SRPReportFactory()

        assert report.status is None
        assert report.active_due_at() is None

    def test_str(self):
        flaw = FlawFactory(cve_id="CVE-2024-1234")
        report = SRPReportWithMilestonesFactory(flaw=flaw)

        assert str(report) == f"SRP Report {report.uuid} for CVE-2024-1234"

    def test_flaw_reverse_relation(self):
        report = SRPReportFactory()

        assert list(report.flaw.srp_reports.all()) == [report]

    @pytest.mark.parametrize(
        "status",
        [
            SRPReport.SRPReportStatus.NOT_REQUIRED,
            SRPReport.SRPReportStatus.NOT_APPLICABLE,
            SRPReport.SRPReportStatus.PRE_REQUIRED,
            SRPReport.SRPReportStatus.DEFERRED,
            SRPReport.SRPReportStatus.BLOCKED,
        ],
    )
    def test_timer_started_not_required_for_other_statuses(self, status):
        # Use additional-info milestones so due_at comes from request_received_at
        # and does not require report.timer_started_at.
        report = SRPReportFactory(
            timer_started_at=None,
            evidence=(
                "Manual create justification."
                if status == SRPReport.SRPReportStatus.PRE_REQUIRED
                else ""
            ),
        )
        milestone_type = SRPReport.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE
        SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=milestone_type,
            status=status,
            request_received_at=timezone.now(),
        )

        report = SRPReport.objects.get(pk=report.pk)
        assert report.status == f"{milestone_type}:{status}"
        assert report.timer_started_at is None
        report.validate()

    def test_srp_reference_not_required_when_prepared(self):
        report = SRPReportFactory(
            timer_started_at=timezone.now(),
            srp_reference_id="",
        )
        SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReport.MilestoneType.LEVEL_24H,
            status=SRPReport.SRPReportStatus.PREPARED,
        )

        report = SRPReport.objects.get(pk=report.pk)
        assert (
            report.status
            == f"{SRPReport.MilestoneType.LEVEL_24H}:{SRPReport.SRPReportStatus.PREPARED}"
        )
        assert report.srp_reference_id == ""
        report.validate()

    @pytest.mark.parametrize("evidence", ["", "   "])
    def test_evidence_required_when_pre_required(self, evidence):
        report = SRPReportFactory(
            timer_started_at=None,
            evidence=evidence,
        )
        SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReport.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
            status=SRPReport.SRPReportStatus.PRE_REQUIRED,
            request_received_at=timezone.now(),
        )

        report = SRPReport.objects.get(pk=report.pk)
        with pytest.raises(
            ValidationError,
            match="evidence must be set when status is PRE_REQUIRED",
        ):
            report.validate()

    def test_evidence_not_required_when_required(self):
        report = SRPReportWithMilestonesFactory(evidence="")

        assert report.evidence == ""
        report.validate()

    def test_flaw_protect_on_delete(self):
        flaw = FlawFactory()
        SRPReportFactory(flaw=flaw)

        with pytest.raises(ProtectedError):
            flaw.delete()


class TestSRPReportMilestone:
    def test_create_and_save(self):
        milestone = SRPReportMilestoneFactory()

        assert milestone.uuid is not None
        assert milestone.status == SRPReport.SRPReportStatus.REQUIRED
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
            match="unique_srp_report_milestone_type_level",
        ):
            duplicate.save()

    def test_multiple_additional_information_response_allowed(self):
        report = SRPReportFactory()
        first = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
        )
        second = SRPReportMilestoneFactory(
            srp_report=report,
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
        )

        assert first.milestone_type == second.milestone_type
        assert report.milestones.count() == 2

    def test_cascade_delete_with_srp_report(self):
        milestone = SRPReportMilestoneFactory()
        report_uuid = milestone.srp_report.uuid
        milestone_uuid = milestone.uuid

        milestone.srp_report.delete()

        assert not SRPReport.objects.filter(uuid=report_uuid).exists()
        assert not SRPReportMilestone.objects.filter(uuid=milestone_uuid).exists()


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
