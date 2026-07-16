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
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.no_cra_reporting,
    pytest.mark.no_cra_notifications,
]


def _report_kwargs(**overrides):
    flaw = overrides.pop("flaw", None) or FlawFactory()
    defaults = {
        "flaw": flaw,
        "title": "Test report",
        "responsibility_scope": SRPReport.ResponsibilityScope.MANUFACTURER,
        "reportable_event_type": (
            SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
        ),
        "timer_started_at": timezone.now(),
        "status": SRPReport.SRPReportStatus.REQUIRED,
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
        assert report.status == SRPReport.SRPReportStatus.REQUIRED
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
        [SRPReport.SRPReportStatus.REQUIRED, SRPReport.SRPReportStatus.PREPARED],
    )
    def test_timer_started_required(self, status):
        report = SRPReport(**_report_kwargs(status=status, timer_started_at=None))

        with pytest.raises(
            ValidationError,
            match="timer_started_at must be set",
        ):
            report.save()

    @pytest.mark.parametrize(
        "status",
        [
            SRPReport.SRPReportStatus.NOT_REQUIRED,
            SRPReport.SRPReportStatus.NOT_APPLICABLE,
            SRPReport.SRPReportStatus.DEFERRED,
            SRPReport.SRPReportStatus.BLOCKED,
        ],
    )
    def test_timer_started_not_required_for_other_statuses(self, status):
        report = SRPReportFactory(status=status, timer_started_at=None)

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
            status=SRPReport.SRPReportStatus.PREPARED,
            timer_started_at=timezone.now(),
            srp_reference_id="",
        )

        assert report.srp_reference_id == ""

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
