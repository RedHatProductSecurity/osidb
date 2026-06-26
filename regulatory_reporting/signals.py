import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from osidb.models import Flaw
from regulatory_reporting.models import SRPReport, SRPReportMilestone

logger = logging.getLogger(__name__)


INCIDENT_STATES_THAT_REQUIRE_SRP_REPORT = [
    Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
    Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
]

REPORTABLE_EVENT_TYPE_MAP = {
    Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED: SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY,
    Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED: SRPReport.ReportableEventType.SEVERE_INCIDENT,
}


def create_srp_report_milestones(srp_report: SRPReport):
    milestone_types = [
        SRPReportMilestone.MilestoneType.LEVEL_24H,
        SRPReportMilestone.MilestoneType.LEVEL_72H,
        SRPReportMilestone.MilestoneType.LEVEL_FINAL,
    ]

    for milestone_type in milestone_types:
        SRPReportMilestone.objects.create(
            srp_report=srp_report,
            milestone_type=milestone_type,
            status=SRPReport.SRPReportStatus.REQUIRED,
            acl_read=srp_report.acl_read,
            acl_write=srp_report.acl_write,
        )


@receiver(post_save, sender=Flaw)
def create_srp_report(sender, instance: Flaw, created: bool, **kwargs):
    if instance.major_incident_state not in INCIDENT_STATES_THAT_REQUIRE_SRP_REPORT:
        return

    srp_report, created = SRPReport.objects.get_or_create(
        flaw=instance,
        reportable_event_type=REPORTABLE_EVENT_TYPE_MAP[instance.major_incident_state],
        defaults={
            "title": instance.title,
            "status": SRPReport.SRPReportStatus.REQUIRED,
            "responsibility_scope": SRPReport.ResponsibilityScope.MANUFACTURER,
            "timer_started_at": instance.major_incident_start_dt,
            "acl_read": instance.acl_read,
            "acl_write": instance.acl_write,
        },
    )

    if not created:
        srp_report.title = instance.title
        srp_report.acl_read = instance.acl_read
        srp_report.acl_write = instance.acl_write
        srp_report.timer_started_at = instance.major_incident_start_dt
        srp_report.save()
        logger.info(f"Updated SRP Report {srp_report.uuid} for {instance.cve_id}")
    else:
        create_srp_report_milestones(srp_report)
        logger.info(f"Created SRP Report {srp_report.uuid} for {instance.cve_id}")
