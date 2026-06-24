import logging

from django.db.models.signals import post_save
from django.dispatch import receiver

from osidb.models import Flaw
from regulatory_reporting.models import SRPReport

logger = logging.getLogger(__name__)


INCIDENT_STATES_THAT_REQUIRE_SRP_REPORT = [
    Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
    Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
]

REPORTABLE_EVENT_TYPE_MAP = {
    Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED: SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY,
    Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED: SRPReport.ReportableEventType.SEVERE_INCIDENT,
}


@receiver(post_save, sender=Flaw)
def create_srp_report(sender, instance: Flaw, created: bool, **kwargs):
    if instance.major_incident_state not in INCIDENT_STATES_THAT_REQUIRE_SRP_REPORT:
        return

    srp_report, created = SRPReport.objects.get_or_create(
        flaw=instance,
        defaults={
            "title": instance.title,
            "status": SRPReport.SRPReportStatus.REQUIRED,
            "responsibility_scope": SRPReport.ResponsibilityScope.MANUFACTURER,
            "reportable_event_type": REPORTABLE_EVENT_TYPE_MAP[
                instance.major_incident_state
            ],
            "timer_started_at": instance.major_incident_start_dt,
            "acl_read": instance.acl_read,
            "acl_write": instance.acl_write,
        },
    )
