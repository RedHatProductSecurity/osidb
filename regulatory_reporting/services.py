import logging

from django.template.loader import render_to_string

from osidb.models import Flaw
from osidb.models.flaw import FlawSource

from .models import SRPReport, SRPReportMilestone
from .models.upstream import UpstreamNotification

logger = logging.getLogger(__name__)

REDHAT_IDENTIFIED_SOURCES = {FlawSource.REDHAT}


def create_srp_report_milestones(
    srp_report: SRPReport,
    status: str = SRPReport.SRPReportStatus.REQUIRED,
):
    """
    Create the required SRP milestones (24h, 72h, final) for a new SRP Report.

    Does NOT create additional_information_response milestones - those are
    created on-demand when requests are received.

    Args:
        srp_report: The SRP Report to create milestones for
        status: Initial status for created milestones (default REQUIRED)
    """
    milestone_types = [
        SRPReportMilestone.MilestoneType.LEVEL_24H,
        SRPReportMilestone.MilestoneType.LEVEL_72H,
        SRPReportMilestone.MilestoneType.LEVEL_FINAL,
    ]

    for milestone_type in milestone_types:
        milestone = SRPReportMilestone.objects.create(
            srp_report=srp_report,
            milestone_type=milestone_type,
            status=status,
            acl_read=srp_report.acl_read,
            acl_write=srp_report.acl_write,
        )
        logger.info(
            f"Created {milestone_type} milestone for SRP Report {srp_report.uuid} "
            f"for Flaw {srp_report.flaw.uuid}, created at {milestone.created_dt}, due at {milestone.due_at}"
        )


def update_srp_report_milestones(srp_report: SRPReport):
    """
    Update the milestones for an existing SRP Report.

    Args:
        srp_report: The SRP Report to update milestones for
    """
    all_milestones = SRPReportMilestone.objects.filter(srp_report=srp_report)
    for milestone in all_milestones:
        milestone.acl_read = srp_report.acl_read
        milestone.acl_write = srp_report.acl_write
        milestone.save()
        logger.info(
            f"Updated {milestone.milestone_type} milestone for SRP Report {srp_report.uuid} "
            f"for Flaw {srp_report.flaw.uuid}, created at {milestone.created_dt}, due at {milestone.due_at}"
        )


def _is_public_feed_only(flaw: Flaw) -> bool:
    return bool(flaw.source and FlawSource(flaw.source).is_from_snippet)


def is_flaw_upstream_notifiable(flaw: Flaw) -> bool:
    if flaw.is_embargoed:
        return False

    source = FlawSource(flaw.source)
    if source in REDHAT_IDENTIFIED_SOURCES:
        return True
    if _is_public_feed_only(flaw):
        return False

    return False


def build_upstream_notification_context(notification: UpstreamNotification) -> dict:
    """
    Build the template context for a maintainer notification email
    """
    flaw = notification.flaw
    upstream_project = notification.upstream_project

    flaw_id = flaw.cve_id or flaw.uuid

    return {
        "flaw_id": flaw_id,
        "vulnerability_summary": flaw.cve_description,
        "upstream_component": upstream_project.component_name,
        "impact": flaw.impact,
        "corrective_measure": flaw.mitigation,
        "contact_info": upstream_project.security_contact,
        "confidentiality_notice": (
            "This information is confidential until public disclosure."
            if flaw.is_embargoed
            else ""
        ),
    }


def render_upstream_notification_preview(
    notification: UpstreamNotification,
) -> dict:
    """
    Live rendering the maintainer notification email
    """
    context = build_upstream_notification_context(notification)

    text_body = render_to_string(
        "email/upstream_maintainer_notification.txt", context=context
    )
    html_body = render_to_string(
        "email/upstream_maintainer_notification.html", context=context
    )

    return {"text_body": text_body, "html_body": html_body}
