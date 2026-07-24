from django.template.loader import render_to_string

from osidb.models import Flaw
from osidb.models.flaw import FlawSource

from .models.upstream import UpstreamNotification

REDHAT_IDENTIFIED_SOURCES = {FlawSource.REDHAT}


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
