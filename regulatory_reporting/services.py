import json
import logging

from django.db import transaction
from django.template.loader import render_to_string
from django.utils import timezone

from osidb.models import Flaw, FlawCVSS
from osidb.models.flaw import FlawSource
from regulatory_reporting.constants import MILESTONES_TYPES_BY_REPORTABLE_EVENT_TYPE
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.models.upstream import UpstreamNotification

logger = logging.getLogger(__name__)

REDHAT_IDENTIFIED_SOURCES = {FlawSource.REDHAT}


def create_srp_report_milestones(
    srp_report: SRPReport,
    status: str = SRPReportMilestone.SRPReportMilestoneStatus.REQUIRED,
):
    """
    Create the required SRP milestones for a new SRP Report.

    For KEV / severe-incident reports: creates 24h, 72h, and final milestones.
    For ADDITIONAL_INFORMATION_REQUEST reports: creates a single
    additional_information_response milestone (no 24h/72h/final).

    Extra additional_information_response milestones may still be created
    on-demand via the milestone POST API when further requests are received.

    Args:
        srp_report: The SRP Report to create milestones for
        status: Initial status for created milestones (default REQUIRED)
    """

    for milestone_type in MILESTONES_TYPES_BY_REPORTABLE_EVENT_TYPE[
        srp_report.reportable_event_type
    ]:
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


def create_srp_report(flaw_instance: Flaw, incident_state: Flaw.FlawMajorIncident):
    """
    create SRP Report and milestones when Flaw is marked as KEV or Major Incident approved.

    Triggers on:
    - EXPLOITS_KEV_APPROVED → Creates report with that reportable_event_type
    - MAJOR_INCIDENT_APPROVED → Creates report with that reportable_event_type

    reportable_event_type matches Flaw.major_incident_state directly.
    Uses Flaw.major_incident_start_dt as the SLA timer start.
    """
    if incident_state not in (
        Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED,
        Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED,
    ):
        raise ValueError(
            f"Unsupported incident_state {incident_state!r}; "
            "SRP reports can only be created for EXPLOITS_KEV_APPROVED "
            "or MAJOR_INCIDENT_APPROVED"
        )

    with transaction.atomic():
        locked_flaw = Flaw.objects.select_for_update().get(pk=flaw_instance.pk)
        if locked_flaw.major_incident_state != incident_state:
            raise ValueError(
                f"incident_state {incident_state!r} does not match persisted "
                f"major_incident_state {locked_flaw.major_incident_state!r}"
            )

        event_type = locked_flaw.major_incident_state

        srp_report, report_created = SRPReport.objects.get_or_create(
            flaw=locked_flaw,
            reportable_event_type=event_type,
            defaults={
                "title": locked_flaw.title or f"SRP Report for {locked_flaw.uuid}",
                "status": SRPReport.SRPReportStatus.REQUIRED,
                "responsibility_scope": SRPReport.ResponsibilityScope.MANUFACTURER,
                "timer_started_at": locked_flaw.major_incident_start_dt,
                "acl_read": locked_flaw.acl_read,
                "acl_write": locked_flaw.acl_write,
            },
        )

        if not report_created:
            srp_report.title = locked_flaw.title or f"SRP Report for {locked_flaw.uuid}"
            srp_report.acl_read = locked_flaw.acl_read
            srp_report.acl_write = locked_flaw.acl_write
            srp_report.timer_started_at = locked_flaw.major_incident_start_dt
            srp_report.save()
            update_srp_report_milestones(srp_report)
            logger.info(
                f"Updated SRP Report {srp_report.uuid} for Flaw {locked_flaw.uuid} "
            )
        else:
            create_srp_report_milestones(srp_report)
            logger.info(
                f"Created SRP Report {srp_report.uuid} for Flaw {locked_flaw.uuid}, "
                f"event type {event_type}"
            )
        return srp_report


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


# --- SRP Payload Preparation ---


class SRPPayloadBuilder:
    """
    Base class for building SRP payload snapshots.

    Collects ENISA-required fields from OSIDB data and stores the result
    in milestone.meta_attr as simple key-value pairs.

    Subclass per milestone type to add stage-specific fields and required
    field definitions. Set previous_milestone_type to carry forward fields
    from an earlier milestone snapshot.

    Generated with Claude Opus 4.6 (claude-opus-4-6).
    """

    REQUIRED_COMMON_FIELDS = [
        "notification_type",
        "notification_level",
        "manufacturer_or_steward_name",
        "report_title",
        "product_identity",
        "product_type",
        "product_category",
        "member_states_available",
    ]

    REQUIRED_VULNERABILITY_FIELDS = []
    REQUIRED_INCIDENT_FIELDS = []

    expected_milestone_type = None
    previous_milestone_type = None

    def __init__(self, milestone):
        if (
            self.expected_milestone_type
            and milestone.milestone_type != self.expected_milestone_type
        ):
            raise ValueError(
                f"Expected {self.expected_milestone_type} milestone, "
                f"got {milestone.milestone_type}"
            )
        self.milestone = milestone
        self.srp_report = milestone.srp_report
        self.flaw = self.srp_report.flaw

    def _build_common_fields(self):
        fields = {}

        fields["notification_type"] = (
            SRPReport.ReportableEventType.enisa_notification_type(
                self.srp_report.reportable_event_type
            )
        )
        fields["notification_level"] = self.milestone.milestone_type
        fields["manufacturer_or_steward_name"] = (
            self.srp_report.manufacturer_or_steward_name or ""
        )
        fields["report_title"] = self.srp_report.title or ""
        fields["product_identity"] = self._collect_product_identity()
        fields["product_type"] = ""
        fields["product_category"] = ""

        member_states = self.srp_report.member_states_available or []
        fields["member_states_available"] = json.dumps(member_states)

        return fields

    def _collect_product_identity(self):
        products = []
        for affect in self.flaw.affects.all():
            products.append(
                {
                    "ps_product": affect.ps_product or "",
                    "ps_module": affect.ps_module or "",
                    "ps_component": affect.ps_component or "",
                }
            )
        return json.dumps(products)

    def _build_general_information(self):
        parts = []
        if self.flaw.title:
            parts.append(self.flaw.title)
        desc = self.flaw.selected_cve_description
        if desc:
            parts.append(desc)
        if self.flaw.statement:
            parts.append(self.flaw.statement)
        return "\n\n".join(parts)

    def _build_corrective_measures_taken(self):
        parts = []
        if self.flaw.mitigation:
            parts.append(self.flaw.mitigation)
        if self.flaw.statement:
            parts.append(self.flaw.statement)

        for affect in self.flaw.affects.all():
            if affect.resolution and affect.resolution != "":
                parts.append(
                    f"{affect.ps_module}/{affect.ps_component}: {affect.resolution}"
                )

        return "\n\n".join(parts)

    def _build_user_mitigations(self):
        parts = []
        if self.flaw.mitigation:
            parts.append(self.flaw.mitigation)
        if self.flaw.statement:
            parts.append(self.flaw.statement)
        return "\n\n".join(parts)

    def _build_vulnerability_fields(self):
        return {}

    def _build_incident_fields(self):
        return {}

    def _get_required_fields(self):
        required = list(self.REQUIRED_COMMON_FIELDS)
        if (
            self.srp_report.reportable_event_type
            == SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED
        ):
            required += self.REQUIRED_VULNERABILITY_FIELDS
        elif (
            self.srp_report.reportable_event_type
            == SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        ):
            required += self.REQUIRED_INCIDENT_FIELDS
        return required

    def _get_missing_required_fields(self, payload):
        missing = []
        for key in self._get_required_fields():
            value = payload.get(key, "")
            if not value or value == "[]":
                missing.append(key)
        return missing

    def _get_previous_snapshot(self):
        if not self.previous_milestone_type:
            return {}
        previous = self.srp_report.milestones.filter(
            milestone_type=self.previous_milestone_type,
        ).first()
        if previous and previous.meta_attr.get("payload_snapshot"):
            return json.loads(previous.meta_attr["payload_snapshot"])
        return {}

    def prepare(self):
        """
        Build the payload and store it in milestone.meta_attr.

        Does NOT call milestone.save() -- caller is responsible for saving.
        """
        payload = self._build_common_fields()

        if (
            self.srp_report.reportable_event_type
            == SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED
        ):
            payload.update(self._build_vulnerability_fields())
        elif (
            self.srp_report.reportable_event_type
            == SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        ):
            payload.update(self._build_incident_fields())

        for key, value in self._get_previous_snapshot().items():
            if key not in payload:
                payload[key] = value

        missing = self._get_missing_required_fields(payload)

        self.milestone.meta_attr["payload_snapshot"] = json.dumps(payload)
        self.milestone.meta_attr["prepared_at"] = timezone.now().isoformat()
        self.milestone.missing_required_fields = json.dumps(missing)

        return self.milestone


class SRPPayloadBuilder24h(SRPPayloadBuilder):
    """Payload builder for 24h early warning milestone."""

    expected_milestone_type = SRPReportMilestone.MilestoneType.LEVEL_24H

    REQUIRED_VULNERABILITY_FIELDS = ["cve_id"]
    REQUIRED_INCIDENT_FIELDS = ["suspected_unlawful_or_malicious_acts"]

    def _build_vulnerability_fields(self):
        return {"cve_id": self.flaw.cve_id or ""}

    def _build_incident_fields(self):
        return {"suspected_unlawful_or_malicious_acts": ""}


class SRPPayloadBuilder72h(SRPPayloadBuilder):
    """Payload builder for 72h notification milestone.

    Carries forward fields from the 24h milestone snapshot, then adds
    72h-required fields from OSIDB data.
    """

    expected_milestone_type = SRPReportMilestone.MilestoneType.LEVEL_72H
    previous_milestone_type = SRPReportMilestone.MilestoneType.LEVEL_24H

    REQUIRED_VULNERABILITY_FIELDS = [
        "cve_id",
        "general_information",
        "general_nature_of_vulnerability",
        "general_nature_of_exploit",
        "corrective_or_mitigating_measures_taken",
        "corrective_or_mitigating_measures_users_can_take",
    ]

    REQUIRED_INCIDENT_FIELDS = [
        "suspected_unlawful_or_malicious_acts",
        "general_incident_information",
        "incident_detected_at",
        "incident_occurred_at",
        "initial_incident_assessment",
        "corrective_or_mitigating_measures_taken",
        "corrective_or_mitigating_measures_users_can_take",
    ]

    def _build_vulnerability_fields(self):
        fields = {}
        fields["cve_id"] = self.flaw.cve_id or ""
        fields["general_information"] = self._build_general_information()
        cwe = self.flaw.cwe_id or ""
        fields["general_nature_of_vulnerability"] = cwe
        fields["general_nature_of_exploit"] = cwe
        fields["corrective_or_mitigating_measures_taken"] = (
            self._build_corrective_measures_taken()
        )
        fields["corrective_or_mitigating_measures_users_can_take"] = (
            self._build_user_mitigations()
        )
        fields["information_sensitivity"] = ""
        return fields

    def _build_incident_fields(self):
        fields = {}
        fields["suspected_unlawful_or_malicious_acts"] = ""
        fields["general_incident_information"] = self._build_general_information()
        fields["incident_detected_at"] = ""
        fields["incident_occurred_at"] = ""

        parts = []
        if self.flaw.comment_zero:
            parts.append(self.flaw.comment_zero)
        if self.flaw.statement:
            parts.append(self.flaw.statement)
        fields["initial_incident_assessment"] = "\n\n".join(parts)

        fields["corrective_or_mitigating_measures_taken"] = (
            self._build_corrective_measures_taken()
        )
        fields["corrective_or_mitigating_measures_users_can_take"] = (
            self._build_user_mitigations()
        )
        fields["information_sensitivity"] = ""
        return fields


class SRPPayloadBuilderFinal(SRPPayloadBuilder):
    """Payload builder for final report milestone.

    Carries forward fields from the 72h milestone snapshot, then adds
    final-report-required fields from OSIDB data.
    """

    expected_milestone_type = SRPReportMilestone.MilestoneType.LEVEL_FINAL
    previous_milestone_type = SRPReportMilestone.MilestoneType.LEVEL_72H

    REQUIRED_VULNERABILITY_FIELDS = [
        "cve_id",
        "general_information",
        "general_nature_of_vulnerability",
        "general_nature_of_exploit",
        "corrective_or_mitigating_measures_taken",
        "corrective_or_mitigating_measures_users_can_take",
        "full_vulnerability_description",
        "vulnerability_severity",
        "vulnerability_impact",
        "security_update_or_corrective_measure_details",
    ]

    REQUIRED_INCIDENT_FIELDS = [
        "suspected_unlawful_or_malicious_acts",
        "general_incident_information",
        "incident_detected_at",
        "incident_occurred_at",
        "initial_incident_assessment",
        "corrective_or_mitigating_measures_taken",
        "corrective_or_mitigating_measures_users_can_take",
        "detailed_incident_description",
        "incident_severity",
        "incident_impact",
        "likely_threat_or_root_cause",
        "applied_and_ongoing_mitigation_measures",
    ]

    def _build_full_description(self):
        parts = []
        if self.flaw.title:
            parts.append(self.flaw.title)
        desc = self.flaw.selected_cve_description
        if desc:
            parts.append(desc)
        if self.flaw.comment_zero:
            parts.append(self.flaw.comment_zero)
        if self.flaw.statement:
            parts.append(self.flaw.statement)
        return "\n\n".join(parts)

    def _build_severity(self):
        parts = []
        if self.flaw.impact:
            parts.append(f"Impact: {self.flaw.impact}")

        rh_cvss = (
            self.flaw.cvss_scores.filter(issuer=FlawCVSS.CVSSIssuer.REDHAT)
            .order_by("-version")
            .first()
        )
        if rh_cvss:
            parts.append(f"CVSS {rh_cvss.version}: {rh_cvss.score}")

        return ", ".join(parts)

    def _build_vulnerability_impact(self):
        parts = []
        if self.flaw.impact:
            parts.append(f"Flaw impact: {self.flaw.impact}")
        for affect in self.flaw.affects.all():
            if affect.affectedness:
                parts.append(
                    f"{affect.ps_module}/{affect.ps_component}: {affect.affectedness}"
                )
        return "\n".join(parts)

    def _build_vulnerability_fields(self):
        fields = {}
        fields["cve_id"] = self.flaw.cve_id or ""
        fields["general_information"] = self._build_general_information()

        cwe = self.flaw.cwe_id or ""
        fields["general_nature_of_vulnerability"] = cwe
        fields["general_nature_of_exploit"] = cwe

        fields["corrective_or_mitigating_measures_taken"] = (
            self._build_corrective_measures_taken()
        )
        fields["corrective_or_mitigating_measures_users_can_take"] = (
            self._build_user_mitigations()
        )
        fields["information_sensitivity"] = ""
        fields["corrective_or_mitigating_measure_available_at"] = ""
        fields["full_vulnerability_description"] = self._build_full_description()
        fields["vulnerability_severity"] = self._build_severity()
        fields["vulnerability_impact"] = self._build_vulnerability_impact()
        fields["known_or_suspected_malicious_actor"] = ""
        fields["security_update_or_corrective_measure_details"] = ""
        return fields

    def _build_incident_fields(self):
        fields = {}
        fields["suspected_unlawful_or_malicious_acts"] = ""
        fields["general_incident_information"] = self._build_general_information()
        fields["incident_detected_at"] = ""
        fields["incident_occurred_at"] = ""

        parts = []
        if self.flaw.comment_zero:
            parts.append(self.flaw.comment_zero)
        if self.flaw.statement:
            parts.append(self.flaw.statement)
        fields["initial_incident_assessment"] = "\n\n".join(parts)

        fields["corrective_or_mitigating_measures_taken"] = (
            self._build_corrective_measures_taken()
        )
        fields["corrective_or_mitigating_measures_users_can_take"] = (
            self._build_user_mitigations()
        )
        fields["information_sensitivity"] = ""
        fields["detailed_incident_description"] = self._build_full_description()
        fields["incident_severity"] = self._build_severity()
        fields["incident_impact"] = self._build_vulnerability_impact()
        fields["likely_threat_or_root_cause"] = self.flaw.cwe_id or ""
        fields["applied_and_ongoing_mitigation_measures"] = (
            self._build_corrective_measures_taken()
        )
        return fields


BUILDER_BY_MILESTONE_TYPE = {
    SRPReportMilestone.MilestoneType.LEVEL_24H: SRPPayloadBuilder24h,
    SRPReportMilestone.MilestoneType.LEVEL_72H: SRPPayloadBuilder72h,
    SRPReportMilestone.MilestoneType.LEVEL_FINAL: SRPPayloadBuilderFinal,
}


def prepare_payload(milestone):
    """Prepare the SRP payload for any milestone type."""
    builder_cls = BUILDER_BY_MILESTONE_TYPE.get(milestone.milestone_type)
    if not builder_cls:
        raise ValueError(f"No builder for milestone type {milestone.milestone_type}")
    return builder_cls(milestone).prepare()


def prepare_24h_payload(milestone):
    return SRPPayloadBuilder24h(milestone).prepare()


def prepare_72h_payload(milestone):
    return SRPPayloadBuilder72h(milestone).prepare()


def prepare_final_payload(milestone):
    return SRPPayloadBuilderFinal(milestone).prepare()
