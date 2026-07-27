import json

from django.utils import timezone

from osidb.models import Flaw
from osidb.models.flaw import FlawSource

from .models.srp_report import SRPReport
from .models.srp_report_milestone import SRPReportMilestone

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


# --- SRP Payload Preparation ---


class SRPPayloadBuilder:
    """
    Base class for building SRP payload snapshots.

    Collects ENISA-required fields from OSIDB data and stores the result
    in milestone.meta_attr as simple key-value pairs.

    Subclass per milestone type to add stage-specific fields and required
    field definitions. 72h/final subclasses add carry-forward logic.

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

        fields["notification_type"] = self.srp_report.reportable_event_type
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
        for affect in self.flaw.affects.select_related("tracker").all():
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

        for affect in self.flaw.affects.select_related("tracker").all():
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
            == SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
        ):
            required += self.REQUIRED_VULNERABILITY_FIELDS
        elif (
            self.srp_report.reportable_event_type
            == SRPReport.ReportableEventType.SEVERE_INCIDENT
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

    def prepare(self):
        """
        Build the payload and store it in milestone.meta_attr.

        Does NOT call milestone.save() -- caller is responsible for saving.
        """
        payload = self._build_common_fields()

        if (
            self.srp_report.reportable_event_type
            == SRPReport.ReportableEventType.ACTIVELY_EXPLOITED_VULNERABILITY
        ):
            payload.update(self._build_vulnerability_fields())
        elif (
            self.srp_report.reportable_event_type
            == SRPReport.ReportableEventType.SEVERE_INCIDENT
        ):
            payload.update(self._build_incident_fields())

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

    def _get_previous_snapshot(self):
        previous = self.srp_report.milestones.filter(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H,
        ).first()
        if previous and previous.meta_attr.get("payload_snapshot"):
            return json.loads(previous.meta_attr["payload_snapshot"])
        return {}

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

    def prepare(self):
        previous_snapshot = self._get_previous_snapshot()
        result = super().prepare()
        current = json.loads(self.milestone.meta_attr["payload_snapshot"])
        for key, value in previous_snapshot.items():
            if key not in current:
                current[key] = value
        self.milestone.meta_attr["payload_snapshot"] = json.dumps(current)
        missing = self._get_missing_required_fields(current)
        self.milestone.missing_required_fields = json.dumps(missing)
        return result


class SRPPayloadBuilderFinal(SRPPayloadBuilder):
    """Payload builder for final report milestone.

    Carries forward fields from the 72h milestone snapshot, then adds
    final-report-required fields from OSIDB data.
    """

    expected_milestone_type = SRPReportMilestone.MilestoneType.LEVEL_FINAL

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

    def _get_previous_snapshot(self):
        previous = self.srp_report.milestones.filter(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
        ).first()
        if previous and previous.meta_attr.get("payload_snapshot"):
            return json.loads(previous.meta_attr["payload_snapshot"])
        return {}

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

        rh_cvss = self.flaw.cvss_scores.filter(issuer="RH").order_by("-version").first()
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

    def prepare(self):
        previous_snapshot = self._get_previous_snapshot()
        result = super().prepare()
        current = json.loads(self.milestone.meta_attr["payload_snapshot"])
        for key, value in previous_snapshot.items():
            if key not in current:
                current[key] = value
        self.milestone.meta_attr["payload_snapshot"] = json.dumps(current)
        missing = self._get_missing_required_fields(current)
        self.milestone.missing_required_fields = json.dumps(missing)
        return result


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
