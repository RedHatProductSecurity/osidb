"""SRP payload field schema exposed to OSIM.

The external SRP service currently does not expose a machine-readable field
definition API for its CRA forms: there is no upstream source for field order,
labels, requirement levels, input types, or copy-forward behavior. Until that
exists, PAYLOAD_FIELD_DEFINITIONS is OSIDB's local representation of the
current SRP form behavior. It documents and mocks the form shape this CRA SRP
editing workflow is implementing, and gives OSIM stable metadata to render.

Keep metadata and values separate. The payload builders in services.py own
generated/effective values; this module owns form metadata only. When SRP
provides a proper definition API, this module should be replaced or adapted to
consume that source instead of maintaining this list by hand.
"""

import json

from django.utils.dateparse import parse_datetime

from apps.regulatory_reporting.constants import ENISA_STATE_CODES

AEV_EVENT = "EXPLOITS_KEV_APPROVED"
SI_EVENT = "MAJOR_INCIDENT_APPROVED"
PAYLOAD_MILESTONE_TYPES = {"24h", "72h", "final"}

REQUIREMENT_NOT_APPLICABLE = "not_applicable"
REQUIREMENT_COPIED_OR_UPDATED = "copied_or_updated"
REQUIREMENT_OPTIONAL = "optional"
REQUIREMENT_REQUIRED = "required"
REQUIREMENT_REQUIRED_IF_AVAILABLE = "required_if_available"

DERIVED_DISPLAY_MODE = "derived_readonly"

EU_MEMBER_STATE_OPTIONS = sorted(ENISA_STATE_CODES)
INVALID_PAYLOAD_OVERRIDE = object()


def _field(
    key,
    label,
    section,
    event_scope,
    display_mode,
    input_type,
    requirements,
    options=None,
):
    field = {
        "key": key,
        "label": label,
        "section": section,
        "event_scope": event_scope,
        "display_mode": display_mode,
        "input_type": input_type,
        "requirements": requirements,
    }
    if input_type == "boolean" and options is None:
        options = ["Yes", "No"]
    if options:
        field["options"] = options
    return field


PAYLOAD_FIELD_DEFINITIONS = [
    _field(
        "notification_type",
        "Notification Type",
        "common",
        "both",
        DERIVED_DISPLAY_MODE,
        "text",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "report_title",
        "Title",
        "common",
        "both",
        "generated_editable_override",
        "text",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "summary",
        "Summary",
        "common",
        "both",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "manufacturer_or_steward_name",
        "Manufacturer Name",
        "common",
        "both",
        "generated_editable_override",
        "text",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "member_states_available",
        "Member States Where Product Available (Concerned CSIRT)",
        "common",
        "both",
        "generated_editable_override",
        "multi_select",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
        EU_MEMBER_STATE_OPTIONS,
    ),
    _field(
        "product_name",
        "Product Name",
        "product",
        "both",
        "generated_editable_override",
        "text",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "product_version",
        "Product Version",
        "product",
        "both",
        "generated_editable_override",
        "text",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "product_type",
        "Product Type",
        "product",
        "both",
        "manual_editable",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "product_class",
        "Product Class",
        "product",
        "both",
        "manual_editable",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "product_category",
        "Product Category",
        "product",
        "both",
        "manual_editable",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "end_of_support",
        "End of Support Indicator",
        "product",
        "both",
        "manual_editable",
        "boolean",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "component_name",
        "Component Name",
        "product",
        "both",
        "generated_editable_override",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "mitigating_measure_expected_shortly",
        "Mitigating Measure Expected Shortly",
        "common",
        "both",
        "manual_editable",
        "boolean",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "user_action_able_to_reduce_impact",
        "User Action Able to Reduce Impact",
        "common",
        "both",
        "manual_editable",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "information_sensitivity",
        "Considered Sensitivity of Information",
        "common",
        "both",
        "manual_editable",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "corrective_or_mitigating_measures_taken",
        "Corrective or Mitigating Measures Taken",
        "common",
        "both",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "corrective_or_mitigating_measures_users_can_take",
        "Corrective or Mitigating Measures That Users Can Take",
        "common",
        "both",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "attack_vector",
        "Attack Vector",
        "common",
        "both",
        "manual_editable",
        "text",
        {
            "24h": REQUIREMENT_NOT_APPLICABLE,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_OPTIONAL,
        },
    ),
    _field(
        "cve_id",
        "CVE ID",
        "aev",
        "aev",
        "generated_editable_override",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "euvd_id",
        "EUVD ID",
        "aev",
        "aev",
        "manual_editable",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "general_information",
        "General Information",
        "aev",
        "aev",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_REQUIRED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "general_nature_of_vulnerability",
        "General Nature of Vulnerability",
        "aev",
        "aev",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_NOT_APPLICABLE,
            "72h": REQUIREMENT_REQUIRED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "general_nature_of_exploit",
        "General Nature of Exploit",
        "aev",
        "aev",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_NOT_APPLICABLE,
            "72h": REQUIREMENT_REQUIRED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "corrective_or_mitigating_measure_available_at",
        "Date When Corrective or Mitigating Measure Has Been Available",
        "aev",
        "aev",
        "manual_editable",
        "datetime",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "security_update_or_corrective_measure_details",
        "Details About the Security Update/Corrective Measure Available",
        "aev",
        "aev",
        "manual_editable",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "full_vulnerability_description",
        "Full Description of the Vulnerability",
        "aev",
        "aev",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_NOT_APPLICABLE,
            "72h": REQUIREMENT_NOT_APPLICABLE,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "vulnerability_severity",
        "Full Description of the Severity of the Vulnerability",
        "aev",
        "aev",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "vulnerability_impact",
        "Full Description of the Impact of the Vulnerability",
        "aev",
        "aev",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "aev_detected_at",
        "Date and Time When You Become Aware of the Actively Exploited Vulnerability",
        "aev",
        "aev",
        "generated_editable_override",
        "datetime",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "known_or_suspected_malicious_actor",
        "Malicious Actor That Has Exploited/Is Exploiting the Vulnerability",
        "aev",
        "aev",
        "manual_editable",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED_IF_AVAILABLE,
        },
    ),
    _field(
        "pec",
        "Particular Exceptional Circumstances",
        "aev",
        "aev",
        "manual_editable",
        "textarea",
        {
            "24h": REQUIREMENT_NOT_APPLICABLE,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_NOT_APPLICABLE,
        },
    ),
    _field(
        "pec_delay_reason",
        "PEC Delay Reason",
        "aev",
        "aev",
        "manual_editable",
        "textarea",
        {
            "24h": REQUIREMENT_NOT_APPLICABLE,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_NOT_APPLICABLE,
        },
    ),
    _field(
        "further_information",
        "Further Information",
        "aev",
        "aev",
        "manual_editable",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "suspected_unlawful_or_malicious_acts",
        "Incident Is Suspected of Unlawful or Malicious Acts",
        "si",
        "si",
        "manual_editable",
        "boolean",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
        ["Yes", "No", "Unknown"],
    ),
    _field(
        "general_incident_information",
        "General Information About the Nature of the Incident",
        "si",
        "si",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_REQUIRED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "applied_and_ongoing_mitigation_measures",
        "Applied and Ongoing Mitigation Measures",
        "si",
        "si",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "detailed_incident_description",
        "Detailed Description of the Incident",
        "si",
        "si",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_NOT_APPLICABLE,
            "72h": REQUIREMENT_NOT_APPLICABLE,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "incident_severity",
        "Detailed Description of the Severity of the Incident",
        "si",
        "si",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "incident_impact",
        "Detailed Description of the Impact of the Incident",
        "si",
        "si",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "likely_threat_or_root_cause",
        "Type of Threat or Root Cause That Is Likely to Have Triggered Incident",
        "si",
        "si",
        "generated_editable_override",
        "text",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_OPTIONAL,
            "final": REQUIREMENT_REQUIRED,
        },
    ),
    _field(
        "incident_detected_at",
        "Date and Time When You Become Aware of the Incident (UTC time)",
        "si",
        "si",
        "generated_editable_override",
        "datetime",
        {
            "24h": REQUIREMENT_REQUIRED,
            "72h": REQUIREMENT_COPIED_OR_UPDATED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
    _field(
        "incident_occurred_at",
        "Date and Time When the Incident Occurred (UTC time)",
        "si",
        "si",
        "manual_editable",
        "datetime",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_REQUIRED,
            "final": REQUIREMENT_OPTIONAL,
        },
    ),
    _field(
        "initial_incident_assessment",
        "Initial Assessment of the Incident",
        "si",
        "si",
        "generated_editable_override",
        "textarea",
        {
            "24h": REQUIREMENT_OPTIONAL,
            "72h": REQUIREMENT_REQUIRED,
            "final": REQUIREMENT_COPIED_OR_UPDATED,
        },
    ),
]


def _event_matches(field, event_type):
    return (
        field["event_scope"] == "both"
        or (field["event_scope"] == "aev" and event_type == AEV_EVENT)
        or (field["event_scope"] == "si" and event_type == SI_EVENT)
    )


def get_payload_field_definitions(event_type, milestone_type):
    if milestone_type not in PAYLOAD_MILESTONE_TYPES:
        return []
    return [
        field
        for field in PAYLOAD_FIELD_DEFINITIONS
        if _event_matches(field, event_type)
        and field["requirements"][milestone_type] != REQUIREMENT_NOT_APPLICABLE
    ]


def get_payload_field_definition_map(event_type, milestone_type):
    return {
        field["key"]: field
        for field in get_payload_field_definitions(event_type, milestone_type)
    }


def _normalise_multi_select_override(field, value):
    if isinstance(value, list):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return INVALID_PAYLOAD_OVERRIDE
        if not isinstance(parsed, list):
            return INVALID_PAYLOAD_OVERRIDE
    else:
        return INVALID_PAYLOAD_OVERRIDE

    options = set(field.get("options", []))
    invalid = [
        item
        for item in parsed
        if not isinstance(item, str) or (options and item not in options)
    ]
    if invalid:
        return INVALID_PAYLOAD_OVERRIDE
    return json.dumps(parsed)


def normalise_payload_override_value(field, value):
    """Return a payload-ready override value, or INVALID_PAYLOAD_OVERRIDE."""
    if field["input_type"] == "multi_select":
        return _normalise_multi_select_override(field, value)

    if not isinstance(value, str):
        return INVALID_PAYLOAD_OVERRIDE

    if value == "":
        return value

    options = field.get("options")
    if options and value not in options:
        return INVALID_PAYLOAD_OVERRIDE

    if field["input_type"] == "datetime":
        try:
            if parse_datetime(value) is None:
                return INVALID_PAYLOAD_OVERRIDE
        except ValueError:
            return INVALID_PAYLOAD_OVERRIDE

    return value


def get_required_payload_keys(event_type, milestone_type):
    return [
        field["key"]
        for field in get_payload_field_definitions(event_type, milestone_type)
        if field["requirements"][milestone_type] == REQUIREMENT_REQUIRED
    ]


def get_conditionally_required_payload_keys(event_type, milestone_type):
    return [
        field["key"]
        for field in get_payload_field_definitions(event_type, milestone_type)
        if field["requirements"][milestone_type] == REQUIREMENT_REQUIRED_IF_AVAILABLE
    ]


def get_copied_or_updated_payload_keys(event_type, milestone_type):
    return frozenset(
        field["key"]
        for field in get_payload_field_definitions(event_type, milestone_type)
        if field["requirements"][milestone_type] == REQUIREMENT_COPIED_OR_UPDATED
    )


def get_overridable_payload_keys(event_type, milestone_type):
    return frozenset(
        field["key"]
        for field in get_payload_field_definitions(event_type, milestone_type)
        if field["display_mode"] != DERIVED_DISPLAY_MODE
    )


def _is_empty(value):
    return value in (None, "", "[]", [])


def _normalise_value(field, value):
    if field["input_type"] == "multi_select":
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                return [item.strip() for item in value.split(",") if item.strip()]
            return parsed if isinstance(parsed, list) else []
    return value if value is not None else ""


def build_payload_field_rows(
    event_type,
    milestone_type,
    payload,
    additional_details,
    missing_required,
    missing_conditionally_required,
    applied_override_keys,
):
    missing_keys = set(missing_required) | set(missing_conditionally_required)
    rows = []
    for field in get_payload_field_definitions(event_type, milestone_type):
        value = _normalise_value(field, payload.get(field["key"], ""))
        row = {
            "key": field["key"],
            "label": field["label"],
            "section": field["section"],
            "requirement": field["requirements"][milestone_type],
            "input_type": field["input_type"],
            "editable": field["display_mode"] != DERIVED_DISPLAY_MODE,
            "value": value,
            "missing": field["key"] in missing_keys
            or (
                field["requirements"][milestone_type] == REQUIREMENT_REQUIRED
                and _is_empty(value)
            ),
            "source": (
                "manual_override"
                if field["key"] in applied_override_keys
                else "generated"
            ),
        }
        if "options" in field:
            row["options"] = field["options"]
        rows.append(row)
    return rows
