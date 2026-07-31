import json

import pytest
from django.utils import timezone

from osidb.models import Flaw
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
)
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.services import (
    prepare_24h_payload,
    prepare_72h_payload,
    prepare_final_payload,
    prepare_payload,
)
from regulatory_reporting.tests.factories import (
    SRPReportMilestoneFactory,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.cra_reporting,
    pytest.mark.no_cra_notifications,
]

# The cra_reporting marker enables the create_srp_report signal, so creating
# a Flaw with major_incident_state=EXPLOITS_KEV_APPROVED or
# MAJOR_INCIDENT_APPROVED auto-creates the SRPReport and its 24h/72h/final
# milestones, just like production.


def _create_vulnerability_report(report_attrs=None, **flaw_kwargs):
    """Create a Flaw that triggers a vulnerability SRP report via signal."""
    flaw_kwargs["major_incident_state"] = Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
    flaw_kwargs.setdefault("embargoed", False)
    flaw_kwargs.setdefault("major_incident_start_dt", timezone.now())
    flaw = FlawFactory(**flaw_kwargs)
    report = SRPReport.objects.get(flaw=flaw)
    if report_attrs:
        for k, v in report_attrs.items():
            setattr(report, k, v)
        report.save()
    return report


def _create_incident_report(report_attrs=None, **flaw_kwargs):
    """Create a Flaw that triggers an incident SRP report via signal."""
    flaw_kwargs["major_incident_state"] = Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
    flaw_kwargs.setdefault("embargoed", False)
    flaw_kwargs.setdefault("major_incident_start_dt", timezone.now())
    flaw = FlawFactory(**flaw_kwargs)
    report = SRPReport.objects.get(flaw=flaw)
    if report_attrs:
        for k, v in report_attrs.items():
            setattr(report, k, v)
        report.save()
    return report


def _get_milestone(report, milestone_type):
    return report.milestones.get(milestone_type=milestone_type)


def _clear_flaw_fields(report, **fields):
    """Clear Flaw fields via queryset update to bypass blank=False validation.

    Needed for missing-required-field tests: title/comment_zero cannot be
    emptied through FlawFactory/save(), but payload builders must still handle
    empty descriptive inputs.
    """
    Flaw.objects.filter(pk=report.flaw_id).update(**fields)
    report.flaw.refresh_from_db()


def _prepare_chain_up_to_72h(report):
    """Prepare 24h snapshot so 72h can carry forward."""
    m24 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
    prepare_24h_payload(m24)
    m24.save()
    return _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_72H)


def _prepare_chain_up_to_final(report):
    """Prepare 24h and 72h snapshots so final can carry forward."""
    m24 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
    prepare_24h_payload(m24)
    m24.save()
    m72 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_72H)
    prepare_72h_payload(m72)
    m72.save()
    return _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_FINAL)


# ── 24h Milestone Tests ──


class TestPrepare24hPayloadValidation:
    def test_raises_for_72h_milestone(self):
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
            srp_report__flaw__major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with pytest.raises(ValueError, match="Expected 24h milestone"):
            prepare_24h_payload(milestone)

    def test_raises_for_final_milestone(self):
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL,
            srp_report__flaw__major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with pytest.raises(ValueError, match="Expected 24h milestone"):
            prepare_24h_payload(milestone)


class TestPrepare24hPayloadCommonFields:
    def test_notification_type_from_report(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["notification_type"] == "actively_exploited_vulnerability"

    def test_notification_level_is_24h(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["notification_level"] == "24h"

    def test_report_title_matches_flaw_title(self):
        report = _create_vulnerability_report(title="CVE-2026-99999 kernel: overflow")
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["report_title"] == report.title
        assert "kernel: overflow" in payload["report_title"]

    def test_manufacturer_name_from_report(self):
        report = _create_vulnerability_report(
            report_attrs={"manufacturer_or_steward_name": "Red Hat, Inc."},
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["manufacturer_or_steward_name"] == "Red Hat, Inc."

    def test_manufacturer_name_empty_when_not_set(self):
        report = _create_vulnerability_report(
            report_attrs={"manufacturer_or_steward_name": ""},
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["manufacturer_or_steward_name"] == ""

    def test_product_type_is_empty(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["product_type"] == ""

    def test_product_category_is_empty(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["product_category"] == ""

    def test_member_states_from_report(self):
        report = _create_vulnerability_report(
            report_attrs={"member_states_available": ["IE", "DE"]},
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert json.loads(payload["member_states_available"]) == ["IE", "DE"]

    def test_member_states_empty_list_when_not_set(self):
        report = _create_vulnerability_report(
            report_attrs={"member_states_available": []},
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert json.loads(payload["member_states_available"]) == []


class TestPrepare24hPayloadProductIdentity:
    def test_product_identity_from_affects(self):
        report = _create_vulnerability_report()
        ps_module = PsModuleFactory(name="rhel-9")
        stream = PsUpdateStreamFactory(ps_module=ps_module)
        AffectFactory(
            flaw=report.flaw,
            ps_update_stream=stream.name,
            ps_component="kernel",
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        products = json.loads(payload["product_identity"])
        assert len(products) == 1
        assert products[0]["ps_module"] == "rhel-9"
        assert products[0]["ps_component"] == "kernel"

    def test_product_identity_multiple_affects(self):
        report = _create_vulnerability_report()
        AffectFactory(flaw=report.flaw, ps_module="rhel-9.5.0", ps_component="kernel")
        AffectFactory(flaw=report.flaw, ps_module="rhel-8.10.0", ps_component="kernel")
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        products = json.loads(payload["product_identity"])
        assert len(products) == 2

    def test_product_identity_empty_when_no_affects(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        products = json.loads(payload["product_identity"])
        assert products == []


class TestPrepare24hPayloadVulnerability:
    def test_cve_id_from_flaw(self):
        report = _create_vulnerability_report(cve_id="CVE-2026-12345")
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["cve_id"] == "CVE-2026-12345"

    def test_cve_id_empty_when_flaw_has_no_cve(self):
        report = _create_vulnerability_report(cve_id="")
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["cve_id"] == ""

    def test_no_incident_fields_for_vulnerability(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "suspected_unlawful_or_malicious_acts" not in payload


class TestPrepare24hPayloadIncident:
    def test_incident_fields_present(self):
        report = _create_incident_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["suspected_unlawful_or_malicious_acts"] == ""

    def test_no_cve_id_field_for_incident(self):
        report = _create_incident_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "cve_id" not in payload

    def test_notification_type_is_severe_incident(self):
        report = _create_incident_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["notification_type"] == "severe_incident"


class TestPrepare24hPayloadMissingFields:
    def test_manual_fields_listed_as_missing(self):
        report = _create_vulnerability_report(
            report_attrs={"manufacturer_or_steward_name": "Red Hat"},
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "product_type" in missing
        assert "product_category" in missing

    def test_empty_member_states_listed_as_missing(self):
        report = _create_vulnerability_report(
            report_attrs={"member_states_available": []},
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "member_states_available" in missing

    def test_missing_cve_id_for_vulnerability(self):
        report = _create_vulnerability_report(cve_id="")
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "cve_id" in missing

    def test_no_missing_cve_id_when_present(self):
        report = _create_vulnerability_report(cve_id="CVE-2026-99999")
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "cve_id" not in missing

    def test_incident_missing_malicious_acts(self):
        report = _create_incident_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "suspected_unlawful_or_malicious_acts" in missing

    def test_no_missing_product_identity_when_affects_exist(self):
        report = _create_vulnerability_report()
        AffectFactory(flaw=report.flaw, ps_module="rhel-9", ps_component="kernel")
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "product_identity" not in missing

    def test_missing_product_identity_when_no_affects(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "product_identity" in missing


class TestPrepare24hPayloadMetaAttr:
    def test_prepared_at_stored_in_meta_attr(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        assert "prepared_at" in milestone.meta_attr
        assert milestone.meta_attr["prepared_at"]

    def test_payload_snapshot_is_valid_json(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert isinstance(payload, dict)

    def test_all_meta_attr_values_are_strings(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        for key, value in milestone.meta_attr.items():
            assert isinstance(value, str), f"meta_attr[{key}] is {type(value)}, not str"

    def test_does_not_call_save(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        original_pk = milestone.pk
        prepare_24h_payload(milestone)
        refreshed = SRPReportMilestone.objects.get(pk=original_pk)
        assert refreshed.meta_attr.get("payload_snapshot") is None

    def test_idempotent_produces_fresh_snapshot(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        first_prepared_at = milestone.meta_attr["prepared_at"]
        first_payload = milestone.meta_attr["payload_snapshot"]

        prepare_24h_payload(milestone)
        second_prepared_at = milestone.meta_attr["prepared_at"]
        second_payload = milestone.meta_attr["payload_snapshot"]

        assert second_prepared_at >= first_prepared_at
        assert second_payload == first_payload


# ── 72h Milestone Tests ──


class TestPrepare72hPayloadValidation:
    def test_raises_for_24h_milestone(self):
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H,
            srp_report__flaw__major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with pytest.raises(ValueError, match="Expected 72h milestone"):
            prepare_72h_payload(milestone)

    def test_raises_for_final_milestone(self):
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_FINAL,
            srp_report__flaw__major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with pytest.raises(ValueError, match="Expected 72h milestone"):
            prepare_72h_payload(milestone)


class TestPrepare72hPayloadCarryForward:
    def test_carries_forward_common_fields_from_24h(self):
        report = _create_vulnerability_report()
        m24 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(m24)
        snapshot = json.loads(m24.meta_attr["payload_snapshot"])
        snapshot["only_in_24h"] = "kept"
        m24.meta_attr["payload_snapshot"] = json.dumps(snapshot)
        m24.save()

        m72 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_72H)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert payload["only_in_24h"] == "kept"

    def test_72h_overrides_notification_level(self):
        report = _create_vulnerability_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert payload["notification_level"] == "72h"

    def test_works_without_24h_snapshot(self):
        report = _create_vulnerability_report()
        m72 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_72H)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert isinstance(payload, dict)
        assert "notification_type" in payload


class TestPrepare72hPayloadVulnerability:
    def test_cve_id_present(self):
        report = _create_vulnerability_report(cve_id="CVE-2026-72001")
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert payload["cve_id"] == "CVE-2026-72001"

    def test_general_information_from_flaw(self):
        report = _create_vulnerability_report(
            title="Buffer overflow in libfoo",
            cve_description="A buffer overflow vulnerability in libfoo allows...",
            statement="This affects all versions prior to 2.0.",
        )
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "Buffer overflow in libfoo" in payload["general_information"]

    def test_nature_of_vulnerability_from_cwe(self):
        report = _create_vulnerability_report(cwe_id="CWE-79")
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert payload["general_nature_of_vulnerability"] == "CWE-79"

    def test_nature_of_vulnerability_empty_when_no_cwe(self):
        report = _create_vulnerability_report(cwe_id="")
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert payload["general_nature_of_vulnerability"] == ""

    def test_corrective_measures_from_mitigation(self):
        report = _create_vulnerability_report(mitigation="Apply patch 1.2.3")
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "Apply patch 1.2.3" in payload["corrective_or_mitigating_measures_taken"]

    def test_user_mitigations_from_mitigation(self):
        report = _create_vulnerability_report(
            mitigation="Disable feature X as workaround"
        )
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert (
            "Disable feature X"
            in payload["corrective_or_mitigating_measures_users_can_take"]
        )

    def test_information_sensitivity_is_empty(self):
        report = _create_vulnerability_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert payload["information_sensitivity"] == ""

    def test_no_incident_fields_for_vulnerability(self):
        report = _create_vulnerability_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "incident_detected_at" not in payload
        assert "initial_incident_assessment" not in payload


class TestPrepare72hPayloadIncident:
    def test_incident_fields_present(self):
        report = _create_incident_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "suspected_unlawful_or_malicious_acts" in payload
        assert "general_incident_information" in payload
        assert "incident_detected_at" in payload
        assert "incident_occurred_at" in payload
        assert "initial_incident_assessment" in payload

    def test_incident_timestamps_are_empty(self):
        report = _create_incident_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert payload["incident_detected_at"] == ""
        assert payload["incident_occurred_at"] == ""

    def test_initial_assessment_from_comment_zero(self):
        report = _create_incident_report(comment_zero="Initial analysis shows...")
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "Initial analysis shows" in payload["initial_incident_assessment"]

    def test_no_cve_id_for_incident(self):
        report = _create_incident_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "cve_id" not in payload


class TestPrepare72hPayloadMissingFields:
    def test_missing_general_information_when_no_data(self):
        report = _create_vulnerability_report()
        _clear_flaw_fields(
            report,
            title="",
            cve_description="",
            mitre_cve_description="",
            statement="",
        )
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        missing = json.loads(m72.missing_required_fields)
        assert "general_information" in missing

    def test_missing_nature_of_vulnerability_when_no_cwe(self):
        report = _create_vulnerability_report(cwe_id="")
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        missing = json.loads(m72.missing_required_fields)
        assert "general_nature_of_vulnerability" in missing
        assert "general_nature_of_exploit" in missing

    def test_incident_timestamps_always_missing(self):
        report = _create_incident_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        missing = json.loads(m72.missing_required_fields)
        assert "incident_detected_at" in missing
        assert "incident_occurred_at" in missing


class TestPrepare72hPayloadMetaAttr:
    def test_prepared_at_stored(self):
        report = _create_vulnerability_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        assert "prepared_at" in m72.meta_attr

    def test_all_values_are_strings(self):
        report = _create_vulnerability_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        for key, value in m72.meta_attr.items():
            assert isinstance(value, str), f"meta_attr[{key}] is {type(value)}"

    def test_payload_is_valid_json(self):
        report = _create_vulnerability_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert isinstance(payload, dict)


# ── Final Milestone Tests ──


class TestPrepareFinalPayloadValidation:
    def test_raises_for_24h_milestone(self):
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_24H,
            srp_report__flaw__major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with pytest.raises(ValueError, match="Expected final milestone"):
            prepare_final_payload(milestone)

    def test_raises_for_72h_milestone(self):
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_72H,
            srp_report__flaw__major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with pytest.raises(ValueError, match="Expected final milestone"):
            prepare_final_payload(milestone)


class TestPrepareFinalPayloadCarryForward:
    def test_carries_forward_from_72h(self):
        report = _create_vulnerability_report()
        m24 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(m24)
        m24.save()
        m72 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_72H)
        prepare_72h_payload(m72)
        snapshot = json.loads(m72.meta_attr["payload_snapshot"])
        snapshot["only_in_72h"] = "kept"
        m72.meta_attr["payload_snapshot"] = json.dumps(snapshot)
        m72.save()

        mfinal = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_FINAL)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["only_in_72h"] == "kept"

    def test_final_overrides_notification_level(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["notification_level"] == "final"

    def test_works_without_72h_snapshot(self):
        report = _create_vulnerability_report()
        mfinal = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_FINAL)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert isinstance(payload, dict)


class TestPrepareFinalPayloadVulnerability:
    def test_full_vulnerability_description(self):
        report = _create_vulnerability_report(
            title="Use-after-free in libbar",
            cve_description="A use-after-free vulnerability...",
            comment_zero="Detailed analysis of the vulnerability...",
            statement="Red Hat recommends upgrading to version 3.0.",
        )
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert "Use-after-free in libbar" in payload["full_vulnerability_description"]
        assert "Detailed analysis" in payload["full_vulnerability_description"]

    def test_vulnerability_severity_from_impact(self):
        report = _create_vulnerability_report(impact="CRITICAL")
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert "CRITICAL" in payload["vulnerability_severity"]

    def test_vulnerability_impact_from_affects(self):
        report = _create_vulnerability_report(impact="IMPORTANT")
        AffectFactory(
            flaw=report.flaw,
            ps_module="rhel-9",
            ps_component="openssl",
            affectedness="AFFECTED",
        )
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert "IMPORTANT" in payload["vulnerability_impact"]
        assert "openssl" in payload["vulnerability_impact"]

    def test_known_malicious_actor_is_empty(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["known_or_suspected_malicious_actor"] == ""

    def test_security_update_details_is_empty(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["security_update_or_corrective_measure_details"] == ""

    def test_corrective_measure_available_at_is_empty(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["corrective_or_mitigating_measure_available_at"] == ""


class TestPrepareFinalPayloadIncident:
    def test_incident_fields_present(self):
        report = _create_incident_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert "detailed_incident_description" in payload
        assert "incident_severity" in payload
        assert "incident_impact" in payload
        assert "likely_threat_or_root_cause" in payload
        assert "applied_and_ongoing_mitigation_measures" in payload

    def test_incident_severity_from_impact(self):
        report = _create_incident_report(impact="MODERATE")
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert "MODERATE" in payload["incident_severity"]

    def test_likely_threat_from_cwe(self):
        report = _create_incident_report(cwe_id="CWE-502")
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["likely_threat_or_root_cause"] == "CWE-502"

    def test_likely_threat_empty_when_no_cwe(self):
        report = _create_incident_report(cwe_id="")
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["likely_threat_or_root_cause"] == ""


class TestPrepareFinalPayloadMissingFields:
    def test_missing_full_description_when_empty(self):
        report = _create_vulnerability_report()
        _clear_flaw_fields(
            report,
            title="",
            cve_description="",
            mitre_cve_description="",
            comment_zero="",
            statement="",
        )
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        missing = json.loads(mfinal.missing_required_fields)
        assert "full_vulnerability_description" in missing

    def test_missing_security_update_details(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        missing = json.loads(mfinal.missing_required_fields)
        assert "security_update_or_corrective_measure_details" in missing

    def test_missing_incident_fields(self):
        report = _create_incident_report(cwe_id="")
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        missing = json.loads(mfinal.missing_required_fields)
        assert "likely_threat_or_root_cause" in missing


class TestPrepareFinalPayloadMetaAttr:
    def test_prepared_at_stored(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        assert "prepared_at" in mfinal.meta_attr

    def test_all_values_are_strings(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        for key, value in mfinal.meta_attr.items():
            assert isinstance(value, str), f"meta_attr[{key}] is {type(value)}"


# ── Generic prepare_payload() Tests ──


class TestPreparePayloadDispatch:
    def test_dispatches_24h(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["notification_level"] == "24h"

    def test_dispatches_72h(self):
        report = _create_vulnerability_report()
        m72 = _prepare_chain_up_to_72h(report)
        prepare_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert payload["notification_level"] == "72h"

    def test_dispatches_final(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["notification_level"] == "final"

    def test_raises_for_unknown_type(self):
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
            srp_report__flaw__major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with pytest.raises(ValueError, match="No builder"):
            prepare_payload(milestone)
