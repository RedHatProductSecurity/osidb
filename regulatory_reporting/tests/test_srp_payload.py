import json
from types import SimpleNamespace

import pytest
from django.utils import timezone

from osidb.models import Flaw, FlawCVSS
from osidb.tests.factories import (
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
)
from regulatory_reporting.models import SRPReport, SRPReportMilestone
from regulatory_reporting.serializers import (
    SRPReportMilestoneCreateSerializer,
    SRPReportMilestoneSerializer,
)
from regulatory_reporting.services import (
    BUILDER_BY_MILESTONE_TYPE,
    SRPPayloadBuilder,
    prepare_24h_payload,
    prepare_72h_payload,
    prepare_final_payload,
    prepare_payload,
)
from regulatory_reporting.tests.factories import (
    SRPReportMilestoneFactory,
    SRPReportWithMilestonesFactory,
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


def _create_vulnerability_report(
    report_attrs=None,
    reportable_event_type=SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED,
    **flaw_kwargs,
):
    """Create a Flaw."""
    flaw_kwargs["major_incident_state"] = Flaw.FlawMajorIncident.EXPLOITS_KEV_APPROVED
    flaw_kwargs.setdefault("embargoed", False)
    flaw_kwargs.setdefault("major_incident_start_dt", timezone.now())
    flaw = FlawFactory(**flaw_kwargs)
    report = SRPReportWithMilestonesFactory(
        flaw=flaw,
        reportable_event_type=reportable_event_type,
    )
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
        report = _create_vulnerability_report(
            report_attrs={"title": "CVE-2026-99999 kernel: overflow"}
        )
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
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            report_attrs={
                "incident_state": Flaw.FlawMajorIncident.MAJOR_INCIDENT_APPROVED
            },
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["suspected_unlawful_or_malicious_acts"] == ""

    def test_no_cve_id_field_for_incident(self):
        report = _create_vulnerability_report(
            report_attrs={"cve_id": ""},
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "cve_id" not in payload

    def test_notification_type_is_severe_incident(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )
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
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )
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
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "suspected_unlawful_or_malicious_acts" in payload
        assert "general_incident_information" in payload
        assert "incident_detected_at" in payload
        assert "incident_occurred_at" in payload
        assert "initial_incident_assessment" in payload

    def test_incident_detected_at_carried_from_24h(self):
        """incident_detected_at is carried forward from the 24h snapshot.

        The 24h builder derives it from flaw.major_incident_start_dt.
        The 72h builder initialises it to "" as a placeholder; carry-forward
        in prepare() replaces empty-string placeholders with earlier values.
        incident_occurred_at has no 24h source, so it stays empty.
        """
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        # major_incident_start_dt is set by default in _create_vulnerability_report
        assert (
            payload["incident_detected_at"]
            == report.flaw.major_incident_start_dt.isoformat()
        )
        assert payload["incident_occurred_at"] == ""

    def test_initial_assessment_from_comment_zero(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            comment_zero="Initial analysis shows...",
        )
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "Initial analysis shows" in payload["initial_incident_assessment"]

    def test_no_cve_id_for_incident(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )
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

    def test_incident_occurred_at_always_missing(self):
        """incident_occurred_at has no automatic source so is always missing at 72h.

        incident_detected_at is NOT missing when the 24h snapshot carried a
        value from flaw.major_incident_start_dt (see test_incident_detected_at_carried_from_24h).
        """
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )
        m72 = _prepare_chain_up_to_72h(report)
        prepare_72h_payload(m72)
        missing = json.loads(m72.missing_required_fields)
        assert "incident_occurred_at" in missing
        assert "incident_detected_at" not in missing


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

    def test_vulnerability_severity_prefers_highest_rh_cvss_version(self):
        report = _create_vulnerability_report(impact="IMPORTANT")
        FlawCVSSFactory(
            flaw=report.flaw,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION3,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        FlawCVSSFactory(
            flaw=report.flaw,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION4,
            vector=("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
        )
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert "CVSS V4:" in payload["vulnerability_severity"]
        assert "CVSS V3:" not in payload["vulnerability_severity"]

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
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED
        )
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert "detailed_incident_description" in payload
        assert "incident_severity" in payload
        assert "incident_impact" in payload
        assert "likely_threat_or_root_cause" in payload
        assert "applied_and_ongoing_mitigation_measures" in payload

    def test_incident_severity_from_impact(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            impact="MODERATE",
        )
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert "MODERATE" in payload["incident_severity"]

    def test_likely_threat_from_cwe(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            cwe_id="CWE-502",
        )
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        payload = json.loads(mfinal.meta_attr["payload_snapshot"])
        assert payload["likely_threat_or_root_cause"] == "CWE-502"

    def test_likely_threat_empty_when_no_cwe(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            cwe_id="",
        )
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
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            cwe_id="",
        )
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


class TestAdditionalDetailsOverride:
    def test_additional_details_overrides_auto_derived_field(self):
        """Coordinator-set values win over auto-derived ones."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {"product_type": "software"}
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["product_type"] == "software"

    def test_additional_details_satisfies_missing_required_field(self):
        """A required field supplied via additional_details is not listed as missing."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {
            "product_type": "software",
            "product_category": "operating_system",
        }
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "product_type" not in missing
        assert "product_category" not in missing

    def test_missing_required_field_still_reported_when_not_in_additional_details(self):
        """Required fields absent from both auto-derived and additional_details are still missing."""
        report = _create_vulnerability_report(
            report_attrs={"manufacturer_or_steward_name": ""},
        )
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {
            "product_type": "software"
        }  # only satisfies one
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "product_category" in missing  # not in additional_details
        assert "product_type" not in missing  # was supplied

    def test_empty_additional_details_has_no_effect(self):
        """Empty additional_details is a no-op — regression guard."""
        report = _create_vulnerability_report(cve_id="CVE-2026-11111")
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {}
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["cve_id"] == "CVE-2026-11111"
        assert payload["product_type"] == ""

    def test_derived_field_cannot_be_overridden(self):
        """Fields computed by OSIDB (notification_type, notification_level,
        product_identity) must be ignored even when present in additional_details."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {
            "notification_type": "HACKED",
            "notification_level": "HACKED",
            "product_identity": "HACKED",
            "product_type": "software",  # this one should still go through
        }
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["notification_type"] != "HACKED"
        assert payload["notification_level"] != "HACKED"
        assert payload["product_identity"] != "HACKED"
        assert payload["product_type"] == "software"

    def test_unknown_key_is_dropped(self):
        """Keys not present in the assembled payload are silently ignored."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {"totally_unknown_field": "injected"}
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "totally_unknown_field" not in payload

    def test_wrong_type_value_is_dropped(self):
        """A non-str override value (e.g. int) is skipped; the auto-derived
        value wins and the required-field check is not bypassed."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {"product_type": 42}  # int, not str
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        # auto-derived default (empty string) wins because 42 was rejected
        assert payload["product_type"] == ""

    def test_member_states_available_list_is_json_serialised(self):
        """A list override for member_states_available is converted to a
        JSON string to match the type set by _build_common_fields."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {"member_states_available": ["DE", "FR"]}
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["member_states_available"] == json.dumps(["DE", "FR"])

    def test_member_states_available_wrong_type_is_dropped(self):
        """A non-list, non-str override for member_states_available is dropped."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {"member_states_available": 123}
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        # falls back to auto-derived value (json.dumps([]))
        assert payload["member_states_available"] == json.dumps([])

    def test_member_states_available_invalid_entry_is_dropped(self):
        """A list containing a non-string or out-of-allow-list entry is rejected
        wholesale; the auto-derived value is used instead."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {"member_states_available": ["DE", 42, "FR"]}
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["member_states_available"] == json.dumps([])

    @pytest.mark.parametrize(
        "bad_str",
        [
            "not-json",  # malformed JSON
            '"DE"',  # valid JSON but not a list
            '["DE", 42]',  # list with a non-string entry
            '["DE", "XX"]',  # list with an out-of-allow-list code
        ],
    )
    def test_member_states_available_invalid_str_is_dropped(self, bad_str):
        """String overrides that are malformed JSON, non-list JSON, or contain
        invalid entries are rejected; the auto-derived value is used."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {"member_states_available": bad_str}
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["member_states_available"] == json.dumps([])

    def test_member_states_available_valid_json_str_is_accepted(self):
        """A pre-serialised JSON string carrying valid member-state codes
        (e.g. carried from a previous payload snapshot) is parsed, validated,
        and re-serialised to the canonical format."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {
            "member_states_available": json.dumps(["IE", "DE"])
        }
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["member_states_available"] == json.dumps(["IE", "DE"])


class TestPreparePayloadOnSubmitted:
    def test_prepares_payload_when_status_becomes_submitted(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        assert milestone.meta_attr.get("payload_snapshot") is None

        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone.save()

        milestone.refresh_from_db()
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["notification_level"] == "24h"
        assert "prepared_at" in milestone.meta_attr

    def test_does_not_reprepare_when_already_submitted_and_details_unchanged(self):
        """Non-additional_details field changes on a submitted milestone must
        not trigger a re-prepare (prepared_at should stay the same)."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone.save()
        first_prepared_at = milestone.meta_attr["prepared_at"]

        milestone.request_source = "manual update"
        milestone.save()
        milestone.refresh_from_db()
        assert milestone.meta_attr["prepared_at"] == first_prepared_at

    def test_reprepares_when_additional_details_changes_on_submitted_milestone(self):
        """Changing additional_details on an already-submitted milestone must
        atomically rebuild the snapshot so it stays current."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone.save()
        milestone.refresh_from_db()
        first_prepared_at = milestone.meta_attr["prepared_at"]
        first_payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert first_payload["product_type"] == ""

        milestone.additional_details = {"product_type": "firmware"}
        milestone.save()
        milestone.refresh_from_db()

        updated_payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert updated_payload["product_type"] == "firmware"
        # prepared_at must have advanced to reflect the re-prepare
        assert milestone.meta_attr["prepared_at"] > first_prepared_at

    def test_additional_details_excluded_from_update_fields_does_not_reprepare(
        self,
    ):
        """When save() is called with update_fields that does not include
        additional_details, an in-memory change to additional_details must not
        trigger snapshot preparation (the field is not being persisted)."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone.save()
        milestone.refresh_from_db()
        first_prepared_at = milestone.meta_attr["prepared_at"]

        # Mutate additional_details in memory but persist only an unrelated field.
        milestone.additional_details = {"product_type": "firmware"}
        milestone.save(update_fields=["request_source"])
        milestone.refresh_from_db()

        assert milestone.meta_attr["prepared_at"] == first_prepared_at

    def test_does_not_prepare_for_prepared_status(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.IN_REVIEW
        milestone.save()
        milestone.refresh_from_db()
        assert milestone.meta_attr.get("payload_snapshot") is None

    def test_skips_additional_information_response(self):
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
            srp_report__flaw__major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            status=SRPReportMilestone.SRPReportMilestoneStatus.REQUIRED,
        )
        milestone.status = SRPReportMilestone.SRPReportMilestoneStatus.SUBMITTED
        milestone.save()
        milestone.refresh_from_db()
        assert milestone.meta_attr.get("payload_snapshot") is None


# ── Step 1: Required date fields in 24h builders ──


class TestPrepare24hDateFields:
    def test_aev_detected_at_from_flaw_reported_dt(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["aev_detected_at"] == report.flaw.reported_dt.isoformat()

    def test_aev_detected_at_empty_when_no_reported_dt(self):
        report = _create_vulnerability_report()
        _clear_flaw_fields(report, reported_dt=None)
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["aev_detected_at"] == ""

    def test_aev_detected_at_is_required_24h(self):
        report = _create_vulnerability_report()
        _clear_flaw_fields(report, reported_dt=None)
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "aev_detected_at" in missing

    def test_no_missing_aev_detected_at_when_reported_dt_set(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "aev_detected_at" not in missing

    def test_incident_detected_at_from_major_incident_start_dt(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
        )
        # major_incident_start_dt is set by default in _create_vulnerability_report
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert (
            payload["incident_detected_at"]
            == report.flaw.major_incident_start_dt.isoformat()
        )

    def test_incident_detected_at_empty_when_no_start_dt(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
        )
        _clear_flaw_fields(report, major_incident_start_dt=None)
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["incident_detected_at"] == ""

    def test_incident_detected_at_is_required_24h(self):
        report = _create_vulnerability_report(
            reportable_event_type=SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
        )
        _clear_flaw_fields(report, major_incident_start_dt=None)
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(milestone.missing_required_fields)
        assert "incident_detected_at" in missing

    def test_aev_detected_at_carried_forward_to_72h(self):
        """aev_detected_at is set by 24h and carried forward; 72h does not override it."""
        report = _create_vulnerability_report()
        m24 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(m24)
        m24.save()

        m72 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_72H)
        prepare_72h_payload(m72)
        payload = json.loads(m72.meta_attr["payload_snapshot"])
        assert "aev_detected_at" in payload
        assert payload["aev_detected_at"] == report.flaw.reported_dt.isoformat()


# ── Step 2: Final AEV required field ──


class TestPrepareFinalCorrectiveMeasureRequired:
    def test_corrective_measure_available_at_required_at_final(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        missing = json.loads(mfinal.missing_required_fields)
        assert "corrective_or_mitigating_measure_available_at" in missing

    def test_corrective_measure_available_at_satisfied_via_additional_details(self):
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        mfinal.additional_details = {
            "corrective_or_mitigating_measure_available_at": "2025-06-01T00:00:00+00:00"
        }
        prepare_final_payload(mfinal)
        missing = json.loads(mfinal.missing_required_fields)
        assert "corrective_or_mitigating_measure_available_at" not in missing


# ── Step 3: Optional CRA payload keys ──


class TestOptionalCRAKeys:
    def test_product_class_in_all_payloads(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "product_class" in payload
        assert payload["product_class"] == ""

    def test_end_of_support_in_all_payloads(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "end_of_support" in payload
        assert payload["end_of_support"] == ""

    def test_mitigating_measure_expected_shortly_in_all_payloads(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "mitigating_measure_expected_shortly" in payload

    def test_attack_vector_in_all_payloads(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "attack_vector" in payload

    def test_euvd_id_in_aev_payload(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "euvd_id" in payload
        assert payload["euvd_id"] == ""

    def test_further_information_in_aev_payload(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "further_information" in payload
        assert payload["further_information"] == ""

    def test_pec_keys_only_in_72h_payload(self):
        """pec/pec_delay_reason are set by the 72h builder; absent in 24h and
        in Final when built without a prior 72h snapshot."""
        report = _create_vulnerability_report()

        m24 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(m24)
        m24.save()
        assert "pec" not in json.loads(m24.meta_attr["payload_snapshot"])
        assert "pec_delay_reason" not in json.loads(m24.meta_attr["payload_snapshot"])

        m72 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_72H)
        prepare_72h_payload(m72)
        assert "pec" in json.loads(m72.meta_attr["payload_snapshot"])
        assert "pec_delay_reason" in json.loads(m72.meta_attr["payload_snapshot"])

    def test_euvd_id_overridable_via_additional_details(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        milestone.additional_details = {"euvd_id": "EUVD-2025-001"}
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert payload["euvd_id"] == "EUVD-2025-001"

    def test_information_sensitivity_in_24h_payload(self):
        """information_sensitivity added as optional key at 24h (decision 2)."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        payload = json.loads(milestone.meta_attr["payload_snapshot"])
        assert "information_sensitivity" in payload
        assert payload["information_sensitivity"] == ""


# ── Step 4: Conditionally required fields ──


class TestConditionallyRequiredFields:
    def test_missing_conditionally_required_stored_in_meta_attr(self):
        """Final AEV without malicious actor: key appears in meta_attr."""
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        missing = json.loads(mfinal.meta_attr["missing_conditionally_required_fields"])
        assert "known_or_suspected_malicious_actor" in missing

    def test_conditionally_required_satisfied_when_provided(self):
        """Supply known_or_suspected_malicious_actor via additional_details: absent from list."""
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        mfinal.additional_details = {"known_or_suspected_malicious_actor": "APT-29"}
        prepare_final_payload(mfinal)
        missing = json.loads(mfinal.meta_attr["missing_conditionally_required_fields"])
        assert "known_or_suspected_malicious_actor" not in missing

    def test_conditionally_required_empty_for_24h(self):
        """24h has no REQUIRED_IF_AVAILABLE fields defined."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        prepare_24h_payload(milestone)
        missing = json.loads(
            milestone.meta_attr["missing_conditionally_required_fields"]
        )
        assert missing == []

    def test_conditionally_required_not_in_missing_required_fields(self):
        """Conditionally required fields must NOT appear in missing_required_fields."""
        report = _create_vulnerability_report()
        mfinal = _prepare_chain_up_to_final(report)
        prepare_final_payload(mfinal)
        required_missing = json.loads(mfinal.missing_required_fields)
        assert "known_or_suspected_malicious_actor" not in required_missing


# ── Step 5: Serializer validation of additional_details keys ──


def _milestone_patch_serializer(milestone, additional_details):
    """Instantiate SRPReportMilestoneSerializer for a PATCH of additional_details."""
    request = SimpleNamespace(
        data={"additional_details": additional_details},
        query_params={},
        method="PATCH",
        user=SimpleNamespace(groups=SimpleNamespace(all=lambda: [])),
    )
    return SRPReportMilestoneSerializer(
        milestone,
        data={"additional_details": additional_details},
        partial=True,
        context={"request": request},
    )


def _milestone_create_serializer(additional_details):
    """Instantiate SRPReportMilestoneCreateSerializer for a POST (no instance)."""
    request = SimpleNamespace(
        data={"additional_details": additional_details},
        query_params={},
        method="POST",
        user=SimpleNamespace(groups=SimpleNamespace(all=lambda: [])),
    )
    return SRPReportMilestoneCreateSerializer(
        data={"additional_details": additional_details},
        context={"request": request},
    )


class TestAdditionalDetailsKeyValidation:
    def test_unknown_key_raises_validation_error(self):
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        ser = _milestone_patch_serializer(milestone, {"nonexistent_key": "x"})
        assert not ser.is_valid()
        assert "additional_details" in ser.errors

    def test_derived_field_raises_validation_error(self):
        """notification_type is DERIVED; must be rejected even though it exists in payload."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        ser = _milestone_patch_serializer(milestone, {"notification_type": "hacked"})
        assert not ser.is_valid()
        assert "additional_details" in ser.errors

    def test_pec_key_rejected_on_final_milestone(self):
        """pec is only in 72h OVERRIDABLE_VULNERABILITY_KEYS; must fail on final."""
        report = _create_vulnerability_report()
        mfinal = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_FINAL)
        ser = _milestone_patch_serializer(mfinal, {"pec": "delayed"})
        assert not ser.is_valid()
        assert "additional_details" in ser.errors

    def test_valid_common_key_accepted(self):
        """product_type is overridable for all milestone types."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        ser = _milestone_patch_serializer(milestone, {"product_type": "software"})
        assert ser.is_valid(), ser.errors

    def test_valid_vulnerability_key_accepted_on_24h(self):
        """euvd_id is in 24h OVERRIDABLE_VULNERABILITY_KEYS."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        ser = _milestone_patch_serializer(milestone, {"euvd_id": "EUVD-2025-001"})
        assert ser.is_valid(), ser.errors

    def test_pec_key_accepted_on_72h_milestone(self):
        """pec is valid at 72h."""
        report = _create_vulnerability_report()
        m72 = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_72H)
        ser = _milestone_patch_serializer(m72, {"pec": "delayed"})
        assert ser.is_valid(), ser.errors

    def test_mixed_valid_and_invalid_keys_rejected(self):
        """Even one unknown key causes rejection."""
        report = _create_vulnerability_report()
        milestone = _get_milestone(report, SRPReportMilestone.MilestoneType.LEVEL_24H)
        ser = _milestone_patch_serializer(
            milestone, {"product_type": "software", "unknown_key": "bad"}
        )
        assert not ser.is_valid()
        assert "additional_details" in ser.errors

    def test_create_with_additional_details_rejected(self):
        """Create serializer rejects any additional_details on additional_information_response."""
        ser = _milestone_create_serializer({"any_key": "value"})
        assert not ser.is_valid()
        assert "additional_details" in ser.errors

    def test_patch_additional_information_response_rejected(self):
        """PATCH additional_information_response milestone rejects all additional_details keys."""
        report = _create_vulnerability_report()
        milestone = SRPReportMilestoneFactory(
            milestone_type=SRPReportMilestone.MilestoneType.LEVEL_ADDITIONAL_INFORMATION_RESPONSE,
            srp_report=report,
            acl_read=report.acl_read,
            acl_write=report.acl_write,
        )
        ser = _milestone_patch_serializer(milestone, {"product_type": "software"})
        assert not ser.is_valid()
        assert "additional_details" in ser.errors


# ── Step 6: Overridable-keys drift guard ──


class TestOverridableKeysDriftGuard:
    """overridable_keys must always be a subset of the assembled payload.

    Ensures that adding a new overridable key without the matching payload
    field is caught before it reaches production.
    """

    @pytest.mark.parametrize(
        "milestone_type,event_type",
        [
            (
                SRPReportMilestone.MilestoneType.LEVEL_24H,
                SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED,
            ),
            (
                SRPReportMilestone.MilestoneType.LEVEL_72H,
                SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED,
            ),
            (
                SRPReportMilestone.MilestoneType.LEVEL_FINAL,
                SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED,
            ),
            (
                SRPReportMilestone.MilestoneType.LEVEL_24H,
                SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            ),
            (
                SRPReportMilestone.MilestoneType.LEVEL_72H,
                SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            ),
            (
                SRPReportMilestone.MilestoneType.LEVEL_FINAL,
                SRPReport.ReportableEventType.MAJOR_INCIDENT_APPROVED,
            ),
        ],
    )
    def test_overridable_keys_subset_of_payload(self, milestone_type, event_type):
        report = _create_vulnerability_report(reportable_event_type=event_type)
        milestone = _get_milestone(report, milestone_type)
        builder_cls = BUILDER_BY_MILESTONE_TYPE[milestone_type]
        builder = builder_cls(milestone)
        payload = builder._build_common_fields()
        if event_type == SRPReport.ReportableEventType.EXPLOITS_KEV_APPROVED:
            payload.update(builder._build_vulnerability_fields())
        else:
            payload.update(builder._build_incident_fields())

        overridable = builder_cls.overridable_keys(event_type)
        assert overridable <= set(payload.keys()), (
            f"Overridable keys drifted out of payload for "
            f"{milestone_type}/{event_type}: {overridable - set(payload.keys())}"
        )
        assert not overridable & SRPPayloadBuilder.DERIVED_PAYLOAD_FIELDS, (
            f"Overridable keys overlap DERIVED_PAYLOAD_FIELDS: "
            f"{overridable & SRPPayloadBuilder.DERIVED_PAYLOAD_FIELDS}"
        )
