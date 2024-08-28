"""
Bugzilla specific tracker test cases
"""

import json
from typing import Any, Dict

import pytest
from django.utils.timezone import datetime, make_aware

from apps.sla.tests.test_framework import load_sla_policies
from apps.trackers.exceptions import (
    ComponentUnavailableError,
    NoSecurityLevelAvailableError,
    NoTargetReleaseVersionAvailableError,
)
from apps.trackers.jira.constants import PS_ADDITIONAL_FIELD_TO_JIRA
from apps.trackers.jira.query import JiraPriority, OldTrackerJiraQueryBuilder
from apps.trackers.models import JiraProjectFields
from apps.trackers.tests.factories import JiraProjectFieldsFactory
from osidb.models import (
    Affect,
    CompliancePriority,
    ContractPriority,
    Flaw,
    Impact,
    PsUpdateStream,
    Tracker,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestOldTrackerJiraQueryBuilder:
    """
    test Jira tracker query building
    """

    @pytest.mark.parametrize(
        "flaw_impact,affect_impact,expected_impact",
        [
            (Impact.LOW, Impact.LOW, JiraPriority.MINOR),
            (Impact.MODERATE, Impact.NOVALUE, JiraPriority.NORMAL),
            (Impact.MODERATE, Impact.LOW, JiraPriority.MINOR),
            (Impact.CRITICAL, Impact.NOVALUE, JiraPriority.CRITICAL),
            (Impact.CRITICAL, Impact.LOW, JiraPriority.MINOR),
            (Impact.LOW, Impact.LOW, JiraPriority.MINOR),
            (Impact.LOW, Impact.MODERATE, JiraPriority.NORMAL),
            (Impact.LOW, Impact.CRITICAL, JiraPriority.CRITICAL),
        ],
    )
    def test_generate_query(self, flaw_impact, affect_impact, expected_impact):
        """
        test that query has all fields correctly generated
        """
        field = JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="priority",
            field_name="Priority",
            allowed_values=[
                "Blocker",
                "Critical",
                "Major",
                "Normal",
                "Minor",
                "Undefined",
            ],
        )
        field.save()
        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="versions",
            field_name="Affects Version/s",
            allowed_values=["1.2.3"],
        ).save()
        expected1 = {
            "fields": {
                "priority": {"name": expected_impact},
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Bug"},
                "summary": "CVE-2999-1000 foo-component: some description [bar-1.2.3]",
                "labels": [
                    "CVE-2999-1000",
                    "pscomponent:foo-component",
                    "SecurityTracking",
                    "Security",
                ],
                "versions": [
                    {"name": "1.2.3"},
                ],
            }
        }
        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=flaw_impact,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=affect_impact,
        )
        ps_module = PsModuleFactory(
            name="foo-module", bts_name="jboss", bts_key="FOOPROJECT"
        )
        stream = PsUpdateStreamFactory(
            ps_module=ps_module, name="bar-1.2.3", version="1.2.3"
        )
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=stream.name,
            embargoed=flaw.is_embargoed,
        )
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="security",
            field_name="Security Level",
            allowed_values=[
                "Embargoed Security Issue",
                "Red Hat Employee",
                "Red Hat Engineering Authorized",
                "Red Hat Partner",
                "Restricted",
                "Team",
            ],
        )

        quer_builder = OldTrackerJiraQueryBuilder(tracker)
        quer_builder.generate()
        validate_minimum_key_value(minimum=expected1, evaluated=quer_builder._query)

    @pytest.mark.parametrize(
        "meta, expected_labels",
        [
            (
                {"test": 1},
                [
                    "CVE-2000-2000",
                    "CVE-2000-2001",
                    "Security",
                    "SecurityTracking",
                    "flaw:bz#42",
                    "flaw:bz#72",
                    "flawuuid:b46a4c34-3c29-4fbd-8543-95d460bb3ceb",
                    "flawuuid:7f30f723-317d-4eff-97ed-65fc844e7c69",
                    "flawuuid:f3979e01-47ca-48e0-830c-ebe6fc02b259",
                    "pscomponent:component",
                ],
            ),
            (
                # Labels stored as str, as happens in HStoreField
                {
                    "labels": '["CVE-2000-2000", "SecurityTracking", "pscomponent:component", "Security", "validation-requested", "custom_label"]'
                },
                [
                    "CVE-2000-2000",
                    "CVE-2000-2001",
                    "Security",
                    "SecurityTracking",
                    "custom_label",
                    "flaw:bz#42",
                    "flaw:bz#72",
                    "flawuuid:b46a4c34-3c29-4fbd-8543-95d460bb3ceb",
                    "flawuuid:7f30f723-317d-4eff-97ed-65fc844e7c69",
                    "flawuuid:f3979e01-47ca-48e0-830c-ebe6fc02b259",
                    "pscomponent:component",
                ],
            ),
            (
                {"labels": []},
                [
                    "CVE-2000-2000",
                    "CVE-2000-2001",
                    "Security",
                    "SecurityTracking",
                    "flaw:bz#42",
                    "flaw:bz#72",
                    "flawuuid:b46a4c34-3c29-4fbd-8543-95d460bb3ceb",
                    "flawuuid:7f30f723-317d-4eff-97ed-65fc844e7c69",
                    "flawuuid:f3979e01-47ca-48e0-830c-ebe6fc02b259",
                    "pscomponent:component",
                ],
            ),
            (
                {
                    "labels": [
                        "CVE-1",
                        "CVE-2000-2000",
                        "CVE-2000-0001",
                        "Security",
                        "SecurityTracking",
                        "flaw:bz#42",
                        "flaw:bz#72",
                        "foobaa",
                        "foobar",
                        "foobaz",
                        "pscomponent:component",
                        "pscomponent:foobar",
                        "validation-requested",
                    ]
                },
                [
                    "CVE-1",
                    "CVE-2000-2000",
                    "CVE-2000-2001",
                    "Security",
                    "SecurityTracking",
                    "flaw:bz#42",
                    "flaw:bz#72",
                    "flawuuid:b46a4c34-3c29-4fbd-8543-95d460bb3ceb",
                    "flawuuid:7f30f723-317d-4eff-97ed-65fc844e7c69",
                    "flawuuid:f3979e01-47ca-48e0-830c-ebe6fc02b259",
                    "foobaa",
                    "foobar",
                    "foobaz",
                    "pscomponent:component",
                ],
            ),
        ],
    )
    def test_generate_labels(self, meta, expected_labels):
        """
        test that the query for the Jira labels is generated correctly
        """
        if "labels" in meta and not isinstance(meta["labels"], str):
            # Do what jiraffe/convertors.py::JiraTrackerConvertor._normalize normally does
            # when saving meta_attr (improve readability of pytest parameters).
            meta["labels"] = json.dumps(meta["labels"])
        flaw1 = FlawFactory(
            uuid="b46a4c34-3c29-4fbd-8543-95d460bb3ceb",
            bz_id="42",
            cve_id="CVE-2000-2000",
        )
        flaw2 = FlawFactory(
            uuid="7f30f723-317d-4eff-97ed-65fc844e7c69",
            bz_id="72",
            embargoed=flaw1.embargoed,
            cve_id=None,
        )
        flaw3 = FlawFactory(
            uuid="f3979e01-47ca-48e0-830c-ebe6fc02b259",
            bz_id=None,
            embargoed=flaw1.embargoed,
            cve_id="CVE-2000-2001",
        )
        ps_module = PsModuleFactory(bts_name="jboss")
        affect1 = AffectFactory(
            flaw=flaw1,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect3 = AffectFactory(
            flaw=flaw3,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect1, affect2, affect3],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw1.is_embargoed,
            meta_attr=meta,
        )

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert f"flawuuid:{flaw1.uuid}" in labels
        assert f"flawuuid:{flaw2.uuid}" in labels
        assert f"flawuuid:{flaw3.uuid}" in labels
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        assert "flaw:bz#42" in labels
        assert "flaw:bz#72" in labels
        assert "flaw:bz#" not in labels
        assert len(labels) == len(expected_labels)
        assert sorted(labels) == sorted(expected_labels)

    def test_generate_label_contract_priority(self):
        """
        test that the query for the Jira label contract-priority is generated correctly
        """
        flaw1 = FlawFactory(bz_id="42", cve_id="CVE-2000-2000")
        ps_module = PsModuleFactory(bts_name="jboss")
        affect1 = AffectFactory(
            flaw=flaw1,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect1],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw1.is_embargoed,
        )
        ContractPriority(ps_update_stream=ps_update_stream.name).save()

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert "contract-priority" in labels
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        assert "flaw:bz#42" in labels
        assert f"flawuuid:{flaw1}" in labels
        assert len(labels) == 7

    @pytest.mark.parametrize(
        "impact,yml_components",
        [
            (Impact.LOW, []),
            (Impact.MODERATE, []),
            (Impact.IMPORTANT, ["dummy_value", "component"]),
            (Impact.IMPORTANT, ["dummy_value", "foobar"]),
            (Impact.CRITICAL, []),
        ],
    )
    def test_generate_label_compliance_priority(self, impact, yml_components):
        """
        test that the query for the Jira label compliance-priority is generated correctly
        """
        flaw1 = FlawFactory(bz_id="42", cve_id="CVE-2000-2000", impact=impact)
        ps_module = PsModuleFactory(bts_name="jboss")
        affect1 = AffectFactory(
            flaw=flaw1,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=impact,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect1],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw1.is_embargoed,
        )
        ContractPriority(ps_update_stream=ps_update_stream.name).save()
        CompliancePriority(
            ps_module=ps_module.name,
            components=yml_components,
            streams=["dummy_value", ps_update_stream.name],
        ).save()

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert "contract-priority" in labels
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        assert "flaw:bz#42" in labels
        assert f"flawuuid:{flaw1}" in labels
        if impact == "LOW" or "foobar" in yml_components:
            assert "compliance-priority" not in labels
            assert len(labels) == 7
        else:
            assert "compliance-priority" in labels
            assert len(labels) == 8

    @pytest.mark.parametrize(
        "external_system_id, affectedness, preexisting_val_req_lbl, result_val_req_lbl",
        [
            # New tracker with NEW affect gets the label added on save.
            (None, Affect.AffectAffectedness.NEW, None, True),
            # New tracker with non-NEW affect doesn't get the label added on save.
            (None, Affect.AffectAffectedness.AFFECTED, None, False),
            # Existing tracker with the label already present keeps it after update
            # when its affects are NEW.
            ("JIRA-123", Affect.AffectAffectedness.NEW, True, True),
            # Existing tracker with the label already present doesn't keep it after update
            # when its affects are not NEW.
            ("JIRA-123", Affect.AffectAffectedness.AFFECTED, True, False),
            # Existing tracker without the label present gets the label added if all
            # its affects are NEW.
            ("JIRA-123", Affect.AffectAffectedness.NEW, False, True),
            # Existing tracker without the label already present doesn't get the label added
            # if all its affects are not NEW.
            ("JIRA-123", Affect.AffectAffectedness.AFFECTED, False, False),
        ],
    )
    def test_generate_label_validation_requested(
        self,
        external_system_id,
        affectedness,
        preexisting_val_req_lbl,
        result_val_req_lbl,
    ):
        """
        test that the validation-requested label in the Jira query is generated correctly
        """
        flaw1 = FlawFactory(bz_id="1", cve_id="CVE-2000-2000")
        flaw2 = FlawFactory(bz_id="2", embargoed=flaw1.embargoed, cve_id=None)
        ps_module = PsModuleFactory(bts_name="jboss")
        affect1 = AffectFactory(
            flaw=flaw1,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=affectedness,
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=affectedness,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        if not external_system_id:
            # New tracker being created
            meta_attr = {"test": 1}
        else:
            # Existing tracker supposedly being updated
            if preexisting_val_req_lbl:
                meta_attr = {
                    "labels": '["CVE-2000-2000", "Security", "SecurityTracking", "pscomponent:component", "validation-requested"]'
                }
            else:
                meta_attr = {
                    "labels": '["CVE-2000-2000", "Security", "SecurityTracking", "pscomponent:component"]'
                }
        tracker = TrackerFactory(
            affects=[affect1, affect2],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw1.is_embargoed,
            external_system_id=external_system_id,
            meta_attr=meta_attr,
        )
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="security",
            field_name="Security Level",
            allowed_values=[
                "Embargoed Security Issue",
                "Red Hat Employee",
                "Red Hat Engineering Authorized",
                "Red Hat Partner",
                "Restricted",
                "Team",
            ],
        )

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        assert "flaw:bz#1" in labels
        assert "flaw:bz#2" in labels
        assert f"flawuuid:{flaw1}" in labels
        assert f"flawuuid:{flaw2}" in labels
        if result_val_req_lbl:
            assert "validation-requested" in labels
            assert len(labels) == 9
        else:
            assert "validation-requested" not in labels
            assert len(labels) == 8

        # NOTE: In real usage, this query is sent to Jira and it overwrites the list of
        # labels stored in Jira, so if the label is not generated anymore, it effectively
        # deletes it from Jira.

    def test_generate_sla(self, clean_policies):
        """
        test that the query for the Jira SLA timestamps is generated correctly
        """
        flaw = FlawFactory(
            embargoed=False,
            reported_dt=make_aware(datetime(2000, 1, 1)),
        )
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            type=Tracker.TrackerType.BUGZILLA,
        )

        JiraProjectFields(
            project_key=ps_module.bts_key,
            field_id="priority",
            field_name="Priority",
            allowed_values=[
                "Blocker",
                "Critical",
                "Major",
                "Normal",
                "Minor",
                "Undefined",
            ],
        ).save()
        # this value is used in RH instance of Jira however
        # it is always fetched from project meta anyway
        target_start_id = "customfield_12313941"
        JiraProjectFields(
            project_key=ps_module.bts_key,
            field_id=target_start_id,
            field_name="Target start",
        ).save()
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="security",
            field_name="Security Level",
            allowed_values=[
                "Embargoed Security Issue",
                "Red Hat Employee",
                "Red Hat Engineering Authorized",
                "Red Hat Partner",
                "Restricted",
                "Team",
            ],
        )

        sla_file = """
---
name: Not Embargoed
description: suitable for whatever we find on the street
conditions:
  flaw:
    - is not embargoed
sla:
  duration: 10
  start: reported date
  type: calendar days
"""

        load_sla_policies(sla_file)

        query = OldTrackerJiraQueryBuilder(tracker).query

        assert target_start_id in query["fields"]
        assert query["fields"][target_start_id] == "2000-01-01T00:00:00+00:00"
        assert "duedate" in query["fields"]
        assert query["fields"]["duedate"] == "2000-01-11T00:00:00+00:00"

    @pytest.mark.parametrize(
        "embargoed, private, valid_jira_field",
        [
            (False, False, True),
            (True, False, True),
            (False, True, True),
            (True, True, True),
            (False, False, False),
            (True, False, False),
            (False, True, False),
        ],
    )
    def test_generate_security(self, embargoed, private, valid_jira_field):
        """
        test that the query for the Jira has security level generated correctly
        """
        flaw1 = FlawFactory(cve_id="CVE-2000-2000", embargoed=embargoed)
        ps_module = PsModuleFactory(bts_name="jboss", private_trackers_allowed=private)
        affect1 = AffectFactory(
            flaw=flaw1,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        tracker = TrackerFactory(
            affects=[affect1],
            type=Tracker.TrackerType.JIRA,
            embargoed=flaw1.is_embargoed,
        )
        if valid_jira_field:
            JiraProjectFieldsFactory(
                project_key=ps_module.bts_key,
                field_id="security",
                field_name="Security Level",
                allowed_values=[
                    "Embargoed Security Issue",
                    "Red Hat Employee",
                    "Red Hat Engineering Authorized",
                    "Red Hat Partner",
                    "Restricted",
                    "Team",
                ],
            )

        if valid_jira_field or (not private and not embargoed):
            query_builder = OldTrackerJiraQueryBuilder(tracker)
            query_builder._query = {"fields": {}}
            query_builder.generate_security()
            security = query_builder.query["fields"]["security"]

            if embargoed:
                assert security == {"name": "Embargoed Security Issue"}
            elif private:
                assert security == {"name": "Red Hat Employee"}
            else:
                assert security is None
        else:
            with pytest.raises(NoSecurityLevelAvailableError):
                query_builder = OldTrackerJiraQueryBuilder(tracker)
                query_builder._query = {"fields": {}}
                query_builder.generate_security()

    @pytest.mark.parametrize(
        "additional_fields, jira_fields",
        [
            ({}, {}),
            (
                {"jboss": {"fixVersions": "rhel-8.1.0.z"}},
                {"fixVersions": [{"name": "rhel-8.1.0.z"}]},
            ),
            (
                {
                    "jboss": {
                        "fixVersions": "rhel-8.9.0",
                        "release_blocker": "Approved Blocker",
                    }
                },
                {
                    "fixVersions": [{"name": "rhel-8.9.0"}],
                    "customfield_12319743": {"value": "Approved Blocker"},
                },
            ),
        ],
    )
    def test_generate_additional_fields(self, additional_fields, jira_fields):
        """
        Test that additional fields are correctly parsed and converted to Jira fields.
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module, additional_fields=additional_fields
        )
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
        )

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_additional_fields()

        # Additional fields are optional
        if "jboss" in additional_fields:
            for field in additional_fields["jboss"]:
                jira_field = PS_ADDITIONAL_FIELD_TO_JIRA[field]
                assert (
                    query_builder.query["fields"][jira_field] == jira_fields[jira_field]
                )
        else:
            for field in PS_ADDITIONAL_FIELD_TO_JIRA.values():
                assert field not in query_builder.query["fields"]

    @pytest.mark.parametrize(
        "component_cc, private_tracker_cc, default_cc, component, exists",
        [
            (True, True, True, "component", True),
            (True, True, True, "component", False),
            (True, True, True, "foobar", False),
            (True, False, False, "component", False),
            (False, True, False, "component", False),
            (False, False, True, "component", False),
        ],
    )
    def test_generate_cc(
        self, component_cc, private_tracker_cc, default_cc, component, exists
    ):
        """
        Test that CC lists are generated for a new tracker
        """

        # For brevity of pytest.mark.parametrize's arguments
        if component_cc:
            component_cc = {"component": ["a@redhat.com", "a2", "ee"]}
        else:
            component_cc = {}
        if private_tracker_cc:
            private_tracker_cc = ["b@redhat.com", "b2", "ee"]
        else:
            private_tracker_cc = []
        if default_cc:
            default_cc = ["c@redhat.com", "c2", "ee"]
        else:
            default_cc = []
        if exists:
            external_system_id = "1234"
        else:
            external_system_id = ""

        ps_module = PsModuleFactory(
            bts_name="jboss",
            component_cc=component_cc,
            private_tracker_cc=private_tracker_cc,
            default_cc=default_cc,
            private_trackers_allowed=True,
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
        )
        flaw = FlawFactory()
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_component=component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            external_system_id=external_system_id,
            embargoed=flaw.embargoed,
        )
        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="contributors",
            field_name="Contributors",
            allowed_values=[],
        )

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_cc()
        if exists:
            assert "contributors" not in query_builder.query["fields"]
            assert query_builder.query["fields"] == {}
            assert query_builder.query_comment is None
        else:
            if component == "component":
                expected_component_cc = component_cc.get("component", [])
            else:
                # If the PS module's component is not listed in product definition's component_cc,
                # there is no match.
                expected_component_cc = []

            if tracker.embargoed:
                expected_private_tracker_cc = private_tracker_cc
            else:
                expected_private_tracker_cc = []

            expected_cc = sorted(
                set(expected_component_cc + expected_private_tracker_cc + default_cc)
            )

            if expected_cc:
                expected_fields = {"contributors": [{"name": n} for n in expected_cc]}
                expected_comment = "Added involved users: " + ", ".join(
                    [f"[~{u}]" for u in expected_cc]
                )
            else:
                expected_fields = {}
                expected_comment = None

            assert query_builder.query["fields"] == expected_fields
            assert query_builder.query_comment == expected_comment

    @pytest.mark.parametrize(
        "target_release, target_version, valid_jira_field, available_field",
        [
            ("4.1.0", None, True, True),
            (None, "One-off release", True, True),
            ("4.1.0", None, True, False),
            (None, None, False, False),
            ("42.17", None, False, True),
            (None, "20.77", False, True),
        ],
    )
    def test_generate_target_release(
        self, target_release, target_version, valid_jira_field, available_field
    ):
        """
        Test generation of Target Release/Target Version fields from PsUpdateStream.
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
            target_release=(
                target_release if target_release is not None else target_version
            ),
        )
        flaw = FlawFactory()
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw.embargoed,
        )

        # Create mock field
        if available_field:
            if target_release is not None:
                field_id = "customfield_12311240"
                field_name = "Target Release"
            else:
                field_id = "customfield_12319940"
                field_name = "Target Version"
            JiraProjectFieldsFactory(
                project_key=ps_module.bts_key,
                field_id=field_id,
                field_name=field_name,
                allowed_values=[
                    "4.1.0",
                    "One-off release",
                ],
            )

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        if not available_field:
            # If the field is not available in the project, nothing is generated
            query_builder.generate_target_release()
            assert "customfield_12311240" not in query_builder.query["fields"]
            assert "customfield_12319940" not in query_builder.query["fields"]
        elif valid_jira_field:
            query_builder.generate_target_release()
            query_value = query_builder.query["fields"].get(field_id)
            if target_release is not None:
                assert query_value == {"name": target_release}
            elif target_version is not None:
                assert query_value == [{"name": target_version}]
        else:
            with pytest.raises(NoTargetReleaseVersionAvailableError):
                query_builder.generate_target_release()

    def test_generate_target_release_empty_string(self):
        """
        test generation of Target Release/Target Version fields
        with PsUpdateStream.target_release being an empty string

        reproducer of https://issues.redhat.com/browse/OSIDB-2909
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
            target_release="",
        )
        assert PsUpdateStream.objects.first().target_release == ""
        affect = AffectFactory(
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.NEW,
            resolution=Affect.AffectResolution.NOVALUE,
        )
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=affect.flaw.embargoed,
        )

        JiraProjectFieldsFactory(
            project_key=ps_module.bts_key,
            field_id="customfield_12311240",
            field_name="Target Release",
            allowed_values=["random"],
        )

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}

        # should not raise here
        query_builder.generate_target_release()
        assert not query_builder._query["fields"]

    @pytest.mark.parametrize(
        "bts_key,jpf_avail,component,default_component,result_component,result_exception",
        [
            ("fooproj", True, "component", None, "component", False),
            ("fooproj", True, "barfoo", None, "foobar", False),
            ("fooproj", True, "imaginary", None, "imaginary", True),
            ("fooproj", True, "compo/nent", None, "compo/nent", False),
            ("fooproj", True, "comp/onent", None, "comp/onent", True),
            ("fooproj", False, "comp/onent", None, "comp/onent", False),
            ("fooproj", True, "comp/onent", "comp-bar", "comp-bar", False),
            ("fooproj", False, "comp/onent", "comp-bar", "comp/onent", False),
            ("RHEL", True, "compo/nent", None, "nent", False),
            ("RHEL", True, "comp/onent", None, "onent", True),
            ("RHEL", False, "comp/onent", None, "onent", False),
            ("RHEL", True, "barfoo", None, "foobar", False),
        ],
    )
    def test_generate_component(
        self,
        bts_key,
        jpf_avail,
        component,
        default_component,
        result_component,
        result_exception,
    ):
        """
        Test that "components" field is generated for a new tracker
        """

        ps_module = PsModuleFactory(
            bts_name="jboss",
            private_trackers_allowed=True,
            component_overrides={"barfoo": "foobar"},
            bts_key=bts_key,
            default_component=default_component,
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
        )
        flaw = FlawFactory()
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_component=component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw.embargoed,
        )
        if jpf_avail:
            JiraProjectFieldsFactory(
                project_key=ps_module.bts_key,
                field_id="components",
                field_name="components",
                allowed_values=[
                    "comp-foo",
                    "comp-bar",
                    "component",
                    "foobar",
                    "compo/nent",
                    "nent",
                ],
            )

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        if result_exception:
            with pytest.raises(ComponentUnavailableError):
                query_builder.generate_component()
        else:
            query_builder.generate_component()
            assert query_builder.query["fields"]["components"] == [
                {"name": result_component}
            ]

    @pytest.mark.parametrize(
        "field_present,pd_version,generated_response,generated_version",
        [
            (True, "1.2.3", True, "1.2.3"),
            (True, None, False, None),
            (True, "", False, None),
            (False, "1.2.3", False, None),
            (False, None, False, None),
            (False, "", False, None),
        ],
    )
    def test_generate_version(
        self, field_present, pd_version, generated_response, generated_version
    ):
        """
        test that version is not generated for null/empty versions
        """
        if field_present:
            JiraProjectFields(
                project_key="FOOPROJECT",
                field_id="versions",
                field_name="Affects Version/s",
                allowed_values=["1.2.3"],
            ).save()

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.LOW,
        )
        ps_module = PsModuleFactory(
            name="foo-module", bts_name="jboss", bts_key="FOOPROJECT"
        )
        stream = PsUpdateStreamFactory(
            ps_module=ps_module, name="bar-1.2.3", version=pd_version
        )
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=stream.name,
            embargoed=flaw.is_embargoed,
        )

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_versions()
        if generated_response:
            assert query_builder.query["fields"]["versions"] == [
                {"name": generated_version}
            ]
        else:
            assert "versions" not in query_builder.query["fields"]


def validate_minimum_key_value(minimum: Dict[str, Any], evaluated: Dict[str, Any]):
    """
    Compare two given dictionaries and fail test if minimum is not contained in evaluated
    """
    for key in minimum.keys():
        if type(minimum[key]) is dict:
            validate_minimum_key_value(minimum[key], evaluated[key])
        elif type(minimum[key]) is list:
            for v in minimum[key]:
                assert v in evaluated[key]
        else:
            assert minimum[key] == evaluated[key]
