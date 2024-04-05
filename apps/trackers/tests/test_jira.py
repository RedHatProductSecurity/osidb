"""
Bugzilla specific tracker test cases
"""
import json
from typing import Any, Dict
from unittest.mock import mock_open, patch

import pytest
from django.utils.timezone import datetime, make_aware

from apps.trackers.exceptions import NoSecurityLevelAvailableError
from apps.trackers.jira.constants import PS_ADDITIONAL_FIELD_TO_JIRA
from apps.trackers.jira.query import JiraPriority, TrackerJiraQueryBuilder
from apps.trackers.models import JiraProjectFields
from apps.trackers.tests.factories import JiraProjectFieldsFactory
from osidb.models import (
    Affect,
    CompliancePriority,
    ContractPriority,
    Flaw,
    Impact,
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


class TestTrackerJiraQueryBuilder:
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

        quer_builder = TrackerJiraQueryBuilder(tracker)
        quer_builder.generate()
        validate_minimum_key_value(minimum=expected1, evaluated=quer_builder._query)

    @pytest.mark.parametrize(
        "meta, expected_labels",
        [
            (
                {"test": 1},
                [
                    "SecurityTracking",
                    "Security",
                    "pscomponent:component",
                    "CVE-2000-2000",
                ],
            ),
            (
                # Labels stored as str, as happens in HStoreField
                {
                    "labels": '["CVE-2000-2000", "SecurityTracking", "pscomponent:component", "Security", "validation-requested", "custom_label"]'
                },
                [
                    "custom_label",
                    "SecurityTracking",
                    "Security",
                    "pscomponent:component",
                    "CVE-2000-2000",
                ],
            ),
            (
                {"labels": []},
                [
                    "SecurityTracking",
                    "Security",
                    "pscomponent:component",
                    "CVE-2000-2000",
                ],
            ),
            (
                {
                    "labels": [
                        "CVE-2000-2000",
                        "Security",
                        "foobar",
                        "CVE-2000-0001",
                        "CVE-1",
                        "SecurityTracking",
                        "foobaz",
                        "pscomponent:component",
                        "pscomponent:foobar",
                        "foobaa",
                        "validation-requested",
                    ]
                },
                [
                    "foobar",
                    "CVE-1",
                    "foobaz",
                    "foobaa",
                    "SecurityTracking",
                    "Security",
                    "pscomponent:component",
                    "CVE-2000-2000",
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
        flaw1 = FlawFactory(cve_id="CVE-2000-2000")
        flaw2 = FlawFactory(embargoed=flaw1.embargoed, cve_id=None)
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
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect1, affect2],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw1.is_embargoed,
            meta_attr=meta,
        )

        query_builder = TrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        assert len(labels) == len(expected_labels)
        assert labels == expected_labels

    def test_generate_label_contract_priority(self):
        """
        test that the query for the Jira label contract-priority is generated correctly
        """
        flaw1 = FlawFactory(cve_id="CVE-2000-2000")
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

        query_builder = TrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert "contract-priority" in labels
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        assert len(labels) == 5

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
        flaw1 = FlawFactory(cve_id="CVE-2000-2000", impact=impact)
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

        query_builder = TrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert "contract-priority" in labels
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        if impact == "LOW" or "foobar" in yml_components:
            assert "compliance-priority" not in labels
            assert len(labels) == 5
        else:
            assert "compliance-priority" in labels
            assert len(labels) == 6

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
        flaw1 = FlawFactory(cve_id="CVE-2000-2000")
        flaw2 = FlawFactory(embargoed=flaw1.embargoed, cve_id=None)
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

        query_builder = TrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        if result_val_req_lbl:
            assert "validation-requested" in labels
            assert len(labels) == 5
        else:
            assert "validation-requested" not in labels
            assert len(labels) == 4

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

        with patch("builtins.open", mock_open(read_data=sla_file)):
            query = TrackerJiraQueryBuilder(tracker).query

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
            query_builder = TrackerJiraQueryBuilder(tracker)
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
                query_builder = TrackerJiraQueryBuilder(tracker)
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

        query_builder = TrackerJiraQueryBuilder(tracker)
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
