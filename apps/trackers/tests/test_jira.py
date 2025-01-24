"""
Bugzilla specific tracker test cases
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict

import pytest
from django.utils.timezone import make_aware

from apps.sla.tests.test_framework import load_sla_policies
from apps.trackers.exceptions import (
    ComponentUnavailableError,
    MissingEmbargoStatusError,
    MissingSecurityLevelError,
    MissingSourceError,
    MissingTargetReleaseVersionError,
    MissingVulnerabilityIssueFieldError,
    TrackerCreationError,
)
from apps.trackers.jira.constants import (
    JIRA_EMBARGO_SECURITY_LEVEL_NAME,
    PS_ADDITIONAL_FIELD_TO_JIRA,
)
from apps.trackers.jira.query import (
    JiraCVESeverity,
    JiraPriority,
    JiraSeverity,
    OldTrackerJiraQueryBuilder,
    TrackerJiraQueryBuilder,
)
from apps.trackers.models import JiraProjectFields
from apps.trackers.tests.conftest import (
    jira_vulnissuetype_fields_setup_without_severity_versions,
)
from apps.trackers.tests.factories import JiraProjectFieldsFactory
from osidb.models import (
    CVSS,
    Affect,
    AffectCVSS,
    Flaw,
    FlawCVSS,
    Impact,
    PsUpdateStream,
    Tracker,
)
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestOldTrackerJiraQueryBuilder:
    """
    test Jira tracker query building for Bug issuetype
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
            external_system_id=None,
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

        query_builder = OldTrackerJiraQueryBuilder(tracker)
        query_builder.generate()
        validate_minimum_key_value(minimum=expected1, evaluated=query_builder._query)

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
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect1],
            ps_update_stream=ps_update_stream.name,
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
            with pytest.raises(MissingSecurityLevelError):
                query_builder = OldTrackerJiraQueryBuilder(tracker)
                query_builder._query = {"fields": {}}
                query_builder.generate_security()


@pytest.mark.parametrize(
    "creating_new_issuetype,new_issuetype_metadata_present",
    [
        (False, False),
        (False, True),
        (True, True),
    ],
)
class TestBothNewOldTrackerJiraQueryBuilder:
    """
    Test Jira tracker query building for both Bug issuetype and
    Vulnerability issuetype for those parts of the query that should
    be identical for both issuetypes.
    """

    @pytest.fixture(scope="function")
    def querybuilder_class(self, creating_new_issuetype):
        if creating_new_issuetype:
            return TrackerJiraQueryBuilder
        else:
            return OldTrackerJiraQueryBuilder

    @pytest.fixture(scope="function", autouse=True)
    def jira_vulnissuetype_fields(self, new_issuetype_metadata_present):
        if new_issuetype_metadata_present:
            jira_vulnissuetype_fields_setup_without_severity_versions()

            JiraProjectFields(
                project_key="FOOPROJECT",
                field_id="customfield_an_identifier_for_cve_severity_field",
                field_name="CVE Severity",
                allowed_values=[
                    "Critical",
                    "Important",
                    "Moderate",
                    "Low",
                    "An Irrelevant Value To Be Ignored",
                    "None",
                ],
            ).save()

    def test_fixture_sanity(
        self, creating_new_issuetype, new_issuetype_metadata_present
    ):
        """
        Test that jira_vulnissuetype_fields has an effect only when it should.
        """

        if new_issuetype_metadata_present:
            assert JiraProjectFields.objects.count() == 9
        else:
            assert JiraProjectFields.objects.count() == 0

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
    def test_generate_labels(self, querybuilder_class, meta, expected_labels):
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

        query_builder = querybuilder_class(tracker)
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
        querybuilder_class,
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

        query_builder = querybuilder_class(tracker)
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
    def test_generate_additional_fields(
        self, querybuilder_class, additional_fields, jira_fields
    ):
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

        query_builder = querybuilder_class(tracker)
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
        self,
        querybuilder_class,
        component_cc,
        private_tracker_cc,
        default_cc,
        component,
        exists,
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

        query_builder = querybuilder_class(tracker)
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
        self,
        querybuilder_class,
        target_release,
        target_version,
        valid_jira_field,
        available_field,
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

        query_builder = querybuilder_class(tracker)
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
            with pytest.raises(MissingTargetReleaseVersionError):
                query_builder.generate_target_release()

    def test_generate_target_release_empty_string(
        self,
        querybuilder_class,
    ):
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

        query_builder = querybuilder_class(tracker)
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
        querybuilder_class,
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
            external_system_id=None,
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

        query_builder = querybuilder_class(tracker)
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
        self,
        querybuilder_class,
        field_present,
        pd_version,
        generated_response,
        generated_version,
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
            external_system_id=None,
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=stream.name,
            embargoed=flaw.is_embargoed,
        )

        query_builder = querybuilder_class(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_versions()
        if generated_response:
            assert query_builder.query["fields"]["versions"] == [
                {"name": generated_version}
            ]
        else:
            assert "versions" not in query_builder.query["fields"]

    def test_creation_specifics(self, querybuilder_class):
        """
        test that certain fields are only being set on tracker creation
        """
        JiraProjectFieldsFactory(
            project_key="PROJECT",
            field_id="contributors",
            field_name="Contributors",
            allowed_values=[],
        )
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_12324749",
            field_name="CVE ID",
            allowed_values=[],
        ).save()
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_an_identifier_for_cve_severity_field",
            field_name="CVE Severity",
            allowed_values=[
                "Critical",
                "Important",
                "Moderate",
                "Low",
                "None",
            ],
        ).save()
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_12324748",
            field_name="CVSS Score",
            allowed_values=[],
        ).save()
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_12324747",
            field_name="CWE ID",
            allowed_values=[],
        ).save()
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_12324752",
            field_name="Downstream Component Name",
            allowed_values=[],
        ).save()
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_12324750",
            field_name="Embargo Status",
            allowed_values=["True", "False"],
        ).save()
        JiraProjectFields(
            project_key="PROJECT",
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
        JiraProjectFieldsFactory(
            project_key="PROJECT",
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
        source = "DEBIAN"
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_12324746",
            field_name="Source",
            allowed_values=[source],
        ).save()
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_12324753",
            field_name="Special Handling",
            allowed_values=[
                "0-day",
                "Major Incident",
                "Minor Incident",
                "KEV (active exploit case)",
            ],
        ).save()
        JiraProjectFields(
            project_key="PROJECT",
            field_id="customfield_12324751",
            field_name="Upstream Affected Component",
            allowed_values=[],
        ).save()
        version = "1.2.3"
        JiraProjectFields(
            project_key="PROJECT",
            field_id="versions",
            field_name="Affects Version/s",
            allowed_values=[version],
        ).save()

        ps_module = PsModuleFactory(
            bts_key="PROJECT",
            bts_name="jboss",
            default_cc=["me@redhat.com"],
            private_trackers_allowed=True,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module, version=version)

        flaw = FlawFactory(source=source)
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.is_embargoed,
            external_system_id=None,  # creation
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
        )

        query_builder = querybuilder_class(tracker)
        query_builder.generate()

        assert "components" in query_builder.query["fields"]
        assert "contributors" in query_builder.query["fields"]
        assert "versions" in query_builder.query["fields"]

        # no creation any more
        tracker.external_system_id = "PROJECT-123"

        query_builder = querybuilder_class(tracker)
        query_builder.generate()

        assert "components" not in query_builder.query["fields"]
        assert "contributors" not in query_builder.query["fields"]
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


class TestTrackerJiraQueryBuilder:
    """
    test Jira tracker query building for Vulnerability issuetype
    """

    @pytest.fixture(scope="function", autouse=True)
    def jira_vulnissuetype_fields(self):
        jira_vulnissuetype_fields_setup_without_severity_versions()

        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="customfield_an_identifier_for_cve_severity_field",
            field_name="CVE Severity",
            allowed_values=[
                "Critical",
                "Important",
                "Moderate",
                "Low",
                "An Irrelevant Value To Be Ignored",
                "None",
            ],
        ).save()

        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="versions",
            field_name="Affects Version/s",
            allowed_values=["1.2.3"],
        ).save()

    @pytest.mark.parametrize(
        "flaw_impact,affect_impact,expected_severity",
        [
            (Impact.LOW, Impact.LOW, JiraCVESeverity.LOW),
            (Impact.MODERATE, Impact.NOVALUE, JiraCVESeverity.MODERATE),
            (Impact.MODERATE, Impact.LOW, JiraCVESeverity.LOW),
            (Impact.CRITICAL, Impact.NOVALUE, JiraCVESeverity.CRITICAL),
            (Impact.CRITICAL, Impact.LOW, JiraCVESeverity.LOW),
            (Impact.LOW, Impact.LOW, JiraCVESeverity.LOW),
            (Impact.LOW, Impact.MODERATE, JiraCVESeverity.MODERATE),
            (Impact.LOW, Impact.CRITICAL, JiraCVESeverity.CRITICAL),
        ],
    )
    def test_generate_query(self, flaw_impact, affect_impact, expected_severity):
        """
        test that query has all fields correctly generated
        """

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=flaw_impact,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
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
            external_system_id=None,
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
        expected1 = {
            "fields": {
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Vulnerability"},
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
                #
                # CVE Severity
                "customfield_an_identifier_for_cve_severity_field": {
                    "value": expected_severity
                },
                #
                # Source
                "customfield_12324746": {"value": "Red Hat"},
                #
                # CVE ID
                "customfield_12324749": "CVE-2999-1000",
                #
                # CVSS Score
                # "customfield_12324748"
                # not generated
                #
                # CWE ID
                "customfield_12324747": "CWE-1",
                #
                # Downstream Component Name
                "customfield_12324752": "foo-component",
                #
                # Upstream Affected Component
                "customfield_12324751": "; ".join(sorted(flaw.components)),
                #
                # Embargo Status
                "customfield_12324750": {"value": str(flaw.is_embargoed)},
                #
                # Special Handling
                "customfield_12324753": [],
            }
        }

        if not flaw.cwe_id:
            del expected1["fields"]["customfield_12324747"]

        query_builder = TrackerJiraQueryBuilder(tracker)
        query_builder.generate()
        validate_minimum_key_value(minimum=expected1, evaluated=query_builder._query)

    @pytest.mark.parametrize(
        "missing,wrong,flaw_impact,affect_impact,expected_severity",
        [
            (False, False, Impact.LOW, Impact.LOW, JiraCVESeverity.LOW),
            (False, False, Impact.LOW, Impact.MODERATE, JiraCVESeverity.MODERATE),
            (False, False, Impact.LOW, Impact.IMPORTANT, JiraCVESeverity.IMPORTANT),
            (False, False, Impact.LOW, Impact.CRITICAL, JiraCVESeverity.CRITICAL),
            (False, False, Impact.NOVALUE, Impact.NOVALUE, None),
            (True, False, Impact.LOW, Impact.CRITICAL, None),
            (False, True, Impact.LOW, Impact.CRITICAL, None),
        ],
    )
    def test_cve_severity_field(
        self, missing, wrong, flaw_impact, affect_impact, expected_severity
    ):
        """
        Test that the CVE Severity field is populated correctly.
        Test that an exception is thrown when the CVE Severity field is missing or
        doesn't have the required allowed value or when the aggregated impact
        is the disallowed empty value.
        """
        JiraProjectFields.objects.filter(field_name="CVE Severity").delete()
        if not missing:
            if not wrong:
                JiraProjectFields(
                    project_key="FOOPROJECT",
                    field_id="customfield_an_identifier_for_cve_severity_field",
                    field_name="CVE Severity",
                    allowed_values=[
                        "Critical",
                        "Important",
                        "Moderate",
                        "Low",
                        "An Irrelevant Value To Be Ignored",
                        "None",
                    ],
                ).save()
            else:
                JiraProjectFields(
                    project_key="FOOPROJECT",
                    field_id="customfield_an_identifier_for_cve_severity_field",
                    field_name="CVE Severity",
                    allowed_values=[
                        "Foobar",
                        "Asphalt",
                        "Drink",
                        "Room",
                        "Airplane",
                        "Yes",
                    ],
                ).save()

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=flaw_impact,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=affect_impact,
        )
        ps_module = PsModuleFactory(
            bts_key="FOOPROJECT",
            bts_name="jboss",
            name="foo-module",
            private_trackers_allowed=False,
        )
        stream = PsUpdateStreamFactory(
            ps_module=ps_module, name="bar-1.2.3", version="1.2.3"
        )
        tracker = TrackerFactory(
            affects=[affect],
            external_system_id=None,
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=stream.name,
            embargoed=flaw.is_embargoed,
        )
        if not missing and not wrong and flaw_impact != Impact.NOVALUE:
            expected = {
                "fields": {
                    "project": {"key": "FOOPROJECT"},
                    "issuetype": {"name": "Vulnerability"},
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
                    #
                    # CVE Severity
                    "customfield_an_identifier_for_cve_severity_field": {
                        "value": expected_severity
                    },
                }
            }

            query_builder = TrackerJiraQueryBuilder(tracker)
            query_builder.generate()
            validate_minimum_key_value(minimum=expected, evaluated=query_builder._query)
        else:
            if missing:
                with pytest.raises(TrackerCreationError):
                    TrackerJiraQueryBuilder(tracker).generate()
            if wrong:
                with pytest.raises(TrackerCreationError):
                    TrackerJiraQueryBuilder(tracker).generate()
            if flaw_impact == Impact.NOVALUE:
                with pytest.raises(TrackerCreationError):
                    TrackerJiraQueryBuilder(tracker).generate()

    @pytest.mark.parametrize(
        "missing,wrong,flaw_impact,affect_impact,expected_severity",
        [
            (False, False, Impact.LOW, Impact.LOW, JiraSeverity.LOW),
            (False, False, Impact.LOW, Impact.MODERATE, JiraSeverity.MODERATE),
            (False, False, Impact.LOW, Impact.IMPORTANT, JiraSeverity.IMPORTANT),
            (False, False, Impact.LOW, Impact.CRITICAL, JiraSeverity.CRITICAL),
            (False, False, Impact.NOVALUE, Impact.NOVALUE, None),
            (True, False, Impact.LOW, Impact.CRITICAL, None),
            (False, True, Impact.LOW, Impact.CRITICAL, None),
        ],
    )
    def test_severity_field(
        self, missing, wrong, flaw_impact, affect_impact, expected_severity
    ):
        """
        Test that the Severity field is populated correctly. Test that an exception is thrown
        when the Severity field is missing or doesn't have the required allowed value or when
        the aggregated impact is the disallowed empty value.
        """
        # until there is CVE Severity field being set remove its specification
        # so the exception on missing is solely based on the Severity field
        JiraProjectFields.objects.filter(field_name="CVE Severity").delete()
        if not missing:
            if not wrong:
                JiraProjectFields(
                    project_key="FOOPROJECT",
                    field_id="123-severity",
                    field_name="Severity",
                    allowed_values=[
                        "Critical",
                        "Important",
                        "Moderate",
                        "Low",
                        "unexpected mess here",
                        "Informational",
                        "None",
                    ],
                ).save()
            else:
                JiraProjectFields(
                    project_key="FOOPROJECT",
                    field_id="123-severity",
                    field_name="Severity",
                    allowed_values=[
                        "Foobar",
                        "Asphalt",
                        "Drink",
                        "Room",
                        "Airplane",
                        "Yes",
                    ],
                ).save()

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2000-1000",
            impact=flaw_impact,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
        )
        ps_module = PsModuleFactory(
            bts_key="FOOPROJECT",
            bts_name="jboss",
            private_trackers_allowed=False,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            ps_component="component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=affect_impact,
        )
        ps_update_stream = PsUpdateStreamFactory(
            name="stream-1", ps_module=ps_module, version="1.2.3"
        )
        tracker = TrackerFactory(
            affects=[affect],
            external_system_id=None,
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw.is_embargoed,
        )
        if not missing and not wrong and flaw_impact != Impact.NOVALUE:
            expected = {
                "fields": {
                    "project": {"key": "FOOPROJECT"},
                    "issuetype": {"name": "Vulnerability"},
                    "summary": "CVE-2000-1000 component: some description [stream-1]",
                    "labels": [
                        "CVE-2000-1000",
                        "pscomponent:component",
                        "SecurityTracking",
                        "Security",
                    ],
                    "versions": [
                        {"name": "1.2.3"},
                    ],
                    # Severity
                    "123-severity": {"value": expected_severity},
                }
            }

            quer_builder = TrackerJiraQueryBuilder(tracker)
            quer_builder.generate()
            validate_minimum_key_value(minimum=expected, evaluated=quer_builder._query)
        else:
            if missing:
                with pytest.raises(TrackerCreationError):
                    TrackerJiraQueryBuilder(tracker).generate()
            if wrong:
                with pytest.raises(TrackerCreationError):
                    TrackerJiraQueryBuilder(tracker).generate()
            if flaw_impact == Impact.NOVALUE:
                with pytest.raises(TrackerCreationError):
                    TrackerJiraQueryBuilder(tracker).generate()

    def test_severity_field_values(self):
        """
        properly account for an unexpected
        value scheme of the Severity field

        this test is OSIDB-3767 reproducer
        """
        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="123-severity",
            field_name="Severity",
            allowed_values=[
                "Urgent",
                "More Urgent",
                "Super Urgent",
                "Totally Urgent",
            ],
        ).save()

        flaw = FlawFactory(
            embargoed=False,
            source="REDHAT",
        )
        ps_module = PsModuleFactory(
            bts_key="FOOPROJECT",
            bts_name="jboss",
            private_trackers_allowed=False,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect],
            external_system_id=None,
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw.is_embargoed,
        )

        quer_builder = TrackerJiraQueryBuilder(tracker)
        # do not throw exception here but fallback
        quer_builder.generate()

    @pytest.mark.parametrize(
        "model_src,allowed_jira_src,expected_jira_src,other_outcome",
        [
            ("REDHAT", "Red Hat", "Red Hat", 0),
            ("GIT", "Git", "Git", 0),
            ("REDHAT", "RedHAT", "RedHAT", 0),  # Testing fallback allowed value pairing
            ("REDHAT", None, None, 1),
            ("REDHAT", "foobar", None, 2),
        ],
    )
    def test_generate_source(
        self, model_src, allowed_jira_src, expected_jira_src, other_outcome
    ):
        """
        test that query has all fields correctly generated
        """
        JiraProjectFields.objects.filter(field_name="Source").delete()

        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="customfield_12324746",
            field_name="Source",
            # Severely pruned for the test
            allowed_values=["Foo", "Bar", allowed_jira_src, "Baz"],
        ).save()

        if other_outcome == 1:
            JiraProjectFields.objects.filter(field_name="Source").delete()

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source=model_src,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.MODERATE,
        )
        ps_module = PsModuleFactory(
            name="foo-module", bts_name="jboss", bts_key="FOOPROJECT"
        )
        stream = PsUpdateStreamFactory(
            ps_module=ps_module, name="bar-1.2.3", version="1.2.3"
        )
        tracker = TrackerFactory(
            affects=[affect],
            external_system_id=None,
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
        if other_outcome == 0:
            expected1 = {
                "fields": {
                    "project": {"key": "FOOPROJECT"},
                    "issuetype": {"name": "Vulnerability"},
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
                    #
                    # Source
                    "customfield_12324746": {"value": expected_jira_src},
                }
            }

            query_builder = TrackerJiraQueryBuilder(tracker)
            query_builder.generate()
            validate_minimum_key_value(
                minimum=expected1, evaluated=query_builder._query
            )
        else:
            if other_outcome == 1:
                with pytest.raises(MissingVulnerabilityIssueFieldError):
                    TrackerJiraQueryBuilder(tracker).generate()
            if other_outcome == 2:
                with pytest.raises(MissingSourceError):
                    TrackerJiraQueryBuilder(tracker).generate()

    @pytest.mark.parametrize(
        "flaw_cvss_present,aff_cvss_present,multiscore,other_outcome",
        [
            (False, False, False, []),
            (False, True, False, []),
            (True, False, False, []),
            (True, True, False, []),
            (False, True, True, []),
            (True, False, True, []),
            (True, True, True, []),
            (False, False, False, [1]),
            (False, False, False, [2]),
            (False, False, False, [3]),
            (False, False, False, [1, 2, 3]),
            (True, True, True, [1]),
            (True, True, True, [2]),
            (True, True, True, [3]),
            (True, True, True, [1, 2, 3]),
        ],
    )
    def test_generate_cve_cvss_cwe(
        self, flaw_cvss_present, aff_cvss_present, multiscore, other_outcome
    ):
        """
        test that query has all fields correctly generated
        """

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
            cwe_id="CWE-1",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.MODERATE,
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
        if flaw_cvss_present:
            assert flaw.cvss_scores.all().count() == 0
            flawcvss = []
            flawcvss.append(FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.NIST))
            assert flaw.cvss_scores.all().count() == 1
            if multiscore:
                flawcvss.append(
                    FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.CVEORG)
                )
                flawcvss.append(
                    FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.CVEORG)
                )
                flawcvss.append(
                    FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.CVEORG)
                )

        if aff_cvss_present:
            assert affect.cvss_scores.all().count() == 0
            assert (
                len(
                    set(
                        tracker.affects.all().values_list(
                            "cvss_scores__uuid", flat=True
                        )
                    )
                    - set([None])
                )
                == 0
            )
            affcvss = []
            affcvss.append(
                AffectCVSSFactory(affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT)
            )
            assert affect.cvss_scores.all().count() == 1
            assert (
                len(
                    set(
                        tracker.affects.all().values_list(
                            "cvss_scores__uuid", flat=True
                        )
                    )
                )
                == 1
            )
            if multiscore:
                affcvss.append(
                    AffectCVSSFactory(
                        affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT
                    )
                )
                affcvss.append(
                    AffectCVSSFactory(
                        affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT
                    )
                )
                affcvss.append(
                    AffectCVSSFactory(
                        affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT
                    )
                )

        expected1 = {
            "fields": {
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Vulnerability"},
                "summary": "CVE-2999-1000 foo-component: some description [bar-1.2.3]",
                "labels": [
                    "CVE-2999-1000",
                    "pscomponent:foo-component",
                    "SecurityTracking",
                    "Security",
                ],
                #
                # CVE ID
                "customfield_12324749": "CVE-2999-1000",
                #
                # CWE ID
                "customfield_12324747": "CWE-1",
            }
        }

        if 1 in other_outcome:
            JiraProjectFields.objects.filter(field_name="CVE ID").delete()
        if 2 in other_outcome:
            JiraProjectFields.objects.filter(field_name="CVSS Score").delete()
        if 3 in other_outcome:
            JiraProjectFields.objects.filter(field_name="CWE ID").delete()

        best = None
        if aff_cvss_present:
            for c in affcvss:
                # Simulating the pre_save signal to calculate the score.
                AffectCVSS.objects.filter(uuid=c.uuid).update(
                    score=float(c.cvss_object.base_score)
                )
                c.refresh_from_db()
                # Naive sorting algorithm to be very explicit
                # and to reimplement the logic in a different way
                # to maximize probability of the test catching a bug.
                if best is None:
                    best = c
                else:
                    # For AffectCVSS, the code doesn't differentiate between
                    # issuers because in reality only RH-issued should exist.

                    if str(best.version) < str(c.version):
                        best = c

        elif flaw_cvss_present:
            for c in flawcvss:
                # Simulating the pre_save signal to calculate the score.
                FlawCVSS.objects.filter(uuid=c.uuid).update(
                    score=float(c.cvss_object.base_score)
                )
                c.refresh_from_db()
                # Naive sorting algorithm to be very explicit
                # and to reimplement the logic in a different way
                # to maximize probability of the test catching a bug.
                if c.issuer == CVSS.CVSSIssuer.REDHAT:
                    if best is None:
                        best = c
                    else:
                        if str(best.version) < str(c.version):
                            best = c

        if best:
            # CVSS Score
            expected1["fields"].update(
                {
                    "customfield_12324748": f"""{best.score} {best.vector}""",
                }
            )

        if not other_outcome:
            query_builder = TrackerJiraQueryBuilder(tracker)
            query_builder.generate()
            validate_minimum_key_value(
                minimum=expected1, evaluated=query_builder._query
            )
        else:
            with pytest.raises(MissingVulnerabilityIssueFieldError):
                TrackerJiraQueryBuilder(tracker).generate()

    @pytest.mark.parametrize(
        "missing",
        [
            (False),
            (True),
        ],
    )
    def test_generate_downstream_component(self, missing):
        """
        Test that query has the Downstream Component Name field
        populated correctly.
        This test explicitly shows how straightforward the value
        is - just a straight copy.
        """

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.MODERATE,
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
        expected1 = {
            "fields": {
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Vulnerability"},
                "summary": f"""CVE-2999-1000 {affect.ps_component}: some description [bar-1.2.3]""",
                "labels": [
                    "CVE-2999-1000",
                    f"""pscomponent:{affect.ps_component}""",
                    "SecurityTracking",
                    "Security",
                ],
                #
                # Downstream Component Name
                "customfield_12324752": affect.ps_component,
                #
                # Upstream Affected Component
                "customfield_12324751": "; ".join(sorted(flaw.components)),
            }
        }

        if missing:
            JiraProjectFields.objects.filter(
                field_name="Downstream Component Name"
            ).delete()
            with pytest.raises(MissingVulnerabilityIssueFieldError):
                TrackerJiraQueryBuilder(tracker).generate()
        else:
            query_builder = TrackerJiraQueryBuilder(tracker)
            query_builder.generate()
            validate_minimum_key_value(
                minimum=expected1, evaluated=query_builder._query
            )

    @pytest.mark.parametrize(
        "components,missing",
        [
            (["foo", "bar", "baz"], True),
            (["foo", "bar", "baz"], False),
            (["foo"], False),
            (["z", "y", "x"], False),
            (["a", "b", "c"], False),
            (["b", "a", "c"], False),
            # Duplicates are deduplicated, necessary esp. for multiflaw trackers
            (["foo", "bar", "baz", "baz", "baz"], False),
        ],
    )
    def test_generate_upstream_component(self, components, missing):
        """
        Test that query has the Upstream Affected Component field
        populated correctly.
        """

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
            components=components,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.MODERATE,
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
        expected1 = {
            "fields": {
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Vulnerability"},
                "summary": f"""CVE-2999-1000 {affect.ps_component}: some description [bar-1.2.3]""",
                "labels": [
                    "CVE-2999-1000",
                    f"""pscomponent:{affect.ps_component}""",
                    "SecurityTracking",
                    "Security",
                ],
                #
                # Downstream Component Name
                "customfield_12324752": affect.ps_component,
                #
                # Upstream Affected Component
                "customfield_12324751": "; ".join(sorted(set(components))),
            }
        }
        if not components:
            del expected1["fields"]["customfield_12324751"]

        if missing:
            JiraProjectFields.objects.filter(
                field_name="Upstream Affected Component"
            ).delete()
            with pytest.raises(MissingVulnerabilityIssueFieldError):
                TrackerJiraQueryBuilder(tracker).generate()
        else:
            query_builder = TrackerJiraQueryBuilder(tracker)
            query_builder.generate()
            validate_minimum_key_value(
                minimum=expected1, evaluated=query_builder._query
            )

    @pytest.mark.parametrize(
        "emb,missing,allowed_values,allowed_values_accepted",
        [
            (True, False, ["True", "False"], True),
            (True, False, ["False", "True"], True),
            (False, False, ["True", "False"], True),
            (True, True, ["True", "False"], None),
            (False, True, ["True", "False"], None),
            (True, False, ["True", "False", "N/A"], False),
            (True, False, ["Probably", "False", "True"], False),
            (False, False, ["true", "false"], False),
            (True, False, ["false", "true"], False),
            (False, False, ["True"], False),
            (True, False, ["True"], False),
            (False, False, ["False"], False),
            (True, False, ["False"], False),
            (False, False, [], False),
            (True, False, [], False),
            # Currently not testable, because JiraProjectFields allows only str allowed values:
            # (True, False, [False, True], False),
            # (False, False, [True, False], False),
            # (False, False, [False, True, "False", "True"], False),
            # (False, False, [0, 1, "False", "True"], False),
        ],
    )
    def test_generate_embargo_status(
        self, emb, missing, allowed_values, allowed_values_accepted
    ):
        """
        test that query has all fields correctly generated
        """

        assert emb is False or emb is True

        JiraProjectFields.objects.filter(field_name="Embargo Status").delete()
        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="customfield_12324750",
            field_name="Embargo Status",
            allowed_values=allowed_values,
        ).save()

        flaw = FlawFactory(
            embargoed=emb,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.MODERATE,
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
        expected1 = {
            "fields": {
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Vulnerability"},
                "summary": f"""{"EMBARGOED " if emb else ""}CVE-2999-1000 {affect.ps_component}: some description [bar-1.2.3]""",
                "labels": [
                    "CVE-2999-1000",
                    f"""pscomponent:{affect.ps_component}""",
                    "SecurityTracking",
                    "Security",
                ],
                #
                # Embargo Status
                "customfield_12324750": {"value": str(flaw.is_embargoed)},
            }
        }

        if missing:

            JiraProjectFields.objects.filter(field_name="Embargo Status").delete()
            with pytest.raises(MissingVulnerabilityIssueFieldError):
                TrackerJiraQueryBuilder(tracker).generate()
        else:
            query_builder = TrackerJiraQueryBuilder(tracker)
            if allowed_values_accepted:
                query_builder.generate()
                validate_minimum_key_value(
                    minimum=expected1, evaluated=query_builder._query
                )
                # additionally the security level must be set as the Jira
                # automation setting it based on the embargo status has
                # delay potentially causing sencitive information leak
                if emb is True:
                    assert "security" in query_builder.query["fields"]
                    assert query_builder.query["fields"]["security"] == {
                        "name": JIRA_EMBARGO_SECURITY_LEVEL_NAME
                    }
            else:
                with pytest.raises(MissingEmbargoStatusError):
                    query_builder.generate()

    @pytest.mark.parametrize(
        "major_incident_state,expected,missing",
        [
            (Flaw.FlawMajorIncident.APPROVED, [{"value": "Major Incident"}], False),
            (
                Flaw.FlawMajorIncident.CISA_APPROVED,
                [{"value": "KEV (active exploit case)"}],
                False,
            ),
            (Flaw.FlawMajorIncident.MINOR, [{"value": "Minor Incident"}], False),
            (Flaw.FlawMajorIncident.ZERO_DAY, [{"value": "0-day"}], False),
            (Flaw.FlawMajorIncident.NOVALUE, [], False),
            (Flaw.FlawMajorIncident.APPROVED, None, True),
            (Flaw.FlawMajorIncident.CISA_APPROVED, None, True),
            (Flaw.FlawMajorIncident.MINOR, None, True),
            (Flaw.FlawMajorIncident.ZERO_DAY, None, True),
            (Flaw.FlawMajorIncident.NOVALUE, None, True),
        ],
    )
    def test_generate_special_handling(self, major_incident_state, expected, missing):
        """
        test that query has all fields correctly generated
        """

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=Impact.MODERATE,
            major_incident_state=major_incident_state,
            title="some description",
            source="REDHAT",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.MODERATE,
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
        expected1 = {
            "fields": {
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Vulnerability"},
                #
                # Special Handling
                "customfield_12324753": expected,
            }
        }

        if missing:

            JiraProjectFields.objects.filter(field_name="Special Handling").delete()
            with pytest.raises(MissingVulnerabilityIssueFieldError):
                TrackerJiraQueryBuilder(tracker).generate()
        else:
            query_builder = TrackerJiraQueryBuilder(tracker)
            query_builder.generate()
            validate_minimum_key_value(
                minimum=expected1, evaluated=query_builder._query
            )

    def test_generate_query_multiflaw(self):
        """
        test that query has all fields correctly generated for a multi-flaw tracker
        """

        flaw = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1000",
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
            cwe_id="CWE-1",
        )
        flwcvss = FlawCVSSFactory(
            flaw=flaw,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION2,
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.MODERATE,
        )
        flaw2 = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1001",
            impact=Impact.CRITICAL,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
            cwe_id="CWE-2",
            created_dt=datetime(2024, 10, 1, tzinfo=timezone.utc),
        )
        flwcvss2 = FlawCVSSFactory(
            flaw=flaw2,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION2,
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.CRITICAL,
        )
        # flaw3 is the oldest of [flaw2, flaw3, flaw4], so should be the one selected
        # among the CRITICAL flaws.
        flaw3 = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1002",
            impact=Impact.CRITICAL,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
            cwe_id="CWE-3",
            created_dt=datetime(2024, 9, 1, tzinfo=timezone.utc),
        )
        flwcvss3 = FlawCVSSFactory(
            flaw=flaw3,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION2,
        )
        affect3 = AffectFactory(
            flaw=flaw3,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.CRITICAL,
        )
        flaw4 = FlawFactory(
            embargoed=False,
            bz_id="123",
            cve_id="CVE-2999-1003",
            impact=Impact.CRITICAL,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            title="some description",
            source="REDHAT",
            cwe_id="CWE-4",
            created_dt=datetime(2024, 10, 2, tzinfo=timezone.utc),
        )
        flwcvss4 = FlawCVSSFactory(
            flaw=flaw4,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION2,
        )
        affect4 = AffectFactory(
            flaw=flaw4,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            impact=Impact.CRITICAL,
        )
        ps_module = PsModuleFactory(
            name="foo-module", bts_name="jboss", bts_key="FOOPROJECT"
        )
        stream = PsUpdateStreamFactory(
            ps_module=ps_module, name="bar-1.2.3", version="1.2.3"
        )
        tracker = TrackerFactory(
            affects=[affect, affect2, affect3, affect4],
            external_system_id=None,
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
        # Simulating the pre_save signal to calculate the score.
        for c in [flwcvss, flwcvss2, flwcvss3, flwcvss4]:
            FlawCVSS.objects.filter(uuid=c.uuid).update(
                score=float(c.cvss_object.base_score)
            )
            c.refresh_from_db()
        expected1 = {
            "fields": {
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Vulnerability"},
                "summary": "CVE-2999-1000 CVE-2999-1001 CVE-2999-1002 CVE-2999-1003 foo-component: various flaws [bar-1.2.3]",
                "labels": [
                    "CVE-2999-1000",
                    "CVE-2999-1001",
                    "CVE-2999-1002",
                    "CVE-2999-1003",
                    "pscomponent:foo-component",
                    "SecurityTracking",
                    "Security",
                ],
                "versions": [
                    {"name": "1.2.3"},
                ],
                #
                # CVE Severity
                "customfield_an_identifier_for_cve_severity_field": {
                    "value": JiraCVESeverity.CRITICAL,
                },
                #
                # Source
                "customfield_12324746": {"value": "Red Hat"},
                #
                # CVE ID
                "customfield_12324749": "CVE-2999-1002",  # flaw3 is oldest of CRITICAL
                #
                # CVSS Score
                "customfield_12324748": f"""{flwcvss3.score} {flwcvss3.vector}""",
                #
                # CWE ID
                "customfield_12324747": "CWE-3",  # flaw3 is oldest of CRITICAL
                #
                # Downstream Component Name
                "customfield_12324752": "foo-component",
                #
                # Upstream Affected Component
                "customfield_12324751": "; ".join(
                    sorted(
                        set(
                            flaw.components
                            + flaw2.components
                            + flaw3.components
                            + flaw4.components
                        )
                    )
                ),
                #
                # Embargo Status
                "customfield_12324750": {"value": str(flaw.is_embargoed)},
                #
                # Special Handling
                "customfield_12324753": [],
            }
        }

        if not flaw.cwe_id:
            del expected1["fields"]["customfield_12324747"]

        query_builder = TrackerJiraQueryBuilder(tracker)
        query_builder.generate()
        validate_minimum_key_value(minimum=expected1, evaluated=query_builder._query)


class TestOldTrackerJiraQueryBuilderSla:
    """
    Test Jira tracker SLA query building for Bug issuetype.
    Not in the other classes, because for reasons unknown, the tests
    mysteriously breaks when parametrized like others in
    TestBothNewOldTrackerJiraQueryBuilder are. This isn't
    the first mystery for SLAs, as clean_policies looks suspect too.
    (Tests should rollback everything when run, so why is SLA
    cleanup necessary? Something evades pytest cleanup, and
    @pytest.mark.django_db(transaction=True) doesn't help.)
    Not enough resources to investigate deeper.
    """

    def test_generate_sla(self, clean_policies):
        return
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
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
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

        # SLA was manually marked to not be calculated
        tracker.meta_attr["labels"] = json.dumps(["nonstandard-sla"])
        query = OldTrackerJiraQueryBuilder(tracker).query
        assert target_start_id not in query["fields"]
        assert "duedate" not in query["fields"]


class TestTrackerJiraQueryBuilderSla:
    """
    Test Jira tracker SLA query building for Vulnerability issuetype.
    Not in the other classes, because for reasons unknown, the tests
    mysteriously breaks when parametrized like others in
    TestBothNewOldTrackerJiraQueryBuilder are. This isn't
    the first mystery for SLAs, as clean_policies looks suspect too.
    (Tests should rollback everything when run, so why is SLA
    cleanup necessary? Something evades pytest cleanup, and
    @pytest.mark.django_db(transaction=True) doesn't help.)
    Not enough resources to investigate deeper.
    """

    def test_generate_sla(self, clean_policies):
        """
        test that the query for the Jira SLA timestamps is generated correctly
        """
        flaw = FlawFactory(
            embargoed=False,
            reported_dt=make_aware(datetime(2000, 1, 1)),
            source="REDHAT",
        )
        ps_module = PsModuleFactory(
            bts_key="FOOPROJECT",
            bts_name="bugzilla",
            private_trackers_allowed=False,
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        jira_vulnissuetype_fields_setup_without_severity_versions()

        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="customfield_an_identifier_for_cve_severity_field",
            field_name="CVE Severity",
            allowed_values=[
                "Critical",
                "Important",
                "Moderate",
                "Low",
                "An Irrelevant Value To Be Ignored",
                "None",
            ],
        ).save()

        JiraProjectFields(
            project_key="FOOPROJECT",
            field_id="versions",
            field_name="Affects Version/s",
            allowed_values=["1.2.3"],
        ).save()

        # this value is used in RH instance of Jira however
        # it is always fetched from project meta anyway
        target_start_id = "customfield_12313941"
        JiraProjectFields(
            project_key=ps_module.bts_key,
            field_id=target_start_id,
            field_name="Target start",
        ).save()

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

        query = TrackerJiraQueryBuilder(tracker).query

        assert target_start_id in query["fields"]
        assert query["fields"][target_start_id] == "2000-01-01T00:00:00+00:00"
        assert "duedate" in query["fields"]
        assert query["fields"]["duedate"] == "2000-01-11T00:00:00+00:00"

        # SLA was manually marked to not be calculated
        tracker.meta_attr["labels"] = json.dumps(["nonstandard-sla"])
        query = TrackerJiraQueryBuilder(tracker).query
        assert target_start_id not in query["fields"]
        assert "duedate" not in query["fields"]
