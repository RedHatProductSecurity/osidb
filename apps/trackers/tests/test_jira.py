"""
Bugzilla specific tracker test cases
"""
from typing import Any, Dict

import pytest

from apps.trackers.jira.query import JiraPriority, TrackerJiraQueryBuilder
from apps.trackers.models import JiraProjectFields
from osidb.models import Affect, Flaw, Impact, Tracker
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
            (Impact.MODERATE, Impact.LOW, JiraPriority.NORMAL),
            (Impact.CRITICAL, Impact.LOW, JiraPriority.CRITICAL),
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
                {"name": "Blocker"},
                {"name": "Critical"},
                {"name": "Major"},
                {"name": "Normal"},
                {"name": "Minor"},
                {"name": "Undefined"},
            ],
        )
        field.save()
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
        stream = PsUpdateStreamFactory(ps_module=ps_module, name="bar-1.2.3")
        tracker = TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=stream.name,
            embargoed=flaw.is_embargoed,
        )

        quer_builder = TrackerJiraQueryBuilder(tracker)
        quer_builder.generate()
        validate_minimum_key_value(minimum=expected1, evaluated=quer_builder._query)

    def test_generate_labels(self):
        """
        test that the query for the Jira labels is generated correctly
        """
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
        )

        query_builder = TrackerJiraQueryBuilder(tracker)
        query_builder._query = {"fields": {}}
        query_builder.generate_labels()

        labels = query_builder.query["fields"]["labels"]
        assert "SecurityTracking" in labels
        assert "Security" in labels
        assert "pscomponent:component" in labels
        assert "CVE-2000-2000" in labels
        assert len(labels) == 4


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
