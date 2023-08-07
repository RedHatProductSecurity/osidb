"""
    tests of Jira BTS Tracker class

    This class uses VCR in order to not call real Jira endpoints
    during regular tests, and it is recommendend to use Stage Jira instance for
    generating new cassettes.
"""

from typing import Any, Dict

import pytest

from apps.trackers.jira.core import JiraPriority, JiraTracker
from apps.trackers.models import JiraProjectFields
from osidb.models import Affect, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestJiraTracker(object):
    def test_jira_text_generation(self):
        """
        Test that JiraTracker class is able to proper generate a Jira object able to be created / updated
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
                "priority": {"name": JiraPriority.MINOR},
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Bug"},
                "summary": "CVE-2999-1000 foo-component: CVE-2999-1000 kernel: some description [bar-1.2.3]",
                "labels": [
                    "CVE-2999-1000",
                    "pscomponent:foo-component",
                    "SecurityTracking",
                    "Security",
                ],
            }
        }
        regular_flaw = FlawFactory(
            embargoed=False, bz_id="123", cve_id="CVE-2999-1000", impact=Impact.LOW
        )
        regular_affect = AffectFactory(
            flaw=regular_flaw, ps_module="foo-module", ps_component="foo-component"
        )
        ps_module = PsModuleFactory(
            name="foo-module", bts_name="jboss", bts_key="FOOPROJECT"
        )
        stream = PsUpdateStreamFactory(ps_module=ps_module, name="bar-1.2.3")
        tracker1 = JiraTracker(
            regular_flaw, regular_affect, stream
        ).generate_bts_object()
        validate_minimum_key_value(minimum=expected1, evaluated=tracker1)

        expected2 = {
            "fields": {
                "priority": {"name": JiraPriority.MINOR},
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Bug"},
                "summary": "CVE-2999-1000 foo-component: CVE-2999-1000 kernel: some description [bar-1.2.3]",
                "labels": [
                    "CVE-2999-1000",
                    "pscomponent:foo-component",
                    "SecurityTracking",
                    "Security",
                ],
            }
        }
        tracker2 = JiraTracker(
            regular_flaw, regular_affect, stream
        ).generate_bts_object()
        validate_minimum_key_value(minimum=expected2, evaluated=tracker2)

        embargoed_flaw = FlawFactory(
            embargoed=True,
            bz_id="456",
            cve_id="CVE-2999-1001",
            impact=Impact.CRITICAL,
        )
        embargoed_affect = AffectFactory(
            flaw=embargoed_flaw,
            ps_module="foo-module",
            ps_component="foo-component",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
        )
        expected3 = {
            "fields": {
                "priority": {"name": JiraPriority.CRITICAL},
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Bug"},
                "security": {"name": "Embargoed Security Issue"},
                "summary": "CVE-2999-1001 foo-component: EMBARGOED CVE-2999-1001 kernel: some description [bar-1.2.3]",
                "labels": [
                    "CVE-2999-1001",
                    "pscomponent:foo-component",
                    "SecurityTracking",
                    "Security",
                ],
            }
        }
        tracker3 = JiraTracker(
            embargoed_flaw, embargoed_affect, stream
        ).generate_bts_object()
        validate_minimum_key_value(minimum=expected3, evaluated=tracker3)

        expected4 = {
            "key": "FOOPROJECT-140",
            "fields": {
                "priority": {"name": JiraPriority.CRITICAL},
                "project": {"key": "FOOPROJECT"},
                "issuetype": {"name": "Bug"},
                "security": {"name": "Embargoed Security Issue"},
                "summary": "CVE-2999-1001 foo-component: EMBARGOED CVE-2999-1001 kernel: some description [bar-1.2.3]",
                "labels": [
                    "CVE-2999-1001",
                    "pscomponent:foo-component",
                    "SecurityTracking",
                    "Security",
                ],
            },
        }
        embargoed_affect2 = AffectFactory(
            flaw=embargoed_flaw, ps_module="foo-module", ps_component="foo-component"
        )
        assert not embargoed_affect2.trackers.exists()
        TrackerFactory(
            affects=[embargoed_affect],
            embargoed=True,
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=stream.name,
            external_system_id="FOOPROJECT-140",
        )
        tracker4 = JiraTracker(
            embargoed_flaw, embargoed_affect2, stream
        ).generate_bts_object()
        validate_minimum_key_value(minimum=expected4, evaluated=tracker4)


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
