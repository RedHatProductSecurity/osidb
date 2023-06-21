"""
Tests of Trackers service

This class uses VCR in order to not call real endpoints
during regular tests, and it is recommendend to use Stage
BTS instances for generating new cassettes.
"""

import pytest

from apps.trackers.jira import JiraTracker
from apps.trackers.models import JiraProjectFields
from apps.trackers.service import JiraTrackerQuerier
from apps.trackers.tests.test_bts_tracker import validate_minimum_key_value
from osidb.models import Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
)

pytestmark = pytest.mark.unit


class TestJiraService(object):
    def test_jira_connection(self, user_token):
        """
        Test that tracker is able to instantiate a Jira connection object
        """
        assert JiraTrackerQuerier(token=user_token).jira_conn

    @pytest.mark.vcr
    def test_create_bts_affect_tracker(
        self, user_token, stage_jira_project, jira_test_url
    ):
        """
        Test that service is able to create a tracker in Jira for a given affect
        """
        field = JiraProjectFields(
            project_key=stage_jira_project,
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
        # Remove randomness to reuse VCR every possible time
        flaw1 = FlawFactory(
            bz_id="123",
            cve_id="CVE-2999-2001",
            embargoed=False,
            uuid="0bd02877-e04c-4174-a436-cafb7b79f111",
            impact=Impact.MODERATE,
        )
        affect1 = AffectFactory(
            flaw=flaw1, ps_module="foo-module", ps_component="fixed-ps-component-0"
        )
        flaw2 = FlawFactory(
            bz_id="456",
            cve_id="CVE-2999-2002",
            embargoed=True,
            uuid="4c534902-c270-4302-97f5-878bece153f3",
            impact=Impact.CRITICAL,
        )
        affect2 = AffectFactory(
            flaw=flaw2, ps_module="foo-module", ps_component="fixed-ps-component-1"
        )

        assert not affect1.trackers.exists()
        assert not affect2.trackers.exists()

        ps_module = PsModuleFactory(
            name="foo-module", bts_name="jboss", bts_key=stage_jira_project
        )
        stream1 = PsUpdateStreamFactory(ps_module=ps_module, name="bar-1.2.3")
        stream2 = PsUpdateStreamFactory(ps_module=ps_module, name="baz-2")

        bts = JiraTrackerQuerier(token=user_token)
        bts._jira_server = jira_test_url

        response1 = bts.create_bts_affect_tracker(affect1, [stream1])
        assert response1.status_code == 201
        tracker1 = JiraTracker(flaw1, affect1, stream1)
        expected1 = tracker1.generate_bts_object()
        expected1["fields"].pop("description")
        issue1 = response1.data[0]["issue"].raw
        validate_minimum_key_value(expected1, issue1)
        assert Tracker.objects.get(
            type=Tracker.TrackerType.JIRA, external_system_id=issue1["key"]
        )

        response2 = bts.create_bts_affect_tracker(affect2, [stream1, stream2])
        assert response2.status_code == 201

        tracker2 = JiraTracker(flaw2, affect2, stream1)
        tracker3 = JiraTracker(flaw2, affect2, stream2)

        expected2 = tracker2.generate_bts_object()
        expected2["fields"].pop("description")
        issue2 = response2.data[0]["issue"].raw
        validate_minimum_key_value(expected2, issue2)

        expected3 = tracker3.generate_bts_object()
        expected3["fields"].pop("description")
        issue3 = response2.data[1]["issue"].raw
        validate_minimum_key_value(expected3, issue3)
