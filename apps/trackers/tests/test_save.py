"""
tracker saver tests
"""

from unittest.mock import patch

import pytest

from apps.bbsync.save import BugzillaSaver
from apps.trackers.bugzilla.save import TrackerBugzillaSaver
from apps.trackers.exceptions import UnsupportedTrackerError
from apps.trackers.jira.save import TrackerJiraSaver
from apps.trackers.save import TrackerSaver
from collectors.bzimport.collectors import BugzillaTrackerCollector
from collectors.jiraffe.collectors import JiraTrackerCollector
from osidb.models import Affect, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestTrackerSaver:
    def test_refuse_multi_cve_flaw(self):
        """
        test that a multi-CVE flaw is refused with the expected
        error message when attemting to file a tracker against it
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw1 = FlawFactory(bz_id="12345", cve_id="CVE-2020-1111")
        flaw2 = FlawFactory(
            bz_id="12345", cve_id="CVE-2020-2222", embargoed=flaw1.embargoed
        )

        affect1 = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=affect1.ps_module,
            ps_component=affect1.ps_component,
        )

        tracker = TrackerFactory(
            affects=[affect1, affect2],
            embargoed=flaw1.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        with pytest.raises(
            UnsupportedTrackerError,
            match="Creating trackers for flaws with multiple CVEs is not supported",
        ):
            TrackerSaver(tracker, bz_api_key="SECRET")

    def test_bugzilla(self):
        """
        test that the general TrackerSaver turns into TrackerBugzillaSaver for Bugzilla trackers
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        assert isinstance(
            TrackerSaver(tracker, bz_api_key="SECRET"), TrackerBugzillaSaver
        )

    def test_bugzilla_no_secret(self):
        """
        test that the tracker filing is refused with the expected error message
        when attemting to file a Bugzilla tracker without providing the API key
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        with pytest.raises(
            AssertionError,
            match="Bugzilla API key not provided",
        ):
            TrackerSaver(tracker)

    def test_jira(self):
        """
        test that the general TrackerSaver turns into TrackerJiraSaver for Jira trackers
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
        )

        assert isinstance(
            TrackerSaver(tracker, jira_token="SECRET"), TrackerJiraSaver  # nosec
        )

    def test_jira_no_secret(self):
        """
        test that the tracker filing is refused with the expected error message
        when attemting to file a Jira tracker without providing the access token
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
        )

        with pytest.raises(
            AssertionError,
            match="Jira access token not provided",
        ):
            TrackerSaver(tracker)


class TestTrackerModelSave:
    """
    test the tracker model save funtionality
    which integrates with the TrackerSaver class
    """

    def test_bugzilla_db_only(self):
        """
        test the default Bugzilla tracker database only save
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        with (
            patch.object(
                BugzillaSaver, "save", return_value=tracker
            ) as bugzilla_save_mock,
            patch.object(
                BugzillaTrackerCollector, "sync_tracker"
            ) as bugzilla_load_mock,
        ):
            tracker.save(bz_api_key="SECRET")

            assert not bugzilla_save_mock.called
            assert not bugzilla_load_mock.called

    def test_bugzilla_backend(self, enable_bugzilla_sync):
        """
        test the Bugzilla tracker backend save
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        with (
            patch.object(
                BugzillaSaver, "save", return_value=tracker
            ) as bugzilla_save_mock,
            patch.object(
                BugzillaTrackerCollector, "sync_tracker"
            ) as bugzilla_load_mock,
        ):
            tracker.save(bz_api_key="SECRET")

            assert bugzilla_save_mock.called
            assert bugzilla_load_mock.called

    def test_jira_db_only(self):
        """
        test the default Jira tracker database only save
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
        )

        with (
            patch.object(
                TrackerJiraSaver, "save", return_value=tracker
            ) as jira_save_mock,
            patch.object(JiraTrackerCollector, "collect") as jira_load_mock,
        ):
            tracker.save(jira_token="SECRET")  # nosec

            assert not jira_save_mock.called
            assert not jira_load_mock.called

    def test_jira_backend(self, enable_jira_sync):
        """
        test the Jira tracker backend save
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
        )

        with (
            patch.object(
                TrackerJiraSaver, "save", return_value=tracker
            ) as jira_save_mock,
            patch.object(JiraTrackerCollector, "collect") as jira_load_mock,
        ):
            tracker.save(jira_token="SECRET")  # nosec

            assert jira_save_mock.called
            assert jira_load_mock.called
