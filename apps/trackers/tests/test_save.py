"""
tracker saver tests
"""

import uuid
from datetime import datetime
from datetime import timezone as dt_timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from bugzilla.exceptions import BugzillaError
from django.utils import timezone
from freezegun import freeze_time
from jira import JIRAError

from apps.bbsync.save import BugzillaSaver
from apps.trackers.bugzilla.save import TrackerBugzillaSaver
from apps.trackers.exceptions import BTSException, UnsupportedTrackerError
from apps.trackers.jira.query import OldTrackerJiraQueryBuilder, TrackerJiraQueryBuilder
from apps.trackers.jira.save import TrackerJiraSaver, parse_jira_datetime
from apps.trackers.save import TrackerSaver
from collectors.bzimport.collectors import (
    BugzillaTrackerCollector,
    BZTrackerDownloadManager,
)
from collectors.jiraffe.collectors import (
    JiraTrackerCollector,
    JiraTrackerDownloadManager,
)
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
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )
        affect2 = AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
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
            ps_update_stream=ps_update_stream.name,
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
            ps_update_stream=ps_update_stream.name,
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

    def test_jira(self, jira_token, jira_email):
        """
        test that the general TrackerSaver turns into TrackerJiraSaver for Jira trackers
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
        )

        assert isinstance(
            TrackerSaver(tracker, jira_token=jira_token, jira_email=jira_email),
            TrackerJiraSaver,  # nosec
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
            ps_update_stream=ps_update_stream.name,
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

    def test_empty_bz_id(self, jira_token, jira_email):
        """
        test we can fill a tracker without bz_id
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        # need two empty bz_id flaws to test conflict
        FlawFactory(bz_id=None)
        flaw = FlawFactory(bz_id=None)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
            flaw=flaw,
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
        )

        TrackerSaver(tracker, jira_token=jira_token, jira_email=jira_email)  # nosec


class TestTrackerModelSave:
    """
    test the tracker model save funtionality
    which integrates with the TrackerSaver class
    """

    def test_bugzilla_db_only(self, monkeypatch):
        """
        test the default Bugzilla tracker database only save
        """
        import osidb.models.tracker as tracker

        monkeypatch.setattr(tracker, "SYNC_TRACKERS_TO_BZ", False)

        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
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

    def test_bugzilla_backend(self, enable_bz_sync):
        """
        test the Bugzilla tracker backend save
        """
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
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
            patch.object(
                BZTrackerDownloadManager, "link_tracker_with_affects"
            ) as bugzilla_tracker_link_mock,
        ):
            tracker.save(bz_api_key="SECRET")

            assert bugzilla_save_mock.called
            # the rest is done async
            assert not bugzilla_load_mock.called
            assert not bugzilla_tracker_link_mock.called

    def test_jira_db_only(self):
        """
        test the default Jira tracker database only save
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
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

    def test_jira_backend(self, enable_jira_tracker_sync, jira_token, jira_email):
        """
        test the Jira tracker backend save
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
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
            patch.object(
                JiraTrackerDownloadManager, "link_tracker_with_affects"
            ) as jira_tracker_link_mock,
        ):
            tracker.save(jira_token=jira_token, jira_email=jira_email)  # nosec

            assert jira_save_mock.called
            # the rest is done async
            assert not jira_load_mock.called
            assert not jira_tracker_link_mock.called


class TestTrackerJiraSaverIssuetype:
    """
    Test handling of jira issuetype in TrackerJiraSaver
    """

    @pytest.mark.parametrize(
        "issuetype_param,expected_builder",
        [
            (None, OldTrackerJiraQueryBuilder),
            ("Bug", OldTrackerJiraQueryBuilder),
            ("Vulnerability", TrackerJiraQueryBuilder),
            ("Invalid", None),
        ],
    )
    def test_jira_issuetype(
        self, issuetype_param, expected_builder, jira_email, jira_token
    ):
        """
        test that the general TrackerSaver turns into TrackerJiraSaver for Jira trackers
        """
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
        )

        i = TrackerSaver(
            tracker,
            jira_token=jira_token,
            jira_email=jira_email,
            jira_issuetype=issuetype_param,
        )  # nosec
        assert isinstance(i, TrackerJiraSaver)
        assert i._jira_issuetype == issuetype_param
        if expected_builder is not None:
            assert i.get_builder() is expected_builder
        else:
            with pytest.raises(BTSException):
                i.get_builder()

    @pytest.mark.parametrize(
        "issuetype_param",
        [None, "Bug", "Vulnerability", "Invalid"],
    )
    def test_jira_error_logging(self, caplog, issuetype_param, jira_token, jira_email):
        ps_module = PsModuleFactory(bts_name="jboss")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )

        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.JIRA,
            uuid=str(uuid.uuid4()),
        )
        saver = TrackerSaver(
            tracker,
            jira_token=jira_token,
            jira_issuetype=issuetype_param,
            jira_email=jira_email,
        )
        mock_builder = type(
            "MockQueryBuilder",
            (),
            {"query": {"fields": {}}, "query_comment": None},
        )()
        with (
            patch.object(
                saver,
                "get_builder",
                return_value=lambda tracker: mock_builder,
            ) as mock_get_builder,
            patch.object(
                saver.jira_conn,
                "create_issue",
                side_effect=JIRAError(
                    status_code=422, text="JIRAError during tracker creation"
                ),
            ) as mock_create_issue,
        ):
            with caplog.at_level("ERROR"):
                with pytest.raises(JIRAError):
                    saver.create(tracker)

        assert mock_get_builder.called
        assert mock_create_issue.called
        assert "JIRAError during tracker creation" in caplog.text
        assert str(tracker.uuid) in caplog.text


class TestTrackerCreateTimestamps:
    """
    OSIDB-5468: BTS create must replace the Unix-epoch placeholder timestamps
    """

    def _tracker(self, bts_name, tracker_type, **extra):
        """
        build a tracker linked to a single affect for the given BTS
        """
        ps_module = PsModuleFactory(bts_name=bts_name)
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="component",
        )
        return TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=tracker_type,
            **extra,
        )

    def test_parse_jira_datetime_with_and_without_fractional_seconds(self):
        """
        parse Jira timestamps with and without fractional seconds
        """
        with_ms = parse_jira_datetime("2026-08-21T15:15:21.123+0000")
        without_ms = parse_jira_datetime("2026-08-21T15:15:21+0000")
        assert with_ms == datetime(
            2026, 8, 21, 15, 15, 21, 123000, tzinfo=dt_timezone.utc
        )
        assert without_ms == datetime(2026, 8, 21, 15, 15, 21, tzinfo=dt_timezone.utc)
        assert parse_jira_datetime(None) is None
        assert parse_jira_datetime("not-a-date") is None

    def test_jira_create_copies_issue_timestamps(self, jira_token, jira_email):
        """
        copy created/updated timestamps from the Jira create response
        """
        tracker = self._tracker(
            "jboss", Tracker.TrackerType.JIRA, external_system_id=""
        )
        tracker.created_dt = timezone.datetime(1970, 1, 1, tzinfo=timezone.utc)
        tracker.updated_dt = timezone.datetime(1970, 1, 1, tzinfo=timezone.utc)

        issue = SimpleNamespace(
            key="RHEL-1234",
            fields=SimpleNamespace(
                created="2026-08-21T15:15:21.000+0000",
                updated="2026-08-21T15:16:09.000+0000",
            ),
        )
        mock_builder = type(
            "MockQueryBuilder",
            (),
            {"query": {"fields": {}}, "query_comment": None},
        )
        saver = TrackerSaver(
            tracker, jira_token=jira_token, jira_email=jira_email, jira_issuetype="Bug"
        )
        mock_conn = Mock()
        mock_conn.create_issue.return_value = issue
        saver._jira_conn = mock_conn
        saver._jira_conn_timestamp = datetime.now()

        with patch.object(
            saver, "get_builder", return_value=lambda _tracker: mock_builder()
        ):
            result = saver.create(tracker)

        mock_conn.create_issue.assert_called_once()

        assert result.external_system_id == "RHEL-1234"
        assert result.created_dt == datetime(
            2026, 8, 21, 15, 15, 21, tzinfo=dt_timezone.utc
        )
        assert result.updated_dt == datetime(
            2026, 8, 21, 15, 16, 9, tzinfo=dt_timezone.utc
        )

    def test_bugzilla_create_copies_bug_timestamps(self):
        """
        copy created/updated timestamps from the Bugzilla bug after create
        """
        tracker = self._tracker(
            "bugzilla", Tracker.TrackerType.BUGZILLA, external_system_id=""
        )
        tracker.created_dt = timezone.datetime(1970, 1, 1, tzinfo=timezone.utc)
        tracker.updated_dt = timezone.datetime(1970, 1, 1, tzinfo=timezone.utc)

        saver = TrackerBugzillaSaver(tracker)

        def fake_bz_create(self):
            """
            stub Bugzilla create to only assign an external bug id
            """
            self.instance.bz_id = "999888"
            return self.instance

        with (
            patch("apps.trackers.bugzilla.save.BugzillaSaver.create", fake_bz_create),
            patch.object(
                saver,
                "get_bug_data",
                return_value={
                    "creation_time": "2026-08-21T15:15:21Z",
                    "last_change_time": "2026-08-21T15:16:09Z",
                },
            ) as get_bug_data_mock,
        ):
            result = saver.create()

        get_bug_data_mock.assert_called_once_with(
            "999888", include_fields=["creation_time", "last_change_time"]
        )
        assert result.bz_id == "999888"
        assert result.created_dt == datetime(
            2026, 8, 21, 15, 15, 21, tzinfo=dt_timezone.utc
        )
        assert result.updated_dt == datetime(
            2026, 8, 21, 15, 16, 9, tzinfo=dt_timezone.utc
        )

    def test_bugzilla_create_timestamps_stay_utc_in_non_utc_timezone(self):
        """
        treat Bugzilla Z timestamps as UTC rather than the active Django timezone
        """
        tracker = self._tracker(
            "bugzilla", Tracker.TrackerType.BUGZILLA, external_system_id=""
        )
        tracker.created_dt = timezone.datetime(1970, 1, 1, tzinfo=timezone.utc)
        tracker.updated_dt = timezone.datetime(1970, 1, 1, tzinfo=timezone.utc)

        saver = TrackerBugzillaSaver(tracker)

        def fake_bz_create(self):
            """
            stub Bugzilla create to only assign an external bug id
            """
            self.instance.bz_id = "999888"
            return self.instance

        with (
            timezone.override("America/New_York"),
            patch("apps.trackers.bugzilla.save.BugzillaSaver.create", fake_bz_create),
            patch.object(
                saver,
                "get_bug_data",
                return_value={
                    "creation_time": "2026-08-21T15:15:21Z",
                    "last_change_time": "2026-08-21T15:16:09Z",
                },
            ),
        ):
            result = saver.create()

        created_utc = datetime(2026, 8, 21, 15, 15, 21, tzinfo=dt_timezone.utc)
        updated_utc = datetime(2026, 8, 21, 15, 16, 9, tzinfo=dt_timezone.utc)
        assert result.created_dt == created_utc
        assert result.updated_dt == updated_utc
        assert result.created_dt.utctimetuple() == created_utc.utctimetuple()
        assert result.updated_dt.utctimetuple() == updated_utc.utctimetuple()

    @freeze_time("2026-08-27T18:00:00Z")
    def test_bugzilla_create_falls_back_when_get_bug_data_fails(self):
        """
        keep bz_id and use current time when Bugzilla timestamp fetch fails
        """
        tracker = self._tracker(
            "bugzilla", Tracker.TrackerType.BUGZILLA, external_system_id=""
        )
        tracker.created_dt = timezone.datetime(1970, 1, 1, tzinfo=timezone.utc)
        tracker.updated_dt = timezone.datetime(1970, 1, 1, tzinfo=timezone.utc)

        saver = TrackerBugzillaSaver(tracker)

        def fake_bz_create(self):
            """
            stub Bugzilla create to only assign an external bug id
            """
            self.instance.bz_id = "999888"
            return self.instance

        with (
            patch("apps.trackers.bugzilla.save.BugzillaSaver.create", fake_bz_create),
            patch.object(
                saver,
                "get_bug_data",
                side_effect=BugzillaError({}),
            ),
        ):
            result = saver.create()

        assert result.bz_id == "999888"
        assert result.created_dt == timezone.now()
        assert result.updated_dt == timezone.now()
