import pytest

from osidb.models import Erratum, Tracker
from osidb.tests.factories import TrackerFactory

from ..core import (
    get_all_errata,
    get_errata_to_sync,
    get_flaws_and_trackers_for_erratum,
    link_bugs_to_errata,
)

BZ_CASSETTE = "TestErrataToolCollection.test_get_bz_trackers_for_erratum.yaml"
JIRA_CASSETTE = "TestErrataToolCollection.test_get_jira_trackers_for_erratum.yaml"

pytestmark = pytest.mark.unit


class TestErrataToolCollection:
    @pytest.mark.vcr
    def test_get_all_errata(self):
        """Test that we can get all errata with CVEs from Errata Tool for initial collector run"""
        errata_id_name_pairs = get_all_errata()

        assert len(errata_id_name_pairs) == 5421

    @pytest.mark.vcr
    def test_get_errata_to_sync(self, sample_search_time):
        """Test that we can search Errata Tool for all errata updated after last collector success time"""
        errata_id_name_pairs = get_errata_to_sync(sample_search_time)

        assert len(errata_id_name_pairs) == 66
        # Using stage data for this + above cassette to avoid pulling in very new / still-embargoed CVEs

    @pytest.mark.vcr
    def test_get_bz_trackers_for_erratum(self, sample_erratum_with_bz_bugs):
        """Test that we can get all flaws and Bugzilla trackers linked to an erratum"""
        (
            flaws,
            bz_tracker_ids,
            jira_tracker_ids,
        ) = get_flaws_and_trackers_for_erratum(sample_erratum_with_bz_bugs)

        assert len(flaws) == 2
        assert len(bz_tracker_ids) == 2
        assert len(jira_tracker_ids) == 0
        # This + all below cassettes use (unembargoed) prod errata to be more realistic
        # if you need to re-record, comment out "with patch" above,
        # delete "stage." in config.settings.ERRATA_TOOL_SERVER,
        # and rerun tests with "--record-mode=rewrite" in Tox arguments

    @pytest.mark.vcr
    def test_get_jira_trackers_for_erratum(self, sample_erratum_with_jira_issues):
        """Test that we can get all flaws and Jira trackers linked to an erratum"""
        # The test uses the same code as above, but no errata I've checked have both Bugzilla and Jira trackers
        (
            flaws,
            bz_tracker_ids,
            jira_tracker_ids,
        ) = get_flaws_and_trackers_for_erratum(sample_erratum_with_jira_issues)

        assert len(flaws) == 1
        assert len(bz_tracker_ids) == 0
        assert len(jira_tracker_ids) == 1

    @pytest.mark.default_cassette(BZ_CASSETTE)
    @pytest.mark.vcr
    def test_link_bz_bugs_to_errata(
        self, sample_erratum_with_bz_bugs, sample_erratum_name
    ):
        """Test that a given (et_id, advisory_name) pair can have its data fetched, saved to the DB, and linked"""
        TrackerFactory.create(
            external_system_id="2021161", type=Tracker.TrackerType.BUGZILLA
        )
        TrackerFactory.create(
            external_system_id="2021168", type=Tracker.TrackerType.BUGZILLA
        )
        link_bugs_to_errata([(sample_erratum_with_bz_bugs, sample_erratum_name)])

        # One erratum was created
        assert Erratum.objects.count() == 1
        # Which is linked to two Bugzilla trackers, the same as above
        assert Erratum.objects.first().trackers.count() == 2

    @pytest.mark.default_cassette(JIRA_CASSETTE)
    @pytest.mark.vcr
    def test_link_jira_issues_to_errata(
        self, sample_erratum_with_jira_issues, sample_erratum_name
    ):
        """Test that a given (et_id, advisory_name) pair can have its data fetched, saved to the DB, and linked"""
        # The test uses the same code as above, but no errata I've checked have both Bugzilla and Jira trackers
        TrackerFactory.create(
            external_system_id="LOG-2064", type=Tracker.TrackerType.JIRA
        )
        link_bugs_to_errata([(sample_erratum_with_jira_issues, sample_erratum_name)])

        # One erratum was created
        assert Erratum.objects.count() == 1
        # Which is linked to one Jira tracker, the same as above
        assert Erratum.objects.first().trackers.count() == 1

    @pytest.mark.vcr
    def test_skip_saving_when_flaws_missing(
        self, sample_erratum_with_no_flaws, sample_erratum_name
    ):
        """Test that we will not save an Erratum into the DB if it has no linked flaws in Errata Tool"""
        link_bugs_to_errata([(sample_erratum_with_no_flaws, sample_erratum_name)])

        # No erratum was created
        assert Erratum.objects.count() == 0

    @pytest.mark.default_cassette(JIRA_CASSETTE)
    @pytest.mark.vcr
    def test_skip_linking_when_trackers_missing(
        self, sample_erratum_with_jira_issues, sample_erratum_name
    ):
        """Test that a given (et_id, advisory_name) pair can have its data fetched, saved to the DB, and not linked"""
        # Today we skip linking errata to trackers if they do not already exist
        # Once the bzimport refactor is complete, we can run dependent collectors to create trackers
        # Then the ET collector can link them even when they do not already exist, and this test can go away
        link_bugs_to_errata([(sample_erratum_with_jira_issues, sample_erratum_name)])

        # One erratum was created
        assert Erratum.objects.count() == 1
        # Which is not linked to any trackers
        assert Erratum.objects.first().trackers.count() == 0
