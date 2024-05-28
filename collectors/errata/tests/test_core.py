import pytest
from django.utils import timezone

from collectors.framework.models import CollectorMetadata
from osidb.models import Affect, Erratum, Tracker
from osidb.tests.factories import (
    AffectFactory,
    ErratumFactory,
    PsModuleFactory,
    TrackerFactory,
)

from ..core import (
    get_all_errata,
    get_batch_end,
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

        assert len(errata_id_name_pairs) == 3

    @pytest.mark.parametrize(
        "bz_updated,jira_updated,expected_end",
        [
            (
                timezone.datetime(2020, 1, 1, tzinfo=timezone.utc),
                timezone.datetime(2020, 1, 1, tzinfo=timezone.utc),
                timezone.datetime(2020, 1, 1, tzinfo=timezone.utc),
            ),
            (
                timezone.datetime(2021, 1, 1, tzinfo=timezone.utc),
                timezone.datetime(2020, 1, 1, tzinfo=timezone.utc),
                timezone.datetime(2020, 1, 1, tzinfo=timezone.utc),
            ),
            (
                timezone.datetime(2020, 1, 1, tzinfo=timezone.utc),
                timezone.datetime(2021, 1, 1, tzinfo=timezone.utc),
                timezone.datetime(2020, 1, 1, tzinfo=timezone.utc),
            ),
        ],
    )
    def test_get_batch_end(self, bz_updated, jira_updated, expected_end):
        """
        test that the batch end logic respect the dependencies
        """
        CollectorMetadata(
            data_state=CollectorMetadata.DataState.COMPLETE,
            name="collectors.bzimport.tasks.bztracker_collector",
            updated_until_dt=bz_updated,
        ).save()
        CollectorMetadata(
            data_state=CollectorMetadata.DataState.COMPLETE,
            name="collectors.bzimport.tasks.jira_tracker_collector",
            updated_until_dt=jira_updated,
        ).save()

        assert expected_end == get_batch_end()

    @pytest.mark.vcr
    def test_get_errata_to_sync(self, sample_search_time):
        """Test that we can search Errata Tool for all errata updated after last collector success time"""
        errata_id_name_pairs = get_errata_to_sync(sample_search_time)

        assert len(errata_id_name_pairs) == 2

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
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        TrackerFactory.create(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            external_system_id="2021161",
            type=Tracker.TrackerType.BUGZILLA,
        )
        TrackerFactory.create(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            external_system_id="2021168",
            type=Tracker.TrackerType.BUGZILLA,
        )
        link_bugs_to_errata(
            [
                {
                    "et_id": sample_erratum_with_bz_bugs,
                    "advisory_name": sample_erratum_name,
                    "created_dt": "2023-01-08T00:41:10Z",
                    "shipped_dt": "2023-02-08T00:41:10Z",
                    "updated_dt": "2023-03-08T00:41:10Z",
                }
            ]
        )

        # One erratum was created
        assert Erratum.objects.count() == 1
        # Which is linked to two Bugzilla trackers, the same as above
        assert Erratum.objects.first().trackers.count() == 2
        assert Erratum.objects.first().created_dt == timezone.datetime(
            2023, 1, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().shipped_dt == timezone.datetime(
            2023, 2, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().updated_dt == timezone.datetime(
            2023, 3, 8, 0, 41, 10, tzinfo=timezone.utc
        )

    @pytest.mark.default_cassette(BZ_CASSETTE)
    @pytest.mark.vcr
    def test_unlink_from_errata(self, sample_erratum_with_bz_bugs, sample_erratum_name):
        """
        test that erratum-tracker link removals are respected
        reproducer for https://issues.redhat.com/browse/OSIDB-2752
        """
        ps_module1 = PsModuleFactory(bts_name="bugzilla")
        ps_module2 = PsModuleFactory(bts_name="jboss")
        affect1 = AffectFactory(
            ps_module=ps_module1.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )
        affect2 = AffectFactory(
            ps_module=ps_module2.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        TrackerFactory.create(
            affects=[affect1],
            embargoed=affect1.flaw.embargoed,
            external_system_id="2021161",
            type=Tracker.TrackerType.BUGZILLA,
        )
        TrackerFactory.create(
            affects=[affect1],
            embargoed=affect1.flaw.embargoed,
            external_system_id="2021168",
            type=Tracker.TrackerType.BUGZILLA,
        )

        # extra trackers
        bugzilla_tracker = TrackerFactory.create(
            affects=[affect1],
            embargoed=affect1.flaw.embargoed,
            external_system_id="7",
            type=Tracker.TrackerType.BUGZILLA,
        )
        jira_tracker = TrackerFactory.create(
            affects=[affect2],
            embargoed=affect2.flaw.embargoed,
            external_system_id="PROJECT-7",
            type=Tracker.TrackerType.JIRA,
        )

        # existing erratum linked to the trackers
        erratum = ErratumFactory.create(
            et_id=sample_erratum_with_bz_bugs,
            advisory_name=sample_erratum_name,
        )
        erratum.trackers.add(bugzilla_tracker)
        erratum.trackers.add(jira_tracker)

        assert Erratum.objects.count() == 1
        assert Erratum.objects.first().trackers.count() == 2
        assert bugzilla_tracker.errata.first() == erratum
        assert jira_tracker.errata.first() == erratum

        link_bugs_to_errata(
            [
                {
                    "et_id": sample_erratum_with_bz_bugs,
                    "advisory_name": sample_erratum_name,
                    "created_dt": "2023-01-08T00:41:10Z",
                    "shipped_dt": "2023-02-08T00:41:10Z",
                    "updated_dt": "2023-03-08T00:41:10Z",
                }
            ]
        )

        # no new erratum was created
        assert Erratum.objects.count() == 1
        assert Erratum.objects.first().trackers.count() == 2
        assert not bugzilla_tracker.errata.first()
        assert not jira_tracker.errata.first()

    @pytest.mark.default_cassette(JIRA_CASSETTE)
    @pytest.mark.vcr
    def test_link_jira_issues_to_errata(
        self, sample_erratum_with_jira_issues, sample_erratum_name
    ):
        """Test that a given (et_id, advisory_name) pair can have its data fetched, saved to the DB, and linked"""
        ps_module = PsModuleFactory(bts_name="jboss")
        affect = AffectFactory(
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        # The test uses the same code as above, but no errata I've checked have both Bugzilla and Jira trackers
        TrackerFactory.create(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            external_system_id="LOG-2064",
            type=Tracker.TrackerType.JIRA,
        )
        link_bugs_to_errata(
            [
                {
                    "et_id": sample_erratum_with_jira_issues,
                    "advisory_name": sample_erratum_name,
                    "created_dt": "2023-01-08T00:41:10Z",
                    "shipped_dt": "2023-02-08T00:41:10Z",
                    "updated_dt": "2023-03-08T00:41:10Z",
                }
            ]
        )

        # One erratum was created
        assert Erratum.objects.count() == 1
        # Which is linked to one Jira tracker, the same as above
        assert Erratum.objects.first().trackers.count() == 1
        assert Erratum.objects.first().created_dt == timezone.datetime(
            2023, 1, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().shipped_dt == timezone.datetime(
            2023, 2, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().updated_dt == timezone.datetime(
            2023, 3, 8, 0, 41, 10, tzinfo=timezone.utc
        )

    @pytest.mark.default_cassette(JIRA_CASSETTE)
    @pytest.mark.vcr
    def test_skip_linking_when_trackers_missing(
        self, sample_erratum_with_jira_issues, sample_erratum_name
    ):
        """Test that a given (et_id, advisory_name) pair can have its data fetched, saved to the DB, and not linked"""
        # Today we skip linking errata to trackers if they do not already exist
        # Once the bzimport refactor is complete, we can run dependent collectors to create trackers
        # Then the ET collector can link them even when they do not already exist, and this test can go away
        link_bugs_to_errata(
            [
                {
                    "et_id": sample_erratum_with_jira_issues,
                    "advisory_name": sample_erratum_name,
                    "created_dt": "2023-01-08T00:41:10Z",
                    "shipped_dt": "2023-02-08T00:41:10Z",
                    "updated_dt": "2023-03-08T00:41:10Z",
                }
            ]
        )

        # One erratum was created
        assert Erratum.objects.count() == 1
        # Which is not linked to any trackers
        assert Erratum.objects.first().trackers.count() == 0
        assert Erratum.objects.first().created_dt == timezone.datetime(
            2023, 1, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().shipped_dt == timezone.datetime(
            2023, 2, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().updated_dt == timezone.datetime(
            2023, 3, 8, 0, 41, 10, tzinfo=timezone.utc
        )

    @pytest.mark.vcr
    def test_update_advisory_name(
        self, sample_erratum_with_bz_bugs, sample_erratum_name
    ):
        """Test that when advisory_name changes the Erratum is updated during linking"""
        ps_module = PsModuleFactory(bts_name="bugzilla")
        affect = AffectFactory(
            ps_module=ps_module.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        TrackerFactory.create(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            external_system_id="2021161",
            type=Tracker.TrackerType.BUGZILLA,
        )
        TrackerFactory.create(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            external_system_id="2021168",
            type=Tracker.TrackerType.BUGZILLA,
        )

        link_bugs_to_errata(
            [
                {
                    "et_id": sample_erratum_with_bz_bugs,
                    "advisory_name": f"{sample_erratum_name}-01",
                    "created_dt": "2023-01-08T00:41:10Z",
                    "shipped_dt": "2023-02-08T00:41:10Z",
                    "updated_dt": "2023-03-08T00:41:10Z",
                }
            ]
        )

        # One erratum was created
        assert Erratum.objects.count() == 1
        assert Erratum.objects.first().advisory_name == f"{sample_erratum_name}-01"
        assert Erratum.objects.first().created_dt == timezone.datetime(
            2023, 1, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().shipped_dt == timezone.datetime(
            2023, 2, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().updated_dt == timezone.datetime(
            2023, 3, 8, 0, 41, 10, tzinfo=timezone.utc
        )

        link_bugs_to_errata(
            [
                {
                    "et_id": sample_erratum_with_bz_bugs,
                    "advisory_name": f"{sample_erratum_name}-02",
                    "created_dt": "2023-01-08T00:41:10Z",
                    "shipped_dt": "2023-03-08T00:41:10Z",
                    "updated_dt": "2023-05-08T00:41:10Z",
                }
            ]
        )

        # Erratum is updated
        assert Erratum.objects.count() == 1
        assert Erratum.objects.first().advisory_name == f"{sample_erratum_name}-02"
        assert Erratum.objects.first().created_dt == timezone.datetime(
            2023, 1, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().shipped_dt == timezone.datetime(
            2023, 3, 8, 0, 41, 10, tzinfo=timezone.utc
        )
        assert Erratum.objects.first().updated_dt == timezone.datetime(
            2023, 5, 8, 0, 41, 10, tzinfo=timezone.utc
        )
