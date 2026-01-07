import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from pytest_django.asserts import assertNumQueries

from apps.workflows.workflow import WorkflowModel
from osidb.models import Affect, Flaw, Impact, Tracker, FlawSource
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.queryset


def assertNumQueriesLessThan(max_queries, using="default"):
    """
    Context manager that asserts the number of queries is less than or equal to max_queries.
    This is useful for query regression tests where the exact count may vary slightly
    between environments due to transaction handling or other implementation details.
    """

    class _AssertNumQueriesLessThan(CaptureQueriesContext):
        def __exit__(self, exc_type, exc_value, traceback):
            super().__exit__(exc_type, exc_value, traceback)
            if exc_type is not None:
                return
            num_queries = len(self.captured_queries)
            assert num_queries <= max_queries, (
                f"{num_queries} queries executed, expected <= {max_queries}"
            )

    return _AssertNumQueriesLessThan(connection)


@pytest.mark.parametrize("embargoed", [False, True])
class TestQuerySetRegression:
    """
    Test that the number of queries executed by a given endpoint
    does not regress over time. This is done by comparing the number of queries
    executed by the endpoint to a known good value.
    """

    def test_flaw_list(self, auth_client, test_api_v2_uri, embargoed):
        for _ in range(3):
            flaw = FlawFactory(
                embargoed=embargoed,
                impact=Impact.LOW,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            AffectFactory.create_batch(
                3,
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
            )
        with assertNumQueriesLessThan(62):  # initial value -> 113
            response = auth_client().get(f"{test_api_v2_uri}/flaws")
            assert response.status_code == 200

    def test_flaw_list_filtered(self, auth_client, test_api_v2_uri, embargoed):
        """
        Using the same subset of fields as OSIM
        """
        for _ in range(3):
            flaw = FlawFactory(
                embargoed=embargoed,
                impact=Impact.LOW,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            AffectFactory.create_batch(
                3,
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
            )

        with assertNumQueries(58):  # initial value -> 61
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws?include_fields=cve_id,uuid,impact,source,created_dt,updated_dt,classification,title,unembargo_dt,embargoed,owner,labels"
            )
            assert response.status_code == 200

    def test_empty_flaw(self, auth_client, test_api_v2_uri, embargoed):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with assertNumQueries(58):  # initial value -> 60
            response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    def test_flaw_with_affects(self, auth_client, test_api_v2_uri, embargoed):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        AffectFactory.create_batch(
            3,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.MODERATE,
        )

        with assertNumQueries(61):  # initial value -> 78
            response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    def test_flaw_with_affects_history(self, auth_client, test_api_v2_uri, embargoed):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        AffectFactory.create_batch(
            3,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.MODERATE,
        )

        with assertNumQueries(62):  # initial value -> 82
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_history=true"
            )
            assert response.status_code == 200

    def test_flaw_with_affects_trackers(self, auth_client, test_api_v2_uri, embargoed):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        for _ in range(3):
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affect = AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
                ps_update_stream=ps_update_stream.name,
            )
            TrackerFactory(
                affects=[affect],
                embargoed=embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )
        with assertNumQueriesLessThan(66):  # initial value -> 93
            response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    def test_affect_list(self, auth_client, test_api_v2_uri, embargoed):
        for _ in range(3):
            flaw = FlawFactory(
                embargoed=embargoed,
                impact=Impact.LOW,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )

        # Query count varies between 56-57 depending on transaction SAVEPOINT cleanup
        # which is environment-dependent. Using <= 57 to allow for this variation.
        with assertNumQueriesLessThan(57):  # initial value -> 69
            response = auth_client().get(f"{test_api_v2_uri}/affects")
            assert response.status_code == 200

    def test_affect_list_history(self, auth_client, test_api_v2_uri, embargoed):
        for _ in range(3):
            flaw = FlawFactory(
                embargoed=embargoed,
                impact=Impact.LOW,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            AffectFactory(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )

        with assertNumQueries(55):  # initial value -> 69
            response = auth_client().get(
                f"{test_api_v2_uri}/affects?include_history=true"
            )
            assert response.status_code == 200

    def test_related_flaws(self, auth_client, test_api_v2_uri, embargoed):
        """
        Test query performance for related flaws endpoint.
        This query usually takes a lot of time to process from OSIM when
        fetching flaws that have affects sharing the same ps_module and ps_component.
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        ps_component = "kernel"

        for _ in range(3):
            flaw = FlawFactory(
                embargoed=embargoed,
                impact=Impact.MODERATE,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            AffectFactory(
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                ps_component=ps_component,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
            )

        with assertNumQueries(59):
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws?include_fields=cve_id,uuid,affects,"
                f"created_dt,updated_dt&affects__ps_module={ps_module.name}"
                f"&affects__ps_component={ps_component}&order=-created_dt&limit=10"
            )
            assert response.status_code == 200


    @pytest.mark.parametrize("affect_quantity", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    def test_flaw_promote(
        self,
        auth_client,
        enable_jira_task_async_sync,
        test_api_uri,
        embargoed,
        jira_token,
        bugzilla_token,
        affect_quantity,
    ):
        """
        Test query performance for flaws promote endpoint as number of affects increases.
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        if not embargoed:
            flaw.set_internal()
            flaw.save()

        for _ in range(affect_quantity):
            affect = AffectFactory(
                flaw=flaw,
                ps_update_stream=ps_update_stream.name,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
            )

            TrackerFactory(
                affects=[affect],
                embargoed=embargoed,
                ps_update_stream=ps_update_stream.name,
                type=Tracker.BTS2TYPE[ps_module.bts_name],
            )
            # Make children internal in the non-embargoed scenario so set_public_nested has work to do
            if not embargoed:
                # Ensure related objects start as internal, then promotion will flip them public
                affect.set_internal()
                affect.save(raise_validation_error=False)
                if affect.tracker:
                    affect.tracker.set_internal()
                    affect.tracker.save(raise_validation_error=False)

        # Force initial classification because signals are muted in queryset tests
        flaw.classification = {
            "workflow": "DEFAULT",
            "state": WorkflowModel.WorkflowState.NEW,
        }
        # NEW -> TRIAGE requires owner
        flaw.owner = "Alice"
        # TRIAGE -> PRE_SECONDARY_ASSESSMENT requires source and title
        flaw.source = FlawSource.CUSTOMER
        flaw.title = flaw.title or "Sample title"
        flaw.save(raise_validation_error=False)
        # Ensure a Jira task exists so workflow transitions trigger adjust_acls/set_public_nested
        flaw.task_key = "OSIM-1"
        flaw.save(raise_validation_error=False)

        headers = {
            "HTTP_JIRA_API_KEY": jira_token,
            "HTTP_BUGZILLA_API_KEY": bugzilla_token,
        }



        # when not it increases becuase of the nested set_public_nested call
        if not embargoed:
            expected_queries = (
                2 * affect_quantity**3
                + 147 * affect_quantity**2
                + 133 * affect_quantity
                + 480
            ) // 6
        else:
            expected_queries = 58

        # Promote to TRIAGE
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )

        assert response.status_code == 200

        flaw.refresh_from_db()

        # Promote to PRE_SECONDARY_ASSESSMENT using async task sync
        # this one runs the nested set_public_nested call and set_history_public
        test_data = {"affects_quantity": affect_quantity, "embargoed": embargoed}

        with assertNumQueries(expected_queries, kwargs=test_data):
            response = auth_client().post(
                f"{test_api_uri}/flaws/{flaw.uuid}/promote",
                data={},
                format="json",
                **headers,
            )
