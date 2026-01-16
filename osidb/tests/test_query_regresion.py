import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from pytest_django.asserts import assertNumQueries

from osidb.models import Affect, Flaw, Impact, Tracker
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


class TestQuerySetRegression:
    """
    Test that the number of queries executed by a given endpoint
    does not regress over time. This is done by comparing the number of queries
    executed by the endpoint to a known good value.
    """

    @pytest.mark.parametrize("embargoed,query_count", [(False, 63), (True, 62)])
    def test_flaw_list(self, auth_client, test_api_v2_uri, embargoed, query_count):
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
        with assertNumQueriesLessThan(query_count):  # initial value -> 113
            response = auth_client().get(f"{test_api_v2_uri}/flaws")
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 58), (True, 58)])
    def test_flaw_list_filtered(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
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

        with assertNumQueries(query_count):  # initial value -> 61
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws?include_fields=cve_id,uuid,impact,source,created_dt,updated_dt,classification,title,unembargo_dt,embargoed,owner,labels"
            )
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 58), (True, 58)])
    def test_empty_flaw(self, auth_client, test_api_v2_uri, embargoed, query_count):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with assertNumQueries(query_count):  # initial value -> 60
            response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 61), (True, 61)])
    def test_flaw_with_affects(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
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

        with assertNumQueries(query_count):  # initial value -> 78
            response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 62), (True, 62)])
    def test_flaw_with_affects_history(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
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

        with assertNumQueries(query_count):  # initial value -> 62
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_history=true"
            )
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 59), (True, 60)])
    def test_flaw_excluding_affects_is_faster(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
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

        # Excluding affects should avoid the expensive affects* prefetch path in the view.
        with assertNumQueriesLessThan(query_count) as ctx:
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws/{flaw.uuid}?exclude_fields=affects,trackers"
            )
            assert response.status_code == 200
            data = response.json()
            assert "affects" not in data
            assert "trackers" not in data

        # Excluding affects and trackers should avoid the heavy Affect manager queryset (annotations/subqueries).
        executed_sql = "\n".join(
            q["sql"] for q in ctx.captured_queries if f"{flaw.uuid}" in q["sql"]
        )
        assert "affects" not in executed_sql
        assert "trackers" not in executed_sql

    @pytest.mark.parametrize("embargoed,query_count", [(False, 50), (True, 50)])
    def test_flaw_include_fields_does_not_prefetch_affects(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
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

        # Requesting only scalar fields should not prefetch heavy relations like affects.
        with assertNumQueriesLessThan(query_count) as ctx:
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_fields=uuid,cve_id"
            )
            assert response.status_code == 200
            data = response.json()
            assert "affects" not in data
            assert set(data.keys()) == {
                "revision",
                "version",
                "dt",
                "uuid",
                "env",
                "cve_id",
            }

        # With include_fields limited to scalars, we should not touch affects at all.
        executed_sql = "\n".join(q["sql"] for q in ctx.captured_queries)
        assert '"osidb_affect"' not in executed_sql

    @pytest.mark.parametrize("embargoed,query_count", [(False, 66), (True, 67)])
    def test_flaw_with_affects_trackers(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
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
        with assertNumQueriesLessThan(query_count):  # initial value -> 93
            response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 57), (True, 57)])
    def test_affect_list(self, auth_client, test_api_v2_uri, embargoed, query_count):
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
        with assertNumQueriesLessThan(query_count):  # initial value -> 69
            response = auth_client().get(f"{test_api_v2_uri}/affects")
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 55), (True, 55)])
    def test_affect_list_history(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
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

        with assertNumQueries(query_count):  # initial value -> 55
            response = auth_client().get(
                f"{test_api_v2_uri}/affects?include_history=true"
            )
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 59), (True, 59)])
    def test_related_flaws(self, auth_client, test_api_v2_uri, embargoed, query_count):
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

        with assertNumQueries(query_count):
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws?include_fields=cve_id,uuid,affects,"
                f"created_dt,updated_dt&affects__ps_module={ps_module.name}"
                f"&affects__ps_component={ps_component}&order=-created_dt&limit=10"
            )
            assert response.status_code == 200
