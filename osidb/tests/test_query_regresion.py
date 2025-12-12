import pytest
from django.db import connection
from django.db.models.query import QuerySet
from django.test.utils import CaptureQueriesContext
from pytest_django.asserts import assertNumQueries

from apps.workflows.workflow import WorkflowModel
from osidb.api_views import FlawView
from osidb.models import Affect, Flaw, FlawSource, Impact, Tracker
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 60), (True, 60)])
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 61), (True, 61)])
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 54), (True, 54)])
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 58), (True, 58)])
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

    def test_flaw_update_does_not_prefetch_affects(
        self, auth_client, test_api_v2_uri, monkeypatch, bugzilla_token, jira_token
    ):
        """
        Regression test: PUT /flaws/{uuid} should not use the heavy
        "GET with no query params" prefetch path for affects.
        """
        flaw = FlawFactory(
            embargoed=False,
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

        # Gate: only capture QuerySet.prefetch_related calls made during FlawView.get_queryset().
        in_get_queryset = {"active": False}
        orig_get_queryset = FlawView.get_queryset

        def _spy_get_queryset(self):
            in_get_queryset["active"] = True
            try:
                return orig_get_queryset(self)
            finally:
                in_get_queryset["active"] = False

        monkeypatch.setattr(FlawView, "get_queryset", _spy_get_queryset, raising=True)

        prefetch_calls: list[tuple[str, ...]] = []
        orig_prefetch_related = QuerySet.prefetch_related

        def _spy_prefetch_related(self, *lookups):
            if in_get_queryset["active"]:
                prefetch_calls.append(tuple(lookups))
            return orig_prefetch_related(self, *lookups)

        monkeypatch.setattr(
            QuerySet, "prefetch_related", _spy_prefetch_related, raising=True
        )

        response = auth_client().put(
            f"{test_api_v2_uri}/flaws/{flaw.uuid}",
            {
                "comment_zero": flaw.comment_zero,
                "embargoed": flaw.embargoed,
                "impact": "MODERATE",
                "title": flaw.title,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )
        assert response.status_code == 200

        assert not prefetch_calls, (
            f"Unexpected affects prefetches during PUT: {prefetch_calls}"
        )

    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "embargoed,affect_quantity,expected_queries",
        [
            (True, 1, 76),
            (True, 10, 76),
            (True, 100, 76),
            (False, 1, 113),  # down from 119
            (False, 10, 311),  # down from 389
            (False, 100, 2291),  # down from 3089
        ],
    )
    def test_flaw_promote(
        self,
        auth_client,
        enable_jira_task_async_sync,
        test_api_uri,
        jira_token,
        bugzilla_token,
        embargoed,
        affect_quantity,
        expected_queries,
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

        # Force initial classification to start the promote chain from NEW.
        # Even with signals enabled, setting task_key later can trigger workflow
        # auto-adjust and skip ahead because required fields are already filled.
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

        # Promote to TRIAGE
        response = auth_client().post(
            f"{test_api_uri}/flaws/{flaw.uuid}/promote",
            data={},
            format="json",
            **headers,
        )

        assert response.status_code == 200

        # Promote to PRE_SECONDARY_ASSESSMENT using async task sync
        # this one runs the nested set_public_nested call and set_history_public

        with assertNumQueriesLessThan(expected_queries):
            response = auth_client().post(
                f"{test_api_uri}/flaws/{flaw.uuid}/promote",
                data={},
                format="json",
                **headers,
            )
