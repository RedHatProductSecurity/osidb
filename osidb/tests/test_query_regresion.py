from contextlib import contextmanager

import pytest
from django.db import connection, reset_queries

from osidb.models import Affect, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.queryset

EXCLUDE_QUERIES = [
    "SET osidb.acl",
    'SELECT "auth_group"',
    'SELECT "auth_user"',
    "SAVEPOINT",
    'SELECT "django_content_type"',
]


@contextmanager
def numQueriesCloseTo(value, exact=False):
    """
    Context manager to assert that the number of queries executed is close to a given value.
    If the value is less than 100, a 10% tolerance is used.
    If the value is greater than or equal to 100, a 1% tolerance is used.
    """
    __tracebackhide__ = True
    reset_queries()
    yield
    relevant_queries = len(
        [
            q
            for q in connection.queries
            if not any(map(q["sql"].__contains__, EXCLUDE_QUERIES))
        ]
    )

    if exact:
        assert relevant_queries == value
    rel = 0.1 if value < 100 else 0.01
    assert relevant_queries == pytest.approx(value, rel=rel)


class TestQuerySetRegression:
    """
    Test that the number of queries executed by a given endpoint
    does not regress over time. This is done by comparing the number of queries
    executed by the endpoint to a known good value.
    """

    def test_flaw_list(self, auth_client, test_api_uri):
        for _ in range(100):
            flaw = FlawFactory()
            AffectFactory.create(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )

        with numQueriesCloseTo(512):  # initial value -> 512
            response = auth_client().get(f"{test_api_uri}/flaws")
            assert response.status_code == 200

    def test_flaw_list_filtered(self, auth_client, test_api_uri):
        """
        Using the same subset of fields as OSIM
        """
        for _ in range(100):
            flaw = FlawFactory()
            AffectFactory.create(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )

        with numQueriesCloseTo(103):  # initial value -> 303
            response = auth_client().get(
                f"{test_api_uri}/flaws?include_fields=cve_id,uuid,impact,source,created_dt,updated_dt,classification,title,unembargo_dt,embargoed,owner,labels"
            )
            assert response.status_code == 200

    def test_empty_flaw(self, auth_client, test_api_uri):
        flaw = FlawFactory()
        with numQueriesCloseTo(10):  # initial value -> 10
            response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    @pytest.mark.parametrize(
        "affect_count, expected_queries",
        [
            (1, 16),  # initial value -> 16
            (10, 52),  # initial value -> 52
            (100, 412),  # initial value -> 412
        ],
    )
    def test_flaw_with_affects(
        self, auth_client, test_api_uri, affect_count, expected_queries
    ):
        flaw = FlawFactory()
        AffectFactory.create_batch(
            affect_count,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        with numQueriesCloseTo(expected_queries):
            response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    @pytest.mark.parametrize(
        "affect_count, expected_queries",
        [
            (1, 19),  # initial value -> 19
            (10, 64),  # initial value -> 64
            (100, 514),  # initial value -> 514
        ],
    )
    def test_flaw_with_affects_history(
        self, auth_client, test_api_uri, affect_count, expected_queries
    ):
        flaw = FlawFactory()
        AffectFactory.create_batch(
            affect_count,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
        )

        with numQueriesCloseTo(expected_queries):
            response = auth_client().get(
                f"{test_api_uri}/flaws/{flaw.uuid}?include_history=true"
            )
            assert response.status_code == 200

    @pytest.mark.parametrize(
        "affect_count, tracker_count, expected_queries",
        [
            (1, 1, 21),  # initial value -> 21
            (10, 2, 89),  # initial value -> 89
            (100, 3, 866),  # initial value -> 866
        ],
    )
    def test_flaw_with_affects_trackers(
        self, auth_client, test_api_uri, affect_count, tracker_count, expected_queries
    ):
        flaw = FlawFactory()
        for _ in range(affect_count):
            ps_module = PsModuleFactory()
            affect = AffectFactory.create(
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_module=ps_module.name,
            )
            for _ in range(tracker_count):
                ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
                TrackerFactory(
                    affects=[affect],
                    embargoed=affect.flaw.embargoed,
                    ps_update_stream=ps_update_stream.name,
                    type=Tracker.BTS2TYPE[ps_module.bts_name],
                )
        with numQueriesCloseTo(expected_queries):
            response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    def test_affect_list(self, auth_client, test_api_uri):
        for _ in range(100):
            AffectFactory.create(
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
            )

        with numQueriesCloseTo(405):  # initial value -> 405
            response = auth_client().get(f"{test_api_uri}/affects")
            assert response.status_code == 200
