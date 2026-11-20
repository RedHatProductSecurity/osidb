import pytest
from django.db import connection
from django.db.models.query import QuerySet
from django.test.utils import CaptureQueriesContext

from osidb.acls import ACL
from osidb.api_views import FlawView
from osidb.models import Affect, Flaw, FlawSource, Impact, Tracker
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawCommentFactory,
    FlawCVSSFactory,
    FlawFactory,
    FlawReferenceFactory,
    PackageFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
    UpstreamDataFactory,
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 65), (True, 65)])
    def test_flaw_list(self, auth_client, test_api_v2_uri, embargoed, query_count):
        for _ in range(3):
            flaw = FlawFactory(
                embargoed=embargoed,
                impact=Impact.MODERATE,
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 68), (True, 68)])
    def test_flaw_list_filtered(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
        """
        Using the same subset of fields as OSIM
        """
        for _ in range(3):
            flaw = FlawFactory(
                embargoed=embargoed,
                impact=Impact.MODERATE,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            AffectFactory.create_batch(
                3,
                flaw=flaw,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                impact=Impact.MODERATE,
            )

        with assertNumQueriesLessThan(query_count):  # initial value -> 61
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws?include_fields=cve_id,uuid,impact,source,created_dt,updated_dt,classification,title,unembargo_dt,embargoed,owner,labels"
            )
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 60), (True, 60)])
    def test_empty_flaw(self, auth_client, test_api_v2_uri, embargoed, query_count):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        with assertNumQueriesLessThan(query_count):  # initial value -> 60
            response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 63), (True, 63)])
    def test_flaw_with_affects(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        AffectFactory.create_batch(
            3,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.MODERATE,
        )

        with assertNumQueriesLessThan(query_count):  # initial value -> 78
            response = auth_client().get(f"{test_api_v2_uri}/flaws/{flaw.uuid}")
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 68), (True, 68)])
    def test_flaw_with_affects_history(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        AffectFactory.create_batch(
            3,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            impact=Impact.MODERATE,
        )

        with assertNumQueriesLessThan(query_count):  # initial value -> 62
            response = auth_client().get(
                f"{test_api_v2_uri}/flaws/{flaw.uuid}?include_history=true"
            )
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 61), (True, 61)])
    def test_flaw_excluding_affects_is_faster(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.MODERATE,
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 51), (True, 51)])
    def test_flaw_include_fields_does_not_prefetch_affects(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.MODERATE,
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 70), (True, 69)])
    def test_flaw_with_affects_trackers(
        self, auth_client, test_api_v2_uri, embargoed, query_count
    ):
        flaw = FlawFactory(
            embargoed=embargoed,
            impact=Impact.MODERATE,
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

    @pytest.mark.parametrize("embargoed,query_count", [(False, 59), (True, 59)])
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

        # Query count varies with transaction SAVEPOINT cleanup; product names
        # for the page are fetched in one query.
        with assertNumQueriesLessThan(query_count):  # initial value -> 69
            response = auth_client().get(f"{test_api_v2_uri}/affects")
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 57), (True, 57)])
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

        with assertNumQueriesLessThan(query_count):  # initial value -> 55
            response = auth_client().get(
                f"{test_api_v2_uri}/affects?include_history=true"
            )
            assert response.status_code == 200

    @pytest.mark.parametrize("embargoed,query_count", [(False, 65), (True, 65)])
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

        with assertNumQueriesLessThan(query_count):
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
            impact=Impact.MODERATE,
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
            (True, 1, 79),
            (True, 10, 79),
            (True, 100, 79),
            (False, 1, 116),  # down from 119
            (False, 10, 314),  # down from 389
            (False, 100, 2294),  # down from 3089
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
            flaw.set_acls(ACL.INTERNAL)
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
                affect.set_acls(ACL.INTERNAL)
                affect.save(raise_validation_error=False)
                if affect.tracker:
                    affect.tracker.set_acls(ACL.INTERNAL)
                    affect.tracker.save(raise_validation_error=False)

        # Force initial classification to start the promote chain from NEW.
        # Even with signals enabled, setting task_key later can trigger workflow
        # auto-adjust and skip ahead because required fields are already filled.
        flaw.classification = {
            "workflow": "DEFAULT",
            "state": "NEW",
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
        # this one runs the nested set_acls_nested calls

        with assertNumQueriesLessThan(expected_queries):
            response = auth_client().post(
                f"{test_api_uri}/flaws/{flaw.uuid}/promote",
                data={},
                format="json",
                **headers,
            )


# Written with Claude Code (claude-opus-5).
def is_per_flaw_tracker_query(sql):
    """
    Identify the per-flaw tracker lookup issued by FlawAffectsTrackersField.

    This is the query reported as an N+1 by Datadog (OSIDB-5681):

        SELECT DISTINCT "osidb_tracker"."external_system_id", ...
        FROM "osidb_affect" INNER JOIN "osidb_tracker" ON (...)
        WHERE ("osidb_affect"."flaw_id" = ... AND "osidb_affect"."tracker_id" IS NOT NULL)
    """
    return (
        "SELECT DISTINCT" in sql
        and '"osidb_tracker"."external_system_id"' in sql
        and 'FROM "osidb_affect"' in sql
        and '"osidb_affect"."flaw_id" =' in sql
    )


class TestFlawListTrackersNPlusOne:
    """
    OSIDB-5681: the computed `trackers` field on GET /flaws must be resolved in a
    bounded number of queries for the whole page, not one query per flaw.
    """

    NUM_FLAWS = 5
    TRACKERS_PER_FLAW = 2

    def build_flaws(self):
        """Create NUM_FLAWS flaws, each with TRACKERS_PER_FLAW tracked affects."""
        expected = {}
        for _ in range(self.NUM_FLAWS):
            flaw = FlawFactory(
                embargoed=False,
                impact=Impact.MODERATE,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )
            external_ids = set()
            for _ in range(self.TRACKERS_PER_FLAW):
                ps_module = PsModuleFactory()
                ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
                affect = AffectFactory(
                    flaw=flaw,
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                    impact=Impact.MODERATE,
                    ps_update_stream=ps_update_stream.name,
                )
                tracker = TrackerFactory(
                    affects=[affect],
                    embargoed=False,
                    ps_update_stream=ps_update_stream.name,
                    type=Tracker.BTS2TYPE[ps_module.bts_name],
                )
                external_ids.add(tracker.external_system_id)
            expected[str(flaw.uuid)] = external_ids
        return expected

    @pytest.mark.parametrize(
        "query_params",
        [
            # the view prefetches affects for this, but IncludeFieldsFilterSet
            # discards the prefetch because `trackers` is not a Flaw model field
            "include_fields=uuid,cve_id,trackers",
            # the view skips the affects prefetch, but `trackers` is still rendered
            "exclude_fields=affects",
        ],
    )
    def test_trackers_resolved_without_per_flaw_query(
        self, auth_client, test_api_v2_uri, query_params
    ):
        """
        Serializing `trackers` for a page of flaws must not scale with page size,
        and must still return the correct tracker IDs for every flaw.
        """
        expected = self.build_flaws()

        with CaptureQueriesContext(connection) as ctx:
            response = auth_client().get(f"{test_api_v2_uri}/flaws?{query_params}")
            assert response.status_code == 200
            results = response.json()["results"]

        # correctness: a batched implementation must not lose or mix up trackers
        assert len(results) == self.NUM_FLAWS
        actual = {flaw["uuid"]: set(flaw["trackers"]) for flaw in results}
        assert actual == expected

        # performance: at most one tracker lookup for the whole page
        per_flaw_queries = [
            q["sql"]
            for q in ctx.captured_queries
            if is_per_flaw_tracker_query(q["sql"])
        ]
        assert len(per_flaw_queries) <= 1, (
            f"{len(per_flaw_queries)} per-flaw tracker queries for "
            f"{self.NUM_FLAWS} flaws (N+1); first was:\n{per_flaw_queries[0]}"
        )


def is_per_object_alert_query(sql):
    """
    Identify a single-object alert lookup issued by AlertMixinSerializer.

    This is the query reported as an N+1 by Datadog (OSIDB-5680):

        SELECT "osidb_alert"."acl_read", ... "django_content_type"."model"
        FROM "osidb_alert" INNER JOIN "django_content_type" ON (...)
        WHERE ("osidb_alert"."content_type_id" = N AND "osidb_alert"."object_id" = ...)

    A batched lookup uses `object_id IN (...)` instead and is not matched here.
    """
    return (
        'FROM "osidb_alert"' in sql
        and '"osidb_alert"."content_type_id" =' in sql
        and '"osidb_alert"."object_id" =' in sql
    )


def collect_alerts(node, found):
    """
    Walk a serialized response and collect {object uuid: {alert names}}.

    Every object rendered by AlertMixinSerializer carries both `uuid` and
    `alerts`, so this finds flaws and all of their alert-bearing children.
    """
    if isinstance(node, list):
        for item in node:
            collect_alerts(item, found)
    elif isinstance(node, dict):
        if "uuid" in node and isinstance(node.get("alerts"), list):
            found[str(node["uuid"])] = {alert["name"] for alert in node["alerts"]}
        for value in node.values():
            collect_alerts(value, found)
    return found


# Alert-bearing objects built per flaw by TestFlawListAlertsNPlusOne, keyed by
# the name used to declare which of them a request variant must render.
#
# "package" is deliberately absent: PackageSerializer renders no `uuid`, so a
# package cannot be matched by uuid in the response. Packages are still covered
# by the per-object query assertion.
ALERT_CATEGORIES = (
    "flaw",
    "affect",
    "affect_cvss",
    "comment",
    "flaw_cvss",
    "reference",
    "acknowledgment",
    "upstream_data",
)


def categories_except(*excluded):
    """The alert-bearing categories a response variant renders."""
    return tuple(c for c in ALERT_CATEGORIES if c not in excluded)


class TestFlawListAlertsNPlusOne:
    """
    OSIDB-5680: the `alerts` field of a flaw and of each of its alert-bearing
    children must be resolved in a bounded number of queries for the whole page,
    not one query per serialized object.
    """

    NUM_FLAWS = 3

    def build_flaws(self):
        """
        Create NUM_FLAWS flaws, each with one of every alert-bearing child, and
        put a distinguishable alert on every one of those objects so that no
        object's expected alert set is empty.

        Returns {category: {object uuid: {alert names}}} read back from the
        database.
        """
        created = {}

        def add_alert(category, instance):
            instance.alert(
                name=f"osidb_5680_{str(instance.uuid)[:8]}",
                description="alert used to verify batched alert serialization",
            )
            created.setdefault(category, []).append(instance)
            return instance

        for _ in range(self.NUM_FLAWS):
            flaw = add_alert(
                "flaw",
                FlawFactory(
                    embargoed=False,
                    impact=Impact.MODERATE,
                    # a private source is required for acknowledgments
                    source=FlawSource.CUSTOMER,
                    major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
                ),
            )
            affect = add_alert(
                "affect",
                AffectFactory(
                    flaw=flaw,
                    affectedness=Affect.AffectAffectedness.AFFECTED,
                    resolution=Affect.AffectResolution.DELEGATED,
                    impact=Impact.MODERATE,
                ),
            )
            add_alert("affect_cvss", AffectCVSSFactory(affect=affect))
            add_alert("comment", FlawCommentFactory(flaw=flaw))
            add_alert("flaw_cvss", FlawCVSSFactory(flaw=flaw))
            add_alert("reference", FlawReferenceFactory(flaw=flaw))
            add_alert("acknowledgment", FlawAcknowledgmentFactory(flaw=flaw))
            add_alert("upstream_data", UpstreamDataFactory(flaw=flaw))
            add_alert("package", PackageFactory(flaw=flaw))

        # every alert an object has is valid here: validation alerts are written
        # by save() right after it bumps last_validated_dt, and add_alert() runs
        # later still
        return {
            category: {
                str(instance.uuid): set(instance.alerts.values_list("name", flat=True))
                for instance in instances
            }
            for category, instances in created.items()
        }

    @pytest.mark.parametrize(
        "query_params,rendered_categories",
        [
            # the plain listing reported by Datadog: everything is rendered
            ("", ALERT_CATEGORIES),
            # affects and their children are dropped from the response
            ("exclude_fields=affects", categories_except("affect", "affect_cvss")),
            # IncludeFieldsFilterSet drops the view's prefetches and rebuilds
            # them from the requested fields. The flaw itself renders no
            # `alerts` here because `alerts` is not among the requested
            # top-level fields.
            #
            # `affects` is left out of the request on purpose:
            # IncludeFieldsFilterSet only prefetches one relation level, so an
            # affect's own children (its cvss_scores and tracker) are not
            # prefetched at all and keep costing a query each. That is a
            # pre-existing limitation of these filters, documented in
            # SparseFieldsFilterSet._filter_fields, and it is not specific to
            # alerts. The affects path is covered by the two variants above,
            # which go through the view's prefetches.
            (
                "include_fields=uuid,comments,cvss_scores,references,"
                "acknowledgments,package_versions,upstream_data",
                categories_except("flaw", "affect", "affect_cvss"),
            ),
        ],
    )
    def test_alerts_resolved_without_per_object_query(
        self, auth_client, test_api_v2_uri, query_params, rendered_categories
    ):
        """
        Serializing `alerts` for a page of flaws must not scale with the number
        of serialized objects, and must still return every object's own alerts.
        """
        created = self.build_flaws()

        # the expected objects are chosen from the fixture by category, not
        # read back out of the response, so that a response which silently
        # drops a whole relation fails here
        expected = {
            uuid: alert_names
            for category in rendered_categories
            for uuid, alert_names in created[category].items()
        }
        assert len(expected) == self.NUM_FLAWS * len(rendered_categories)

        with CaptureQueriesContext(connection) as ctx:
            response = auth_client().get(f"{test_api_v2_uri}/flaws?{query_params}")
            assert response.status_code == 200
            results = response.json()["results"]

        assert len(results) == self.NUM_FLAWS

        # correctness: every expected object must be present, with its own
        # alerts and nobody else's
        rendered = collect_alerts(results, {})
        assert rendered == expected

        # performance: no object may be looked up on its own
        per_object_queries = [
            q["sql"]
            for q in ctx.captured_queries
            if is_per_object_alert_query(q["sql"])
        ]
        assert not per_object_queries, (
            f"{len(per_object_queries)} per-object alert queries for "
            f"{len(rendered)} serialized objects (N+1); "
            f"first was:\n{per_object_queries[0]}"
        )
