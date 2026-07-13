"""
Test that the ACLMixinManager no longer adds embargoed/visibility annotations
by default, and that .with_acl_annotations() adds them when needed.

The annotations are CASE/WHEN expressions that are only needed for API
filtering and serialization, not for internal model operations like signal
handlers, validators, and refresh_from_db.
"""

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from osidb.models import Affect, Flaw, Impact, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit

ACL_ANNOTATION_MARKERS = ('AS "embargoed"', 'AS "visibility"')


def _annotated_queries(captured):
    """Return captured queries whose SQL contains ACL annotation markers."""
    return [
        q["sql"]
        for q in captured
        if any(marker in q["sql"] for marker in ACL_ANNOTATION_MARKERS)
    ]


class TestDefaultQueriesNoAnnotations:
    """
    Default manager queries should NOT include embargoed/visibility annotations.
    """

    def test_flaw_objects_get(self):
        flaw = FlawFactory(embargoed=False)

        with CaptureQueriesContext(connection) as ctx:
            Flaw.objects.get(pk=flaw.pk)

        annotated = _annotated_queries(ctx.captured_queries)
        assert not annotated, (
            "Flaw.objects.get() includes ACL annotations.\n" + "\n".join(annotated)
        )

    def test_affect_objects_get(self):
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw)

        with CaptureQueriesContext(connection) as ctx:
            Affect.objects.get(pk=affect.pk)

        annotated = _annotated_queries(ctx.captured_queries)
        assert not annotated, (
            "Affect.objects.get() includes ACL annotations.\n" + "\n".join(annotated)
        )

    def test_tracker_objects_filter(self):
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        TrackerFactory(
            affects=[affect],
            embargoed=False,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        with CaptureQueriesContext(connection) as ctx:
            list(Tracker.objects.filter(affects__flaw=flaw).distinct())

        annotated = _annotated_queries(ctx.captured_queries)
        assert not annotated, (
            "Tracker.objects.filter() includes ACL annotations.\n"
            + "\n".join(annotated)
        )

    def test_refresh_from_db_no_annotations(self):
        flaw = FlawFactory(embargoed=False)

        with CaptureQueriesContext(connection) as ctx:
            flaw.refresh_from_db()

        annotated = _annotated_queries(ctx.captured_queries)
        assert not annotated, (
            "Flaw.refresh_from_db() includes ACL annotations.\n" + "\n".join(annotated)
        )


class TestWithAclAnnotations:
    """
    .with_acl_annotations() should add the annotations when explicitly requested.
    """

    def test_with_acl_annotations_adds_embargoed(self):
        flaw = FlawFactory(embargoed=False)

        with CaptureQueriesContext(connection) as ctx:
            Flaw.objects.with_acl_annotations().get(pk=flaw.pk)

        annotated = _annotated_queries(ctx.captured_queries)
        assert annotated, (
            "with_acl_annotations() did not add ACL annotations to the query."
        )

    def test_with_acl_annotations_filter_embargoed(self):
        FlawFactory(embargoed=False)
        FlawFactory(embargoed=True)

        non_embargoed = Flaw.objects.with_acl_annotations().filter(embargoed=False)
        assert non_embargoed.exists()

    def test_with_acl_annotations_filter_visibility(self):
        FlawFactory(embargoed=False)

        public = Flaw.objects.with_acl_annotations().filter(visibility="PUBLIC")
        assert public.exists()


class TestSavePathNoAnnotations:
    """
    Model save paths (signal handlers, validators, TrackingMixin) should
    not fire annotated queries.
    """

    def test_flaw_save_no_acl_annotation(self):
        flaw = FlawFactory(embargoed=False, impact=Impact.LOW)

        flaw.impact = Impact.MODERATE
        with CaptureQueriesContext(connection) as ctx:
            flaw.save()

        annotated = _annotated_queries(ctx.captured_queries)
        assert not annotated, (
            "Flaw.save() fires queries with ACL annotations.\n" + "\n".join(annotated)
        )

    def test_affect_save_no_acl_annotation(self):
        flaw = FlawFactory(embargoed=False, impact=Impact.LOW)
        affect = AffectFactory(flaw=flaw, impact=Impact.LOW)

        affect.impact = Impact.MODERATE
        with CaptureQueriesContext(connection) as ctx:
            affect.save()

        annotated = _annotated_queries(ctx.captured_queries)
        assert not annotated, (
            "Affect.save() fires queries with ACL annotations.\n" + "\n".join(annotated)
        )
