from datetime import datetime, timezone
from uuid import uuid4

import pghistory
import pytest
from django.conf import settings

from osidb.core import set_user_acls
from osidb.models import Affect, PsModule, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestEndpointsAudit:
    """
    tests specific to /audit endpoint
    """

    def test_access_audit(
        self,
        auth_client,
        client,
        test_api_uri,
        public_read_groups,
        public_write_groups,
        embargoed_read_groups,
        embargoed_write_groups,
        ldap_test_username,
        ldap_test_password,
        root_url,
    ):
        """ """

        flaw1 = FlawFactory(embargoed=True)
        assert flaw1.acl_read == embargoed_read_groups
        assert flaw1.acl_write == embargoed_write_groups

        affect1 = AffectFactory(flaw=flaw1)
        assert affect1.acl_read == embargoed_read_groups
        assert affect1.acl_write == embargoed_write_groups

        assert pghistory.models.Events.objects.tracks(flaw1).count() == 1
        assert pghistory.models.Events.objects.tracks(affect1).count() == 1

        response = auth_client().get(f"{test_api_uri}/audit")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 2

        with pghistory.context(test=True):
            flaw2 = FlawFactory(embargoed=False, components=["curl"])
            assert flaw2.acl_read == public_read_groups
            assert flaw2.acl_write == public_write_groups

            # log in with public user and attempt to access embargoed event history
            post_data = {
                "username": "pubread",  # pragma: allowlist secret
                "password": "password",  # pragma: allowlist secret
            }
            response = auth_client().post(f"{root_url}/auth/token", post_data)
            assert response.status_code == 200
            body = response.json()
            assert "access" in body
            assert "refresh" in body
            token = body["access"]

            response = client.get(
                f"{test_api_uri}/audit", HTTP_AUTHORIZATION=f"Bearer {token}"
            )

            assert response.status_code == 200
            body = response.json()

            # should only select the newest flaw event (which has context)
            assert body["count"] == 1
            assert body["results"][0]["pgh_context"] == {"test": True}

    def test_audit_retrieve_by_pgh_slug(self, auth_client, test_api_uri):
        """GET /audit/{pgh_slug} returns that single event (pgh_slug contains dot)."""
        _ = FlawFactory(embargoed=False)
        response_list = auth_client().get(f"{test_api_uri}/audit")
        assert response_list.status_code == 200
        results = response_list.json()["results"]
        assert len(results) >= 1
        pgh_slug = results[0]["pgh_slug"]
        assert "." in pgh_slug, "pgh_slug must contain a dot (e.g. osidb.FlawAudit:id)"

        response_detail = auth_client().get(f"{test_api_uri}/audit/{pgh_slug}")
        assert response_detail.status_code == 200
        body = response_detail.json()
        assert body["pgh_slug"] == pgh_slug
        assert "pgh_created_at" in body
        assert "pgh_label" in body
        assert "pgh_data" in body

        response_filtered = auth_client().get(
            f"{test_api_uri}/audit?pgh_slug={pgh_slug}&pgh_obj_id={body['pgh_obj_id']}"
        )
        assert response_filtered.status_code == 200
        filtered_body = response_filtered.json()
        assert filtered_body["count"] == 1
        assert filtered_body["results"][0]["pgh_slug"] == pgh_slug

        response_mismatch = auth_client().get(
            f"{test_api_uri}/audit?pgh_slug={pgh_slug}&pgh_obj_id={uuid4()}"
        )
        assert response_mismatch.status_code == 200
        mismatch_body = response_mismatch.json()
        assert mismatch_body["count"] == 0
        assert mismatch_body["results"] == []

    def test_audit_list_filter_by_pgh_obj_id(self, auth_client, test_api_uri):
        """GET /audit?pgh_obj_id=<uuid> returns only events for that object."""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw)
        flaw_events_count = pghistory.models.Events.objects.tracks(flaw).count()
        affect_events_count = pghistory.models.Events.objects.tracks(affect).count()
        assert flaw_events_count >= 1
        assert affect_events_count >= 1

        response = auth_client().get(f"{test_api_uri}/audit?pgh_obj_id={flaw.uuid}")
        assert response.status_code == 200
        body = response.json()
        assert body["count"] == flaw_events_count
        for result in body["results"]:
            assert result["pgh_obj_id"] == str(flaw.uuid)
            assert result["pgh_obj_model"] == "osidb.Flaw"

        response_affect = auth_client().get(
            f"{test_api_uri}/audit?pgh_obj_id={affect.uuid}"
        )
        assert response_affect.status_code == 200
        body_affect = response_affect.json()
        assert body_affect["count"] == affect_events_count
        for result in body_affect["results"]:
            assert result["pgh_obj_id"] == str(affect.uuid)
            assert "Affect" in result["pgh_obj_model"]

    def test_audit_related_history_unaudited_model_returns_empty_page(
        self, auth_client, test_api_uri
    ):
        """Unaudited pgh_obj_model with related history returns an empty page."""
        response = auth_client().get(
            f"{test_api_uri}/audit?include_relation_events=true"
            "&pgh_obj_model=osidb.PsUpdateStream"
        )

        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 0
        assert body["results"] == []

    def test_audit_includes_affect_history_from_flaw_context(
        self, auth_client, test_api_uri
    ):
        """GET /audit can expose affect history from the flaw context."""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw)

        response = auth_client().get(
            f"{test_api_uri}/audit?include_relation_events=true"
            f"&pgh_obj_model=osidb.Flaw&pgh_obj_id={flaw.uuid}"
        )

        assert response.status_code == 200
        affect_events = [
            result
            for result in response.json()["results"]
            if result["pgh_obj_model"] == "osidb.Affect"
            and result["pgh_obj_id"] == str(affect.uuid)
        ]
        assert affect_events
        assert affect_events[0]["pgh_label"] == "insert"
        assert affect_events[0]["pgh_slug"].startswith("osidb.AffectAudit:")
        assert affect_events[0]["pgh_data"]["flaw_id"] == str(flaw.uuid)

    def test_audit_includes_deleted_affect_history_from_flaw_context(
        self, auth_client, test_api_uri
    ):
        """Deleted affects remain visible from the flaw audit feed."""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw)
        affect_id = affect.uuid

        affect.delete()

        response = auth_client().get(
            f"{test_api_uri}/audit?include_relation_events=true"
            f"&pgh_obj_model=osidb.Flaw&pgh_obj_id={flaw.uuid}"
        )

        assert response.status_code == 200
        delete_events = [
            result
            for result in response.json()["results"]
            if result["pgh_obj_model"] == "osidb.Affect"
            and result["pgh_obj_id"] == str(affect_id)
            and result["pgh_label"] == "delete"
        ]
        assert delete_events
        assert delete_events[0]["pgh_data"]["flaw_id"] == str(flaw.uuid)

    def test_audit_includes_tracker_history_from_flaw_context(
        self, auth_client, test_api_uri
    ):
        """Tracker history linked through an affect is visible from the flaw feed."""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw, tracker=None, affectedness=Affect.AffectAffectedness.NEW
        )
        ps_module = PsModule.objects.get(name=affect.ps_module)
        tracker = TrackerFactory(
            embargoed=False,
            affects=[affect],
            ps_update_stream=affect.ps_update_stream,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        response = auth_client().get(
            f"{test_api_uri}/audit?include_relation_events=true"
            f"&pgh_obj_model=osidb.Flaw&pgh_obj_id={flaw.uuid}"
        )

        assert response.status_code == 200
        results = response.json()["results"]
        tracker_events = [
            result
            for result in results
            if result["pgh_obj_model"] == "osidb.Tracker"
            and result["pgh_obj_id"] == str(tracker.uuid)
        ]
        assert tracker_events
        assert tracker_events[0]["pgh_label"] == "insert"
        assert tracker_events[0]["pgh_slug"].startswith("osidb.TrackerAudit:")

        affect_tracker_events = [
            result
            for result in results
            if result["pgh_obj_model"] == "osidb.Affect"
            and result["pgh_obj_id"] == str(affect.uuid)
            and result["pgh_data"].get("tracker_id") == str(tracker.uuid)
        ]
        assert affect_tracker_events
        assert affect_tracker_events[0]["pgh_diff"]["tracker_id"] == [
            None,
            str(tracker.uuid),
        ]

    def test_audit_does_not_release_mixed_visibility_tracker_history(
        self, auth_client, test_api_uri
    ):
        """A public flaw feed must not expose an embargoed shared tracker."""
        ps_module = PsModuleFactory(bts_name="bugzilla")
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        flaw = FlawFactory(embargoed=True)
        embargoed_flaw = FlawFactory(embargoed=True)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="kernel",
        )
        embargoed_affect = AffectFactory(
            flaw=embargoed_flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=affect.ps_update_stream,
            ps_component=affect.ps_component,
        )
        tracker = TrackerFactory(
            embargoed=True,
            affects=[affect, embargoed_affect],
            ps_update_stream=affect.ps_update_stream,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        set_user_acls(settings.ALL_GROUPS)
        flaw.unembargo_dt = datetime(2000, 1, 1, tzinfo=timezone.utc)
        flaw.unembargo()
        tracker.refresh_from_db()

        assert tracker.is_embargoed

        response = auth_client("pubread").get(
            f"{test_api_uri}/audit?include_relation_events=true"
            f"&pgh_obj_model=osidb.Flaw&pgh_obj_id={flaw.uuid}"
        )

        assert response.status_code == 200
        results = response.json()["results"]
        assert not any(
            result["pgh_obj_model"] == "osidb.Tracker"
            and result["pgh_obj_id"] == str(tracker.uuid)
            for result in results
        )

    def test_audit_retrieves_related_audit_slug_without_flag(
        self, auth_client, test_api_uri
    ):
        """Related audit slugs should be retrievable as normal audit events."""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw)

        response_related = auth_client().get(
            f"{test_api_uri}/audit?include_relation_events=true"
            f"&pgh_obj_model=osidb.Flaw&pgh_obj_id={flaw.uuid}"
        )
        assert response_related.status_code == 200
        event = next(
            result
            for result in response_related.json()["results"]
            if result["pgh_obj_model"] == "osidb.Affect"
            and result["pgh_obj_id"] == str(affect.uuid)
        )
        pgh_slug = event["pgh_slug"]

        response_list = auth_client().get(f"{test_api_uri}/audit?pgh_slug={pgh_slug}")

        assert response_list.status_code == 200
        list_body = response_list.json()
        assert list_body["count"] == 1
        assert list_body["results"][0]["pgh_slug"] == pgh_slug

        response = auth_client().get(f"{test_api_uri}/audit/{pgh_slug}")

        assert response.status_code == 200
        body = response.json()
        assert body["pgh_slug"] == pgh_slug
        assert body["pgh_obj_id"] == str(affect.uuid)
        assert body["pgh_obj_model"] == "osidb.Affect"
        assert body["pgh_data"]["flaw_id"] == str(flaw.uuid)
