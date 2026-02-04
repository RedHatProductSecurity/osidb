import pghistory
import pytest

from osidb.tests.factories import AffectFactory, FlawFactory

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
