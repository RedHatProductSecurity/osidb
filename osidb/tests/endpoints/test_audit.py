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
