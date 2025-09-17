import uuid

import pytest
from bugzilla.exceptions import BugzillaError
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from django.utils.timezone import datetime
from freezegun import freeze_time
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient

from osidb.core import generate_acls, set_user_acls
from osidb.helpers import ensure_list, get_execution_env
from osidb.models import Affect, Flaw, Impact
from osidb.pagination import HardLimitOffsetPagination
from osidb.tests.factories import AffectFactory, FlawFactory

pytestmark = pytest.mark.unit


class TestEndpoints(object):
    def test_osidb_service_health(self, client):
        """test access to osidb service health endpoint"""
        response = client.get("/osidb/healthy")
        assert response.status_code == 200

    def test_status(self, auth_client, test_api_uri):
        """test access to osidb service status endpoint"""

        response = auth_client().get(f"{test_api_uri}/status")
        assert response.status_code == 200
        body = response.json()
        assert body["osidb_data"]["flaw_count"] == 0

    def test_manifest(self, auth_client, test_api_uri):
        """test access to osidb package manifest endpoint"""

        response = auth_client().get(f"{test_api_uri}/manifest")
        assert response.status_code == 200
        packages = response.json()["packages"]
        assert all(
            key in packages[0]
            for key in (
                "pkg_name",
                "project_name",
                "version",
                "source",
                "home_page",
                "purl",
            )
        )

    def test_whoami(self, auth_client, root_url):
        res = auth_client().get(f"{root_url}/osidb/whoami").json()
        assert res["username"] == "testuser"
        assert res["email"] == "monke@banana.com"
        assert "data-prodsec" in res["groups"]
        assert res["profile"] is None

    @pytest.mark.parametrize("third_party", ["jira", "bugzilla"])
    def test_set_integration_tokens(
        self,
        auth_client,
        root_url,
        mock_hvac_client_instance,
        third_party,
        set_hvac_test_env_vars,
    ):
        auth_client().patch(f"{root_url}/osidb/integrations", data={third_party: "foo"})
        mock_hvac_client_instance.secrets.kv.v2.patch.assert_called_once_with(
            path=f"/osidb-integrations/{get_execution_env()}/{third_party}",
            secret={"testuser": "foo"},
            mount_point="apps",
        )

    def test_set_both_integration_tokens(
        self,
        auth_client,
        root_url,
        mock_hvac_client_instance,
        set_hvac_test_env_vars,
    ):
        auth_client().patch(
            f"{root_url}/osidb/integrations", data={"jira": "foo", "bugzilla": "bar"}
        )
        mock_hvac_client_instance.secrets.kv.v2.patch.assert_any_call(
            path=f"/osidb-integrations/{get_execution_env()}/jira",
            secret={"testuser": "foo"},
            mount_point="apps",
        )
        mock_hvac_client_instance.secrets.kv.v2.patch.assert_any_call(
            path=f"/osidb-integrations/{get_execution_env()}/bugzilla",
            secret={"testuser": "bar"},
            mount_point="apps",
        )

    def test_set_no_integration_tokens(
        self,
        auth_client,
        root_url,
        set_hvac_test_env_vars,
    ):
        r = auth_client().patch(f"{root_url}/osidb/integrations", data={})
        assert r.status_code == 400
        assert (
            r.json()["non_field_errors"][0]
            == "At least one third-party integration token must be provided"
        )

    @pytest.mark.parametrize(
        "mocked,expected",
        [
            ({"jira": "foo"}, {"jira": "foo", "bugzilla": None}),
            ({"bugzilla": "bar"}, {"jira": None, "bugzilla": "bar"}),
            ({"jira": "foo", "bugzilla": "bar"}, {"jira": "foo", "bugzilla": "bar"}),
            ({}, {"jira": None, "bugzilla": None}),
        ],
    )
    def test_get_integration_tokens(
        self,
        auth_client,
        root_url,
        set_hvac_test_env_vars,
        mock_hvac_client_instance,
        mocked,
        expected,
    ):
        def read_secret_version_mocked(*args, **kwargs):
            if "jira" in str(kwargs.get("path")):
                _d = {"testuser": mocked.get("jira")}
            else:
                _d = {"testuser": mocked.get("bugzilla")}
            return {"data": {"data": _d}}

        mock_hvac_client_instance.secrets.kv.v2.read_secret_version.side_effect = (
            read_secret_version_mocked
        )
        r = auth_client().get(f"{root_url}/osidb/integrations")
        assert r.status_code == 200
        body = r.json()
        assert body["jira"] == expected["jira"]
        assert body["bugzilla"] == expected["bugzilla"]


class TestEndpointsACLs:
    """
    ACL specific tests
    """

    def hash_acl(self, acl):
        """
        shortcut to get ACL from the group(s)
        """
        return [uuid.UUID(ac) for ac in generate_acls(ensure_list(acl))]

    @pytest.mark.parametrize(
        "embargoed,acl_read,acl_write",
        [
            (False, settings.INTERNAL_READ_GROUP, settings.INTERNAL_WRITE_GROUP),
            (True, settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP),
        ],
    )
    def test_flaw_create(
        self, auth_client, test_api_uri, embargoed, acl_read, acl_write
    ):
        """
        test proper embargo status and ACLs when creating a flaw by sending a POST request
        """
        flaw_data = {
            "title": "Foo",
            "comment_zero": "test",
            "impact": "LOW",
            "components": ["curl"],
            "source": "DEBIAN",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": None if embargoed else "2000-1-1T22:03:26.065Z",
            "mitigation": "mitigation",
            "embargoed": embargoed,
        }
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        flaw = Flaw.objects.first()
        assert flaw.acl_read == self.hash_acl(acl_read)
        assert flaw.acl_write == self.hash_acl(acl_write)

        response = auth_client().get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["embargoed"] == embargoed
        assert response.json()["mitigation"] == "mitigation"

    @pytest.mark.parametrize(
        "embargoed,acl_read,acl_write",
        [
            (False, settings.PUBLIC_READ_GROUPS, settings.PUBLIC_WRITE_GROUP),
            (True, settings.EMBARGO_READ_GROUP, settings.EMBARGO_WRITE_GROUP),
        ],
    )
    def test_flaw_update(
        self,
        auth_client,
        test_api_uri,
        embargoed,
        acl_read,
        acl_write,
    ):
        """
        test proper embargo status and ACLs when updating a flaw by sending a PUT request
        while the embargo status and ACLs itself are not being changed
        """
        flaw = FlawFactory(embargoed=embargoed)
        AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert original_body["embargoed"] == embargoed

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "embargoed": embargoed,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["title"] != body["title"]
        assert "appended test title" in body["title"]
        assert original_body["embargoed"] == body["embargoed"]

        flaw = Flaw.objects.first()
        assert flaw.acl_read == self.hash_acl(acl_read)
        assert flaw.acl_write == self.hash_acl(acl_write)

    def test_internal_flaw_update(
        self,
        auth_client,
        test_api_uri,
    ):
        """
        test serializer does not change ACLs from internal flaws
        """
        internal_read = [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_READ_GROUP])
        ]
        internal_write = [
            uuid.UUID(acl) for acl in generate_acls([settings.INTERNAL_WRITE_GROUP])
        ]
        flaw = FlawFactory(
            embargoed=False,
            acl_read=internal_read,
            acl_write=internal_write,
        )
        AffectFactory(flaw=flaw)
        assert flaw.is_internal

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert not original_body["embargoed"]

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "owner": "example@redhat.com",
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        flaw = Flaw.objects.get(uuid=flaw.uuid)
        assert flaw.is_internal

    @freeze_time(datetime(2021, 11, 23, tzinfo=timezone.get_current_timezone()))
    def test_flaw_unembargo(self, auth_client, test_api_uri):
        """
        test proper embargo status and ACLs when unembargoing a flaw by sending a PUT request
        """
        future_dt = datetime(2021, 11, 27, tzinfo=timezone.get_current_timezone())
        flaw = FlawFactory(
            embargoed=True,
            unembargo_dt=future_dt,
        )
        AffectFactory(flaw=flaw)

        # the unembargo must happen after the unembargo moment passed
        with freeze_time(future_dt):
            response = auth_client().put(
                f"{test_api_uri}/flaws/{flaw.uuid}",
                {
                    "title": flaw.title.replace("EMBARGOED", "").strip(),
                    "comment_zero": flaw.comment_zero,
                    "embargoed": False,
                    "updated_dt": flaw.updated_dt,
                },
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )

        assert response.status_code == 200
        body = response.json()
        assert body["embargoed"] is False
        assert Flaw.objects.first().embargoed is False

    def test_flaw_create_not_member(self, auth_client, test_api_uri):
        """
        test that creating a Flaw is rejected when the ACL contains a group the user is not a member of
        """
        flaw_data = {
            "title": "EMBARGOED Foo",
            "comment_zero": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": None,
            "embargoed": True,
            "bz_api_key": "SECRET",
        }
        response = auth_client("anon").post(
            f"{test_api_uri}/flaws", flaw_data, format="json"
        )
        assert response.status_code == 400
        assert (
            "Cannot provide access for the LDAP group without being a member: data-topsecret"
            in str(response.content)
        )

    def test_flaw_update_not_member(self, auth_client, test_api_uri):
        """
        test that updating a Flaw is rejected when the ACL contains a group the user is not a member of
        """
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client("pubread").put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
                "bz_api_key": "SECRET",
            },
            format="json",
        )
        assert response.status_code == 400
        assert (
            "Cannot provide access for the LDAP group without being a member: data-prodsec-write"
            in str(response.content)
        )

    def test_flaw_create_cve_description(self, auth_client, test_api_uri):
        """
        test that creating a Flaw with cve_description and without requires_cve_description,
        sets the requires_cve_description field to REQUESTED
        """
        flaw_data = {
            "title": "Foo",
            "comment_zero": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "impact": "LOW",
            "components": ["curl"],
            "source": "DEBIAN",
            "embargoed": False,
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cve_description": "some description",
        }
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["requires_cve_description"] == "REQUESTED"

    def test_flaw_update_cve_description(self, auth_client, test_api_uri):
        """
        test that updating a Flaw with cve_description and without requires_cve_description,
        updates the requires_cve_description field to REQUESTED
        """
        flaw = FlawFactory(
            embargoed=False,
            cve_description="some description",
            requires_cve_description="",
        )
        AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert original_body["requires_cve_description"] == ""

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
                "bz_api_key": "SECRET",
                "cve_description": "some other description",
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        body = response.json()
        assert original_body["cve_description"] != body["cve_description"]
        assert body["requires_cve_description"] == "REQUESTED"


class TestEndpointsAtomicity:
    """
    API atomicity specific tests
    """

    def test_atomic_api(self, auth_client, monkeypatch, test_api_v2_uri):
        """
        test that the API requests are atomic

        this test attempts to delete an affect via a REST API DELETE request
        as it consits of first deleting the affect and then saving a related
        flaw where the flaw save is mocked to fail and we test that the
        affect delete is not commited to the DB - rolled back on failure
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        assert Affect.objects.count() == 2

        with monkeypatch.context() as m:

            def failure_factory(*args, **kwargs):
                # rest_framework.exceptions.ValidationError
                # is handle by the APIView and translated to Bad Request
                # so we do not end up with an uncaught exception
                raise ValidationError({})

            # make the Flaw.save to fail randomly
            m.setattr(Flaw, "save", failure_factory)

            response = auth_client().delete(
                f"{test_api_v2_uri}/affects/{affect.uuid}",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == 400

        set_user_acls(settings.ALL_GROUPS)
        # check that no affect was deleted
        assert Affect.objects.count() == 2

    def test_atomic_error_handling(self, auth_client, monkeypatch, test_api_v2_uri):
        """
        test that the API requests are atomic even when handling an error
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        assert Affect.objects.count() == 2

        with monkeypatch.context() as m:

            def failure_factory(*args, **kwargs):
                # rest_framework.exceptions.ValidationError
                # is handle by the APIView and translated to Bad Request
                # so we do not end up with an uncaught exception
                raise BugzillaError({})

            # make the Flaw.save to fail randomly
            m.setattr(Flaw, "save", failure_factory)

            response = auth_client().delete(
                f"{test_api_v2_uri}/affects/{affect.uuid}",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == 422

        set_user_acls(settings.ALL_GROUPS)
        # check that no affect was deleted
        assert Affect.objects.count() == 2

    def test_nonatomic_api(self, auth_client, monkeypatch, test_api_v2_uri):
        """
        test that the API requests are not atomic when the settings option is disabled
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        assert Affect.objects.count() == 2

        with monkeypatch.context() as m:

            def failure_factory(*args, **kwargs):
                # rest_framework.exceptions.ValidationError
                # is handle by the APIView and translated to Bad Request
                # so we do not end up with an uncaught exception
                raise ValidationError({})

            # make the Flaw.save to fail randomly
            m.setattr(Flaw, "save", failure_factory)

            # turn of the atomicity option
            db_settings = settings.DATABASES
            db_settings["default"]["ATOMIC_REQUESTS"] = False
            m.setattr(settings, "DATABASES", db_settings)

            response = auth_client().delete(
                f"{test_api_v2_uri}/affects/{affect.uuid}",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == 400

            # revert DB settings as it is not done automatically
            db_settings["default"]["ATOMIC_REQUESTS"] = True
            m.setattr(settings, "DATABASES", db_settings)

        # check that the affect was deleted
        # even though the HTTP request failed
        assert Affect.objects.count() == 1


class TestEndpointsBZAPIKey:
    """
    Bugzilla API key specific tests
    """

    def test_flaw_create_no_bz_api_key(
        self,
        auth_client,
        test_api_uri,
        set_hvac_test_env_vars,
        mock_hvac_client_instance,
    ):
        """
        test that creating a Flaw is rejected when no Bugzilla API key is provided
        """
        mock_hvac_client_instance.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {}}
        }
        flaw_data = {
            "title": "Foo",
            "comment_zero": "test",
            "components": ["test"],
            "impact": Impact.LOW,
            "source": "REDHAT",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "embargoed": False,
            "jira_api_key": "SECRET",
        }

        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 400
        assert '"Bugzilla-Api-Key":"This HTTP header is required' in str(
            response.content
        )

    def test_flaw_update_no_bz_api_key(
        self,
        auth_client,
        test_api_uri,
        set_hvac_test_env_vars,
        mock_hvac_client_instance,
    ):
        """
        test that updating a Flaw is rejected when no Bugzilla API key is provided
        """
        mock_hvac_client_instance.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {}}
        }
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw)
        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200

        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            {
                "title": f"{flaw.title} appended test title",
                "comment_zero": flaw.comment_zero,
                "embargoed": False,
                "updated_dt": flaw.updated_dt,
            },
            format="json",
        )
        assert response.status_code == 400
        assert '"Bugzilla-Api-Key":"This HTTP header is required' in str(
            response.content
        )


class TestCustomExceptionHandling:
    @pytest.mark.urls("osidb.tests.urls")
    def test_custom_exception_serialization(self):
        url = reverse("test-view")
        response = APIClient().get(url)
        assert response.status_code == 409
        assert response.json()["detail"] == "This was a big failure"


class TestPagination:
    def test_hard_limit(self, auth_client, test_api_uri, monkeypatch):
        """Test the custom hard limit pagination."""
        monkeypatch.setattr(HardLimitOffsetPagination, "hard_limit", 5)

        for _ in range(10):
            FlawFactory(embargoed=False)

        response = auth_client().get(f"{test_api_uri}/flaws?limit=10")
        assert response.status_code == 200
        assert len(response.json()["results"]) == 5
        # The next page uses the max limit, not the one the user specified
        assert "limit=5" in response.json()["next"]
