import uuid

import pytest

from osidb.models import Affect
from osidb.tests.factories import AffectFactory, FlawFactory, PsModuleFactory

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def enable_bbsync_env_var(monkeypatch) -> None:
    import apps.bbsync.mixins as mixins

    monkeypatch.setattr(mixins, "SYNC_TO_BZ", True)


class TestBBSyncIntegration:
    @property
    def acl_read(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec",
            )
        ]

    @property
    def acl_write(self):
        return [
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                "https://osidb.prod.redhat.com/ns/acls#data-prodsec-write",
            )
        ]

    @pytest.mark.vcr
    def test_flaw_create(self, auth_client, test_api_uri):
        """
        test creating a flaw with Bugzilla two-way sync
        """
        flaw_data = {
            "cve_id": "CVE-2021-0773",
            "title": "Foo",
            "description": "test",
            "impact": "LOW",
            "source": "INTERNET",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
            "bz_api_key": "SECRET",
        }
        response = auth_client.post(f"{test_api_uri}/flaws", flaw_data, format="json")
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] == "CVE-2021-0773"

    @pytest.mark.vcr
    def test_flaw_update(self, auth_client, test_api_uri):
        """
        test updating a flaw with Bugzilla two-way sync
        """
        flaw = FlawFactory(
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            meta_attr={
                "bz_id": "2008346",
            },
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        PsModuleFactory(name="rhel-8")
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="kernel",
        )

        flaw_data = {
            "cve_id": "CVE-2021-0773",
            "title": "Bar",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
            "bz_api_key": "SECRET",
        }
        response = auth_client.put(
            f"{test_api_uri}/flaws/{flaw.uuid}", flaw_data, format="json"
        )
        assert response.status_code == 200

        response = auth_client.get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        assert response.json()["title"] == "Bar"

    @pytest.mark.vcr
    def test_affect_create(self, auth_client, test_api_uri):
        """
        test creating a flaw affect with Bugzilla two-way sync
        """
        flaw = FlawFactory(
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            meta_attr={
                "bz_id": "2008346",
            },
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        PsModuleFactory(name="rhel-8")

        affect_data = {
            "flaw": flaw.uuid,
            "ps_module": "rhel-8",
            "ps_component": "kernel",
            "affectedness": "AFFECTED",
            "resolution": "FIX",
            "embargoed": False,
            "bz_api_key": "SECRET",
        }
        response = auth_client.post(
            f"{test_api_uri}/affects", affect_data, format="json"
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client.get(f"{test_api_uri}/affects/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["ps_module"] == "rhel-8"
        assert response.json()["ps_component"] == "kernel"
        assert response.json()["affectedness"] == "AFFECTED"
        assert response.json()["resolution"] == "FIX"

    @pytest.mark.vcr
    def test_affect_update(self, auth_client, test_api_uri):
        """
        test updating a flaw affect with Bugzilla two-way sync
        """
        flaw = FlawFactory(
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            meta_attr={
                "bz_id": "2008346",
            },
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        PsModuleFactory(name="rhel-8")
        affect = AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="kernel",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.FIX,
        )

        affect_data = {
            "flaw": flaw.uuid,
            "ps_module": "rhel-8",
            "ps_component": "kernel",
            "resolution": "WONTFIX",
            "embargoed": False,
            "bz_api_key": "SECRET",
        }
        response = auth_client.put(
            f"{test_api_uri}/affects/{affect.uuid}", affect_data, format="json"
        )
        assert response.status_code == 200

        response = auth_client.get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        assert response.json()["ps_module"] == "rhel-8"
        assert response.json()["ps_component"] == "kernel"
        assert response.json()["affectedness"] == "AFFECTED"
        assert response.json()["resolution"] == "WONTFIX"

    @pytest.mark.vcr
    def test_affect_delete(self, auth_client, test_api_uri):
        """
        test deleting a flaw affect with Bugzilla two-way sync
        """
        flaw = FlawFactory(
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            meta_attr={
                "bz_id": "2008346",
            },
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        PsModuleFactory(name="rhel-8")
        # we need to create an extra affect
        # not to result in an affect-less flaw
        # which would not pass the validations
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="kernel",
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="openssl",
        )

        data = {"bz_api_key": "SECRET"}

        response = auth_client.delete(
            f"{test_api_uri}/affects/{affect.uuid}", data, format="json"
        )
        assert response.status_code == 204

        response = auth_client.get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == 404

    @pytest.mark.vcr(
        vcr_cassette_name="cassettes/TestBBSyncIntegration.test_flaw_create.yaml"
    )
    def test_flaw_validations(self, auth_client, test_api_uri):
        """
        test that flaw validations are not bypassed when syncing to Bugzilla
        """
        flaw_data = {
            "cve_id": "CVE-2021-0773",
            "title": "Foo",
            "description": "test",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "embargoed": False,
            "bz_api_key": "SECRET",
        }
        response = auth_client.post(f"{test_api_uri}/flaws", flaw_data, format="json")
        assert response.status_code == 400
        assert "CVSSv3 score is missing" in str(response.content)
