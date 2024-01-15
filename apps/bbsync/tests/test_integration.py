import uuid

import pytest
from django.utils import timezone
from freezegun import freeze_time

from apps.bbsync.exceptions import UnsaveableFlawError
from osidb.models import Affect, Flaw
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
            "cve_id": "CVE-2021-0777",
            "title": "Foo",
            "description": "test",
            "impact": "LOW",
            "component": "curl",
            "source": "INTERNET",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "mitigation": "mitigation",
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
        }
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/flaws/{created_uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] == "CVE-2021-0773"
        assert response.json()["title"] == "Foo"
        assert response.json()["component"] == "curl"
        assert response.json()["mitigation"] == "mitigation"

    @pytest.mark.vcr
    def test_flaw_update(self, auth_client, test_api_uri):
        """
        test updating a flaw with Bugzilla two-way sync
        """
        flaw = FlawFactory(
            bz_id="2008346",
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2023-03-13T12:54:13Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
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
            "reported_dt": flaw.reported_dt,
            "unembargo_dt": flaw.unembargo_dt,
            "updated_dt": flaw.updated_dt,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
        }
        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        assert response.json()["title"] == "Bar"

    @pytest.mark.vcr
    def test_flaw_update_add_cve(self, auth_client, test_api_uri):
        """
        test adding a CVE to an existing CVE-less flaw
        """
        flaw = FlawFactory(
            bz_id="1995562",
            cve_id="",
            component="ssh",
            title="I cannot ssh into Matrix",
            description="test",
            impact="MODERATE",
            source="CUSTOMER",
            reported_dt="2022-04-26T00:00:00Z",
            unembargo_dt="2022-04-27T00:00:00Z",
            updated_dt="2023-05-22T14:39:11Z",
            embargoed=False,
        )
        PsModuleFactory(name="jbcs-1")
        PsModuleFactory(name="rhel-8")
        AffectFactory(
            flaw=flaw,
            ps_module="jbcs-1",
            ps_component="ssh",
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="libssh",
        )

        flaw_data = {
            "cve_id": "CVE-2000-3000",
            "title": flaw.title,
            "description": flaw.description,
            "updated_dt": flaw.updated_dt,
            "embargoed": False,
        }
        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] == "CVE-2000-3000"

    @pytest.mark.vcr
    def test_flaw_update_remove_cve(self, auth_client, test_api_uri):
        """
        test removing of a CVE from a flaw
        """
        flaw = FlawFactory(
            bz_id="1995562",
            cve_id="CVE-2000-3000",
            component="ssh",
            title="I cannot ssh into Matrix",
            description="test",
            impact="MODERATE",
            source="CUSTOMER",
            reported_dt="2022-04-26T00:00:00Z",
            unembargo_dt="2022-04-27T00:00:00Z",
            updated_dt="2023-05-22T14:42:14Z",
            embargoed=False,
        )
        PsModuleFactory(name="jbcs-1")
        PsModuleFactory(name="rhel-8")
        AffectFactory(
            flaw=flaw,
            ps_module="jbcs-1",
            ps_component="ssh",
        )
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="libssh",
        )

        flaw_data = {
            "cve_id": None,
            "title": flaw.title,
            "description": flaw.description,
            "updated_dt": flaw.updated_dt,
            "embargoed": False,
        }
        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        assert response.json()["cve_id"] is None

    @pytest.mark.vcr
    @freeze_time(timezone.datetime(2023, 5, 26))
    def test_flaw_update_remove_unembargo_dt(self, auth_client, test_api_uri):
        """
        test removing unembargo_dt from an embargoed flaw
        """
        last_change_time = "2023-05-26T13:10:44Z"
        flaw = FlawFactory.build(
            cve_id="CVE-2022-0508",
            cvss3="2.2/CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N",
            cwe_id="CWE-100",
            component="shower",
            description="the water is everywhere",
            embargoed=True,
            impact="IMPORTANT",
            meta_attr={"bz_id": "2012106", "last_change_time": last_change_time},
            mitigation="call a repairman",
            reported_dt="2022-05-09T00:00:00Z",
            source="CUSTOMER",
            statement="I do not like this",
            summary="something got wrong in my shower",
            title="water overflow",
            unembargo_dt="2022-06-16T00:00:00Z",
            updated_dt=last_change_time,
        )
        flaw.save(raise_validation_error=False)
        PsModuleFactory(component_cc={}, default_cc=[], name="rhel-9")
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-9",
            ps_component="samba",
            affectedness="AFFECTED",
            resolution="FIX",
            impact=None,
            cvss2=None,
            cvss3=None,
        )

        flaw_data = {
            "description": flaw.description,
            "embargoed": flaw.embargoed,
            "title": flaw.title,
            "unembargo_dt": None,
            "updated_dt": flaw.updated_dt,
        }
        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/flaws/{flaw.uuid}")
        assert response.status_code == 200
        assert response.json()["unembargo_dt"] is None

    @pytest.mark.vcr
    def test_affect_create(self, auth_client, test_api_uri):
        """
        test creating a flaw affect with Bugzilla two-way sync
        """
        flaw = FlawFactory(
            bz_id="2008346",
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2023-03-17T11:24:14Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
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
        }
        response = auth_client().post(
            f"{test_api_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/affects/{created_uuid}")
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
            bz_id="2008346",
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2023-03-17T15:33:54Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
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
            updated_dt="2023-03-17T15:33:54Z",
        )

        affect_data = {
            "flaw": flaw.uuid,
            "ps_module": "rhel-8",
            "ps_component": "kernel",
            "resolution": "WONTFIX",
            "embargoed": False,
            "updated_dt": affect.updated_dt,
        }
        response = auth_client().put(
            f"{test_api_uri}/affects/{affect.uuid}",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
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
            bz_id="2008346",
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2023-03-17T15:38:53Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
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

        response = auth_client().delete(
            f"{test_api_uri}/affects/{affect.uuid}",
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
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
        }
        response = auth_client().post(
            f"{test_api_uri}/flaws",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 400
        assert "Component value is required" in str(response.content)

    @pytest.mark.vcr
    def test_flaw_update_multi_cve(self, auth_client, test_api_uri):
        """
        test that flaw with multiple CVE IDs can be updated

        note that this single flaw in Bugzilla actually
        corresponds to multiple flaws in OSIDB
        """
        flaw1 = FlawFactory(
            bz_id="2009119",
            cve_id="CVE-2022-0313",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2023-03-31T16:41:41Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        flaw2 = FlawFactory(
            bz_id="2009119",
            cve_id="CVE-2022-0314",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2023-03-31T16:41:41Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        PsModuleFactory(name="rhel-8")
        AffectFactory(
            flaw=flaw1,
            ps_module="rhel-8",
            ps_component="kernel",
        )
        AffectFactory(
            flaw=flaw2,
            ps_module="rhel-8",
            ps_component="kernel",
        )

        # note that both flaws share BZ ID
        # but here we modify flaw1 only
        flaw_data = {
            "cve_id": "CVE-2022-0313",
            "title": "Bar",  # new title
            "description": "test",
            "reported_dt": flaw1.reported_dt,
            "unembargo_dt": flaw1.unembargo_dt,
            "updated_dt": flaw1.updated_dt,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
        }
        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw1.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        # both OSIDB flaws should be impacted by the modification
        assert Flaw.objects.get(cve_id="CVE-2022-0313").title == "Bar"
        assert Flaw.objects.get(cve_id="CVE-2022-0314").title == "Bar"

    def test_flaw_update_multi_cve_restricted(self, auth_client, test_api_uri):
        """
        test that CVE ID cannot be removed from a multi-CVE flaw

        note that this single flaw in Bugzilla actually
        corresponds to multiple flaws in OSIDB
        """
        flaw1 = FlawFactory(
            bz_id="2009119",
            cve_id="CVE-2022-0313",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2023-03-31T16:41:41Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        flaw2 = FlawFactory(
            bz_id="2009119",
            cve_id="CVE-2022-0314",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2023-03-31T16:41:41Z",
            cvss3="3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        PsModuleFactory(name="rhel-8")
        AffectFactory(
            flaw=flaw1,
            ps_module="rhel-8",
            ps_component="kernel",
        )
        AffectFactory(
            flaw=flaw2,
            ps_module="rhel-8",
            ps_component="kernel",
        )

        # note that both flaws share BZ ID
        # but here we modify flaw1 only
        flaw_data = {
            "cve_id": None,  # attemt to remove CVE ID
            "title": "Foo",
            "description": "test",
            "reported_dt": flaw1.reported_dt,
            "unembargo_dt": flaw1.unembargo_dt,
            "updated_dt": flaw1.updated_dt,
            "cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "embargoed": False,
        }
        with pytest.raises(UnsaveableFlawError, match="Unable to remove a CVE ID"):
            auth_client().put(
                f"{test_api_uri}/flaws/{flaw1.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
            )
