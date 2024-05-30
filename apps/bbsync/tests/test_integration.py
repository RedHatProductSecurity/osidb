import json
import uuid

import pytest
from django.utils import timezone
from freezegun import freeze_time

from apps.bbsync.exceptions import UnsaveableFlawError
from apps.trackers.tests.factories import JiraProjectFieldsFactory
from collectors.bzimport.collectors import BugzillaTrackerCollector, FlawCollector
from collectors.jiraffe.collectors import JiraTrackerCollector
from osidb.models import (
    Affect,
    Flaw,
    FlawAcknowledgment,
    FlawCVSS,
    FlawReference,
    Snippet,
    Tracker,
)
from osidb.tests.factories import (
    AffectFactory,
    FlawAcknowledgmentFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    SnippetFactory,
    TrackerFactory,
)

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
            "cve_id": "CVE-2024-0126",
            "title": "Foo",
            "description": "test",
            "impact": "LOW",
            "component": "curl",
            "source": "INTERNET",
            "reported_dt": "2022-11-22T15:55:22.830Z",
            "unembargo_dt": "2000-1-1T22:03:26.065Z",
            "mitigation": "mitigation",
            "embargoed": False,
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
        assert response.json()["cve_id"] == "CVE-2024-0126"
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
    @pytest.mark.enable_signals
    def test_flawcvss_create(self, auth_client, test_api_uri):
        """
        test creating a flaw cvss v4 with Bugzilla two-way sync
        """
        flaw = FlawFactory(
            bz_id="2008346",
            cve_id="CVE-2021-0773",
            title="Foo",
            description="test",
            reported_dt="2022-11-22T15:55:22.830Z",
            unembargo_dt="2000-1-1T22:03:26.065Z",
            updated_dt="2024-03-14T09:55:39Z",
            acl_read=self.acl_read,
            acl_write=self.acl_write,
            embargoed=False,
        )
        PsModuleFactory(name="rhel-8", default_cc=[], component_cc={})
        AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="kernel",
        )

        cvss_data = {
            "issuer": FlawCVSS.CVSSIssuer.REDHAT,
            "cvss_version": FlawCVSS.CVSSVersion.VERSION4,
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/cvss_scores
        response = auth_client().post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 201

        # Tests "GET" on flaws/{uuid}/cvss_scores
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores"
        )
        assert response.status_code == 200
        assert response.json()["count"] == 1

    @pytest.mark.vcr
    def test_flaw_update_add_cve(self, auth_client, test_api_uri):
        """
        test adding a CVE to an existing CVE-less flaw
        """
        flaw = FlawFactory(
            bz_id="1995562",
            cve_id="",
            components=["ssh"],
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
            HTTP_JIRA_API_KEY="SECRET",
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
            components=["ssh"],
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
            HTTP_JIRA_API_KEY="SECRET",
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
            cwe_id="CWE-100",
            components=["shower"],
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
            resolution="DELEGATED",
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
    def test_flaw_unembargo(self, auth_client, test_api_uri):
        """
        test flaw unembargo with Bugzilla two-way sync
        """
        # freeze time so there is no late unembargo
        with freeze_time(timezone.datetime(2000, 11, 11)):
            last_change_time = "2024-02-06T09:43:57Z"
            flaw = FlawFactory(
                cve_id="CVE-2004-2493",
                components=["test"],
                title="totally descriptive",
                description="test",
                impact="LOW",
                reported_dt="2000-01-01T01:01:01Z",
                unembargo_dt="2000-11-11T22:22:22Z",
                updated_dt=last_change_time,
                # we expect the existing groups to be stored in metadata
                meta_attr={
                    "bz_id": "1984642",
                    "groups": '["qe_staff", "security"]',
                    "last_change_time": last_change_time,
                },
                embargoed=True,
            )
        PsModuleFactory(
            name="rhcertification-8",
            default_cc=[],
            component_cc={},
        )
        affect = AffectFactory(
            flaw=flaw,
            ps_module="rhcertification-8",
            ps_component="openssl",
        )
        assert Affect.objects.get(uuid=affect.uuid).is_embargoed
        assert Flaw.objects.get(uuid=flaw.uuid).is_embargoed

        flaw_data = {
            "cve_id": "CVE-2004-2493",
            "title": "totally descriptive",
            "description": "test",
            "reported_dt": flaw.reported_dt,
            "unembargo_dt": flaw.unembargo_dt,
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
        assert not Affect.objects.get(uuid=affect.uuid).is_embargoed
        assert not Flaw.objects.get(uuid=flaw.uuid).is_embargoed

    @pytest.mark.vcr
    def test_flaw_unembargo_complex(
        self,
        auth_client,
        enable_bugzilla_sync,
        enable_jira_sync,
        test_api_uri,
    ):
        """
        test flaw unembargo with Bugzilla two-way sync
        """
        # change time on one place for easier update
        flaw_last_change_time = "2024-05-03T14:03:53Z"
        tracker1_last_change_time = "2024-05-03T14:09:44Z"
        # TODO no mid-air collision detection
        tracker2_last_change_time = "2000-01-01T00:00:00Z"

        # freeze time so there is no late unembargo
        with freeze_time(timezone.datetime(2000, 11, 11)):
            flaw = FlawFactory(
                cve_id="CVE-2004-2493",
                components=["test"],
                title="totally descriptive",
                description="test",
                impact="LOW",
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
                reported_dt="2000-01-01T01:01:01Z",
                unembargo_dt="2000-11-11T22:22:22Z",
                updated_dt=flaw_last_change_time,
                # we expect the existing groups to be stored in metadata
                meta_attr={
                    "bz_id": "1984642",
                    "groups": '["qe_staff", "security"]',
                    "last_change_time": flaw_last_change_time,
                },
                embargoed=True,
            )
        acknowledgment = FlawAcknowledgmentFactory(
            flaw=flaw,
            name="dear",
            affiliation="sir",
            from_upstream=False,
        )
        ps_module1 = PsModuleFactory(
            bts_name="bugzilla",
            bts_groups={
                "public": ["devel"],
                "embargoed": [
                    "private",
                ],
            },
            bts_key="Red Hat Certification Program",
            name="rhcertification-8",
            default_component="redhat-certification",
            private_trackers_allowed=True,
            default_cc=[],
            component_cc={},
        )
        affect1 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module1.name,
            ps_component="openssl",
            impact=None,
        )
        ps_update_stream1 = PsUpdateStreamFactory(
            name="rhcertification-8-default",
            ps_module=ps_module1,
            version="1.0",
        )
        tracker1 = TrackerFactory(
            affects=[affect1],
            bz_id="2021859",
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream1.name,
            type=Tracker.TrackerType.BUGZILLA,
            updated_dt=tracker1_last_change_time,
            status="NEW",
            # we expect the existing groups to be stored in metadata
            meta_attr={
                "bz_id": "2021859",
                "groups": '["security"]',
                "last_change_time": tracker1_last_change_time,
            },
        )
        ps_module2 = PsModuleFactory(
            bts_name="jboss",
            bts_groups={"public": ["redhat"]},
            bts_key="RHEL",
            name="rhel-8",
            default_cc=[],
            component_cc={},
        )
        affect2 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module2.name,
            ps_component="openssl",
            impact=None,
        )
        ps_update_stream2 = PsUpdateStreamFactory(
            name="rhel-8",
            ps_module=ps_module2,
            version="rhel-8.10.0",
        )
        tracker2 = TrackerFactory(
            affects=[affect2],
            external_system_id="RHEL-12102",
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream2.name,
            type=Tracker.TrackerType.JIRA,
            updated_dt=tracker2_last_change_time,
            status="NEW",
        )

        assert Flaw.objects.get(uuid=flaw.uuid).is_embargoed
        assert FlawAcknowledgment.objects.get(uuid=acknowledgment.uuid).is_embargoed
        assert Affect.objects.get(uuid=affect1.uuid).is_embargoed
        assert Tracker.objects.get(uuid=tracker1.uuid).is_embargoed
        assert Affect.objects.get(uuid=affect2.uuid).is_embargoed
        assert Tracker.objects.get(uuid=tracker2.uuid).is_embargoed

        JiraProjectFieldsFactory(
            project_key=ps_module2.bts_key,
            field_id="priority",
            field_name="Priority",
            allowed_values=[
                "Blocker",
                "Critical",
                "Major",
                "Normal",
                "Minor",
                "Undefined",
            ],
        )
        JiraProjectFieldsFactory(
            project_key=ps_module2.bts_key,
            field_id="security",
            field_name="Security Level",
            allowed_values=[
                "Embargoed Security Issue",
                "Red Hat Employee",
                "Red Hat Engineering Authorized",
                "Red Hat Partner",
                "Restricted",
                "Team",
            ],
        )

        flaw_data = {
            "cve_id": "CVE-2004-2493",
            "title": "totally descriptive",
            "description": "test",
            "reported_dt": flaw.reported_dt,
            "unembargo_dt": flaw.unembargo_dt,
            "updated_dt": flaw.updated_dt,
            "embargoed": False,
        }
        response = auth_client().put(
            f"{test_api_uri}/flaws/{flaw.uuid}",
            flaw_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200

        # explicitly reload to make sure the
        # changes happened in Bugzilla and Jira
        FlawCollector().collect_flaw(flaw.bz_id)
        BugzillaTrackerCollector().sync_tracker(tracker1.external_system_id)
        JiraTrackerCollector().collect(tracker2.external_system_id)

        assert not Flaw.objects.get(uuid=flaw.uuid).is_embargoed
        assert not FlawAcknowledgment.objects.get(uuid=acknowledgment.uuid).is_embargoed
        assert not Affect.objects.get(uuid=affect1.uuid).is_embargoed
        assert not Tracker.objects.get(uuid=tracker1.uuid).is_embargoed
        assert not Affect.objects.get(uuid=affect2.uuid).is_embargoed
        assert not Tracker.objects.get(uuid=tracker2.uuid).is_embargoed

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
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        PsModuleFactory(name="rhel-8")

        affect_data = {
            "flaw": flaw.uuid,
            "ps_module": "rhel-8",
            "ps_component": "kernel",
            "affectedness": "AFFECTED",
            "resolution": "DELEGATED",
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
        assert response.json()["resolution"] == "DELEGATED"

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
            acl_read=self.acl_read,
            acl_write=self.acl_write,
        )
        PsModuleFactory(name="rhel-8")
        affect = AffectFactory(
            flaw=flaw,
            ps_module="rhel-8",
            ps_component="kernel",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
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
            "embargoed": False,
        }
        with pytest.raises(UnsaveableFlawError, match="Unable to remove a CVE ID"):
            auth_client().put(
                f"{test_api_uri}/flaws/{flaw1.uuid}",
                flaw_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
            )


class TestFlawDraftBBSyncIntegration:
    @pytest.mark.vcr
    @pytest.mark.enable_signals
    @pytest.mark.parametrize(
        "source,cve_id,ext_id,jira_id",
        [
            (Snippet.Source.NVD, "CVE-2000-0048", "CVE-2000-0048", "OSIM-2470"),
            (Snippet.Source.OSV, "CVE-2000-0049", "GHSA-0012", "OSIM-2471"),
            (Snippet.Source.OSV, None, "GHSA-0013", "OSIM-2472"),
        ],
    )
    def test_flaw_draft_create(
        self,
        internal_read_groups,
        internal_write_groups,
        source,
        cve_id,
        ext_id,
        jira_id,
        monkeypatch,
    ):
        """
        test creating a flaw draft with Bugzilla two-way sync
        """
        import apps.taskman.mixins as taskman_mixins
        from osidb import models

        monkeypatch.setattr(taskman_mixins, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)
        monkeypatch.setattr(models, "JIRA_TASKMAN_AUTO_SYNC_FLAW", True)

        content = {
            "cve_id": cve_id,
            "cvss_scores": [
                {
                    "issuer": FlawCVSS.CVSSIssuer.REDHAT,
                    "score": 8.1,
                    "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "version": FlawCVSS.CVSSVersion.VERSION3,
                },
            ],
            "cwe_id": "CWE-110",
            "description": "some description",
            "references": [
                {
                    "url": f"https://osv.dev/vulnerability/{ext_id}"
                    if source == Snippet.Source.OSV
                    else f"https://nvd.nist.gov/vuln/detail/{ext_id}",
                    "type": FlawReference.FlawReferenceType.SOURCE,
                },
            ],
            "source": source,
            "title": f"From {source} collector",
            f"published_in_{source.lower()}": "2024-01-21T16:29:00.393Z",
        }

        snippet = SnippetFactory(
            source=source, ext_id=ext_id, cve_id=cve_id, content=content
        )
        flaw = snippet.convert_snippet_to_flaw(jira_token="SECRET")  # nosec

        assert Flaw.objects.all().count() == 1
        assert Flaw.objects.all()[0] == flaw
        assert flaw.cve_id == cve_id
        assert flaw.cvss_scores.all().count() == 1
        assert flaw.cwe_id == content["cwe_id"]
        assert flaw.description == content["description"]
        assert flaw.references.all().count() == 1
        assert flaw.reported_dt
        assert flaw.source == source
        assert flaw.title == f"From {source} collector"

        # check values related to taskman
        assert flaw.group_key == ""
        assert flaw.owner == ""
        assert flaw.task_key == jira_id
        assert flaw.team_id == ""
        assert flaw.workflow_name == "DEFAULT"
        assert flaw.workflow_state == "NEW"

        # only some items in meta_attr are checked
        assert flaw.meta_attr["bz_component"] == "vulnerability-draft"
        if cve_id:
            assert json.loads(flaw.meta_attr["alias"]) == [cve_id]
            assert flaw.meta_attr["bz_summary"] == f"{cve_id} From {source} collector"
            if source == "NVD":
                assert json.loads(flaw.meta_attr["external_ids"]) == [cve_id]
            else:
                assert json.loads(flaw.meta_attr["external_ids"]) == [
                    f"{ext_id}/{cve_id}"
                ]
        else:
            assert json.loads(flaw.meta_attr["alias"]) == [ext_id]
            assert flaw.meta_attr["bz_summary"] == f"From {source} collector"
            assert json.loads(flaw.meta_attr["external_ids"]) == [ext_id]

        # check that all ACLs are internal after Bugzilla two-way sync
        for i in [
            snippet,
            flaw,
            flaw.cvss_scores.first(),
            flaw.references.first(),
            flaw.snippets.first(),
        ]:
            assert internal_read_groups == i.acl_read
            assert internal_write_groups == i.acl_write
