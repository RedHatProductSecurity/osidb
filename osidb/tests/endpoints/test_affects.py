from unittest.mock import patch

import pytest
from rest_framework import status

from osidb.models import Affect, AffectCVSS, Tracker
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestEndpointsAffectsV1:
    """
    tests specific to v1/affects endpoint
    """

    @pytest.mark.enable_signals
    def test_get_affect_with_cvss(self, auth_client, test_api_uri):
        """retrieve specific affect with affectcvss from endpoint"""
        affect = AffectFactory()

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 0

        AffectCVSSFactory(affect=affect)

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 1

    @pytest.mark.parametrize(
        "filter_value,expected_with_trackers,expected_without_trackers",
        [
            (True, 0, 1),
            (False, 1, 0),
        ],
    )
    def test_trackers_isempty_filter(
        self,
        auth_client,
        test_api_uri,
        filter_value,
        expected_with_trackers,
        expected_without_trackers,
    ):
        """
        test that tracker__isempty filter is working correctly
        """
        flaw = FlawFactory()

        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect_with_trackers = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        TrackerFactory(
            affects=[affect_with_trackers],
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw.embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        affect_without_trackers = AffectFactory(flaw=flaw)

        response = auth_client().get(
            f"{test_api_uri}/affects?trackers__isempty={str(filter_value).lower()}"
        )

        assert response.status_code == status.HTTP_200_OK
        body = response.json()

        expected_total = expected_with_trackers + expected_without_trackers
        assert body["count"] == expected_total

        if expected_with_trackers > 0:
            affect_uuids = [result["uuid"] for result in body["results"]]
            assert str(affect_with_trackers.uuid) in affect_uuids

        if expected_without_trackers > 0:
            affect_uuids = [result["uuid"] for result in body["results"]]
            assert str(affect_without_trackers.uuid) in affect_uuids

    @pytest.mark.enable_signals
    def test_get_affect_with_cve_id(self, auth_client, test_api_uri):
        """append cve_id from parent flaw to the Affect serializer"""
        flaw = FlawFactory(cve_id="CVE-2025-1234")
        affect = AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["cve_id"] == flaw.cve_id

    @pytest.mark.enable_signals
    def test_filter_affect_by_cve_id(self, auth_client, test_api_uri):
        flaw = FlawFactory(cve_id="CVE-2025-1234")
        AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_uri}/affects?cve_id={flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 1
        assert response.data["results"][0]["cve_id"] == flaw.cve_id


class TestEndpointsAffects:
    """
    tests specific to v2/affects endpoint
    """

    @pytest.mark.enable_signals
    def test_get_affect_with_cvss(self, auth_client, test_api_v2_uri):
        """retrieve specific affect with affectcvss from endpoint"""
        affect = AffectFactory()

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 0

        AffectCVSSFactory(affect=affect)

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 1

    @pytest.mark.parametrize(
        "flaw_embargo,affect_embargo,fails",
        [
            (False, False, False),
            (True, True, False),
            (False, True, True),
            (True, False, True),
        ],
    )
    def test_affect_create(
        self,
        auth_client,
        test_api_v2_uri,
        flaw_embargo,
        affect_embargo,
        fails,
    ):
        """
        test the creation of Affect records via a REST API POST request
        also with respect to the flaw and affect visibility (which should be equal in Buzilla world)
        """
        flaw = FlawFactory(embargoed=flaw_embargo)
        PsUpdateStreamFactory(name="rhacm-2.11.z")
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": "rhacm-2.11.z",
            "ps_component": "curl",
            "embargoed": affect_embargo,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        if fails:
            assert response.status_code == 400
            assert "ACLs must correspond to the parent flaw:" in str(response.content)

        else:
            assert response.status_code == 201
            body = response.json()
            created_uuid = body["uuid"]

            response = auth_client().get(f"{test_api_v2_uri}/affects/{created_uuid}")
            assert response.status_code == 200
            body = response.json()
            assert body["ps_update_stream"] == "rhacm-2.11.z"

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_affect_update(self, auth_client, test_api_v2_uri, embargoed):
        """
        Test the update of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(embargoed=embargoed)
        ps_update_stream1 = PsUpdateStreamFactory()
        ps_update_stream2 = PsUpdateStreamFactory()
        affect = AffectFactory(flaw=flaw, ps_update_stream=ps_update_stream1.name)
        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            {
                **original_body,
                "ps_update_stream": f"{ps_update_stream2.name}",
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["ps_update_stream"] != body["ps_update_stream"]

    def test_affect_delete(self, auth_client, test_api_v2_uri):
        """
        Test the deletion of Affect records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        affect_url = f"{test_api_v2_uri}/affects/{affect.uuid}"
        response = auth_client().get(affect_url)
        assert response.status_code == 200

        response = auth_client().delete(affect_url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == 200

        response = auth_client().get(affect_url)
        assert response.status_code == 404

    @pytest.mark.enable_signals
    def test_affectcvss_create(self, auth_client, test_api_v2_uri):
        """
        Test the creation of AffectCVSS records via a REST API POST request.
        """
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss_data = {
            "issuer": AffectCVSS.CVSSIssuer.REDHAT,
            "cvss_version": AffectCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on affects/{uuid}/cvss-scores
        response = auth_client().post(
            f"{test_api_v2_uri}/affects/{str(affect.uuid)}/cvss-scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]

        # Tests "GET" on affects/{uuid}/cvss-scores
        response = auth_client().get(
            f"{test_api_v2_uri}/affects/{str(affect.uuid)}/cvss-scores"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on affects/{uuid}/cvss-scores/{uuid}
        response = auth_client().get(
            f"{test_api_v2_uri}/affects/{str(affect.uuid)}/cvss-scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid

    def test_affect_resolved_dt(
        self,
        auth_client,
        test_api_v2_uri,
    ):
        """
        test the resolved_dt behavior on REST API
        """
        flaw = FlawFactory()
        PsUpdateStreamFactory(name="rhacm-2.11.z")
        # check unresolved creation
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": "rhacm-2.11.z",
            "ps_component": "curl",
            "embargoed": flaw.is_embargoed,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid_unresolved = body["uuid"]

        response = auth_client().get(
            f"{test_api_v2_uri}/affects/{created_uuid_unresolved}"
        )
        assert response.status_code == 200
        body = response.json()
        assert not body["resolved_dt"]

        # check resolved creation
        affect_data["affectedness"] = Affect.AffectAffectedness.AFFECTED
        affect_data["resolution"] = Affect.AffectResolution.WONTFIX
        affect_data["ps_component"] = "kernel"

        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid_resolved = body["uuid"]

        response = auth_client().get(
            f"{test_api_v2_uri}/affects/{created_uuid_resolved}"
        )
        assert response.status_code == 200
        body = response.json()
        assert body["resolved_dt"]

        # check unresolved update
        response = auth_client().get(
            f"{test_api_v2_uri}/affects/{created_uuid_unresolved}"
        )
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{created_uuid_unresolved}",
            {
                **original_body,
                "affectedness": Affect.AffectAffectedness.AFFECTED,
                "resolution": Affect.AffectResolution.OOSS,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert body["resolved_dt"]

        # check rsolved update
        response = auth_client().get(
            f"{test_api_v2_uri}/affects/{created_uuid_resolved}"
        )
        assert response.status_code == 200
        original_body = response.json()
        old_resolved_dt = original_body["resolved_dt"]

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{created_uuid_resolved}",
            {
                **original_body,
                "affectedness": Affect.AffectAffectedness.AFFECTED,
                "resolution": Affect.AffectResolution.WONTFIX,
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert body["resolved_dt"]
        assert body["resolved_dt"] == old_resolved_dt

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{created_uuid_resolved}",
            {
                **original_body,
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "updated_dt": body["updated_dt"],
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert not body["resolved_dt"]
        assert body["resolved_dt"] != old_resolved_dt

    @pytest.mark.parametrize(
        "filter_value,expected_with_trackers,expected_without_trackers",
        [
            (True, 0, 1),
            (False, 1, 0),
        ],
    )
    def test_trackers_isempty_filter(
        self,
        auth_client,
        test_api_v2_uri,
        filter_value,
        expected_with_trackers,
        expected_without_trackers,
    ):
        """
        test that tracker__isempty filter is working correctly
        """
        flaw = FlawFactory()

        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect_with_trackers = AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            affectedness=Affect.AffectAffectedness.AFFECTED,
        )
        TrackerFactory(
            affects=[affect_with_trackers],
            ps_update_stream=ps_update_stream.name,
            embargoed=flaw.embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        affect_without_trackers = AffectFactory(flaw=flaw)

        response = auth_client().get(
            f"{test_api_v2_uri}/affects?tracker__isnull={str(filter_value).lower()}"
        )

        assert response.status_code == status.HTTP_200_OK
        body = response.json()

        expected_total = expected_with_trackers + expected_without_trackers
        assert body["count"] == expected_total

        if expected_with_trackers > 0:
            affect_uuids = [result["uuid"] for result in body["results"]]
            assert str(affect_with_trackers.uuid) in affect_uuids

        if expected_without_trackers > 0:
            affect_uuids = [result["uuid"] for result in body["results"]]
            assert str(affect_without_trackers.uuid) in affect_uuids

    @pytest.mark.enable_signals
    def test_get_affect_with_cve_id(self, auth_client, test_api_v2_uri):
        """append cve_id from parent flaw to the Affect serializer"""
        flaw = FlawFactory(cve_id="CVE-2025-1234")
        affect = AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["cve_id"] == flaw.cve_id

    @pytest.mark.enable_signals
    def test_filter_affect_by_cve_id(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(cve_id="CVE-2025-1234")
        AffectFactory(flaw=flaw)

        response = auth_client().get(f"{test_api_v2_uri}/affects?cve_id={flaw.cve_id}")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["count"] == 1
        assert response.data["results"][0]["cve_id"] == flaw.cve_id


class TestEndpointsAffectsBulk:
    """
    tests specific to bulk operations on /affects endpoint
    """

    def test_affect_update_bulk(self, auth_client, test_api_v2_uri):
        """
        Test the bulk update of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789")
        affects = []
        for i in range(20):
            affects.append(AffectFactory(flaw=flaw))

        response = auth_client().get(
            f"{test_api_v2_uri}/affects?flaw__cve_id=CVE-2345-6789"
        )
        assert response.status_code == 200
        original_body = response.json()
        request_affects = original_body["results"]
        orig_uuids = set()
        for aff in request_affects:
            orig_uuids.add(aff["uuid"])
            aff["affectedness"] = "AFFECTED"
            aff["resolution"] = "DELEGATED"
            ps_update_stream = PsUpdateStreamFactory(
                name=f"different {aff['ps_update_stream']}"
            )
            aff["ps_update_stream"] = f"{ps_update_stream.name}"

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/bulk",
            request_affects,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        new_uuids = set()
        for returned_aff in body["results"]:
            new_uuids.add(returned_aff["uuid"])
            assert returned_aff["affectedness"] == "AFFECTED"
            assert returned_aff["resolution"] == "DELEGATED"
            assert returned_aff["ps_update_stream"].startswith("different ")
        assert len(orig_uuids) == len(new_uuids)
        assert orig_uuids == new_uuids
        assert len(body["results"]) == len(request_affects)

    @pytest.mark.enable_signals
    def test_affect_create_bulk(self, auth_client, test_api_v2_uri):
        """
        Test the bulk creation of Affect records via a REST API POST request.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789")
        affects = []
        for i in range(20):
            affects.append(AffectFactory(flaw=flaw))

        assert Affect.objects.count() == 20

        nonbulk_response = auth_client().get(
            f"{test_api_v2_uri}/affects?flaw__cve_id=CVE-2345-6789"
        )
        assert nonbulk_response.status_code == 200

        bulk_request = {}
        i = 0
        for aff in nonbulk_response.json()["results"]:
            tmp_aff = dict(aff)
            del tmp_aff["uuid"]
            del tmp_aff["created_dt"]
            del tmp_aff["updated_dt"]
            del tmp_aff["resolved_dt"]
            del tmp_aff["alerts"]
            tmp_aff["ps_update_stream"] = aff["ps_update_stream"]
            bulk_request[int(tmp_aff["ps_update_stream"][17:])] = tmp_aff
            i += 1

        assert Affect.objects.all().delete()
        assert Affect.objects.count() == 0

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request.values(),
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        assert Affect.objects.count() == 20

        for returned_aff in response.json()["results"]:
            i = int(returned_aff["ps_update_stream"][17:])
            requested_aff = bulk_request[i]
            received_aff = dict(returned_aff)
            del received_aff["uuid"]
            del received_aff["created_dt"]
            del received_aff["updated_dt"]
            del received_aff["resolved_dt"]
            del received_aff["alerts"]
            # For shorter debugging output
            assert sorted(received_aff.keys()) == sorted(requested_aff.keys())
            assert received_aff == requested_aff

    def test_affect_delete_bulk(self, auth_client, test_api_v2_uri):
        """
        Test the bulk deletion of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789")
        affects = []
        for i in range(20):
            affects.append(AffectFactory(flaw=flaw))

        assert Affect.objects.count() == 20

        nonbulk_response = auth_client().get(
            f"{test_api_v2_uri}/affects?flaw__cve_id=CVE-2345-6789"
        )
        assert nonbulk_response.status_code == 200

        bulk_request = []
        for aff in nonbulk_response.json()["results"]:
            bulk_request.append(aff["uuid"])

        response = auth_client().delete(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        assert Affect.objects.count() == 0

    @pytest.mark.enable_signals
    def test_affect_create_bulk_public_acls(self, auth_client, test_api_v2_uri):
        """
        Test the bulk creation of Affect records via a REST API POST request
        with public ACLs (embargoed=False) and verify ACLs match parent flaw.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789", embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "component-foo",
                "embargoed": False,
            }
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        assert Affect.objects.count() == 1

        # Verify that the flaw is public (not embargoed and not internal)
        assert not flaw.is_embargoed
        assert not flaw.is_internal
        assert flaw.is_public

        # Get the created affects from the database to verify ACLs
        created_affect = Affect.objects.get(flaw=flaw)
        assert not created_affect.is_embargoed
        assert not created_affect.is_internal
        assert created_affect.is_public


class TestEndpointsAffectsUpdateTrackers:
    """
    tests of consecutive tracker update trigger
    which may result from /affects endpoint PUT calls
    """

    def test_filter(self, auth_client, test_api_v2_uri):
        """
        test that the tracker update is triggered when expected only
        """
        flaw = FlawFactory(impact="LOW")
        ps_product1 = PsProductFactory(business_unit="Corporate")
        ps_module1 = PsModuleFactory(ps_product=ps_product1)
        ps_update_stream11 = PsUpdateStreamFactory(ps_module=ps_module1)
        affect1 = AffectFactory(
            flaw=flaw,
            impact="LOW",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream11.name,
        )
        tracker1 = TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream11.name,
            status="NEW",
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        ps_update_stream12 = PsUpdateStreamFactory(ps_module=ps_module1)
        affect2 = AffectFactory(
            flaw=flaw,
            impact="LOW",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream12.name,
        )
        TrackerFactory(
            affects=[affect2],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream12.name,
            status="CLOSED",  # already resolved
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        # one more community affect-tracker context
        ps_product2 = PsProductFactory(business_unit="Community")
        ps_module2 = PsModuleFactory(ps_product=ps_product2)
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module2)
        affect3 = AffectFactory(
            flaw=flaw,
            impact="LOW",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream2.name,
        )
        TrackerFactory(
            affects=[affect3],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream2.name,
            status="NEW",
            type=Tracker.BTS2TYPE[ps_module2.bts_name],
        )

        affect1_data = {
            "embargoed": flaw.embargoed,
            "flaw": flaw.uuid,
            "impact": "MODERATE",  # tracker update trigger
            "ps_component": affect1.ps_component,
            "ps_update_stream": affect1.ps_update_stream,
            "updated_dt": affect1.updated_dt,
        }
        affect2_data = {
            "embargoed": flaw.embargoed,
            "flaw": flaw.uuid,
            "impact": "MODERATE",  # tracker update trigger
            "ps_component": affect2.ps_component,
            "ps_update_stream": affect2.ps_update_stream,
            "updated_dt": affect2.updated_dt,
        }
        affect3_data = {
            "embargoed": flaw.embargoed,
            "flaw": flaw.uuid,
            "impact": "MODERATE",  # tracker update trigger
            "ps_component": affect3.ps_component,
            "ps_update_stream": affect3.ps_update_stream,
            "updated_dt": affect3.updated_dt,
        }

        # enable autospec to get self as part of the method call args
        with patch.object(Tracker, "save", autospec=True) as mock_save:
            response = auth_client().put(
                f"{test_api_v2_uri}/affects/{affect1.uuid}",
                affect1_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert mock_save.call_count == 1  # only non-closed and non-community
            assert [tracker1.uuid] == [
                args[0][0].uuid for args in mock_save.call_args_list
            ]
            response = auth_client().put(
                f"{test_api_v2_uri}/affects/{affect2.uuid}",
                affect2_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert mock_save.call_count == 1  # no change
            response = auth_client().put(
                f"{test_api_v2_uri}/affects/{affect3.uuid}",
                affect3_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert mock_save.call_count == 1  # no change

    @pytest.mark.parametrize(
        "to_create,to_update,triggered",
        [
            ({"impact": "IMPORTANT"}, {"impact": "LOW"}, True),
            ({"impact": "MODERATE"}, {"impact": "IMPORTANT"}, True),
            ({"ps_component": "ssh"}, {"ps_component": "bash"}, True),
        ],
    )
    def test_trigger(
        self, auth_client, test_api_v2_uri, to_create, to_update, triggered
    ):
        """
        test that the tracker update is triggered when expected only
        """
        flaw = FlawFactory(impact="LOW")
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            **to_create,
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        affect_data = {
            "embargoed": flaw.embargoed,
            "flaw": flaw.uuid,
            "ps_component": affect.ps_component,
            "ps_update_stream": affect.ps_update_stream,
            "updated_dt": affect.updated_dt,
        }
        for attribute, value in to_update.items():
            affect_data[attribute] = value

        with patch.object(Tracker, "save") as mock_save:
            response = auth_client().put(
                f"{test_api_v2_uri}/affects/{affect.uuid}",
                affect_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert mock_save.called == triggered

    def test_trigger_affect_flaw_change(self, auth_client, test_api_v2_uri):
        """
        test that the tracker update is triggered when an affect-flaw link is modified
        """
        flaw1 = FlawFactory()
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )
        TrackerFactory(
            affects=[affect],
            embargoed=flaw1.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        flaw2 = FlawFactory(embargoed=flaw1.embargoed)
        affect_data = {
            "embargoed": flaw2.embargoed,
            "flaw": flaw2.uuid,  # re-link the affect
            "ps_component": affect.ps_component,
            "ps_update_stream": affect.ps_update_stream,
            "updated_dt": affect.updated_dt,
        }

        with patch.object(Tracker, "save") as mock_save:
            response = auth_client().put(
                f"{test_api_v2_uri}/affects/{affect.uuid}",
                affect_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert mock_save.called


class TestEndpointsAffectsPurl:
    """
    Class for testing the purl field and its ps_component validation/update on the Affects endpoint.
    """

    @pytest.mark.parametrize("ps_component", ["", None, "curl"])
    def test_affect_purl_create(self, auth_client, test_api_v2_uri, ps_component):
        """
        Test that Affect is created when new data contains correct purl
        and its ps_component is either not provided or matches the one included in purl.
        """
        purl = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        flaw = FlawFactory(embargoed=False)
        PsUpdateStreamFactory(name="rhacm-2.11.z")
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": "rhacm-2.11.z",
            "ps_component": ps_component,
            "purl": purl,
            "embargoed": False,
        }

        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_v2_uri}/affects/{created_uuid}")
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["ps_component"] == "curl"
        assert body["purl"] == purl

    @pytest.mark.parametrize("ps_component", ["", None, "curl"])
    def test_affect_purl_update(self, auth_client, test_api_v2_uri, ps_component):
        """
        Test that Affect's purl and ps_component are updated when new data contains correct purl
        and its ps_component is either not provided or matches the one included in purl.
        """
        purl = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw, ps_component="podman", purl="")

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert original_body["ps_component"] == "podman"
        assert original_body["purl"] == ""

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            {**original_body, "ps_component": ps_component, "purl": purl},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_v2_uri}/affects/{created_uuid}")
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["ps_component"] == "curl"
        assert body["purl"] == purl

    @pytest.mark.parametrize(
        "ps_component,purl,error,warning",
        [
            (
                "",
                "rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "invalid purl",
                None,
            ),
            (
                "podman",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                None,
                "purl_ps_component_mismatch",
            ),
            ("", "", "must have either purl or ps_component", None),
            (None, None, "must have either purl or ps_component", None),
        ],
    )
    def test_invalid_data_create(
        self, auth_client, test_api_v2_uri, ps_component, purl, error, warning
    ):
        """
        Test that Affect is not created when new data contains incorrect purl,
        correct purl but its ps_component does not match the one included in purl,
        or purl and ps_component are missing.
        """
        flaw = FlawFactory(embargoed=False)
        PsUpdateStreamFactory(name="rhacm-2.11.z")
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": "rhacm-2.11.z",
            "ps_component": ps_component,
            "purl": purl,
            "embargoed": False,
        }

        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        if error:
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert error in str(response.content)
        elif warning:
            assert response.status_code == status.HTTP_201_CREATED
            assert flaw.alerts.filter(name=warning).exists()

    @pytest.mark.parametrize(
        "ps_component,purl,error,warning",
        [
            (
                "",
                "rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "invalid purl",
                None,
            ),
            (
                "podman",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                None,
                "purl_ps_component_mismatch",
            ),
            ("", "", "must have either purl or ps_component", None),
            (None, None, "must have either purl or ps_component", None),
        ],
    )
    def test_invalid_data_update(
        self, auth_client, test_api_v2_uri, ps_component, purl, error, warning
    ):
        """
        Test that Affect's purl and ps_component are not updated when new data contains incorrect purl,
        correct purl but its ps_component does not match the one included in purl,
        or purl and ps_component are missing.
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw, ps_component="podman", purl="")

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            {**original_body, "ps_component": ps_component, "purl": purl},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        if error:
            assert response.status_code == status.HTTP_400_BAD_REQUEST
            assert error in str(response.content)
        elif warning:
            assert response.status_code == status.HTTP_200_OK
            assert flaw.alerts.filter(name=warning).exists()


class TestEndpointsAffectsCVSSScoresV2:
    """
    Test that editing an AffectCVSS record through the v2 API
    only works with the correct Issuer (REDHAT).
    """

    @pytest.mark.enable_signals
    def test_affectcvss_create(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(impact="LOW")
        affect = AffectFactory(flaw=flaw)
        cvss_data = {
            "cvss_version": AffectCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/{str(affect.uuid)}/cvss-scores",
            data=cvss_data,
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        # CVSS scores created through API should always be of type Red Hat
        assert response.data["issuer"] == AffectCVSS.CVSSIssuer.REDHAT
        assert AffectCVSS.objects.count() == 1

    @pytest.mark.enable_signals
    def test_affectcvss_rh_update(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss = AffectCVSSFactory(
            affect=affect,
            version=AffectCVSS.CVSSVersion.VERSION3,
            vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            issuer=AffectCVSS.CVSSIssuer.REDHAT,
        )

        cvss_data = {
            "cvss_version": AffectCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
            "updated_dt": cvss.updated_dt,
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{str(affect.uuid)}/cvss-scores/{cvss.uuid}",
            data=cvss_data,
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["vector"] == cvss_data["vector"]
        assert cvss.vector != response.data["vector"]

    @pytest.mark.enable_signals
    def test_affectcvss_non_rh_update(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss = AffectCVSSFactory(
            affect=affect,
            version=AffectCVSS.CVSSVersion.VERSION3,
            issuer=AffectCVSS.CVSSIssuer.NIST,
            vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        )

        cvss_data = {
            "cvss_version": AffectCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
            "updated_dt": cvss.updated_dt,
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{str(affect.uuid)}/cvss-scores/{cvss.uuid}",
            data=cvss_data,
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Only Red Hat CVSS scores can be edited" in response.json()["issuer"]
        refreshed_cvss = AffectCVSS.objects.first()
        assert refreshed_cvss and refreshed_cvss.vector == cvss.vector

    @pytest.mark.enable_signals
    def test_affectcvss_rh_delete(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss = AffectCVSSFactory(affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT)

        url = f"{test_api_v2_uri}/affects/{str(affect.uuid)}/cvss-scores/{cvss.uuid}"
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="foo")
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert AffectCVSS.objects.count() == 0

    @pytest.mark.enable_signals
    def test_affectcvss_non_rh_delete(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss = AffectCVSSFactory(affect=affect, issuer=AffectCVSS.CVSSIssuer.NIST)

        url = f"{test_api_v2_uri}/affects/{str(affect.uuid)}/cvss-scores/{cvss.uuid}"
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="foo")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Only Red Hat CVSS scores can be edited" in response.json()["issuer"]
        assert AffectCVSS.objects.count() == 1
