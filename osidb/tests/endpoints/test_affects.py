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


class TestEndpointsAffects:
    """
    tests specific to /affects endpoint
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
        test_api_uri,
        flaw_embargo,
        affect_embargo,
        fails,
    ):
        """
        test the creation of Affect records via a REST API POST request
        also with respect to the flaw and affect visibility (which should be equal in Buzilla world)
        """
        flaw = FlawFactory(embargoed=flaw_embargo)
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_module": "rhacm-2",
            "ps_component": "curl",
            "embargoed": affect_embargo,
        }
        response = auth_client().post(
            f"{test_api_uri}/affects",
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

            response = auth_client().get(f"{test_api_uri}/affects/{created_uuid}")
            assert response.status_code == 200
            body = response.json()
            assert body["ps_module"] == "rhacm-2"

    @pytest.mark.parametrize("embargoed", [False, True])
    def test_affect_update(self, auth_client, test_api_uri, embargoed):
        """
        Test the update of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(embargoed=embargoed)
        affect = AffectFactory(flaw=flaw)
        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_uri}/affects/{affect.uuid}",
            {
                **original_body,
                "ps_module": f"different {affect.ps_module}",
            },
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        body = response.json()
        assert original_body["ps_module"] != body["ps_module"]

    def test_affect_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of Affect records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        # an extra affect needs to be created as otherwise
        # we would endup with an invalid affect-less flaw
        AffectFactory(flaw=flaw)
        affect = AffectFactory(flaw=flaw)

        affect_url = f"{test_api_uri}/affects/{affect.uuid}"
        response = auth_client().get(affect_url)
        assert response.status_code == 200

        response = auth_client().delete(affect_url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == 200

        response = auth_client().get(affect_url)
        assert response.status_code == 404

    @pytest.mark.enable_signals
    def test_affectcvss_create(self, auth_client, test_api_uri):
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

        # Tests "POST" on affects/{uuid}/cvss_scores
        response = auth_client().post(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]

        # Tests "GET" on affects/{uuid}/cvss_scores
        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid

    @pytest.mark.enable_signals
    def test_affectcvss_create_non_rh(self, auth_client, test_api_uri):
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss_data = {
            "issuer": AffectCVSS.CVSSIssuer.NIST,
            "cvss_version": AffectCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on affects/{uuid}/cvss_scores
        response = auth_client().post(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]

        # Tests "GET" on affects/{uuid}/cvss_scores
        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid
        assert response.data["issuer"] == AffectCVSS.CVSSIssuer.REDHAT

    @pytest.mark.parametrize(
        "skip_value,request_provided_value,resulting_value",
        [
            (False, "something", "something"),
            (False, "", ""),
            (False, None, ""),  # null converted to ""
            (True, None, ""),  # omitted value converted to ""
        ],
    )
    @pytest.mark.enable_signals
    def test_affectcvss_create_comment(
        self,
        auth_client,
        test_api_uri,
        skip_value,
        request_provided_value,
        resulting_value,
    ):
        """
        Test the behavior of comment in creation of AffectCVSS records via a REST API POST request.
        """
        flaw = FlawFactory()
        affect = AffectFactory(flaw=flaw)
        cvss_data = {
            "comment": request_provided_value,
            "issuer": AffectCVSS.CVSSIssuer.REDHAT,
            "cvss_version": AffectCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }
        if skip_value:
            del cvss_data["comment"]

        # Tests "POST" on affects/{uuid}/cvss_scores
        response = auth_client().post(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        cvss_uuid = response.data["uuid"]
        assert response.data["comment"] == resulting_value

        # Tests "GET" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.data["comment"] == resulting_value

    @pytest.mark.enable_signals
    def test_affectcvss_update(self, auth_client, test_api_uri):
        """
        Test the update of AffectCVSS records via a REST API PUT request.
        """
        affect = AffectFactory()
        cvss = AffectCVSSFactory(
            affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT, comment=""
        )

        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

        updated_data = response.json().copy()
        updated_data["comment"] = "text"

        # Tests "PUT" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == "text"

    @pytest.mark.enable_signals
    def test_affectcvss_update_non_rh(self, auth_client, test_api_uri):
        affect = AffectFactory()
        cvss = AffectCVSSFactory(
            affect=affect, issuer=AffectCVSS.CVSSIssuer.NIST, comment=""
        )

        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

        updated_data = response.json().copy()
        updated_data["comment"] = "text"

        # Tests "PUT" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

    @pytest.mark.enable_signals
    def test_affectcvss_update_issuer(self, auth_client, test_api_uri):
        affect = AffectFactory()
        cvss = AffectCVSSFactory(
            affect=affect,
            issuer=AffectCVSS.CVSSIssuer.REDHAT,
            comment="",
        )

        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["issuer"] == AffectCVSS.CVSSIssuer.REDHAT

        updated_data = response.json().copy()
        updated_data["issuer"] = AffectCVSS.CVSSIssuer.CVEORG

        # Tests "PUT" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["issuer"] == AffectCVSS.CVSSIssuer.REDHAT

    @pytest.mark.enable_signals
    def test_affectcvss_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of AffectCVSS records via a REST API DELETE request.
        """
        affect = AffectFactory()
        cvss = AffectCVSSFactory(affect=affect, issuer=AffectCVSS.CVSSIssuer.REDHAT)

        url = f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert AffectCVSS.objects.count() == 0

    @pytest.mark.enable_signals
    def test_affectcvss_delete_non_rh(self, auth_client, test_api_uri):
        affect = AffectFactory()
        cvss = AffectCVSSFactory(affect=affect, issuer=AffectCVSS.CVSSIssuer.CVEORG)

        url = f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert AffectCVSS.objects.count() == 1

    def test_affect_history(self, auth_client, test_api_uri):
        """ """
        flaw1 = FlawFactory()
        ps_module = PsModuleFactory()
        affect = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )

        response = auth_client().get(f"{test_api_uri}/affects?include_history=True")

        assert response.status_code == 200
        body = response.json()
        assert body["count"] == 1
        affect1 = body["results"][0]
        assert "history" in affect1
        assert len(affect1["history"]) == 1

        response = auth_client().get(
            f"{test_api_uri}/affects/{str(affect.uuid)}?include_history=True"
        )
        assert response.status_code == 200
        body = response.json()
        assert "history" in body
        assert len(body["history"]) == 1

    def test_affect_resolved_dt(
        self,
        auth_client,
        test_api_uri,
    ):
        """
        test the resolved_dt behavior on REST API
        """
        flaw = FlawFactory()
        # check unresolved creation
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_module": "rhacm-2",
            "ps_component": "curl",
            "embargoed": flaw.is_embargoed,
        }
        response = auth_client().post(
            f"{test_api_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid_unresolved = body["uuid"]

        response = auth_client().get(
            f"{test_api_uri}/affects/{created_uuid_unresolved}"
        )
        assert response.status_code == 200
        body = response.json()
        assert not body["resolved_dt"]

        # check resolved creation
        affect_data["affectedness"] = Affect.AffectAffectedness.AFFECTED
        affect_data["resolution"] = Affect.AffectResolution.WONTFIX
        affect_data["ps_component"] = "kernel"

        response = auth_client().post(
            f"{test_api_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 201
        body = response.json()
        created_uuid_resolved = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/affects/{created_uuid_resolved}")
        assert response.status_code == 200
        body = response.json()
        assert body["resolved_dt"]

        # check unresolved update
        response = auth_client().get(
            f"{test_api_uri}/affects/{created_uuid_unresolved}"
        )
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_uri}/affects/{created_uuid_unresolved}",
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
        response = auth_client().get(f"{test_api_uri}/affects/{created_uuid_resolved}")
        assert response.status_code == 200
        original_body = response.json()
        old_resolved_dt = original_body["resolved_dt"]

        response = auth_client().put(
            f"{test_api_uri}/affects/{created_uuid_resolved}",
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
            f"{test_api_uri}/affects/{created_uuid_resolved}",
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


class TestEndpointsAffectsBulk:
    """
    tests specific to bulk operations on /affects endpoint
    """

    def test_affect_update_bulk(self, auth_client, test_api_uri):
        """
        Test the bulk update of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789")
        affects = []
        for i in range(20):
            affects.append(AffectFactory(flaw=flaw))

        response = auth_client().get(
            f"{test_api_uri}/affects?flaw__cve_id=CVE-2345-6789"
        )
        assert response.status_code == 200
        original_body = response.json()
        request_affects = original_body["results"]
        orig_uuids = set()
        for aff in request_affects:
            orig_uuids.add(aff["uuid"])
            aff["affectedness"] = "AFFECTED"
            aff["resolution"] = "DELEGATED"
            aff["ps_module"] = f"different {aff['ps_module']}"

        response = auth_client().put(
            f"{test_api_uri}/affects/bulk",
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
            assert returned_aff["ps_module"].startswith("different ")
        assert len(orig_uuids) == len(new_uuids)
        assert orig_uuids == new_uuids
        assert len(body["results"]) == len(request_affects)

    def test_affect_create_bulk(self, auth_client, test_api_uri):
        """
        Test the bulk creation of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789")
        affects = []
        for i in range(20):
            affects.append(AffectFactory(flaw=flaw))

        assert Affect.objects.count() == 20

        nonbulk_response = auth_client().get(
            f"{test_api_uri}/affects?flaw__cve_id=CVE-2345-6789"
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
            tmp_aff["ps_module"] = f"psmodule{i}"
            bulk_request[i] = tmp_aff
            i += 1

        assert Affect.objects.all().delete()
        assert Affect.objects.count() == 0

        response = auth_client().post(
            f"{test_api_uri}/affects/bulk",
            bulk_request.values(),
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        assert Affect.objects.count() == 20

        for returned_aff in response.json()["results"]:
            i = int(returned_aff["ps_module"][8:])
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

    def test_affect_delete_bulk(self, auth_client, test_api_uri):
        """
        Test the bulk deletion of Affect records via a REST API PUT request.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789")
        affects = []
        for i in range(20):
            affects.append(AffectFactory(flaw=flaw))

        assert Affect.objects.count() == 20

        nonbulk_response = auth_client().get(
            f"{test_api_uri}/affects?flaw__cve_id=CVE-2345-6789"
        )
        assert nonbulk_response.status_code == 200

        bulk_request = []
        for aff in nonbulk_response.json()["results"]:
            bulk_request.append(aff["uuid"])

        response = auth_client().delete(
            f"{test_api_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        assert Affect.objects.count() == 0


class TestEndpointsAffectsUpdateTrackers:
    """
    tests of consecutive tracker update trigger
    which may result from /affects endpoint PUT calls
    """

    def test_filter(self, auth_client, test_api_uri):
        """
        test that the tracker update is triggered when expected only
        """
        flaw = FlawFactory(impact="LOW")
        ps_product1 = PsProductFactory(business_unit="Corporate")
        ps_module1 = PsModuleFactory(ps_product=ps_product1)
        affect1 = AffectFactory(
            flaw=flaw,
            impact="LOW",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module1.name,
        )
        ps_update_stream11 = PsUpdateStreamFactory(ps_module=ps_module1)
        tracker1 = TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream11.name,
            status="NEW",
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        ps_update_stream12 = PsUpdateStreamFactory(ps_module=ps_module1)
        TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            ps_update_stream=ps_update_stream12.name,
            status="CLOSED",  # already resolved
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        # one more community affect-tracker context
        ps_product2 = PsProductFactory(business_unit="Community")
        ps_module2 = PsModuleFactory(ps_product=ps_product2)
        affect2 = AffectFactory(
            flaw=flaw,
            impact="LOW",
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module2.name,
        )
        ps_update_stream2 = PsUpdateStreamFactory(ps_module=ps_module2)
        TrackerFactory(
            affects=[affect2],
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
            "ps_module": affect1.ps_module,
            "updated_dt": affect1.updated_dt,
        }
        affect2_data = {
            "embargoed": flaw.embargoed,
            "flaw": flaw.uuid,
            "impact": "MODERATE",  # tracker update trigger
            "ps_component": affect2.ps_component,
            "ps_module": affect2.ps_module,
            "updated_dt": affect2.updated_dt,
        }

        # enable autospec to get self as part of the method call args
        with patch.object(Tracker, "save", autospec=True) as mock_save:
            response = auth_client().put(
                f"{test_api_uri}/affects/{affect1.uuid}",
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
                f"{test_api_uri}/affects/{affect2.uuid}",
                affect2_data,
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
    def test_trigger(self, auth_client, test_api_uri, to_create, to_update, triggered):
        """
        test that the tracker update is triggered when expected only
        """
        flaw = FlawFactory(impact="LOW")
        ps_module = PsModuleFactory()
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
            **to_create,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
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
            "ps_module": affect.ps_module,
            "updated_dt": affect.updated_dt,
        }
        for attribute, value in to_update.items():
            affect_data[attribute] = value

        with patch.object(Tracker, "save") as mock_save:
            response = auth_client().put(
                f"{test_api_uri}/affects/{affect.uuid}",
                affect_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            assert response.status_code == status.HTTP_200_OK
            assert mock_save.called == triggered

    def test_trigger_affect_flaw_change(self, auth_client, test_api_uri):
        """
        test that the tracker update is triggered when an affect-flaw link is modified
        """
        flaw1 = FlawFactory()
        ps_module = PsModuleFactory()
        affect = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_module=ps_module.name,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
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
            "ps_module": affect.ps_module,
            "updated_dt": affect.updated_dt,
        }

        with patch.object(Tracker, "save") as mock_save:
            response = auth_client().put(
                f"{test_api_uri}/affects/{affect.uuid}",
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
    def test_affect_purl_create(self, auth_client, test_api_uri, ps_component):
        """
        Test that Affect is created when new data contains correct purl
        and its ps_component is either not provided or matches the one included in purl.
        """
        purl = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        flaw = FlawFactory(embargoed=False)
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_module": "rhacm-2",
            "ps_component": ps_component,
            "purl": purl,
            "embargoed": False,
        }

        response = auth_client().post(
            f"{test_api_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/affects/{created_uuid}")
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["ps_component"] == "curl"
        assert body["purl"] == purl

    @pytest.mark.parametrize("ps_component", ["", None, "curl"])
    def test_affect_purl_update(self, auth_client, test_api_uri, ps_component):
        """
        Test that Affect's purl and ps_component are updated when new data contains correct purl
        and its ps_component is either not provided or matches the one included in purl.
        """
        purl = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw, ps_component="podman", purl="")

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert original_body["ps_component"] == "podman"
        assert original_body["purl"] == ""

        response = auth_client().put(
            f"{test_api_uri}/affects/{affect.uuid}",
            {**original_body, "ps_component": ps_component, "purl": purl},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        created_uuid = body["uuid"]

        response = auth_client().get(f"{test_api_uri}/affects/{created_uuid}")
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["ps_component"] == "curl"
        assert body["purl"] == purl

    @pytest.mark.parametrize(
        "ps_component,purl,error",
        [
            (
                "",
                "rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "invalid purl",
            ),
            (
                "podman",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "ps_component that does not match the one included in purl",
            ),
            ("", "", "must have either purl or ps_component"),
            (None, None, "must have either purl or ps_component"),
        ],
    )
    def test_invalid_data_create(
        self, auth_client, test_api_uri, ps_component, purl, error
    ):
        """
        Test that Affect is not created when new data contains incorrect purl,
        correct purl but its ps_component does not match the one included in purl,
        or purl and ps_component are missing.
        """
        flaw = FlawFactory(embargoed=False)
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_module": "rhacm-2",
            "ps_component": ps_component,
            "purl": purl,
            "embargoed": False,
        }

        response = auth_client().post(
            f"{test_api_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert error in str(response.content)

    @pytest.mark.parametrize(
        "ps_component,purl,error",
        [
            (
                "",
                "rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "invalid purl",
            ),
            (
                "podman",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "ps_component that does not match the one included in purl",
            ),
            ("", "", "must have either purl or ps_component"),
            (None, None, "must have either purl or ps_component"),
        ],
    )
    def test_invalid_data_update(
        self, auth_client, test_api_uri, ps_component, purl, error
    ):
        """
        Test that Affect's purl and ps_component are not updated when new data contains incorrect purl,
        correct purl but its ps_component does not match the one included in purl,
        or purl and ps_component are missing.
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw, ps_component="podman", purl="")

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()

        response = auth_client().put(
            f"{test_api_uri}/affects/{affect.uuid}",
            {**original_body, "ps_component": ps_component, "purl": purl},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert error in str(response.content)
