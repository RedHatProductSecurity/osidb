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
    def test_affectcvss_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of AffectCVSS records via a REST API DELETE request.
        """
        affect = AffectFactory()
        cvss = AffectCVSSFactory(affect=affect)

        url = f"{test_api_uri}/affects/{str(affect.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on affects/{uuid}/cvss_scores/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert AffectCVSS.objects.count() == 0


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
        tracker1 = TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
            status="NEW",
            type=Tracker.BTS2TYPE[ps_module1.bts_name],
        )
        TrackerFactory(
            affects=[affect1],
            embargoed=flaw.embargoed,
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
        TrackerFactory(
            affects=[affect2],
            embargoed=flaw.embargoed,
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
            (
                {"cvss3": "3.7/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"},
                {"cvss3": "2.2/CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N"},
                False,
            ),
            ({"impact": "IMPORTANT"}, {"impact": "LOW"}, False),
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
        TrackerFactory(
            affects=[affect],
            embargoed=flaw.embargoed,
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
        TrackerFactory(
            affects=[affect],
            embargoed=flaw1.embargoed,
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
