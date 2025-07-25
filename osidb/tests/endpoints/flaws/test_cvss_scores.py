import pytest
from rest_framework import status

from apps.trackers.save import TrackerJiraSaver
from osidb.models import Affect, AffectCVSS, FlawCVSS, Impact, PsUpdateStream, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawCVSSFactory,
    FlawFactory,
    TrackerFactory,
)

pytestmark = pytest.mark.unit


class TestEndpointsFlawsCVSSScoresV2:
    """
    Test that editing a FlawCVSS record through the v2 API
    only works with the correct Issuer (REDHAT).
    """

    @pytest.mark.enable_signals
    def test_flawcvss_create(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(impact=Impact.LOW)
        cvss_data = {
            "cvss_version": FlawCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        response = auth_client().post(
            f"{test_api_v2_uri}/flaws/{str(flaw.uuid)}/cvss-scores",
            data=cvss_data,
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED
        # CVSS scores created through API should always be of type Red Hat
        assert response.data["issuer"] == FlawCVSS.CVSSIssuer.REDHAT
        assert FlawCVSS.objects.count() == 1

    @pytest.mark.enable_signals
    def test_flawcvss_rh_update(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory()
        cvss = FlawCVSSFactory(
            flaw=flaw,
            version=FlawCVSS.CVSSVersion.VERSION3,
            vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
        )

        cvss_data = {
            "cvss_version": FlawCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
            "updated_dt": cvss.updated_dt,
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/flaws/{str(flaw.uuid)}/cvss-scores/{cvss.uuid}",
            data=cvss_data,
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["vector"] == cvss_data["vector"]
        assert cvss.vector != response.data["vector"]

    @pytest.mark.enable_signals
    def test_flawcvss_non_rh_update(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory()
        cvss = FlawCVSSFactory(
            flaw=flaw,
            version=FlawCVSS.CVSSVersion.VERSION3,
            issuer=FlawCVSS.CVSSIssuer.NIST,
            vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        )

        cvss_data = {
            "cvss_version": FlawCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
            "updated_dt": cvss.updated_dt,
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/flaws/{str(flaw.uuid)}/cvss-scores/{cvss.uuid}",
            data=cvss_data,
            format="json",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Only Red Hat CVSS scores can be edited" in response.json()["issuer"]
        refreshed_cvss = FlawCVSS.objects.first()
        assert refreshed_cvss and refreshed_cvss.vector == cvss.vector

    @pytest.mark.enable_signals
    def test_flawcvss_rh_delete(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)
        cvss = FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.REDHAT)

        url = f"{test_api_v2_uri}/flaws/{str(flaw.uuid)}/cvss-scores/{cvss.uuid}"
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="foo")
        assert response.status_code == status.HTTP_200_OK
        assert FlawCVSS.objects.count() == 0

    @pytest.mark.enable_signals
    def test_flawcvss_non_rh_delete(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)
        cvss = FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.NIST)

        url = f"{test_api_v2_uri}/flaws/{str(flaw.uuid)}/cvss-scores/{cvss.uuid}"
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="foo")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Only Red Hat CVSS scores can be edited" in response.json()["issuer"]
        assert FlawCVSS.objects.count() == 1


class TestEndpointsFlawsCVSSScores:
    """
    tests specific to /flaws/.../cvss_scores endpoint
    """

    @pytest.mark.enable_signals
    def test_flawcvss_create(self, auth_client, test_api_uri):
        """
        Test the creation of FlawCVSS records via a REST API POST request.
        """
        flaw = FlawFactory(impact=Impact.LOW)
        cvss_data = {
            "issuer": FlawCVSS.CVSSIssuer.REDHAT,
            "cvss_version": FlawCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/cvss_scores
        response = auth_client().post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]

        # Tests "GET" on flaws/{uuid}/cvss_scores
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid

    @pytest.mark.enable_signals
    def test_flawcvss_update(self, auth_client, test_api_uri):
        """
        Test the update of FlawCVSS records via a REST API PUT request.
        """
        flaw = FlawFactory()
        cvss = FlawCVSSFactory(
            flaw=flaw,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION2,
            comment="",
        )

        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

        updated_data = response.json().copy()
        updated_data["comment"] = "text"

        # Tests "PUT" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == "text"

    @pytest.mark.enable_signals
    def test_flawcvss_update_issuer(self, auth_client, test_api_uri):
        flaw = FlawFactory()
        cvss = FlawCVSSFactory(
            flaw=flaw,
            issuer=FlawCVSS.CVSSIssuer.REDHAT,
            version=FlawCVSS.CVSSVersion.VERSION2,
            comment="",
        )

        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["issuer"] == FlawCVSS.CVSSIssuer.REDHAT

        updated_data = response.json().copy()
        updated_data["issuer"] = FlawCVSS.CVSSIssuer.NIST

        # Tests "PUT" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["issuer"] == FlawCVSS.CVSSIssuer.REDHAT

    @pytest.mark.enable_signals
    def test_flawcvss_delete(self, auth_client, test_api_uri):
        """
        Test the deletion of FlawCVSS records via a REST API DELETE request.
        """
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)
        cvss = FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.REDHAT)

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        assert FlawCVSS.objects.count() == 0

    @pytest.mark.enable_signals
    def test_flawcvss_non_rh_create(self, auth_client, test_api_uri):
        flaw = FlawFactory(impact=Impact.LOW)
        cvss_data = {
            "issuer": FlawCVSS.CVSSIssuer.NIST,
            "cvss_version": FlawCVSS.CVSSVersion.VERSION3,
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "embargoed": flaw.embargoed,
        }

        # Tests "POST" on flaws/{uuid}/cvss_scores
        response = auth_client().post(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores",
            data=cvss_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        cvss_uuid = response.data["uuid"]
        # Issuers set through the API POST request are ignored,
        # only REDHAT CVSS Scores can be created through it
        assert response.data["issuer"] == FlawCVSS.CVSSIssuer.REDHAT

        # Tests "GET" on flaws/{uuid}/cvss_scores
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

        # Tests "GET" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss_uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["uuid"] == cvss_uuid

    @pytest.mark.enable_signals
    def test_flawcvss_non_rh_update(self, auth_client, test_api_uri):
        flaw = FlawFactory()
        cvss = FlawCVSSFactory(
            flaw=flaw,
            issuer=FlawCVSS.CVSSIssuer.OSV,
            version=FlawCVSS.CVSSVersion.VERSION2,
            comment="",
        )

        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["comment"] == ""

        updated_data = response.json().copy()
        updated_data["comment"] = "text"

        # Tests "PUT" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        # Since the CVSS items is not issued by Red Hat, any
        # updates are a no-op
        assert response.data["comment"] == ""

    @pytest.mark.enable_signals
    def test_flawcvss_non_rh_delete(self, auth_client, test_api_uri):
        flaw = FlawFactory()
        AffectFactory(flaw=flaw)
        cvss = FlawCVSSFactory(flaw=flaw, issuer=FlawCVSS.CVSSIssuer.CVEORG)

        url = f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        response = auth_client().get(url)
        assert response.status_code == status.HTTP_200_OK

        # Tests "DELETE" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().delete(url, HTTP_BUGZILLA_API_KEY="SECRET")
        assert response.status_code == status.HTTP_200_OK
        # Same as above, should be a no-op
        assert FlawCVSS.objects.count() == 1

    @pytest.mark.enable_signals
    def test_flawcvss_update_tracker(
        self,
        monkeypatch,
        enable_jira_tracker_sync,
        setup_sample_external_resources,
        auth_client,
        test_api_uri,
    ):
        """Test that changes in FlawCVSS API triggers a sync with Jira trackers related"""
        save_performed = False

        def mock_save(self):
            nonlocal save_performed
            save_performed = True
            return self.tracker

        monkeypatch.setattr(TrackerJiraSaver, "save", mock_save)

        ps_update_stream = (
            PsUpdateStream.objects.filter(active_to_ps_module__bts_name="jboss")
            .order_by("name")
            .first()
        )
        ps_component = setup_sample_external_resources["jboss_components"][0]

        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.NEW,
            ps_update_stream=ps_update_stream.name,
            ps_component=ps_component,
        )
        TrackerFactory(
            affects=[affect],
            type=Tracker.TrackerType.JIRA,
            ps_update_stream=ps_update_stream.name,
        )
        cvss = FlawCVSSFactory(
            flaw=flaw,
            issuer=AffectCVSS.CVSSIssuer.REDHAT,
            comment="",
            vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            version=AffectCVSS.CVSSVersion.VERSION3,
        )

        response = auth_client().get(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}"
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["issuer"] == AffectCVSS.CVSSIssuer.REDHAT
        assert response.data["score"] == 8.1

        updated_data = response.json().copy()
        updated_data["vector"] = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"

        # Tests "PUT" on flaws/{uuid}/cvss_scores/{uuid}
        response = auth_client().put(
            f"{test_api_uri}/flaws/{str(flaw.uuid)}/cvss_scores/{cvss.uuid}",
            data=updated_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data["issuer"] == AffectCVSS.CVSSIssuer.REDHAT
        assert response.data["score"] == 7.8
        assert save_performed
