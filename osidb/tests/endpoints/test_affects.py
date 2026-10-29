import logging
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.db.models.query import QuerySet
from django.utils import timezone
from rest_framework import status

from osidb.acls import ACL
from osidb.core import set_user_acls
from osidb.mixins import Alert
from osidb.models import Affect, AffectCVSS, Flaw, Tracker
from osidb.models.ps_constants import UbiPackage
from osidb.tests.factories import (
    AffectCVSSFactory,
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsProductFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
    default_rpm_purl_for_ps_component,
)

pytestmark = pytest.mark.unit


def _community_ps_for_affect():
    """Product stream where affects may omit a PURL (community)."""
    ps_product = PsProductFactory(business_unit="Community")
    ps_module = PsModuleFactory(ps_product=ps_product)
    ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
    return {
        "ps_update_stream": ps_update_stream.name,
        "ps_module": ps_module.name,
    }


def _affect_purl_for_api(affect):
    if affect.purl:
        return str(affect.purl)
    if affect.ps_component:
        return default_rpm_purl_for_ps_component(affect.ps_component)
    return None


class TestEndpointsAffectsV1:
    """
    tests specific to v1/affects endpoint
    """

    @pytest.mark.enable_signals
    def test_get_affect_with_cvss(
        self, auth_client, test_api_uri, refresh_v1_view, transactional_db
    ):
        """retrieve specific affect with affectcvss from endpoint"""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw)
        refresh_v1_view()

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["cvss_scores"]) == 0

        AffectCVSSFactory(affect=affect)
        refresh_v1_view()

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
        refresh_v1_view,
        transactional_db,
    ):
        """
        test that tracker__isempty filter is working correctly
        """
        flaw = FlawFactory(embargoed=False)

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

        refresh_v1_view()

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
    def test_get_affect_with_cve_id(
        self, auth_client, test_api_uri, refresh_v1_view, transactional_db
    ):
        """append cve_id from parent flaw to the Affect serializer"""
        flaw = FlawFactory(cve_id="CVE-2025-1234", embargoed=False)
        affect = AffectFactory(flaw=flaw)

        refresh_v1_view()

        response = auth_client().get(f"{test_api_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert response.data["cve_id"] == flaw.cve_id

    @pytest.mark.enable_signals
    def test_filter_affect_by_cve_id(
        self, auth_client, test_api_uri, refresh_v1_view, transactional_db
    ):
        flaw = FlawFactory(cve_id="CVE-2025-1234", embargoed=False)
        AffectFactory(flaw=flaw)

        refresh_v1_view()

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
        ps_update_stream = PsUpdateStreamFactory(name="rhacm-2.11.z")
        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": "rhacm-2.11.z",
            "ps_component": "curl",
            "purl": default_rpm_purl_for_ps_component("curl"),
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
            assert body["ps_module"] == ps_update_stream.ps_module.name

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
        assert original_body["ps_module"] != body["ps_module"]

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
            "purl": default_rpm_purl_for_ps_component("curl"),
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
        affect_data["purl"] = default_rpm_purl_for_ps_component("kernel")

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


class TestAffectUbiLabel:
    """tests for the ubi label on affect denormalized labels"""

    @pytest.mark.enable_signals
    def test_ubi_label_present(self):
        UbiPackage.objects.create(name="ubi-component", ps_module="rhel-8")
        ps_module = PsModuleFactory(name="rhel-8")
        # Create Z-stream
        PsUpdateStreamFactory(
            name="rhel-8.10.z",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
        )
        # Create Y-stream (future, newer than Z)
        ps_update_stream = PsUpdateStreamFactory(
            name="rhel-8.11",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
        )
        affect = AffectFactory(
            ps_update_stream=ps_update_stream.name,
            ps_component="ubi-component",
        )
        assert "ubi" in affect.labels

    @pytest.mark.enable_signals
    def test_ubi_label_absent(self):
        ps_module = PsModuleFactory(name="rhel-8")
        # Create Z-stream
        PsUpdateStreamFactory(
            name="rhel-8.10.z",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
        )
        # Create Y-stream
        ps_update_stream = PsUpdateStreamFactory(
            name="rhel-8.11",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
        )
        affect = AffectFactory(
            ps_update_stream=ps_update_stream.name,
            ps_component="not-ubi",
        )
        assert "ubi" not in affect.labels

    @pytest.mark.enable_signals
    def test_ubi_label_wrong_ps_module(self):
        UbiPackage.objects.create(name="ubi-component", ps_module="rhel-8")
        ps_module = PsModuleFactory(name="rhel-9")
        # Create Z-stream
        PsUpdateStreamFactory(
            name="rhel-9.10.z",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
        )
        # Create Y-stream
        ps_update_stream = PsUpdateStreamFactory(
            name="rhel-9.11",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
        )
        affect = AffectFactory(
            ps_update_stream=ps_update_stream.name,
            ps_component="ubi-component",
        )
        assert "ubi" not in affect.labels


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

    def test_affect_update_bulk_partial_success(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(embargoed=False)
        first = AffectFactory(flaw=flaw)
        second = AffectFactory(flaw=flaw)
        client = auth_client()
        valid = client.get(f"{test_api_v2_uri}/affects/{first.uuid}").json()
        invalid = client.get(f"{test_api_v2_uri}/affects/{second.uuid}").json()
        valid["affectedness"] = "AFFECTED"
        valid["resolution"] = "DELEGATED"
        invalid["affectedness"] = "INVALID_VALUE"

        response = client.put(
            f"{test_api_v2_uri}/affects/bulk",
            [{"uuid": "not-a-uuid"}, invalid, valid, valid],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        assert [entry["index"] for entry in response.data["failed"]] == [0, 1, 3]
        assert len(response.data["results"]) == 1
        first.refresh_from_db()
        second.refresh_from_db()
        assert first.affectedness == "AFFECTED"
        assert first.updated_by == response.data["results"][0]["updated_by"]
        assert first.updated_by
        assert second.affectedness != "INVALID_VALUE"

    @pytest.mark.django_db(transaction=True)
    def test_affect_update_bulk_failed_validation_does_not_leave_alert(
        self, auth_client, test_api_v2_uri
    ):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()

        def fail_after_alert(instance, **kwargs):
            instance.alert(name="bulk-validation-warning", description="temporary")
            raise ValidationError("Validation failed")

        with patch.object(
            Affect, "validate", autospec=True, side_effect=fail_after_alert
        ):
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                [data],
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )

        assert response.status_code == 400
        assert response.data["failed"][0]["index"] == 0
        assert not Alert.objects.filter(
            object_id=affect.uuid, name="bulk-validation-warning"
        ).exists()

    @pytest.mark.parametrize("bad_stream", [["invalid"], {"name": "invalid"}])
    def test_affect_update_bulk_invalid_stream_type(
        self, auth_client, test_api_v2_uri, bad_stream
    ):
        flaw = FlawFactory(embargoed=False)
        bad = AffectFactory(flaw=flaw)
        good = AffectFactory(flaw=flaw)
        client = auth_client()
        invalid = client.get(f"{test_api_v2_uri}/affects/{bad.uuid}").json()
        valid = client.get(f"{test_api_v2_uri}/affects/{good.uuid}").json()
        invalid["ps_update_stream"] = bad_stream

        response = client.put(
            f"{test_api_v2_uri}/affects/bulk",
            [invalid, valid],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        assert len(response.data["results"]) == 1
        assert response.data["failed"][0]["index"] == 0
        assert "ps_update_stream" in response.data["failed"][0]["errors"]

    def test_affect_update_bulk_purl_derived_duplicate(
        self, auth_client, test_api_v2_uri
    ):
        flaw = FlawFactory(embargoed=False)
        stream = _community_ps_for_affect()
        existing = AffectFactory(flaw=flaw, ps_component="curl", purl="", **stream)
        candidate = AffectFactory(
            flaw=flaw, ps_component="old-component", purl="", **stream
        )
        other = AffectFactory(flaw=flaw, ps_component="unrelated", purl="", **stream)
        client = auth_client()
        invalid = client.get(f"{test_api_v2_uri}/affects/{candidate.uuid}").json()
        valid = client.get(f"{test_api_v2_uri}/affects/{other.uuid}").json()
        invalid.pop("ps_component")
        invalid["purl"] = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        valid["ps_component"] = "updated-unrelated"

        with patch.object(
            Affect, "validate", autospec=True, side_effect=Affect.validate
        ) as validate:
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                [invalid, valid],
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        assert not any(
            call.args[0].uuid == candidate.uuid for call in validate.call_args_list
        )
        assert response.status_code == 200
        assert [entry["index"] for entry in response.data["failed"]] == [0]
        assert len(response.data["results"]) == 1
        candidate.refresh_from_db()
        other.refresh_from_db()
        assert candidate.ps_component == "old-component"
        assert other.ps_component == "updated-unrelated"
        assert Affect.objects.filter(uuid=existing.uuid).exists()

    def test_affect_update_bulk_unembargo(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(embargoed=True)
        affect = AffectFactory(flaw=flaw, embargoed=True)
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()
        data["embargoed"] = False
        # A parent becoming public is the condition under which its affect may be unembargoed.
        Flaw.objects.filter(uuid=flaw.uuid).update(
            acl_read=ACL.PUBLIC.uuid_read,
            acl_write=ACL.PUBLIC.uuid_write,
            unembargo_dt=timezone.now() - timedelta(seconds=1),
            auto_timestamps=False,
        )

        response = client.put(
            f"{test_api_v2_uri}/affects/bulk",
            [data],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200, response.data
        affect.refresh_from_db()
        assert affect.acl_read == ACL.PUBLIC.uuid_read
        assert affect.acl_write == ACL.PUBLIC.uuid_write

    def test_affect_update_bulk_preserves_unrelated_acl_change(
        self, auth_client, test_api_v2_uri
    ):
        affect = AffectFactory(
            flaw=FlawFactory(embargoed=False), affectedness="NEW", resolution=""
        )
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()
        data.update(affectedness="AFFECTED", resolution="DELEGATED")
        changed_acl_write = [*affect.acl_write, ACL.INTERNAL.uuid_write[0]]
        bulk_update = QuerySet.bulk_update

        def change_acl_before_write(queryset, objs, fields, batch_size=None):
            Affect.objects.filter(uuid=affect.uuid).update(
                acl_write=changed_acl_write, auto_timestamps=False
            )
            return bulk_update(queryset, objs, fields, batch_size=batch_size)

        with patch(
            "django.db.models.query.QuerySet.bulk_update",
            autospec=True,
            side_effect=change_acl_before_write,
        ):
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                [data],
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        assert response.status_code == 200, response.data
        affect.refresh_from_db()
        assert affect.acl_write == changed_acl_write
        assert affect.affectedness == "AFFECTED"

    def test_affect_update_bulk_tracker_sync_failure(
        self, auth_client, test_api_v2_uri
    ):
        affect = AffectFactory(flaw=FlawFactory(embargoed=False))
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()
        data["resolution"] = "DELEGATED"
        data["affectedness"] = "AFFECTED"

        with (
            patch(
                "osidb.api_views.AffectSerializer.update_tracker",
                side_effect=ValidationError(
                    "Jira connection failed: private-marker-123"
                ),
            ) as sync,
            patch.object(logging.getLogger("osidb.api_views"), "warning") as warning,
        ):
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                [data],
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        sync.assert_called_once()
        warning.assert_called_once_with(
            "Tracker sync failed for affect %s", affect.uuid
        )
        assert response.status_code == 200
        assert len(response.data["results"]) == 1
        failed = response.data["failed"][0]
        assert failed["update_applied"] is True
        assert "Tracker sync failed" in failed["errors"]["tracker"][0]
        for field in ("uuid", "ps_update_stream", "ps_component", "purl", "ps_module"):
            assert field in failed["input"]
        affect.refresh_from_db()
        assert affect.resolution == "DELEGATED"

    def test_affect_update_bulk_filtered_readback(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw, **_community_ps_for_affect())
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()
        original_component = data["ps_component"]
        data["ps_component"] = "changed-component"
        data["purl"] = ""

        response = client.put(
            f"{test_api_v2_uri}/affects/bulk?ps_component={original_component}",
            [data],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        assert response.data["results"][0]["ps_component"] == "changed-component"

    @pytest.mark.django_db(transaction=True)
    def test_affect_update_bulk_rolls_back_on_flaw_save_failure(
        self, auth_client, test_api_v2_uri
    ):
        affect = AffectFactory(
            flaw=FlawFactory(embargoed=False), affectedness="NEW", resolution=""
        )
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()
        data.update(affectedness="AFFECTED", resolution="DELEGATED")

        with patch(
            "osidb.api_views.Flaw.save", side_effect=ValidationError("Flaw save failed")
        ) as save:
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                [data],
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        save.assert_called_once()
        assert response.status_code == 400
        affect.refresh_from_db()
        assert affect.affectedness == "NEW"
        assert affect.resolution == ""

    @pytest.mark.django_db(transaction=True)
    def test_affect_update_bulk_write_conflict(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(embargoed=False)
        affects = [AffectFactory(flaw=flaw) for _ in range(2)]
        original_states = [a.affectedness for a in affects]
        client = auth_client()
        data = [
            client.get(f"{test_api_v2_uri}/affects/{a.uuid}").json() for a in affects
        ]
        for entry in data:
            entry["affectedness"] = "AFFECTED"
            entry["resolution"] = "DELEGATED"

        with patch(
            "django.db.models.query.QuerySet.bulk_update",
            side_effect=IntegrityError("simulated concurrent conflict"),
        ) as bulk_update:
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        bulk_update.assert_called_once()
        assert response.status_code == 400
        for affect, original in zip(affects, original_states):
            affect.refresh_from_db()
            assert affect.affectedness == original

    def test_affect_update_bulk_change_during_write(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(embargoed=False)
        affects = [
            AffectFactory(flaw=flaw, affectedness="NEW", resolution="")
            for _ in range(2)
        ]
        client = auth_client()
        data = [
            client.get(f"{test_api_v2_uri}/affects/{a.uuid}").json() for a in affects
        ]
        for entry in data:
            entry.update(affectedness="AFFECTED", resolution="DELEGATED")

        bulk_update = QuerySet.bulk_update

        def race(queryset, objs, fields, batch_size=None):
            Affect.objects.filter(uuid=affects[0].uuid).update(
                updated_dt=affects[0].updated_dt + timedelta(seconds=30)
            )
            return bulk_update(queryset, objs, fields, batch_size=batch_size)

        with patch(
            "django.db.models.query.QuerySet.bulk_update",
            autospec=True,
            side_effect=race,
        ):
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
        assert response.status_code == 400
        assert "updated_dt" in response.data
        for affect in affects:
            affect.refresh_from_db()
            assert affect.affectedness == "NEW"

    def test_affect_update_bulk_ignores_flaw_change(self, auth_client, test_api_v2_uri):
        source = FlawFactory(embargoed=False)
        target = FlawFactory(embargoed=False, impact="CRITICAL")
        affect = AffectFactory(flaw=source)
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()
        data["flaw"] = str(target.uuid)

        with patch(
            "osidb.api_views.ProductFamilyLabel.update_relevance"
        ) as update_relevance:
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                [data],
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )

        assert response.status_code == 200, response.data["failed"][0]["errors"]
        affect.refresh_from_db()
        assert affect.flaw_id == source.uuid
        update_relevance.assert_called_once()
        assert update_relevance.call_args.args[0].uuid == source.uuid

    def test_affect_update_bulk_resolved_dates(self, auth_client, test_api_v2_uri):
        flaw = FlawFactory(embargoed=False)
        unresolved = AffectFactory(flaw=flaw, affectedness="NEW", resolution="")
        resolved = AffectFactory(
            flaw=flaw, affectedness="AFFECTED", resolution="WONTFIX"
        )
        client = auth_client()
        first = client.get(f"{test_api_v2_uri}/affects/{unresolved.uuid}").json()
        second = client.get(f"{test_api_v2_uri}/affects/{resolved.uuid}").json()
        assert second["resolved_dt"]
        first.update(affectedness="AFFECTED", resolution="WONTFIX")
        second.update(affectedness="NEW", resolution="")

        response = client.put(
            f"{test_api_v2_uri}/affects/bulk",
            [first, second],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        assert response.data["failed"] == []
        unresolved.refresh_from_db()
        resolved.refresh_from_db()
        assert unresolved.resolved_dt is not None
        assert resolved.resolved_dt is None

    def test_affect_update_bulk_same_second_advances_timestamp(
        self, auth_client, test_api_v2_uri
    ):
        affect = AffectFactory(
            flaw=FlawFactory(embargoed=False), affectedness="NEW", resolution=""
        )
        Affect.objects.filter(uuid=affect.uuid).update(
            updated_dt=timezone.now().replace(microsecond=0), auto_timestamps=False
        )
        affect.refresh_from_db()
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()
        old_updated_dt = affect.updated_dt
        data.update(affectedness="AFFECTED", resolution="DELEGATED")

        with patch(
            "osidb.api_views.timezone.now",
            return_value=old_updated_dt + timedelta(microseconds=999999),
        ):
            response = client.put(
                f"{test_api_v2_uri}/affects/bulk",
                [data],
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )

        assert response.status_code == 200, response.data
        affect.refresh_from_db()
        assert affect.updated_dt == old_updated_dt + timedelta(seconds=1)

        response = client.put(
            f"{test_api_v2_uri}/affects/bulk",
            [data],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 400
        assert "updated_dt" in response.data["failed"][0]["errors"]

    def test_affect_update_bulk_stale_timestamp(self, auth_client, test_api_v2_uri):
        affect = AffectFactory(
            flaw=FlawFactory(embargoed=False), affectedness="NEW", resolution=""
        )
        client = auth_client()
        data = client.get(f"{test_api_v2_uri}/affects/{affect.uuid}").json()
        Affect.objects.filter(uuid=affect.uuid).update(
            updated_dt=affect.updated_dt + timedelta(seconds=30)
        )
        data["affectedness"] = "AFFECTED"
        data["resolution"] = "DELEGATED"

        response = client.put(
            f"{test_api_v2_uri}/affects/bulk",
            [data],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 400
        assert "updated_dt" in response.data["failed"][0]["errors"]
        affect.refresh_from_db()
        assert affect.affectedness != "AFFECTED"

    def test_affect_update_bulk_all_invalid(self, auth_client, test_api_v2_uri):
        response = auth_client().put(
            f"{test_api_v2_uri}/affects/bulk",
            [{"uuid": "not-a-uuid"}],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 400
        assert response.data["results"] == []
        assert response.data["failed"][0]["index"] == 0

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
            # creator fields are set from the authenticated user on bulk_post
            # and differ from factory-created affects which have these empty
            del received_aff["created_by"]
            del received_aff["updated_by"]
            del requested_aff["created_by"]
            del requested_aff["updated_by"]
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

    def test_affect_update_bulk_empty_list(
        self, auth_client, test_api_v2_uri, bugzilla_token, jira_token
    ):
        bulk_request = []
        response = auth_client().put(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["affect"] == ["At least one affect is required."]

    def test_affect_create_bulk_empty_list(
        self, auth_client, test_api_v2_uri, bugzilla_token
    ):
        bulk_request = []
        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["affect"] == ["At least one affect is required."]

    def test_affect_delete_bulk_empty_list(
        self, auth_client, test_api_v2_uri, bugzilla_token
    ):
        bulk_request = []
        response = auth_client().delete(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["affect"] == ["At least one affect is required."]

    def test_affect_update_bulk_non_list_payload(
        self, auth_client, test_api_v2_uri, bugzilla_token, jira_token
    ):
        response = auth_client().put(
            f"{test_api_v2_uri}/affects/bulk",
            {"uuid": "something"},
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["affect"] == ["Expected a list of affects."]

    def test_affect_create_bulk_non_list_payload(
        self, auth_client, test_api_v2_uri, bugzilla_token
    ):
        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            {"flaw": "something"},
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["affect"] == ["Expected a list of affects."]

    def test_affect_delete_bulk_non_list_payload(
        self, auth_client, test_api_v2_uri, bugzilla_token
    ):
        response = auth_client().delete(
            f"{test_api_v2_uri}/affects/bulk",
            {"uuid": "something"},
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["affect"] == ["Expected a list of affects."]

    def test_affect_update_bulk_malformed_entries(
        self, auth_client, test_api_v2_uri, bugzilla_token, jira_token
    ):
        response = auth_client().put(
            f"{test_api_v2_uri}/affects/bulk",
            ["not-a-dict"],
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
            HTTP_JIRA_API_KEY=jira_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["affect"] == ["Expected a dict."]

    def test_affect_create_bulk_malformed_entries(
        self, auth_client, test_api_v2_uri, bugzilla_token
    ):
        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            ["not-a-dict"],
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["affect"] == ["Expected a dict."]

    def test_affect_delete_bulk_malformed_entries(
        self, auth_client, test_api_v2_uri, bugzilla_token
    ):
        response = auth_client().delete(
            f"{test_api_v2_uri}/affects/bulk",
            [{}],
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["uuid"] == ["Expected a UUID string."]

    def test_affect_delete_bulk_invalid_uuid_format(
        self, auth_client, test_api_v2_uri, bugzilla_token
    ):
        response = auth_client().delete(
            f"{test_api_v2_uri}/affects/bulk",
            ["not-a-uuid"],
            format="json",
            HTTP_BUGZILLA_API_KEY=bugzilla_token,
        )

        assert response.status_code == 400
        body = response.json()
        assert body["uuid"] == ["Affect matching query does not exist."]

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
                "purl": default_rpm_purl_for_ps_component("component-foo"),
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

    @pytest.mark.enable_signals
    def test_affect_create_bulk_partial_success(self, auth_client, test_api_v2_uri):
        """
        Test that valid affects are created even when some entries are invalid.
        Invalid entries should be reported in the failed list.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789", embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "valid-component",
                "purl": default_rpm_purl_for_ps_component("valid-component"),
                "embargoed": False,
            },
            {
                "flaw": str(flaw.uuid),
                "affectedness": "INVALID_VALUE",
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "another-component",
                "embargoed": False,
            },
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        body = response.json()
        assert len(body["results"]) == 1
        assert body["results"][0]["ps_component"] == "valid-component"
        assert len(body["failed"]) == 1
        assert body["failed"][0]["index"] == 1

    @pytest.mark.enable_signals
    def test_affect_create_bulk_all_invalid(self, auth_client, test_api_v2_uri):
        """
        Test that when all entries are invalid, none are created and all are
        reported in the failed list.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789", embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": "INVALID_VALUE",
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "component-a",
                "embargoed": False,
            },
            {
                "flaw": str(flaw.uuid),
                "affectedness": "ALSO_INVALID",
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "component-b",
                "embargoed": False,
            },
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        assert response.status_code == 400
        body = response.json()
        assert len(body["results"]) == 0
        assert len(body["failed"]) == 2
        assert Affect.objects.count() == 0

    @pytest.mark.enable_signals
    def test_affect_create_bulk_missing_flaw_rejected(
        self, auth_client, test_api_v2_uri
    ):
        """
        Test that the entire request is rejected when any entry is missing
        the flaw field.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789", embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "valid-component",
                "embargoed": False,
            },
            {
                "affectedness": Affect.AffectAffectedness.NEW,
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "another-component",
                "embargoed": False,
            },
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        assert response.status_code == 400
        assert Affect.objects.count() == 0

    @pytest.mark.enable_signals
    def test_affect_create_bulk_preexisting_duplicate(
        self, auth_client, test_api_v2_uri
    ):
        """
        Test that a batch entry conflicting with a pre-existing DB row is
        caught during validation and reported in errors, while the valid
        entry is still created.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789", embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()

        AffectFactory(
            flaw=flaw,
            ps_update_stream=ps_update_stream.name,
            ps_component="existing-component",
        )
        assert Affect.objects.count() == 1

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "new-component",
                "purl": default_rpm_purl_for_ps_component("new-component"),
                "embargoed": False,
            },
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "existing-component",
                "purl": default_rpm_purl_for_ps_component("existing-component"),
                "embargoed": False,
            },
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        body = response.json()
        assert len(body["results"]) == 1
        assert body["results"][0]["ps_component"] == "new-component"
        assert len(body["failed"]) == 1
        assert body["failed"][0]["index"] == 1
        assert Affect.objects.count() == 2

    @pytest.mark.enable_signals
    def test_affect_create_bulk_intra_batch_duplicate(
        self, auth_client, test_api_v2_uri
    ):
        """
        Test that intra-batch duplicates (same flaw/stream/component within the
        same request) are detected: one is created, the other reported as error.
        """
        flaw = FlawFactory(cve_id="CVE-2345-6789", embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "same-component",
                "purl": default_rpm_purl_for_ps_component("same-component"),
                "embargoed": False,
            },
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "ps_component": "same-component",
                "purl": default_rpm_purl_for_ps_component("same-component"),
                "embargoed": False,
            },
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        body = response.json()
        assert len(body["results"]) == 1
        assert len(body["failed"]) == 1
        assert body["failed"][0]["index"] == 1
        assert Affect.objects.count() == 1

    @pytest.mark.enable_signals
    def test_affect_create_bulk_returns_errors_key(self, auth_client, test_api_v2_uri):
        """
        Test that the bulk create response always includes a failed key.
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
                "purl": default_rpm_purl_for_ps_component("component-foo"),
                "embargoed": False,
            }
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )

        assert response.status_code == 200
        body = response.json()
        assert "results" in body
        assert "failed" in body
        assert len(body["failed"]) == 0
        assert len(body["results"]) == 1

    def test_bulk_post_purl_only(self, auth_client, test_api_v2_uri):
        """
        Bulk POST with purl provided and ps_component key omitted should
        succeed; ps_component is derived from purl.
        """
        purl = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        flaw = FlawFactory(embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "purl": purl,
                "embargoed": False,
            }
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        result = response.json()["results"][0]
        assert result["ps_component"] == "curl"
        assert result["purl"] == purl

    def test_bulk_post_ps_component_only(self, auth_client, test_api_v2_uri):
        """
        Bulk POST with ps_component provided and purl key omitted should
        succeed for community streams (PURL not required there).
        """
        flaw = FlawFactory(embargoed=False)
        comm = _community_ps_for_affect()

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": comm["ps_update_stream"],
                "ps_component": "my-component",
                "embargoed": False,
            }
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        result = response.json()["results"][0]
        assert result["ps_component"] == "my-component"

    def test_bulk_put_purl_only(self, auth_client, test_api_v2_uri):
        """
        Bulk PUT with purl provided and ps_component key omitted should
        succeed; ps_component is derived from purl.
        """
        purl = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_component="old-component",
            purl="",
            **_community_ps_for_affect(),
        )

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original = response.json()

        update_data = {
            "uuid": str(affect.uuid),
            "flaw": str(flaw.uuid),
            "affectedness": original["affectedness"],
            "resolution": original["resolution"],
            "ps_update_stream": original["ps_update_stream"],
            "purl": purl,
            "embargoed": original["embargoed"],
            "updated_dt": original["updated_dt"],
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/bulk",
            [update_data],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == 200
        result = response.json()["results"][0]
        assert result["ps_component"] == "curl"
        assert result["purl"] == purl

    @pytest.mark.parametrize("ps_component_value", ["explicit_null", "omitted"])
    def test_create_purl_only(self, auth_client, test_api_v2_uri, ps_component_value):
        """
        Non-bulk POST with purl provided and ps_component either null or
        entirely absent should succeed; ps_component is derived from purl.
        """
        purl = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        flaw = FlawFactory(embargoed=False)
        PsUpdateStreamFactory(name="test-stream-1.0.z")

        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": "test-stream-1.0.z",
            "purl": purl,
            "embargoed": False,
        }
        if ps_component_value == "explicit_null":
            affect_data["ps_component"] = None

        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        body = response.json()
        assert body["ps_component"] == "curl"
        assert body["purl"] == purl

    @pytest.mark.parametrize("purl_value", ["explicit_null", "omitted"])
    def test_create_ps_component_only(self, auth_client, test_api_v2_uri, purl_value):
        """
        Non-bulk POST with ps_component provided and purl either null or
        entirely absent should succeed for community streams.
        """
        flaw = FlawFactory(embargoed=False)
        comm = _community_ps_for_affect()

        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": comm["ps_update_stream"],
            "ps_component": "my-component",
            "embargoed": False,
        }
        if purl_value == "explicit_null":
            affect_data["purl"] = None

        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        body = response.json()
        assert body["ps_component"] == "my-component"

    @pytest.mark.parametrize("ps_component_value", ["explicit_null", "omitted"])
    def test_update_purl_only(self, auth_client, test_api_v2_uri, ps_component_value):
        """
        Non-bulk PUT with purl provided and ps_component either null or
        entirely absent should succeed; ps_component is derived from purl.
        """
        purl = "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25"
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_component="old-component",
            purl="",
            **_community_ps_for_affect(),
        )

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original = response.json()

        update_data = {**original, "purl": purl}
        if ps_component_value == "explicit_null":
            update_data["ps_component"] = None
        else:
            update_data.pop("ps_component", None)

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            update_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.json()
        assert body["ps_component"] == "curl"
        assert body["purl"] == purl

    def test_bulk_post_neither_purl_nor_ps_component(
        self, auth_client, test_api_v2_uri
    ):
        """
        Bulk POST with both purl and ps_component omitted should report
        the entry in the failed list.
        """
        flaw = FlawFactory(embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()

        bulk_request = [
            {
                "flaw": str(flaw.uuid),
                "affectedness": Affect.AffectAffectedness.NEW,
                "resolution": Affect.AffectResolution.NOVALUE,
                "ps_update_stream": ps_update_stream.name,
                "embargoed": False,
            }
        ]

        response = auth_client().post(
            f"{test_api_v2_uri}/affects/bulk",
            bulk_request,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == 400
        body = response.json()
        assert len(body["results"]) == 0
        assert len(body["failed"]) == 1
        assert "must have either purl or ps_component" in str(body["failed"])

    def test_bulk_put_neither_purl_nor_ps_component(self, auth_client, test_api_v2_uri):
        """
        Bulk PUT clearing both purl and ps_component should fail
        with a validation error.
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_component="old-component",
            purl="",
            **_community_ps_for_affect(),
        )

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original = response.json()

        update_data = {
            "uuid": str(affect.uuid),
            "flaw": str(flaw.uuid),
            "affectedness": original["affectedness"],
            "resolution": original["resolution"],
            "ps_update_stream": original["ps_update_stream"],
            "embargoed": original["embargoed"],
            "updated_dt": original["updated_dt"],
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/bulk",
            [update_data],
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["failed"]
        assert "must have either purl or ps_component" in str(response.data["failed"])

    def test_create_neither_purl_nor_ps_component(self, auth_client, test_api_v2_uri):
        """
        Non-bulk POST with both purl and ps_component omitted should fail
        with a validation error.
        """
        flaw = FlawFactory(embargoed=False)
        PsUpdateStreamFactory(name="test-stream-3.0.z")

        affect_data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": "test-stream-3.0.z",
            "embargoed": False,
        }

        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "must have either purl or ps_component" in str(response.content)

    def test_update_neither_purl_nor_ps_component(self, auth_client, test_api_v2_uri):
        """
        Non-bulk PUT clearing both purl and ps_component should fail
        with a validation error.
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_component="old-component",
            purl="",
            **_community_ps_for_affect(),
        )

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original = response.json()

        update_data = {**original}
        update_data.pop("ps_component", None)
        update_data.pop("purl", None)

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            update_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "must have either purl or ps_component" in str(response.content)

    def test_bulk_put_external_error_includes_context(
        self, auth_client, test_api_v2_uri
    ):
        """bulk PUT external errors should include affect context fields"""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_component="test-component",
            purl="",
            **_community_ps_for_affect(),
        )

        update_data = {
            "uuid": str(affect.uuid),
            "flaw": str(flaw.uuid),
            "affectedness": affect.affectedness,
            "resolution": affect.resolution,
            "ps_update_stream": affect.ps_update_stream,
            "embargoed": affect.is_embargoed,
            "updated_dt": affect.updated_dt,
            "ps_component": affect.ps_component,
        }

        with patch(
            "osidb.api_views._prepare_affect_update_for_bulk",
            side_effect=ValidationError("Jira connection failed"),
        ) as prepare_mock:
            response = auth_client().put(
                f"{test_api_v2_uri}/affects/bulk",
                [update_data],
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )

        prepare_mock.assert_called_once()
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data["failed"]
        failed = response.data["failed"][0]
        assert "Jira connection failed" in str(failed["errors"])
        assert "ps_update_stream" in failed["input"]
        assert "ps_component" in failed["input"]
        assert "purl" in failed["input"]
        assert "ps_module" in failed["input"]


class TestEndpointsAffectsUpdateTrackers:
    """
    tests of consecutive tracker update trigger
    which may result from /affects endpoint PUT calls
    """

    def test_filter(self, auth_client, test_api_v2_uri):
        """
        test that the tracker update is triggered when expected only
        """
        flaw = FlawFactory(impact="MODERATE")
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
            "purl": _affect_purl_for_api(affect1),
            "updated_dt": affect1.updated_dt,
        }
        affect2_data = {
            "embargoed": flaw.embargoed,
            "flaw": flaw.uuid,
            "impact": "MODERATE",  # tracker update trigger
            "ps_component": affect2.ps_component,
            "ps_update_stream": affect2.ps_update_stream,
            "purl": _affect_purl_for_api(affect2),
            "updated_dt": affect2.updated_dt,
        }
        affect3_data = {
            "embargoed": flaw.embargoed,
            "flaw": flaw.uuid,
            "impact": "MODERATE",  # tracker update trigger
            "ps_component": affect3.ps_component,
            "ps_update_stream": affect3.ps_update_stream,
            "purl": _affect_purl_for_api(affect3),
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
        flaw = FlawFactory(impact="IMPORTANT")
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
            "purl": _affect_purl_for_api(affect),
            "updated_dt": affect.updated_dt,
        }
        for attribute, value in to_update.items():
            affect_data[attribute] = value
        if "ps_component" in to_update:
            affect_data["purl"] = default_rpm_purl_for_ps_component(
                to_update["ps_component"]
            )

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

    def test_ignore_affect_flaw_change(self, auth_client, test_api_v2_uri):
        """
        test that an attempt to re-link an affect to a different flaw is ignored

        an affect is permanently bound to its flaw, so a differing flaw in the
        request body is silently dropped and the affect stays linked to its
        original flaw
        """
        flaw1 = FlawFactory(impact="MODERATE")
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

        flaw2 = FlawFactory(embargoed=flaw1.embargoed, impact="MODERATE")
        affect_data = {
            "embargoed": flaw2.embargoed,
            "flaw": flaw2.uuid,  # attempt to re-link the affect
            "ps_component": affect.ps_component,
            "ps_update_stream": affect.ps_update_stream,
            "purl": _affect_purl_for_api(affect),
            "updated_dt": affect.updated_dt,
        }

        with patch.object(Tracker, "save"):
            response = auth_client().put(
                f"{test_api_v2_uri}/affects/{affect.uuid}",
                affect_data,
                format="json",
                HTTP_BUGZILLA_API_KEY="SECRET",
                HTTP_JIRA_API_KEY="SECRET",
            )
            # the re-link is ignored, the update itself succeeds
            assert response.status_code == status.HTTP_200_OK
            assert response.json()["flaw"] == str(flaw1.uuid)

        # the affect stays linked to its original flaw
        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["flaw"] == str(flaw1.uuid)

    def test_keep_affect_flaw_unchanged(self, auth_client, test_api_v2_uri):
        """
        test that an update echoing back the affect's current flaw is accepted
        """
        flaw = FlawFactory(impact="MODERATE")
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            impact="MODERATE",
        )
        affect_data = {
            "embargoed": flaw.embargoed,
            "flaw": flaw.uuid,  # same flaw - allowed
            "ps_component": affect.ps_component,
            "ps_update_stream": affect.ps_update_stream,
            "purl": _affect_purl_for_api(affect),
            "impact": "LOW",
            "updated_dt": affect.updated_dt,
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        # the impact update takes effect in the response and in the DB
        assert response.json()["impact"] == "LOW"
        affect.refresh_from_db()
        assert affect.impact == "LOW"

    def test_ignore_affect_flaw_change_with_unique_conflict(
        self, auth_client, test_api_v2_uri
    ):
        """
        test that re-linking is ignored even when the submitted flaw already has
        an affect with the same update stream and component

        the submitted flaw must be discarded before DRF's unique-together
        validator runs, otherwise the validator checks the submitted flaw and
        rejects an otherwise valid update
        """
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        flaw1 = FlawFactory(impact="MODERATE")
        affect = AffectFactory(
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="shared-component",
            impact="MODERATE",
        )

        # another flaw already owns an affect on the very same stream + component
        flaw2 = FlawFactory(embargoed=flaw1.embargoed, impact="MODERATE")
        AffectFactory(
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            ps_component="shared-component",
        )

        affect_data = {
            "embargoed": flaw2.embargoed,
            "flaw": flaw2.uuid,  # attempt to re-link to the conflicting flaw
            "ps_component": affect.ps_component,
            "ps_update_stream": affect.ps_update_stream,
            "purl": _affect_purl_for_api(affect),
            "impact": "LOW",
            "updated_dt": affect.updated_dt,
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        # the submitted flaw is dropped before the unique-together check, so the
        # update succeeds and the affect stays linked to its original flaw
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["flaw"] == str(flaw1.uuid)
        assert response.json()["impact"] == "LOW"
        affect.refresh_from_db()
        assert affect.flaw == flaw1
        assert affect.impact == "LOW"

    @pytest.mark.parametrize(
        "bogus_flaw",
        [
            "ffffffff-ffff-ffff-ffff-ffffffffffff",  # nonexistent flaw UUID
            "not-a-uuid",  # malformed flaw ID
        ],
    )
    def test_ignore_affect_flaw_change_with_bogus_flaw(
        self, auth_client, test_api_v2_uri, bogus_flaw
    ):
        """
        test that an invalid submitted flaw does not reject the update

        the submitted parent flaw is ignored entirely, so a nonexistent or
        malformed flaw ID must be stripped before field validation rather than
        aborting the request
        """
        flaw = FlawFactory(impact="MODERATE")
        ps_module = PsModuleFactory()
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
        affect = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
            impact="MODERATE",
        )
        affect_data = {
            "embargoed": flaw.embargoed,
            "flaw": bogus_flaw,  # invalid flaw - must be ignored, not rejected
            "ps_component": affect.ps_component,
            "ps_update_stream": affect.ps_update_stream,
            "purl": _affect_purl_for_api(affect),
            "impact": "LOW",
            "updated_dt": affect.updated_dt,
        }

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            affect_data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        # the invalid flaw is dropped before validation; the update succeeds and
        # the affect stays linked to its original flaw
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["flaw"] == str(flaw.uuid)
        affect.refresh_from_db()
        assert affect.flaw == flaw
        assert affect.impact == "LOW"


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
        affect = AffectFactory(
            flaw=flaw,
            ps_component="podman",
            purl="",
            **_community_ps_for_affect(),
        )

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == 200
        original_body = response.json()
        assert original_body["ps_component"] == "podman"
        assert original_body["purl"] is None

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
        "ps_component,purl,error",
        [
            (
                "",
                "rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "Invalid PURL",
            ),
            (
                "podman",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "does not match user-provided ps_component",
            ),
            ("", "", "must have either purl or ps_component"),
            (None, None, "must have either purl or ps_component"),
        ],
    )
    def test_invalid_data_create(
        self, auth_client, test_api_v2_uri, ps_component, purl, error
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
            assert "rhacm-2.11.z" in str(response.content)

    @pytest.mark.parametrize(
        "ps_component,purl,error",
        [
            (
                "",
                "rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "Invalid PURL",
            ),
            (
                "podman",
                "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25",
                "does not match user-provided ps_component",
            ),
            ("", "", "must have either purl or ps_component"),
            (None, None, "must have either purl or ps_component"),
        ],
    )
    def test_invalid_data_update(
        self, auth_client, test_api_v2_uri, ps_component, purl, error
    ):
        """
        Test that Affect's purl and ps_component are not updated when new data contains incorrect purl,
        correct purl but its ps_component does not match the one included in purl,
        or purl and ps_component are missing.
        """
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(
            flaw=flaw,
            ps_component="podman",
            purl="",
            **_community_ps_for_affect(),
        )

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

    def test_affect_read_with_legacy_invalid_purl(self, auth_client, test_api_v2_uri):
        """
        Regression test: an affect whose purl fails current schema validation
        (e.g., pkg:oci with a namespace, which is prohibited by the oci PURL spec)
        but is already present in the database should always be readable via the
        API without errors.  Such data can exist as a result of schema rules being
        tightened after the data was originally written.

        The fix ensures that PURL schema validation is only applied on write
        (i.e. when preparing a value for the database), never on read.
        """
        from django.db import connection

        flaw = FlawFactory(embargoed=False)
        # Save-time validation requires a PURL for standard product streams; use any
        # valid value here and replace it with legacy invalid data via SQL below.
        affect = AffectFactory(flaw=flaw)

        # Bypass Django's ORM to insert a purl that fails current schema
        # validation: pkg:oci with a namespace is prohibited by the oci PURL
        # spec, so it would be rejected on save but may already live in the DB
        # as legacy data.
        legacy_purl = "pkg:oci/myregistry/myimage@sha256:abc123"
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE osidb_affect SET purl = %s WHERE uuid = %s",
                [legacy_purl, str(affect.uuid)],
            )

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["purl"] == legacy_purl


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
        set_user_acls(settings.ALL_GROUPS)
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
        set_user_acls(settings.ALL_GROUPS)
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
        set_user_acls(settings.ALL_GROUPS)
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
        set_user_acls(settings.ALL_GROUPS)
        assert AffectCVSS.objects.count() == 1


class TestAffectCreatorFields:
    """Tests for created_by, updated_by, assist_meta fields and related filters."""

    def test_create_sets_created_by_and_updated_by(self, auth_client, test_api_v2_uri):
        """POST /affects sets created_by and updated_by to the authenticated user."""
        flaw = FlawFactory(embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()
        data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": ps_update_stream.name,
            "ps_component": "curl",
            "purl": default_rpm_purl_for_ps_component("curl"),
            "embargoed": False,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        body = response.json()
        assert body["created_by"] != ""
        assert body["updated_by"] == body["created_by"]

    def test_update_changes_updated_by_not_created_by(
        self, auth_client, test_api_v2_uri
    ):
        """PUT /affects/{uuid} updates updated_by but never changes created_by."""
        flaw = FlawFactory(embargoed=False)
        affect = AffectFactory(flaw=flaw, created_by="original@example.com")
        affect.updated_by = "original@example.com"
        affect.save()

        response = auth_client().get(f"{test_api_v2_uri}/affects/{affect.uuid}")
        body = response.json()

        response = auth_client().put(
            f"{test_api_v2_uri}/affects/{affect.uuid}",
            {**body, "affectedness": "AFFECTED", "resolution": "DELEGATED"},
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
            HTTP_JIRA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_200_OK
        updated_body = response.json()
        assert updated_body["created_by"] == "original@example.com"
        assert updated_body["updated_by"] != updated_body["created_by"]

    def test_created_by_is_read_only(self, auth_client, test_api_v2_uri):
        """Submitting created_by in the request body is silently ignored."""
        flaw = FlawFactory(embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()
        data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": ps_update_stream.name,
            "ps_component": "curl",
            "purl": default_rpm_purl_for_ps_component("curl"),
            "embargoed": False,
            "created_by": "hacker@evil.com",
            "updated_by": "hacker@evil.com",
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        body = response.json()
        assert body["created_by"] != "hacker@evil.com"
        assert body["updated_by"] != "hacker@evil.com"

    def test_assist_meta_is_writable(self, auth_client, test_api_v2_uri):
        """assist_meta can be set by API clients on create and update."""
        flaw = FlawFactory(embargoed=False)
        ps_update_stream = PsUpdateStreamFactory()
        assist_meta = {
            "tool_name": "newcli 3.0.1",
            "tool_input": "newcli -s openssl --include hummingbird-1",
            "tool_output": "...",
            "tool_trigger": "manual",
        }
        data = {
            "flaw": str(flaw.uuid),
            "affectedness": Affect.AffectAffectedness.NEW,
            "resolution": Affect.AffectResolution.NOVALUE,
            "ps_update_stream": ps_update_stream.name,
            "ps_component": "curl",
            "purl": default_rpm_purl_for_ps_component("curl"),
            "embargoed": False,
            "assist_meta": assist_meta,
        }
        response = auth_client().post(
            f"{test_api_v2_uri}/affects",
            data,
            format="json",
            HTTP_BUGZILLA_API_KEY="SECRET",
        )
        assert response.status_code == status.HTTP_201_CREATED
        body = response.json()
        assert body["assist_meta"] == assist_meta

    def test_filter_created_by(self, auth_client, test_api_v2_uri):
        """GET /affects?created_by=X returns only affects with that creator."""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(flaw=flaw, created_by="ace@system")
        AffectFactory(flaw=flaw, created_by="user@example.com")

        response = auth_client().get(f"{test_api_v2_uri}/affects?created_by=ace@system")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1
        assert response.json()["results"][0]["created_by"] == "ace@system"

    def test_filter_is_tool_created(self, auth_client, test_api_v2_uri):
        """GET /affects?is_tool_created=true returns affects with non-null assist_meta."""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(
            flaw=flaw,
            assist_meta={
                "tool_name": "osidb 5.0",
                "tool_input": "...",
                "tool_output": "...",
                "tool_trigger": "...",
            },
        )
        AffectFactory(flaw=flaw, assist_meta=None)

        response = auth_client().get(f"{test_api_v2_uri}/affects?is_tool_created=true")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1

    def test_filter_amended(self, auth_client, test_api_v2_uri):
        """GET /affects?amended=true/false filters on whether created_by != updated_by."""
        flaw = FlawFactory(embargoed=False)
        AffectFactory(
            flaw=flaw, created_by="AffectCreationEngine", updated_by="user@example.com"
        )
        AffectFactory(
            flaw=flaw,
            created_by="AffectCreationEngine",
            updated_by="AffectCreationEngine",
        )

        response = auth_client().get(f"{test_api_v2_uri}/affects?amended=true")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1
        result = response.json()["results"][0]
        assert result["created_by"] != result["updated_by"]

        response = auth_client().get(f"{test_api_v2_uri}/affects?amended=false")
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["count"] == 1
        result = response.json()["results"][0]
        assert result["created_by"] == result["updated_by"]
