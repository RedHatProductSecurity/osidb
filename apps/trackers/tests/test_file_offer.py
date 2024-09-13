"""
Test cases for tracker suggestion generation
"""

import pytest

from osidb.dmodels import PsUpdateStream
from osidb.models import Affect, Flaw, Impact, UbiPackage
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
)

pytestmark = pytest.mark.unit


class TestTrackerSuggestions:
    """
    Test Tracker Suggestion generation
    """

    @pytest.mark.parametrize(
        "affectedness,resolution,is_valid",
        [
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                True,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DEFER,
                False,
            ),
            (
                Affect.AffectAffectedness.NEW,
                Affect.AffectResolution.DEFER,
                False,
            ),
        ],
    )
    def test_trackers_file_offer_invalid(
        self,
        affectedness,
        resolution,
        is_valid,
        user_token,
        auth_client,
        test_app_api_uri,
    ):
        """
        Test auto tracker auto filing defined in product
        definition rules related to invalid affects

        POST -> /file
        """

        flaw = FlawFactory(embargoed=False)
        ps_module_regular = PsModuleFactory(name="regular-module")
        affect = AffectFactory(
            flaw=flaw,
            affectedness=affectedness,
            resolution=resolution,
            ps_component="component-1",
            ps_module="regular-module",
        )
        PsUpdateStreamFactory(
            name="regular-stream-1",
            active_to_ps_module=ps_module_regular,
        )

        headers = {"HTTP_JiraAuthentication": user_token}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        if is_valid:
            assert len(res["not_applicable"]) == 0
            assert len(res["modules_components"]) > 0
            assert (
                res["modules_components"][0]["streams"][0]["ps_update_stream"]
                == "regular-stream-1"
            )
        else:
            assert len(res["not_applicable"]) == 1
            assert res["not_applicable"][0]["uuid"] == str(affect.uuid)
            assert len(res["modules_components"]) == 0

    def test_trackers_file_offer_embargoed(
        self, user_token, auth_client, test_app_api_uri
    ):
        """
        Test auto tracker auto filing defined in product
        definition rules related to embargo status

        POST -> /file
        """

        flaw = FlawFactory(embargoed=False)
        ps_module_regular = PsModuleFactory(
            name="regular-module",
            private_trackers_allowed=True,
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="component-1",
            ps_module="regular-module",
        )
        PsUpdateStreamFactory(
            name="regular-stream-1",
            active_to_ps_module=ps_module_regular,
        )

        flaw_embargoed = FlawFactory(embargoed=True)
        ps_module_public = PsModuleFactory(
            name="public-only-module",
            private_trackers_allowed=False,
        )
        PsUpdateStreamFactory(
            name="public-only-stream-1",
            active_to_ps_module=ps_module_public,
        )
        affect_embargoed = AffectFactory(
            flaw=flaw_embargoed,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="component-1",
            ps_module="public-only-module",
        )

        headers = {"HTTP_JiraAuthentication": user_token}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid, flaw_embargoed.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        assert "not_applicable" in res and len(res["not_applicable"]) > 0
        assert res["not_applicable"][0]["uuid"] == str(affect_embargoed.uuid)
        assert "modules_components" in res and len(res["modules_components"]) > 0
        assert (
            res["modules_components"][0]["streams"][0]["ps_update_stream"]
            == "regular-stream-1"
        )

    def test_trackers_file_offer_ubi(self, user_token, auth_client, test_app_api_uri):
        """
        Test auto tracker auto filing defined in product
        definition rules related to ubi special rules

        POST -> /file
        """
        flaw = FlawFactory(embargoed=False, impact=Impact.MODERATE)

        AffectFactory(
            impact=Impact.MODERATE,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="component-1",
            ps_module="ubi-module",
        )
        UbiPackage(name="component-1").save()
        ps_module_ubi = PsModuleFactory(
            name="ubi-module", special_handling_features=["ubi_packages"]
        )
        PsUpdateStream(
            name="stream-2",
            ps_module=ps_module_ubi,
            active_to_ps_module=ps_module_ubi,
            unacked_to_ps_module=ps_module_ubi,
        ).save()
        PsUpdateStream(
            name="stream-2.0.z",
            ps_module=ps_module_ubi,
            active_to_ps_module=ps_module_ubi,
        ).save()
        PsUpdateStream(
            name="stream-2.1",
            ps_module=ps_module_ubi,
            active_to_ps_module=ps_module_ubi,
            default_to_ps_module=ps_module_ubi,
        ).save()
        PsUpdateStream(
            name="stream-2.0",
            ps_module=ps_module_ubi,
            active_to_ps_module=ps_module_ubi,
            default_to_ps_module=ps_module_ubi,
        ).save()

        headers = {"HTTP_JiraAuthentication": user_token}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        assert len(res["not_applicable"]) == 0
        assert len(res["modules_components"]) > 0
        streams = res["modules_components"][0]["streams"]

        assert sorted([stream["ps_update_stream"] for stream in streams]) == sorted(
            [
                "stream-2",
                "stream-2.0.z",
                "stream-2.1",
                "stream-2.0",
            ]
        )

        streams_dict = {stream["ps_update_stream"]: stream for stream in streams}

        assert (
            "stream-2.0.z" in streams_dict and streams_dict["stream-2.0.z"]["selected"]
        )
        assert (
            "stream-2.0" in streams_dict and not streams_dict["stream-2.0"]["selected"]
        )
        assert "stream-2.1" in streams_dict and streams_dict["stream-2.1"]["selected"]

        # The unacked stream must be deselected when ubi streams are selected.
        # Ref. sfm2/api/blueprints/tracker_bp.py::trackers_file_offer
        assert "stream-2" in streams_dict and not streams_dict["stream-2"]["selected"]

    def test_trackers_file_offer_unacked(
        self, user_token, auth_client, test_app_api_uri
    ):
        """
        Test auto tracker auto filing defined in product
        definition rules related to unacked_ps_update_stream flag

        POST -> /file
        """
        # if flag is present, UBI unacked auto select low impact
        flaw1 = FlawFactory(embargoed=False, impact=Impact.LOW)

        AffectFactory(
            impact=Impact.LOW,
            flaw=flaw1,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="ubi-component",
            ps_module="ubi-module",
        )
        UbiPackage(name="ubi-component").save()
        ps_module_ubi = PsModuleFactory(
            name="ubi-module",
            special_handling_features=["ubi_packages"],
        )
        PsUpdateStream(
            name="stream-2.0.z",
            ps_module=ps_module_ubi,
            active_to_ps_module=ps_module_ubi,
            unacked_to_ps_module=ps_module_ubi,
        ).save()

        # if flag is present, UBI unacked does not select moderate impact
        flaw2 = FlawFactory(embargoed=False, impact=Impact.MODERATE)
        AffectFactory(
            impact=Impact.MODERATE,
            flaw=flaw2,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="ubi-component",
            ps_module="ubi-module",
        )
        PsUpdateStream(
            name="otherstream-3.1.z",
            ps_module=ps_module_ubi,
            active_to_ps_module=ps_module_ubi,
        ).save()

        headers = {"HTTP_JiraAuthentication": user_token}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw1.uuid, flaw2.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        assert len(res["not_applicable"]) == 0
        assert len(res["modules_components"]) > 0
        streams = res["modules_components"][0]["streams"]
        streams_dict = {stream["ps_update_stream"]: stream for stream in streams}

        assert (
            "stream-2.0.z" in streams_dict and streams_dict["stream-2.0.z"]["selected"]
        )
        assert (
            "otherstream-3.1.z" in streams_dict
            and not streams_dict["otherstream-3.1.z"]["selected"]
        )

        # if flag is present, not ubi packages can have unacked with low and moderate impact
        flaw3 = FlawFactory(
            embargoed=False,
            impact=Impact.LOW,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        ps_module_regular = PsModuleFactory(
            name="regular-module",
            private_trackers_allowed=True,
        )
        AffectFactory(
            flaw=flaw3,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="regular-component",
            ps_module="regular-module",
        )
        PsUpdateStream(
            name="regular-stream-1.0",
            ps_module=ps_module_regular,
            active_to_ps_module=ps_module_regular,
            unacked_to_ps_module=ps_module_regular,
        ).save()

        headers = {"HTTP_JiraAuthentication": user_token}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw3.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        assert len(res["not_applicable"]) == 0
        assert len(res["modules_components"]) > 0
        streams = res["modules_components"][0]["streams"]
        streams_dict = {stream["ps_update_stream"]: stream for stream in streams}

        assert (
            "regular-stream-1.0" in streams_dict
            and streams_dict["regular-stream-1.0"]["selected"]
        )

    @pytest.mark.parametrize(
        "handled_by_unacked,handled_by_ubi,major_incident",
        [
            (True, False, False),
            (True, False, True),
            (False, True, False),
            (False, False, False),
        ],
    )
    def test_trackers_file_offer_handler_shadowing(
        self,
        user_token,
        auth_client,
        test_app_api_uri,
        handled_by_unacked,
        handled_by_ubi,
        major_incident,
    ):
        """
        Test that more important handlers suppress behavior
        of less important handlers.

        POST -> /file
        """
        if major_incident:
            flaw = FlawFactory(
                embargoed=False,
                impact=Impact.MODERATE,
                major_incident_state=Flaw.FlawMajorIncident.APPROVED,
            )
        else:
            flaw = FlawFactory(
                embargoed=False,
                impact=Impact.MODERATE,
                major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
            )

        AffectFactory(
            impact=Impact.MODERATE,
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="component-1",
            ps_module="module",
        )

        # When testing the unacked_handler alone, don't test anything UBI-related.
        # When testing ubi_handler, test that this is treated as a UBI package.
        if handled_by_ubi:
            UbiPackage(name="component-1").save()
            ps_module = PsModuleFactory(
                name="module", special_handling_features=["ubi_packages"]
            )
        else:
            ps_module = PsModuleFactory(name="module")

        PsUpdateStream(
            name="stream-2",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
            unacked_to_ps_module=ps_module,
        ).save()
        PsUpdateStream(
            name="stream-2.0.z",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
        ).save()
        PsUpdateStream(
            name="stream-2.0",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
            default_to_ps_module=ps_module,
        ).save()

        headers = {"HTTP_JiraAuthentication": user_token}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        assert len(res["not_applicable"]) == 0
        assert len(res["modules_components"]) > 0
        streams = res["modules_components"][0]["streams"]

        assert sorted([stream["ps_update_stream"] for stream in streams]) == sorted(
            [
                "stream-2",
                "stream-2.0.z",
                "stream-2.0",
            ]
        )

        streams_dict = {stream["ps_update_stream"]: stream for stream in streams}

        if handled_by_unacked:
            assert not streams_dict["stream-2.0.z"]["selected"]
            assert not streams_dict["stream-2.0"]["selected"]
            # The unacked stream:
            if major_incident:
                assert not streams_dict["stream-2"]["selected"]
            else:
                assert streams_dict["stream-2"]["selected"]

        if handled_by_ubi:
            assert streams_dict["stream-2.0.z"]["selected"]
            assert not streams_dict["stream-2.0"]["selected"]
            # The unacked stream must be deselected when ubi streams are selected.
            # Ref. sfm2/api/blueprints/tracker_bp.py::trackers_file_offer
            assert not streams_dict["stream-2"]["selected"]

    @pytest.mark.parametrize(
        "affectedness,resolution,should_suggest",
        [
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.NOVALUE, True),
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.WONTFIX, False),
            (Affect.AffectAffectedness.NEW, Affect.AffectResolution.OOSS, False),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.DELEGATED,
                True,
            ),
            (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.FIX, True),
            (
                Affect.AffectAffectedness.AFFECTED,
                Affect.AffectResolution.WONTFIX,
                False,
            ),
            (Affect.AffectAffectedness.AFFECTED, Affect.AffectResolution.OOSS, False),
            (
                Affect.AffectAffectedness.NOTAFFECTED,
                Affect.AffectResolution.NOVALUE,
                False,
            ),
        ],
    )
    def test_trackers_file_offer_affect_states(
        self,
        auth_client,
        test_app_api_uri,
        user_token,
        affectedness,
        resolution,
        should_suggest,
    ):
        """
        Test that we can suggest trackers only for the
        following combination of Affectedness,Resolution:
         - (NEW, None)
         - (AFFECTED, DELEGATED)
         - (AFFECTED, FIX) - legacy combination

        POST -> /file
        """

        flaw = FlawFactory(
            embargoed=False,
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        ps_module = PsModuleFactory(name="test-module")

        affect = Affect(
            impact=Impact.MODERATE,
            flaw=flaw,
            affectedness=affectedness,
            resolution=resolution,
            ps_component="component-1",
            ps_module=ps_module.name,
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        affect.save(
            raise_validation_error=False
        )  # allow legacy (affectedness,resolution)

        PsUpdateStream(
            name="stream-2",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
            unacked_to_ps_module=ps_module,
        ).save()

        headers = {"HTTP_JiraAuthentication": user_token}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        if should_suggest:
            assert len(res["not_applicable"]) == 0
            assert res["modules_components"][0]["affect"]["uuid"] == str(affect.uuid)
        else:
            assert len(res["modules_components"]) == 0
            assert res["not_applicable"][0]["uuid"] == str(affect.uuid)
