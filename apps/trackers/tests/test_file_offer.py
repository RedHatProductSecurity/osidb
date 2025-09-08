"""
Test cases for tracker suggestion generation
"""

import pytest
from django.utils import timezone
from freezegun import freeze_time

from apps.trackers.product_definition_handlers.base import ProductDefinitionRules
from apps.trackers.product_definition_handlers.default_handler import DefaultHandler
from apps.trackers.product_definition_handlers.major_incident_handler import (
    MajorIncidentHandler,
)
from apps.trackers.product_definition_handlers.moderate_handler import ModerateHandler
from apps.trackers.product_definition_handlers.unacked_handler import UnackedHandler
from osidb.models import Affect, Flaw, Impact, PsUpdateStream, Tracker
from osidb.tests.factories import (
    AffectFactory,
    FlawFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
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
        auth_client,
        test_app_api_uri,
    ):
        """
        Test auto tracker auto filing defined in product
        definition rules related to invalid affects

        POST -> /file
        """

        flaw = FlawFactory(embargoed=False)
        ps_module = PsModuleFactory(name="regular-module")
        ps_update_stream = PsUpdateStreamFactory(
            name="regular-stream-1",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
        )
        affect = AffectFactory(
            flaw=flaw,
            affectedness=affectedness,
            resolution=resolution,
            ps_component="component-1",
            ps_update_stream=ps_update_stream.name,
        )

        headers = {"HTTP_JiraAuthentication": "SECRET"}
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

    def test_trackers_file_offer_embargoed(self, auth_client, test_app_api_uri):
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
        ps_update_stream_regular = PsUpdateStreamFactory(
            name="regular-stream-1",
            ps_module=ps_module_regular,
            active_to_ps_module=ps_module_regular,
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="component-1",
            ps_update_stream=ps_update_stream_regular.name,
        )

        flaw_embargoed = FlawFactory(embargoed=True)
        ps_module_public = PsModuleFactory(
            name="public-only-module",
            private_trackers_allowed=False,
        )
        ps_update_stream_public = PsUpdateStreamFactory(
            name="public-only-stream-1",
            ps_module=ps_module_public,
            active_to_ps_module=ps_module_public,
        )
        affect_embargoed = AffectFactory(
            flaw=flaw_embargoed,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_component="component-1",
            ps_update_stream=ps_update_stream_public.name,
        )

        headers = {"HTTP_JiraAuthentication": "SECRET"}
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
        PsUpdateStream(
            name="stream-2",
            ps_module=ps_module,
            active_to_ps_module=ps_module,
            unacked_to_ps_module=ps_module,
        ).save()

        affect = Affect(
            impact=Impact.MODERATE,
            flaw=flaw,
            affectedness=affectedness,
            resolution=resolution,
            ps_component="component-1",
            ps_update_stream="stream-2",
            acl_read=flaw.acl_read,
            acl_write=flaw.acl_write,
        )
        affect.save(
            raise_validation_error=False
        )  # allow legacy (affectedness,resolution)

        headers = {"HTTP_JiraAuthentication": "SECRET"}
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

    def test_trackers_file_offer_unsupported(self, auth_client, test_app_api_uri):
        """
        test that an unsupported PS module is resolved as not applicable
        """
        # PS module is supported from tomorrow which should have no effect
        # PS module is supported until the day after tomorrow so still supported
        ps_module = PsModuleFactory(
            supported_from_dt=timezone.now() + timezone.timedelta(1),
            supported_until_dt=timezone.now() + timezone.timedelta(2),
        )
        ps_update_stream = PsUpdateStreamFactory(
            ps_module=ps_module,
            active_to_ps_module=ps_module,
            default_to_ps_module=ps_module,
        )

        flaw = FlawFactory(embargoed=False, impact=Impact.CRITICAL)
        AffectFactory(
            flaw=flaw,
            impact=flaw.impact,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=ps_update_stream.name,
        )

        headers = {"HTTP_JiraAuthentication": "SECRET"}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            **headers,
        )
        res = response.json()
        assert not res["not_applicable"]
        assert res["modules_components"]

        # and now it is the day after the support end
        with freeze_time(timezone.now() + timezone.timedelta(3)):
            headers = {"HTTP_JiraAuthentication": "SECRET"}
            response = auth_client().post(
                f"{test_app_api_uri}/file",
                data={"flaw_uuids": [flaw.uuid]},
                format="json",
                **headers,
            )
            res = response.json()
            assert res["not_applicable"]
            assert not res["modules_components"]

    @pytest.mark.parametrize(
        "impact,"
        "streams,"
        "active_streams,"
        "default_streams,"
        "moderate_streams,"
        "unacked_streams,"
        "major_incident_state,"
        "expected_available_streams,"
        "expected_selected_streams",
        [
            # no streams
            (
                Impact.CRITICAL,
                [],
                [],
                [],
                [],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                [],
                [],
            ),
            # inactive streams only
            (
                Impact.CRITICAL,
                ["stream1", "stream2"],
                [],
                [],
                [],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                [],
                [],
            ),
            # inactive and active streams but no default
            (
                Impact.CRITICAL,
                ["stream1", "stream2"],
                ["stream1"],
                [],
                [],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1"],
                [],
            ),
            # default and non-default streams
            (
                Impact.CRITICAL,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                ["stream1"],
            ),
            (
                Impact.IMPORTANT,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                ["stream1"],
            ),
            # no moderate or unacked streams
            (
                Impact.MODERATE,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                [],
            ),
            (
                Impact.LOW,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                [],
            ),
            # unacked streams
            (
                Impact.CRITICAL,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                ["stream2"],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                ["stream1"],  # default beats unacked
            ),
            (
                Impact.MODERATE,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                ["stream2"],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                ["stream2"],  # unacked beats default
            ),
            (
                Impact.LOW,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                ["stream2"],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                [],
            ),
            # moderate streams
            (
                Impact.IMPORTANT,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                ["stream2"],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                ["stream1"],  # default beats moderate
            ),
            (
                Impact.MODERATE,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                ["stream2"],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                ["stream2"],  # moderate beats default
            ),
            (
                Impact.MODERATE,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                [],
                ["stream1"],
                ["stream2"],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                ["stream1", "stream2"],  # both moderate and unacked selected
            ),
            (
                Impact.LOW,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                ["stream2"],
                [],
                Flaw.FlawMajorIncident.NOVALUE,
                ["stream1", "stream2"],
                [],
            ),
            # Major Incident streams
            (
                Impact.LOW,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream2"],
                [],
                [],
                Flaw.FlawMajorIncident.APPROVED,
                ["stream1", "stream2"],
                ["stream2"],  # Major Incident enforces default
            ),
            (
                Impact.LOW,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                [],
                Flaw.FlawMajorIncident.CISA_APPROVED,
                ["stream1", "stream2"],
                ["stream1"],  # Major Incident enforces default
            ),
            (
                Impact.LOW,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                [],
                Flaw.FlawMajorIncident.ZERO_DAY,
                ["stream1", "stream2"],
                ["stream1"],  # Major Incident enforces default
            ),
            (
                Impact.MODERATE,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                ["stream2"],
                [],
                Flaw.FlawMajorIncident.APPROVED,
                ["stream1", "stream2"],
                ["stream1"],  # Major Incident beats moderate
            ),
            (
                Impact.MODERATE,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                ["stream2"],
                [],
                Flaw.FlawMajorIncident.MINOR,
                ["stream1", "stream2"],
                ["stream2"],  # Minor Incident makes no change
            ),
            (
                Impact.MODERATE,
                ["stream1", "stream2", "stream3"],
                ["stream1", "stream2"],
                ["stream1"],
                [],
                ["stream2"],
                Flaw.FlawMajorIncident.APPROVED,
                ["stream1", "stream2"],
                ["stream1"],  # Major Incident beats unacked
            ),
        ],
    )
    def test_trackers_file_offer(
        self,
        auth_client,
        test_app_api_uri,
        impact,
        streams,
        active_streams,
        default_streams,
        moderate_streams,
        unacked_streams,
        major_incident_state,
        expected_available_streams,
        expected_selected_streams,
    ):
        """
        integration tests various tracker file offer scenarios
        """
        # 1) context
        ps_module = PsModuleFactory()

        flaw = FlawFactory(
            embargoed=False,
            impact=impact,
            major_incident_state=major_incident_state,
        )

        for stream in streams:
            ps_update_stream = PsUpdateStreamFactory(
                name=stream,
                ps_module=ps_module,
                active_to_ps_module=ps_module if stream in active_streams else None,
                default_to_ps_module=ps_module if stream in default_streams else None,
                moderate_to_ps_module=ps_module if stream in moderate_streams else None,
                unacked_to_ps_module=ps_module if stream in unacked_streams else None,
            )
            AffectFactory(
                flaw=flaw,
                impact=flaw.impact,
                affectedness=Affect.AffectAffectedness.AFFECTED,
                resolution=Affect.AffectResolution.DELEGATED,
                ps_component="component",
                ps_update_stream=ps_update_stream.name,
            )

        # 2) query
        headers = {"HTTP_JiraAuthentication": "SECRET"}
        response = auth_client().post(
            f"{test_app_api_uri}/file",
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        # 3) response processing
        if not res["modules_components"]:
            available_streams, selected_streams = [], []
        else:
            streams = [
                r["streams"][0] for r in res["modules_components"] if r["streams"]
            ]
            available_streams = sorted(stream["ps_update_stream"] for stream in streams)
            selected_streams = sorted(
                stream["ps_update_stream"] for stream in streams if stream["selected"]
            )

        # 4) assertions
        assert available_streams == expected_available_streams
        assert selected_streams == expected_selected_streams

    @pytest.mark.parametrize(
        "exclude_existing_trackers,expected_stream_1,expected_stream_2,expected_total",
        [
            (None, True, True, 2),  # default behaviour
            (False, True, True, 2),  # explicit False
            (True, False, True, 1),  # explicit True
        ],
    )
    def test_trackers_file_offer_exclude_existing_trackers(
        self,
        auth_client,
        test_app_api_uri,
        exclude_existing_trackers,
        expected_stream_1,
        expected_stream_2,
        expected_total,
    ):
        """
        Test that existing trackers are correctly excluded when exclude_existing_trackers is provided
        """
        flaw = FlawFactory(
            embargoed=False,
            impact=Impact.MODERATE,
            major_incident_state=Flaw.FlawMajorIncident.NOVALUE,
        )
        ps_module = PsModuleFactory(name="test-module")

        # Create two update streams
        stream1 = PsUpdateStreamFactory(
            ps_module=ps_module,
            active_to_ps_module=ps_module,
            moderate_to_ps_module=ps_module,
        )
        stream2 = PsUpdateStreamFactory(
            ps_module=ps_module,
            active_to_ps_module=ps_module,
            moderate_to_ps_module=ps_module,
        )

        # Create an affect for each stream
        affect1 = AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=stream1.name,
        )
        AffectFactory(
            flaw=flaw,
            affectedness=Affect.AffectAffectedness.AFFECTED,
            resolution=Affect.AffectResolution.DELEGATED,
            ps_update_stream=stream2.name,
        )

        # Create an existing tracker for stream1
        TrackerFactory(
            affects=[affect1],
            ps_update_stream=stream1.name,
            embargoed=flaw.embargoed,
            type=Tracker.BTS2TYPE[ps_module.bts_name],
        )

        headers = {"HTTP_JiraAuthentication": "SECRET"}

        # Build URL with parameter if specified
        url = f"{test_app_api_uri}/file"
        if exclude_existing_trackers is not None:
            url += (
                f"?exclude_existing_trackers={str(exclude_existing_trackers).lower()}"
            )

        response = auth_client().post(
            url,
            data={"flaw_uuids": [flaw.uuid]},
            format="json",
            **headers,
        )
        res = response.json()

        assert len(res["modules_components"]) == 2
        available_streams = [
            stream["ps_update_stream"]
            for module in res["modules_components"]
            for stream in module["streams"]
        ]

        # Check expectations
        assert len(available_streams) == expected_total
        assert (stream1.name in available_streams) == expected_stream_1
        assert (stream2.name in available_streams) == expected_stream_2

    class TestDefaultHandler:
        @pytest.mark.parametrize(
            "impact,is_applicable",
            [
                (Impact.CRITICAL, True),
                (Impact.IMPORTANT, True),
                (Impact.MODERATE, False),
                (Impact.LOW, False),
            ],
        )
        def test_is_applicable_impact(self, impact, is_applicable):
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affect = AffectFactory(ps_update_stream=ps_update_stream.name)
            assert is_applicable == DefaultHandler.is_applicable(
                affect, impact, ps_module
            )

        def test_get_offer_no_active_default(self):
            ps_module = PsModuleFactory()
            ps_update_stream1 = PsUpdateStreamFactory(
                ps_module=ps_module,
                active_to_ps_module=None,  # inactive
                default_to_ps_module=ps_module,
            )
            ps_update_stream2 = PsUpdateStreamFactory(
                ps_module=ps_module,
                active_to_ps_module=ps_module,
                default_to_ps_module=None,  # non-default
            )
            affect1 = AffectFactory(ps_update_stream=ps_update_stream1.name)
            affect2 = AffectFactory(ps_update_stream=ps_update_stream2.name)

            framework = ProductDefinitionRules()
            framework.handlers = [DefaultHandler()]
            # no existing active default to be selected
            offer1 = framework.file_tracker_offer(
                affect1, Impact.CRITICAL, ps_update_stream1
            )
            assert offer1 is None
            offer2 = framework.file_tracker_offer(
                affect2, Impact.CRITICAL, ps_update_stream2
            )
            assert offer2
            assert ps_update_stream2.name == offer2["ps_update_stream"]
            assert offer2["selected"] is False

        def test_get_offer(self):
            ps_module = PsModuleFactory()
            stream1 = PsUpdateStreamFactory(
                ps_module=ps_module,
                active_to_ps_module=ps_module,
                default_to_ps_module=ps_module,
            )
            PsUpdateStreamFactory(
                ps_module=ps_module,
                active_to_ps_module=ps_module,
                default_to_ps_module=ps_module,
            )
            affect1 = AffectFactory(ps_update_stream=stream1.name)
            AffectFactory(ps_update_stream=stream1.name)

            framework = ProductDefinitionRules()
            framework.handlers = [DefaultHandler()]
            # the offer for a single affect should include a single stream
            offer = framework.file_tracker_offer(affect1, Impact.CRITICAL, stream1)
            assert offer
            assert stream1.name == offer["ps_update_stream"]
            assert offer["selected"] is True

    class TestMajorIncidentHandler:
        @pytest.mark.parametrize(
            "major_incident_state,is_applicable",
            [
                (Flaw.FlawMajorIncident.APPROVED, True),
                (Flaw.FlawMajorIncident.CISA_APPROVED, True),
                (Flaw.FlawMajorIncident.MINOR, False),
                (Flaw.FlawMajorIncident.ZERO_DAY, True),
                (Flaw.FlawMajorIncident.REQUESTED, False),
                (Flaw.FlawMajorIncident.REJECTED, False),
                (Flaw.FlawMajorIncident.NOVALUE, False),
            ],
        )
        def test_is_applicable(self, major_incident_state, is_applicable):
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affect = AffectFactory(
                flaw__major_incident_state=major_incident_state,
                ps_update_stream=ps_update_stream.name,
            )
            assert is_applicable == MajorIncidentHandler.is_applicable(
                affect, affect.impact, ps_update_stream
            )

        # the offer creation works completely the save way as for the DefaultHandler
        # so we do not need to test it here again as it is already tested there

    class TestModerateHandler:
        @pytest.mark.parametrize(
            "impact,is_applicable",
            [
                (Impact.CRITICAL, False),
                (Impact.IMPORTANT, False),
                (Impact.MODERATE, True),
                (Impact.LOW, False),
            ],
        )
        def test_is_applicable_impact(self, impact, is_applicable):
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(
                active_to_ps_module=ps_module,
                moderate_to_ps_module=ps_module,
            )
            affect = AffectFactory(ps_update_stream=ps_update_stream.name)
            assert is_applicable == ModerateHandler.is_applicable(
                affect, impact, ps_update_stream
            )

        @pytest.mark.parametrize(
            "moderate_stream,is_applicable",
            [
                (False, False),
                (True, True),
            ],
        )
        def test_is_applicable_moderate_stream(self, moderate_stream, is_applicable):
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(
                active_to_ps_module=ps_module,
                moderate_to_ps_module=ps_module if moderate_stream else None,
            )
            affect = AffectFactory(ps_update_stream=ps_update_stream.name)
            assert is_applicable == ModerateHandler.is_applicable(
                affect, Impact.MODERATE, ps_update_stream
            )

        def test_get_offer(self):
            # TODO: Parametrize
            ps_module = PsModuleFactory()

            framework = ProductDefinitionRules()
            framework.handlers = [ModerateHandler()]

            ps_update_stream1 = PsUpdateStreamFactory(
                active_to_ps_module=None,
                moderate_to_ps_module=None,
            )
            ps_update_stream2 = PsUpdateStreamFactory(
                active_to_ps_module=ps_module,
                moderate_to_ps_module=None,
            )
            ps_update_stream3 = PsUpdateStreamFactory(
                active_to_ps_module=ps_module,
                moderate_to_ps_module=ps_module,
            )
            affect1 = AffectFactory(ps_update_stream=ps_update_stream1.name)
            affect2 = AffectFactory(ps_update_stream=ps_update_stream2.name)
            affect3 = AffectFactory(ps_update_stream=ps_update_stream3.name)

            # active streams should be included in the offer
            # and the moderate one should be pre-selected
            offer1 = framework.file_tracker_offer(
                affect1, Impact.MODERATE, ps_update_stream1
            )
            assert offer1 is None

            offer2 = framework.file_tracker_offer(
                affect2, Impact.MODERATE, ps_update_stream2
            )
            assert offer2
            assert ps_update_stream2.name == offer2["ps_update_stream"]
            assert offer2["selected"] is False

            offer3 = framework.file_tracker_offer(
                affect3, Impact.MODERATE, ps_update_stream3
            )
            assert offer3
            assert ps_update_stream3.name == offer3["ps_update_stream"]
            assert offer3["selected"] is True

    class TestUnackedHandler:
        @pytest.mark.parametrize(
            "impact,is_applicable",
            [
                (Impact.CRITICAL, False),
                (Impact.IMPORTANT, False),
                (Impact.MODERATE, True),
                (Impact.LOW, True),
            ],
        )
        def test_is_applicable(self, impact, is_applicable):
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)
            affect = AffectFactory(ps_update_stream=ps_update_stream.name)
            assert is_applicable == UnackedHandler.is_applicable(
                affect, impact, ps_update_stream
            )

        def test_get_offer_present(self):
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(
                active_to_ps_module=None,
                unacked_to_ps_module=ps_module,
            )
            affect = AffectFactory(ps_update_stream=ps_update_stream.name)

            framework = ProductDefinitionRules()
            framework.handlers = [UnackedHandler()]

            # no existing unacked stream to be offered
            assert (
                framework.file_tracker_offer(affect, Impact.MODERATE, ps_update_stream)
                is None
            )

            ps_update_stream.active_to_ps_module = ps_module
            ps_update_stream.save()
            # unacked stream should be included in the offer
            offer = framework.file_tracker_offer(
                affect, Impact.MODERATE, ps_update_stream
            )
            assert offer
            assert ps_update_stream.name == offer["ps_update_stream"]

        @pytest.mark.parametrize(
            "impact,preselected",
            [
                (Impact.MODERATE, True),
                (Impact.LOW, False),
            ],
        )
        def test_get_offer_preselected(self, impact, preselected):
            ps_module = PsModuleFactory()
            ps_update_stream = PsUpdateStreamFactory(
                active_to_ps_module=ps_module,
                unacked_to_ps_module=ps_module,
            )
            affect = AffectFactory(ps_update_stream=ps_update_stream.name)

            framework = ProductDefinitionRules()
            framework.handlers = [UnackedHandler()]

            offer = framework.file_tracker_offer(affect, impact, ps_update_stream)
            assert offer
            assert ps_update_stream.name == offer["ps_update_stream"]
            assert offer["selected"] == preselected
