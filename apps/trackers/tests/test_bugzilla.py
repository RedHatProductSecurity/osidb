"""
Bugzilla specific tracker test cases
"""
import pytest

from apps.bbsync.constants import RHSCL_BTS_KEY
from apps.bbsync.tests.factories import BugzillaComponentFactory, BugzillaProductFactory
from apps.trackers.bugzilla.query import TrackerBugzillaQueryBuilder
from osidb.models import Affect, Tracker
from osidb.tests.factories import (
    AffectFactory,
    PsModuleFactory,
    PsUpdateStreamFactory,
    TrackerFactory,
)


class TestTrackerBugzillaQueryBuilder:
    """
    test Bugzilla tracker query building
    """

    @pytest.mark.parametrize(
        "ps_component,component_overrides,bz_component",
        [
            ("podman", {}, "podman"),
            ("container-tools:rhel8/podman", {}, "podman"),
            ("docker", {"docker": "podman"}, "podman"),
        ],
    )
    def test_generate_product_info(
        self, ps_component, component_overrides, bz_component
    ):
        """
        test that the product info query is correctly generated
        """
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Enterprise Linux 9",
            component_overrides=component_overrides,
            default_component=None,
        )
        ps_update_stream = PsUpdateStreamFactory(ps_module=ps_module)

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_module=ps_module.name,
            ps_component=ps_component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "product" in query
        assert query["product"] == ps_module.bts_key
        assert "component" in query
        assert query["component"] == bz_component  # this is what we mainly test here
        assert "sub_components" not in query
        assert "version" in query
        assert query["version"] == ps_update_stream.version

    @pytest.mark.parametrize(
        "ps_component,collections,bz_component,version",
        [
            ("podman", [], "podman", "unspecified"),
            ("podman", ["docker"], "podman", "unspecified"),
            ("podman", ["podman"], "podman", "podman"),
            ("podman-installer", ["podman"], "installer", "podman"),
        ],
    )
    def test_generate_product_info_rhscl(
        self, ps_component, collections, bz_component, version
    ):
        """
        test that the product info query is correctly generated for RHSCL
        """
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key=RHSCL_BTS_KEY,
            component_overrides={},
            default_component=None,
        )
        ps_update_stream = PsUpdateStreamFactory(
            collections=collections,
            ps_module=ps_module,
            version="default",
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_module=ps_module.name,
            ps_component=ps_component,
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "product" in query
        assert query["product"] == ps_module.bts_key
        assert "component" in query
        assert query["component"] == bz_component  # this is what we mainly test here
        assert "sub_components" not in query
        assert "version" in query
        assert query["version"] == version

    @pytest.mark.parametrize(
        "exists,expected_component",
        [
            (True, "original-component"),
            (False, "default-component"),
        ],
    )
    def test_override_component_with_default(self, exists, expected_component):
        """
        test that the component in the Bugzilla query is overriden
        when not existing in Bugzilla and the default is defined
        """
        if exists:
            product = BugzillaProductFactory(name="Red Hat Enterprise Linux 9")
            BugzillaComponentFactory(name="original-component", product=product)

        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Enterprise Linux 9",
            component_overrides={},
            default_component="default-component",
        )
        ps_update_stream = PsUpdateStreamFactory(
            collections=[],
            ps_module=ps_module,
            version="default-version",
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_module=ps_module.name,
            ps_component="original-component",
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "product" in query
        assert query["product"] == ps_module.bts_key
        assert "component" in query
        assert query["component"] == expected_component
        assert "sub_components" not in query
        assert "version" in query
        assert query["version"] == "default-version"

    def test_override_subcomponent_with_default(self):
        """
        test that the subcomponent in the Bugzilla query is overriden
        when not existing in Bugzilla and the default is defined
        """
        ps_module = PsModuleFactory(
            bts_name="bugzilla",
            bts_key="Red Hat Enterprise Linux 9",
            component_overrides={
                "podman": {
                    "component": "manager",
                    "sub_component": "installer",
                }
            },
            default_component=None,
        )
        ps_update_stream = PsUpdateStreamFactory(
            collections=[],
            ps_module=ps_module,
            version="version",
        )

        affect = AffectFactory(
            affectedness=Affect.AffectAffectedness.AFFECTED,
            ps_module=ps_module.name,
            ps_component="podman",
        )
        tracker = TrackerFactory(
            affects=[affect],
            embargoed=affect.flaw.embargoed,
            ps_update_stream=ps_update_stream.name,
            type=Tracker.TrackerType.BUGZILLA,
        )

        query = TrackerBugzillaQueryBuilder(tracker).query

        assert "product" in query
        assert query["product"] == ps_module.bts_key
        assert "component" in query
        assert query["component"] == "manager"
        assert "sub_components" in query
        assert query["sub_components"] == {"manager": ["installer"]}
        assert "version" in query
        assert query["version"] == "version"
